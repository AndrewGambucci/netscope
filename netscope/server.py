"""Flask + Socket.IO server: serves the UI, receives events from the capture helper."""
from __future__ import annotations

import hmac
import json
import secrets
import socket
import threading
from collections.abc import Callable

from flask import Flask, abort, render_template, request
from flask_socketio import SocketIO

from netscope import __version__, demo, firewall, paths, privilege
from netscope.geo import GeoDB
from netscope.logs import log
from netscope.pipeline import Pipeline
from netscope.settings import Settings

NPCAP_URL = "https://npcap.com/#download"
HELPER_START_TIMEOUT = 90          # seconds: includes time to type a password


def pick_port(preferred: int = 6767) -> int:
    """The preferred port if it's free, otherwise any free port."""
    for candidate in (preferred, 0):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", candidate))
                return s.getsockname()[1]
            except OSError:
                continue
    raise RuntimeError("no free local port")


class HelperListener:
    """Loopback endpoint the capture helper connects back to. Authenticated with a random token."""

    def __init__(self, on_message: Callable[[dict], None], on_disconnect: Callable[[], None]) -> None:
        self.token = secrets.token_urlsafe(24)
        self._on_message = on_message
        self._on_disconnect = on_disconnect
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(2)
        self.port = self._sock.getsockname()[1]
        self.connected = threading.Event()
        threading.Thread(target=self._accept_loop, daemon=True, name="helper-listener").start()

    def _accept_loop(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True, name="helper-conn").start()

    def _serve(self, conn: socket.socket) -> None:
        authed = False
        try:
            with conn, conn.makefile("r", encoding="utf-8", newline="\n") as lines:
                conn.settimeout(10)
                for raw in iter(lambda: lines.readline(8192), ""):
                    try:
                        msg = json.loads(raw)
                    except ValueError:
                        continue
                    if not isinstance(msg, dict):
                        continue
                    if not authed:
                        if msg.get("t") == "hello" and hmac.compare_digest(str(msg.get("token", "")), self.token):
                            authed = True
                            conn.settimeout(None)
                            self.connected.set()
                            continue
                        return                      # wrong/missing token: drop the connection
                    self._on_message(msg)
        except (OSError, ValueError):
            pass
        finally:
            if authed:
                self.connected.clear()
                self._on_disconnect()


class Hub:
    """Owns app state: current status, capture lifecycle, demo mode."""

    def __init__(self, socketio: SocketIO, settings: Settings, geo: GeoDB) -> None:
        self.socketio = socketio
        self.settings = settings
        self.geo = geo
        self.pipeline = Pipeline(geo, settings, socketio.emit)
        self.status: dict = {"mode": "starting", "message": ""}
        self._lock = threading.Lock()
        self._starting_live = False
        self._demo_stop: threading.Event | None = None
        self._listener: HelperListener | None = None
        self._workers = threading.BoundedSemaphore(8)
        self._block_lock = threading.Lock()       # one firewall change (and UAC prompt) at a time

    # ── status ───────────────────────────────────────────────────────────────
    def set_status(self, mode: str, message: str = "", **extra) -> None:
        self.status = {"mode": mode, "message": message, **extra}
        log.info("status: %s %s", mode, message)
        self.socketio.emit("status", self.status)

    # ── helper messages ──────────────────────────────────────────────────────
    @property
    def listener(self) -> HelperListener:
        if self._listener is None:
            self._listener = HelperListener(self._on_helper_message, self._on_helper_gone)
        return self._listener

    def _on_helper_message(self, msg: dict) -> None:
        kind = msg.get("t")
        if kind == "ev":
            # lookups and reverse DNS can block briefly: don't stall the socket reader,
            # but cap concurrency so a SYN flood can't spawn unbounded threads
            if self._workers.acquire(blocking=False):
                def work() -> None:
                    try:
                        self.pipeline.handle(msg)
                    finally:
                        self._workers.release()
                threading.Thread(target=work, daemon=True).start()
        elif kind == "ready":
            self.stop_demo()
            self.set_status("live", "")
        elif kind == "err":
            extra = {"help_url": NPCAP_URL} if msg.get("code") == "npcap" else {}
            self.set_status("error", str(msg.get("message", "Packet capture failed.")), **extra)

    def _on_helper_gone(self) -> None:
        if self.status["mode"] == "live":
            self.set_status("idle", "The capture helper stopped.")

    # ── lifecycle ────────────────────────────────────────────────────────────
    def bootstrap(self, live: bool = True, demo_mode: bool = False) -> None:
        """Background startup: location database first, then capture (or demo)."""
        self.set_status("preparing", "Loading location database…")
        if not self.geo.ready and not self.geo.ensure(lambda m: self.set_status("preparing", m)):
            self.set_status("error", "Could not download the location database. Check your internet "
                                     "connection, then click “Enable live capture” to retry.")
            return
        threading.Thread(target=self.geo.refresh_if_stale, daemon=True).start()
        if demo_mode:
            self.start_demo()
        elif live:
            self.start_live()
        else:
            self.set_status("idle", "Live capture is off.")

    def start_live(self) -> None:
        with self._lock:
            if self._starting_live or self.status["mode"] == "live":
                return
            self._starting_live = True
        listener = self.listener

        def work() -> None:
            try:
                self.set_status("waiting", "Waiting for permission to watch network connections…")
                ok, error = privilege.launch_helper(listener.port, listener.token)
                if not ok:
                    self.set_status("idle", error)
                elif not listener.connected.wait(HELPER_START_TIMEOUT):
                    self.set_status("error", "The capture helper did not start. Click “Enable live capture” to retry.")
                # on success the helper's "ready" message flips the status to live
            finally:
                self._starting_live = False

        threading.Thread(target=work, daemon=True, name="start-live").start()

    def start_demo(self) -> None:
        with self._lock:
            if self._demo_stop is not None:
                return
            self._demo_stop = stop = threading.Event()
        self.pipeline.reset()
        self.set_status("demo", "Showing simulated traffic, not your real connections.")
        threading.Thread(
            target=demo.run, args=(lambda geo, proto, direction: self.pipeline.publish(geo, proto, direction), stop),
            daemon=True, name="demo").start()

    # ── blocking ─────────────────────────────────────────────────────────────
    def check_can_block(self, ip: object) -> str:
        """Canonical IP if it may be blocked, else firewall.BlockError. Only IPs NetScope has itself
        flagged as malicious qualify, so a click can never block a normal connection."""
        if self.status["mode"] == "demo":
            raise firewall.BlockError("This is simulated demo data, so there is nothing real to block.")
        canonical = firewall.normalize_public_ip(ip)
        if not self.pipeline.is_flagged(canonical):
            raise firewall.BlockError("Only IPs flagged as malicious can be blocked.")
        return canonical

    def block(self, ip: object) -> str:
        canonical = self.check_can_block(ip)
        with self._block_lock:
            return firewall.block(canonical)

    def unblock(self, ip: object) -> str:
        with self._block_lock:
            return firewall.unblock(ip)

    def stop_demo(self) -> None:
        with self._lock:
            stop, self._demo_stop = self._demo_stop, None
        if stop:
            stop.set()
            self.pipeline.reset()


def create_server(port: int, geo: GeoDB | None = None, settings: Settings | None = None):
    """Build the Flask app + Socket.IO + Hub bound to `port`. Returns (app, socketio, hub)."""
    app = Flask(__name__, template_folder=str(paths.package_dir() / "templates"),
                static_folder=str(paths.package_dir() / "static"))
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    socketio = SocketIO(app, async_mode="threading",
                        cors_allowed_origins=[f"http://{h}" for h in allowed_hosts])
    settings = settings or Settings()
    geo = geo or GeoDB()
    hub = Hub(socketio, settings, geo)

    @app.before_request
    def _only_local_hosts():
        # Defends against DNS rebinding: a web page on another origin must not be able to read the feed.
        if request.host.lower() not in allowed_hosts:
            abort(403)

    @app.after_request
    def _headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/ping")
    def ping():
        return {"app": "netscope", "version": __version__}

    @app.errorhandler(Exception)
    def _error(exc):
        from werkzeug.exceptions import HTTPException
        if isinstance(exc, HTTPException):
            return exc
        log.exception("unhandled error")
        return "Something went wrong in NetScope. Details are in the log file.", 500

    @socketio.on("connect")
    def _connect():
        socketio.emit("status", hub.status, to=request.sid)
        socketio.emit("settings", settings.as_payload(), to=request.sid)

    @socketio.on("set_home")
    def _set_home(data):
        try:
            settings.set_home(float(data["lat"]), float(data["lon"]), settings.home.label)
        except (KeyError, TypeError, ValueError):
            return
        socketio.emit("settings", settings.as_payload())

    @socketio.on("enable_live")
    def _enable_live():
        hub.stop_demo()
        threading.Thread(target=hub.bootstrap, kwargs={"live": True}, daemon=True).start()

    @socketio.on("start_demo")
    def _start_demo():
        hub.start_demo()

    def _emit_blocked(to=None):
        socketio.emit("blocked", {"ips": firewall.list_blocked(), "supported": firewall.supported()},
                      **({"to": to} if to else {}))

    @socketio.on("get_blocked")
    def _get_blocked():
        sid = request.sid
        threading.Thread(target=_emit_blocked, args=(sid,), daemon=True).start()

    def _change_block(action, data, sid):
        ip = data.get("ip") if isinstance(data, dict) else None
        try:
            done = action(ip)
            result = {"ok": True, "ip": done, "message": ""}
        except firewall.BlockError as e:
            result = {"ok": False, "ip": str(ip)[:64], "message": str(e)}
        except Exception:  # noqa: BLE001 - never leak internals to the page
            log.exception("firewall change failed")
            result = {"ok": False, "ip": str(ip)[:64], "message": "The firewall change failed. See the log file."}
        socketio.emit("block_result", result, to=sid)
        _emit_blocked()

    @socketio.on("block_ip")
    def _block_ip(data):
        sid = request.sid       # the change can wait on a UAC prompt, so run it off the socket thread
        threading.Thread(target=_change_block, args=(hub.block, data, sid), daemon=True, name="block").start()

    @socketio.on("unblock_ip")
    def _unblock_ip(data):
        sid = request.sid
        threading.Thread(target=_change_block, args=(hub.unblock, data, sid), daemon=True, name="unblock").start()

    return app, socketio, hub

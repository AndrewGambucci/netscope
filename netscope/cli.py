"""Command-line entry point: `netscope`, `python -m netscope`, and the frozen app's main()."""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
import urllib.request
import webbrowser

from netscope import APP_NAME, __version__, logs, paths
from netscope.logs import log

PREFERRED_PORT = 6767


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="netscope", description="Real-time network traffic map.")
    p.add_argument("--version", action="store_true", help="print the version and exit")
    p.add_argument("--demo", action="store_true", help="show simulated traffic; no capture permissions needed")
    p.add_argument("--no-capture", action="store_true", help="start the UI without requesting capture permissions")
    p.add_argument("--no-window", action="store_true", help="open in your web browser instead of a native window")
    p.add_argument("--port", type=int, default=None, help=f"local port (default {PREFERRED_PORT}, or any free port)")
    p.add_argument("--create-shortcut", action="store_true", help="create a NetScope launcher on your Desktop and exit")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    # internal: used by the app to start the privileged capture helper
    p.add_argument("--capture-helper", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--token", default="", help=argparse.SUPPRESS)
    p.add_argument("--ignore-cidrs", default=None, help=argparse.SUPPRESS)
    return p.parse_args(argv)


def _already_running(port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/ping", timeout=1) as r:
            return json.load(r).get("app") == "netscope"
    except Exception:
        return False


def _wait_for_server(port: int, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _already_running(port):
            return True
        time.sleep(0.1)
    return False


def _open_ui(url: str, prefer_window: bool) -> None:
    """Native window if pywebview works here, otherwise the default browser. Blocks until closed."""
    if prefer_window:
        try:
            import webview
            webview.create_window(APP_NAME, url, width=1400, height=900, min_size=(900, 600))
            webview.start()
            return
        except Exception as e:
            log.warning("Native window unavailable (%s); using your browser instead.", e)
    webbrowser.open(url)
    log.info("NetScope is running at %s - press Ctrl+C to quit.", url)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if args.capture_helper:
        logs.setup(to_file=False)
        if args.ignore_cidrs is not None:
            os.environ["NETSCOPE_IGNORE_CIDRS"] = args.ignore_cidrs   # read when capture is imported
        from netscope import capture
        return capture.run_helper(args.port or 0, args.token)

    if args.version:
        print(f"{APP_NAME} {__version__}")
        return 0

    logs.setup(args.verbose)

    if args.create_shortcut:
        from netscope import shortcut
        try:
            path = shortcut.create_desktop_shortcut()
        except Exception as e:
            print(f"Could not create the shortcut: {e}", file=sys.stderr)
            return 1
        print(f"Created {path}")
        return 0

    from netscope.server import create_server, pick_port

    if args.port is None and _already_running(PREFERRED_PORT):
        log.info("NetScope is already running - opening it.")
        webbrowser.open(f"http://127.0.0.1:{PREFERRED_PORT}")
        return 0

    port = args.port or pick_port(PREFERRED_PORT)
    app, socketio, hub = create_server(port)

    import logging
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    log.info("%s %s starting on http://127.0.0.1:%s (data: %s)", APP_NAME, __version__, port, paths.data_dir())

    threading.Thread(
        target=lambda: socketio.run(app, host="127.0.0.1", port=port, debug=False, use_reloader=False,
                                    allow_unsafe_werkzeug=True, log_output=False),
        daemon=True, name="server").start()
    if not _wait_for_server(port):
        log.error("The local server did not start.")
        return 1

    threading.Thread(target=hub.bootstrap, kwargs={"live": not args.no_capture, "demo_mode": args.demo},
                     daemon=True, name="bootstrap").start()
    _open_ui(f"http://127.0.0.1:{port}", prefer_window=not args.no_window)
    return 0

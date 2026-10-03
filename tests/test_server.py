import json
import socket
import time

import pytest

from netscope import server
from netscope.geo import GeoDB


class StubGeo(GeoDB):
    ready_flag = True

    @property
    def ready(self):
        return True

    def lookup(self, ip):
        return {"ip": ip, "lat": 1.0, "lon": 2.0, "city": "Testville", "country": "Testland", "cc": "TT"}


@pytest.fixture
def srv():
    port = server.pick_port(0)
    app, socketio, hub = server.create_server(port, geo=StubGeo())
    hub.pipeline._resolve_names = False
    app.config["TESTING"] = True
    return app, socketio, hub, port


def test_index_served_on_local_host(srv):
    app, _, _, port = srv
    r = app.test_client().get("/", headers={"Host": f"127.0.0.1:{port}"})
    assert r.status_code == 200
    assert b"NETSCOPE" in r.data or b"NET<span>SCOPE" in r.data
    assert r.headers["X-Content-Type-Options"] == "nosniff"


def test_static_assets_served(srv):
    app, _, _, port = srv
    c = app.test_client()
    for path in ("/static/app.js", "/static/app.css"):
        assert c.get(path, headers={"Host": f"localhost:{port}"}).status_code == 200


def test_foreign_host_header_is_rejected(srv):
    # DNS-rebinding defence: a page on evil.example resolving to 127.0.0.1 must get nothing
    app, _, _, _ = srv
    assert app.test_client().get("/", headers={"Host": "evil.example"}).status_code == 403


def test_client_receives_status_and_settings_on_connect(srv):
    app, socketio, hub, _ = srv
    hub.set_status("preparing", "hello")
    client = socketio.test_client(app)
    got = {m["name"]: m["args"][0] for m in client.get_received()}
    assert got["status"]["mode"] == "preparing"
    assert got["settings"]["home_set"] is False


def test_set_home_persists_and_broadcasts(srv):
    app, socketio, hub, _ = srv
    client = socketio.test_client(app)
    client.get_received()
    client.emit("set_home", {"lat": 44.98, "lon": -93.27})
    msgs = [m for m in client.get_received() if m["name"] == "settings"]
    assert msgs[-1]["args"][0]["home_lat"] == 44.98 and msgs[-1]["args"][0]["home_set"] is True


def test_set_home_rejects_bad_input(srv):
    app, socketio, hub, _ = srv
    client = socketio.test_client(app)
    client.get_received()
    for bad in ({"lat": 999, "lon": 0}, {"lat": "x", "lon": 1}, {}, None):
        client.emit("set_home", bad)
    assert not [m for m in client.get_received() if m["name"] == "settings"]
    assert hub.settings.home.is_set is False


def test_demo_mode_emits_events(srv):
    app, socketio, hub, _ = srv
    client = socketio.test_client(app)
    client.get_received()
    hub.start_demo()
    try:
        assert client.get_received()[0]["args"][0]["mode"] == "demo"
    finally:
        hub.stop_demo()


# ── blocking ─────────────────────────────────────────────────────────────────
PROBE_EV = {"ip": "185.60.218.35", "port": 22, "direction": "in", "proto": "PROBE"}


@pytest.fixture
def fw(monkeypatch):
    """Replace the real firewall with an in-memory one."""
    rules = set()
    monkeypatch.setattr(server.firewall, "supported", lambda: True)
    monkeypatch.setattr(server.firewall, "block", lambda ip: rules.add(ip) or ip)
    monkeypatch.setattr(server.firewall, "unblock", lambda ip: rules.discard(ip) or ip)
    monkeypatch.setattr(server.firewall, "list_blocked", lambda: sorted(rules))
    return rules


def _block_result(client, event, ip):
    client.get_received()
    client.emit(event, {"ip": ip})
    for _ in range(100):
        msgs = [m["args"][0] for m in client.get_received() if m["name"] == "block_result"]
        if msgs:
            return msgs[0]
        time.sleep(0.03)
    raise AssertionError("no block_result")


def test_flagged_ip_can_be_blocked_and_unblocked(srv, fw):
    app, socketio, hub, _ = srv
    hub.pipeline.handle(PROBE_EV)
    client = socketio.test_client(app)
    assert _block_result(client, "block_ip", PROBE_EV["ip"])["ok"] is True
    assert fw == {PROBE_EV["ip"]}
    assert _block_result(client, "unblock_ip", PROBE_EV["ip"])["ok"] is True
    assert fw == set()


def test_normal_connection_cannot_be_blocked(srv, fw):
    app, socketio, hub, _ = srv
    hub.pipeline.handle({"ip": "142.250.80.46", "port": 443, "direction": "out", "proto": "HTTPS"})
    client = socketio.test_client(app)
    result = _block_result(client, "block_ip", "142.250.80.46")
    assert result["ok"] is False and "malicious" in result["message"]
    assert fw == set()


def test_unseen_and_private_ips_cannot_be_blocked(srv, fw):
    app, socketio, hub, _ = srv
    hub.pipeline.handle({**PROBE_EV, "ip": "192.168.1.9"})         # even if somehow flagged
    client = socketio.test_client(app)
    for ip in ("8.8.8.8", "192.168.1.9", "127.0.0.1", "garbage"):
        assert _block_result(client, "block_ip", ip)["ok"] is False
    assert fw == set()


def test_demo_traffic_cannot_be_blocked(srv, fw):
    app, socketio, hub, _ = srv
    hub.pipeline.handle(PROBE_EV)
    hub.set_status("demo", "")
    client = socketio.test_client(app)
    assert _block_result(client, "block_ip", PROBE_EV["ip"])["ok"] is False
    assert fw == set()


def test_bad_block_payload_is_rejected(srv, fw):
    app, socketio, _, _ = srv
    client = socketio.test_client(app)
    client.get_received()
    client.emit("block_ip", None)
    client.emit("block_ip", {"ip": ["x"]})
    time.sleep(0.3)
    assert fw == set()


# ── helper channel ───────────────────────────────────────────────────────────
def _send(sock, obj):
    sock.sendall((json.dumps(obj) + "\n").encode())


def _wait(predicate, timeout=3.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def test_helper_events_flow_to_clients(srv):
    app, socketio, hub, _ = srv
    client = socketio.test_client(app)
    client.get_received()
    listener = hub.listener
    with socket.create_connection(("127.0.0.1", listener.port)) as helper:
        _send(helper, {"t": "hello", "token": listener.token})
        _send(helper, {"t": "ready"})
        _send(helper, {"t": "ev", "ip": "142.250.80.46", "port": 443, "direction": "out", "proto": "HTTPS"})
        assert _wait(lambda: any(m["name"] == "pkt" for m in client.get_received()))
        assert hub.status["mode"] == "live"


def test_helper_with_wrong_token_is_ignored(srv):
    app, socketio, hub, _ = srv
    client = socketio.test_client(app)
    client.get_received()
    listener = hub.listener
    with socket.create_connection(("127.0.0.1", listener.port)) as helper:
        _send(helper, {"t": "hello", "token": "wrong"})
        _send(helper, {"t": "ev", "ip": "142.250.80.46", "port": 443, "direction": "out", "proto": "HTTPS"})
        time.sleep(0.4)
    assert not [m for m in client.get_received() if m["name"] == "pkt"]
    assert not listener.connected.is_set()


def test_helper_error_is_shown_to_the_user(srv):
    app, socketio, hub, _ = srv
    listener = hub.listener
    with socket.create_connection(("127.0.0.1", listener.port)) as helper:
        _send(helper, {"t": "hello", "token": listener.token})
        _send(helper, {"t": "err", "code": "npcap", "message": "needs npcap"})
        assert _wait(lambda: hub.status["mode"] == "error")
    assert hub.status["help_url"] == server.NPCAP_URL

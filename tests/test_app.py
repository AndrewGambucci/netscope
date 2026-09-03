"""
Tests for the packet classification/filtering logic in app.py. this is the part
responsible for turning raw packets into "new connection" / "inbound probe"
events instead of every packet on the wire.

Run with: pytest
These don't need root or a real GeoLite2 database — geo lookups are stubbed.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from scapy.all import IP, TCP, UDP

import app

LOCAL_IP = "192.168.1.50"
WEB_IP = "142.250.80.46"
REMOTE_IP = "157.240.22.35"

FAKE_GEO = {
    "ip": "0.0.0.0", "lat": 1.0, "lon": 2.0,
    "city": "Testville", "country": "Testland", "cc": "TT",
}


@pytest.fixture(autouse=True)
def reset_state(monkeypatch):
    app._local_ips = {LOCAL_IP}
    app._recent_events.clear()
    app.stats.clear()
    monkeypatch.setattr(app, "lookup", lambda ip: {**FAKE_GEO, "ip": ip})
    monkeypatch.setattr(app, "rdns_lookup", lambda ip: "")
    events = []
    monkeypatch.setattr(app.socketio, "emit", lambda name, payload: events.append(payload))
    return events


def test_outbound_syn_fires_website_event(reset_state):
    pkt = IP(src=LOCAL_IP, dst=WEB_IP) / TCP(sport=51000, dport=443, flags="S")
    app.process_packet(pkt)
    assert len(reset_state) == 1
    assert reset_state[0]["direction"] == "out"
    assert reset_state[0]["proto"] == "HTTPS"


def test_duplicate_outbound_within_window_is_suppressed(reset_state):
    pkt = IP(src=LOCAL_IP, dst=WEB_IP) / TCP(sport=51000, dport=443, flags="S")
    app.process_packet(pkt)
    app.process_packet(pkt)
    assert len(reset_state) == 1


def test_established_ack_is_ignored(reset_state):
    pkt = IP(src=LOCAL_IP, dst=WEB_IP) / TCP(sport=51000, dport=443, flags="A")
    app.process_packet(pkt)
    assert len(reset_state) == 0


def test_inbound_syn_fires_probe_event(reset_state):
    pkt = IP(src=REMOTE_IP, dst=LOCAL_IP) / TCP(sport=4444, dport=22, flags="S")
    app.process_packet(pkt)
    assert len(reset_state) == 1
    assert reset_state[0]["direction"] == "in"
    assert reset_state[0]["proto"] == "PROBE"


def test_reply_syn_ack_is_not_a_probe(reset_state):
    # a SYN-ACK from a remote host we connected to is a normal reply,
    # not an unsolicited inbound probe
    pkt = IP(src=REMOTE_IP, dst=LOCAL_IP) / TCP(sport=443, dport=51001, flags="SA")
    app.process_packet(pkt)
    assert len(reset_state) == 0


def test_outbound_dns_query_fires(reset_state):
    pkt = IP(src=LOCAL_IP, dst=WEB_IP) / UDP(sport=51000, dport=53)
    app.process_packet(pkt)
    assert len(reset_state) == 1
    assert reset_state[0]["proto"] == "DNS"


def test_private_to_private_traffic_is_dropped(reset_state):
    pkt = IP(src="192.168.1.60", dst="192.168.1.70") / TCP(sport=1, dport=443, flags="S")
    app.process_packet(pkt)
    assert len(reset_state) == 0


def test_malformed_packet_does_not_raise(reset_state):
    # a non-IP packet should be skipped quietly, not crash the sniffer thread
    app.process_packet(TCP(sport=1, dport=2, flags="S"))
    assert len(reset_state) == 0


def test_is_private_matches_known_ranges():
    assert app.is_private("192.168.1.1")
    assert app.is_private("10.0.0.5")
    assert app.is_private("127.0.0.1")
    assert not app.is_private("8.8.8.8")


def test_public_traffic_is_not_filtered_by_vendor(reset_state):
    # 17.0.0.0/8 (Apple) was once dropped wholesale, which silently hid real
    # outbound traffic from a tool whose entire purpose is visibility.
    pkt = IP(src=LOCAL_IP, dst="17.253.144.10") / TCP(sport=51000, dport=443, flags="S")
    app.process_packet(pkt)
    assert len(reset_state) == 1


def test_dedup_table_is_bounded(monkeypatch):
    # The dedup dict holds one entry per (ip, port, direction) and would grow
    # without limit across a long capture; entries past the window get swept.
    monkeypatch.setattr(app, "DEDUP_MAX_KEYS", 50)
    monkeypatch.setattr(app, "DEDUP_WINDOW", 0)  # every entry is instantly stale
    for i in range(300):
        app._is_dupe(f"203.0.113.{i % 256}", 443 + i, "out")
    assert len(app._recent_events) <= 51


def test_dedup_still_suppresses_within_window():
    app._recent_events.clear()
    assert app._is_dupe("8.8.8.8", 53, "out") is False
    assert app._is_dupe("8.8.8.8", 53, "out") is True


# ── cross-platform behavior ───────────────────────────────────────────────────

def test_privilege_hint_is_platform_appropriate(monkeypatch):
    monkeypatch.setattr(app, "IS_WINDOWS", True)
    assert "administrator" in app.privilege_hint().lower()
    monkeypatch.setattr(app, "IS_WINDOWS", False)
    assert "sudo" in app.privilege_hint().lower()


def test_npcap_check_is_a_noop_off_windows(monkeypatch):
    # libpcap ships with macOS/Linux, so the driver check must not gate them.
    monkeypatch.setattr(app, "IS_WINDOWS", False)
    assert app.npcap_installed() is True


def test_is_elevated_reports_bool_without_raising():
    # Must never raise: it runs before any capture is attempted, on both OSes.
    assert isinstance(app.is_elevated(), bool)


# ── demo mode ─────────────────────────────────────────────────────────────────

def test_demo_targets_carry_fields_the_ui_requires():
    # A missing "direction" silently made every demo arc render outbound, so
    # demo mode never showed the inbound-probe case the README advertises.
    required = {"ip", "lat", "lon", "city", "country", "cc", "proto", "direction", "hostname"}
    for t in app.DEMO_TARGETS:
        assert required <= set(t), f"{t['ip']} is missing {required - set(t)}"
        assert t["direction"] in ("in", "out")


def test_demo_mode_exercises_both_directions():
    directions = {t["direction"] for t in app.DEMO_TARGETS}
    assert directions == {"in", "out"}
    assert any(t["proto"] == "PROBE" for t in app.DEMO_TARGETS)


def test_home_defaults_to_minneapolis():
    assert 44.8 < app.HOME_LAT < 45.1
    assert -93.4 < app.HOME_LON < -93.1

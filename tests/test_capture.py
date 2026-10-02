"""Packet classification: which packets become events, and in which direction.
No root, no network, no GeoIP database needed."""
import pytest
from scapy.all import IP, TCP, UDP

from netscope import capture

LOCAL = "192.168.1.50"
WEB = "142.250.80.46"
REMOTE = "157.240.22.35"
LOCAL_IPS = {LOCAL}


def classify(pkt):
    return capture.classify(pkt, LOCAL_IPS)


def test_outbound_https_syn():
    ev = classify(IP(src=LOCAL, dst=WEB) / TCP(sport=51000, dport=443, flags="S"))
    assert ev == {"ip": WEB, "port": 443, "direction": "out", "proto": "HTTPS"}


@pytest.mark.parametrize("port,proto", [(80, "HTTP"), (22, "TCP"), (8443, "TCP")])
def test_outbound_protocol_labels(port, proto):
    assert classify(IP(src=LOCAL, dst=WEB) / TCP(sport=1, dport=port, flags="S"))["proto"] == proto


def test_established_traffic_is_ignored():
    assert classify(IP(src=LOCAL, dst=WEB) / TCP(sport=51000, dport=443, flags="A")) is None
    assert classify(IP(src=LOCAL, dst=WEB) / TCP(sport=51000, dport=443, flags="PA")) is None


def test_inbound_syn_is_a_probe():
    ev = classify(IP(src=REMOTE, dst=LOCAL) / TCP(sport=4444, dport=22, flags="S"))
    assert ev["direction"] == "in" and ev["proto"] == "PROBE" and ev["ip"] == REMOTE


def test_syn_ack_reply_is_not_a_probe():
    assert classify(IP(src=REMOTE, dst=LOCAL) / TCP(sport=443, dport=51001, flags="SA")) is None


def test_outbound_dns_query():
    ev = classify(IP(src=LOCAL, dst=WEB) / UDP(sport=51000, dport=53))
    assert ev["proto"] == "DNS" and ev["direction"] == "out"


def test_dns_reply_from_public_resolver_is_not_a_probe():
    assert classify(IP(src=WEB, dst=LOCAL) / UDP(sport=53, dport=51000)) is None


def test_non_dns_udp_is_ignored():
    assert classify(IP(src=LOCAL, dst=WEB) / UDP(sport=51000, dport=443)) is None


def test_lan_to_lan_is_ignored():
    assert classify(IP(src="192.168.1.60", dst="192.168.1.70") / TCP(sport=1, dport=443, flags="S")) is None


def test_non_ip_packet_is_ignored():
    assert classify(TCP(sport=1, dport=2, flags="S")) is None


def test_traffic_to_private_remote_is_ignored():
    assert classify(IP(src=LOCAL, dst="10.0.0.5") / TCP(sport=1, dport=443, flags="S")) is None


def test_apple_block_is_hidden_by_default():
    assert classify(IP(src=LOCAL, dst="17.253.144.10") / TCP(sport=1, dport=443, flags="S")) is None


@pytest.mark.parametrize("ip,public", [
    ("8.8.8.8", True), ("142.250.80.46", True),
    ("192.168.1.1", False), ("10.0.0.5", False), ("172.20.1.1", False), ("127.0.0.1", False),
    ("169.254.1.1", False), ("100.64.1.1", False),       # CGNAT / Tailscale
    ("224.0.0.1", False), ("255.255.255.255", False), ("203.0.113.5", False),
    ("not-an-ip", False),
])
def test_is_public(ip, public):
    assert capture.is_public(ip) is public

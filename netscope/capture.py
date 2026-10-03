"""Packet capture: the only part of NetScope that needs elevated privileges.

This module runs in a small helper process (started by `privilege.launch_helper`),
never in the UI process. It classifies packets and streams compact JSON events to
the UI over a loopback socket; geolocation, de-duplication and display all happen
on the unprivileged side. It only ever inspects packet *headers* (addresses,
ports, TCP flags) - payload bytes are never read.

Signal, not noise: only two things become events -
  out: the SYN that opens a new TCP connection, or a DNS query ("you asked for something")
  in:  an unsolicited SYN, or DNS query, from a public IP ("something is knocking")
Everything else (ACKs, retransmits, keepalives, DNS replies) is dropped by a kernel
BPF filter and by `classify`.
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import sys
import threading
import time

from netscope import paths
from netscope.logs import log

# Must be set before scapy is imported (see paths.private_cache_dir).
os.environ["XDG_CACHE_HOME"] = paths.private_cache_dir()

from scapy.all import IP, TCP, UDP, conf, sniff  # noqa: E402

SNIFF_FILTER = "(tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn) or (udp and port 53)"
NPCAP_MESSAGE = "Packet capture on Windows needs Npcap. Install it, then click “Enable live capture”."

# Apple's 17.0.0.0/8 (iCloud, push, updates) is chatty background noise on a Mac, so it's hidden
# by default. Override with NETSCOPE_IGNORE_CIDRS="a.b.c.d/n,..." (empty string = ignore nothing).
_DEFAULT_IGNORE = "17.0.0.0/8"


def _ignored_networks() -> list[ipaddress.IPv4Network]:
    raw = os.environ.get("NETSCOPE_IGNORE_CIDRS", _DEFAULT_IGNORE)
    nets = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.IPv4Network(part, strict=False))
        except ValueError:
            log.warning("Ignoring invalid CIDR in NETSCOPE_IGNORE_CIDRS: %r", part)
    return nets


IGNORED_NETWORKS = _ignored_networks()


def is_public(ip: str) -> bool:
    """True for a routable, unicast address - i.e. something that is 'out there on the internet'.

    Private, loopback, link-local, carrier-grade NAT (100.64/10, e.g. Tailscale),
    multicast, broadcast and documentation ranges are all not public."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global and not addr.is_multicast


def _is_ignored(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in IGNORED_NETWORKS)


def classify(pkt, local_ips: set[str]) -> dict | None:
    """Turn one packet into {ip, port, direction, proto} or None if it isn't interesting."""
    if IP not in pkt:
        return None
    src, dst = pkt[IP].src, pkt[IP].dst

    if TCP in pkt:
        flags = int(pkt[TCP].flags)
        if not (flags & 0x02) or flags & 0x10:      # need SYN, reject SYN-ACK / ACK
            return None
        port = pkt[TCP].dport
        proto = "HTTPS" if port == 443 else ("HTTP" if port == 80 else "TCP")
    elif UDP in pkt:
        # Queries only. The BPF filter also lets DNS *replies* (source port 53) through, and
        # those must not be mistaken for inbound probes from a public resolver.
        if pkt[UDP].dport != 53:
            return None
        port, proto = 53, "DNS"
    else:
        return None

    src_is_us = src in local_ips or not is_public(src)
    dst_is_us = dst in local_ips or not is_public(dst)
    if src_is_us and not dst_is_us:
        direction, remote = "out", dst
    elif dst_is_us and not src_is_us:
        direction, remote = "in", src
    else:
        return None                                  # LAN<->LAN, or neither end is us

    if not is_public(remote) or _is_ignored(remote):
        return None
    if direction == "in":
        proto = "PROBE"
    return {"ip": remote, "port": port, "direction": direction, "proto": proto}


def get_local_ips() -> set[str]:
    """Every IPv4 address this machine owns (so multi-homed / VPN setups classify correctly)."""
    ips: set[str] = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))                   # UDP connect sends nothing; it just picks a route
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        ips.add(socket.gethostbyname(socket.gethostname()))
    except OSError:
        pass
    try:
        from scapy.all import get_if_addr, get_if_list
        for iface in get_if_list():
            try:
                ips.add(get_if_addr(iface))
            except Exception:
                pass
    except Exception:
        pass
    ips.discard("0.0.0.0")
    return ips


class _Channel:
    """Newline-delimited JSON over a socket, safe to use from the sniffer thread."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._lock = threading.Lock()

    def send(self, obj: dict) -> None:
        data = (json.dumps(obj, separators=(",", ":")) + "\n").encode()
        with self._lock:
            self._sock.sendall(data)


def _explain(exc: Exception) -> tuple[str, str]:
    text = str(exc)
    if sys.platform == "win32" and any(w in text.lower() for w in ("winpcap", "npcap", "wpcap", "layer 2")):
        return "npcap", NPCAP_MESSAGE
    if isinstance(exc, PermissionError):
        return "permission", "Permission denied opening the network interface."
    return "capture", f"Packet capture failed: {text}"


def run_helper(port: int, token: str) -> int:
    """Entry point of the privileged helper process. Returns a process exit code."""
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    except OSError as e:
        log.error("helper: cannot reach NetScope on 127.0.0.1:%s (%s)", port, e)
        return 2
    sock.settimeout(None)
    chan = _Channel(sock)
    chan.send({"t": "hello", "token": token, "pid": os.getpid()})

    def watch_parent() -> None:
        # The UI never sends us anything. EOF means it exited (or was killed): stop capturing.
        try:
            while sock.recv(4096):
                pass
        except OSError:
            pass
        os._exit(0)

    threading.Thread(target=watch_parent, daemon=True).start()

    if sys.platform == "win32" and not conf.use_pcap:
        # scapy couldn't load Npcap: say so now, rather than announcing "ready" and failing a moment later
        chan.send({"t": "err", "code": "npcap", "message": NPCAP_MESSAGE})
        return 1

    local_ips = get_local_ips()

    def refresh_local_ips() -> None:
        nonlocal local_ips
        while True:
            time.sleep(60)                           # laptops change networks
            fresh = get_local_ips()
            if fresh:
                local_ips = fresh

    threading.Thread(target=refresh_local_ips, daemon=True).start()

    def on_packet(pkt) -> None:
        # One malformed packet must never kill the capture loop.
        try:
            event = classify(pkt, local_ips)
            if event:
                chan.send({"t": "ev", **event})
        except (BrokenPipeError, ConnectionError):
            os._exit(0)
        except Exception as e:
            log.debug("skipped packet: %s", e)

    try:
        chan.send({"t": "ready", "local_ips": sorted(local_ips)})
        sniff(prn=on_packet, store=False, filter=SNIFF_FILTER)
    except Exception as e:
        code, message = _explain(e)
        try:
            chan.send({"t": "err", "code": code, "message": message})
        except OSError:
            pass
        return 1
    return 0

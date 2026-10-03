"""Turns raw capture events into map events: validate, de-duplicate, geolocate, name, count."""
from __future__ import annotations

import concurrent.futures
import ipaddress
import socket
import threading
import time
from collections import OrderedDict, defaultdict
from collections.abc import Callable

from netscope.geo import GeoDB
from netscope.settings import Settings

DEDUP_WINDOW = 20          # seconds: one chatty remote can't flood the feed
RDNS_TIMEOUT = 0.5
RDNS_CACHE_SIZE = 4096
VALID_PROTOS = {"HTTPS", "HTTP", "TCP", "DNS", "PROBE"}
VALID_DIRECTIONS = {"in", "out"}
SCAN_WINDOW = 60           # seconds over which one source's probed ports are counted
SCAN_PORTS = 5             # distinct ports hit within the window before a source counts as a port scan
MAX_TRACKED_SOURCES = 4096


def is_malicious(proto: str, direction: str) -> bool:
    """An unsolicited inbound connection attempt from a public IP (capture tags these PROBE)."""
    return proto == "PROBE" and direction == "in"


class Pipeline:
    def __init__(self, geo: GeoDB, settings: Settings, emit: Callable[[str, dict], None],
                 resolve_names: bool = True) -> None:
        self.geo = geo
        self.settings = settings
        self._emit = emit
        self._resolve_names = resolve_names
        self._lock = threading.Lock()
        self._stats: defaultdict[str, int] = defaultdict(int)
        self._recent: dict[tuple, float] = {}
        self._probed: dict[str, dict[int, float]] = {}    # source ip -> {port: last seen}
        self._flagged: OrderedDict[str, None] = OrderedDict()   # every IP seen acting maliciously (bounded)
        self._rdns: OrderedDict[str, str] = OrderedDict()
        self._rdns_pool = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="rdns")

    # ── reverse DNS (bounded cache, hard timeout) ────────────────────────────
    def hostname(self, ip: str) -> str:
        if not self._resolve_names:
            return ""
        with self._lock:
            if ip in self._rdns:
                self._rdns.move_to_end(ip)
                return self._rdns[ip]
        try:
            host = self._rdns_pool.submit(socket.gethostbyaddr, ip).result(timeout=RDNS_TIMEOUT)[0]
        except Exception:
            host = ""
        with self._lock:
            self._rdns[ip] = host
            if len(self._rdns) > RDNS_CACHE_SIZE:
                self._rdns.popitem(last=False)
        return host

    # ── de-duplication ───────────────────────────────────────────────────────
    def _is_dupe(self, ip: str, port: int, direction: str) -> bool:
        key, now = (ip, port, direction), time.time()
        with self._lock:
            last = self._recent.get(key)
            if last is not None and now - last < DEDUP_WINDOW:
                return True
            self._recent[key] = now
            if len(self._recent) > 4096:             # prune expired entries so this can't grow forever
                self._recent = {k: t for k, t in self._recent.items() if now - t < DEDUP_WINDOW}
        return False

    def _ports_probed(self, ip: str, port: int) -> int:
        """Record an inbound probe and return how many distinct ports this source hit recently."""
        now = time.time()
        with self._lock:
            ports = {p: t for p, t in self._probed.get(ip, {}).items() if now - t < SCAN_WINDOW}
            ports[port] = now
            self._probed[ip] = ports
            if len(self._probed) > MAX_TRACKED_SOURCES:
                self._probed = {k: v for k, v in self._probed.items() if now - max(v.values()) < SCAN_WINDOW}
            return len(ports)

    # ── public API ───────────────────────────────────────────────────────────
    def is_flagged(self, ip: str) -> bool:
        """True if this IP has been seen sending an unsolicited inbound connection (real traffic only)."""
        with self._lock:
            return ip in self._flagged

    def reset(self) -> None:
        with self._lock:
            self._stats.clear()
            self._recent.clear()
            self._probed.clear()
            self._flagged.clear()

    def handle(self, event: dict) -> bool:
        """Process one {ip, port, direction, proto} event. True if it reached the UI."""
        try:
            ip = str(ipaddress.ip_address(event["ip"]))
            port = int(event["port"])
            direction, proto = event["direction"], event["proto"]
        except (KeyError, ValueError, TypeError):
            return False
        if direction not in VALID_DIRECTIONS or proto not in VALID_PROTOS:
            return False
        if self._is_dupe(ip, port, direction):
            return False
        geo = self.geo.lookup(ip)
        if geo is None:
            return False                              # no location for this IP: nothing to draw
        scan_ports = 0
        if is_malicious(proto, direction):
            scan_ports = self._ports_probed(ip, port)
            with self._lock:                          # remembered so only flagged IPs can be blocked
                self._flagged[ip] = None
                self._flagged.move_to_end(ip)
                if len(self._flagged) > MAX_TRACKED_SOURCES:
                    self._flagged.popitem(last=False)
        self.publish(geo, proto, direction, self.hostname(ip), port=port, scan_ports=scan_ports)
        return True

    def publish(self, geo: dict, proto: str, direction: str, hostname: str = "",
                port: int | None = None, scan_ports: int = 0) -> None:
        home = self.settings.home
        malicious = is_malicious(proto, direction)
        with self._lock:
            self._stats[geo["country"]] += 1
            top = sorted(self._stats.items(), key=lambda kv: -kv[1])[:8]
        self._emit("pkt", {
            **geo,
            "proto": proto,
            "direction": direction,
            "hostname": hostname,
            "port": port,
            "malicious": malicious,
            "threat": ("scan" if scan_ports >= SCAN_PORTS else "probe") if malicious else "",
            "scan_ports": scan_ports,
            "src_lat": home.lat,
            "src_lon": home.lon,
            "ts": time.time(),
            "top": top,
        })

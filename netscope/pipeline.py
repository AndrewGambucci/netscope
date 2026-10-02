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

    # ── public API ───────────────────────────────────────────────────────────
    def reset(self) -> None:
        with self._lock:
            self._stats.clear()
            self._recent.clear()

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
        self.publish(geo, proto, direction, self.hostname(ip))
        return True

    def publish(self, geo: dict, proto: str, direction: str, hostname: str = "") -> None:
        home = self.settings.home
        with self._lock:
            self._stats[geo["country"]] += 1
            top = sorted(self._stats.items(), key=lambda kv: -kv[1])[:8]
        self._emit("pkt", {
            **geo,
            "proto": proto,
            "direction": direction,
            "hostname": hostname,
            "src_lat": home.lat,
            "src_lon": home.lon,
            "ts": time.time(),
            "top": top,
        })

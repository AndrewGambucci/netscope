"""Scripted sample traffic, so the UI is explorable without capture permissions."""
from __future__ import annotations

import random
import threading
from collections.abc import Callable

TARGETS = [
    ("8.8.8.8",       37.42, -122.08, "Mountain View", "United States", "US", "DNS"),
    ("104.16.0.1",    51.51,   -0.13, "London",        "United Kingdom", "GB", "HTTPS"),
    ("31.13.72.36",   48.86,    2.35, "Paris",         "France", "FR", "HTTPS"),
    ("52.94.236.248", 35.68,  139.69, "Tokyo",         "Japan", "JP", "TCP"),
    ("142.250.80.46", -33.87, 151.21, "Sydney",        "Australia", "AU", "HTTPS"),
    ("13.107.42.14",  47.61, -122.33, "Seattle",       "United States", "US", "TCP"),
    ("157.240.22.35", 37.77, -122.42, "San Francisco", "United States", "US", "HTTPS"),
    ("1.1.1.1",      -27.46,  153.02, "Brisbane",      "Australia", "AU", "DNS"),
    ("185.60.218.35", 55.75,   37.62, "Moscow",        "Russia", "RU", "PROBE"),
    ("203.0.113.5",   22.28,  114.16, "Hong Kong",     "Hong Kong", "HK", "HTTPS"),
    ("190.0.68.0",   -34.60,  -58.38, "Buenos Aires",  "Argentina", "AR", "TCP"),
]


def run(publish: Callable[[dict, str, str], None], stop: threading.Event) -> None:
    """Call publish(geo, proto, direction) every 0.8-2.5 s until `stop` is set."""
    i = 0
    while not stop.wait(random.uniform(0.8, 2.5)):
        ip, lat, lon, city, country, cc, proto = TARGETS[i % len(TARGETS)]
        publish({"ip": ip, "lat": lat, "lon": lon, "city": city, "country": country, "cc": cc},
                proto, "in" if proto == "PROBE" else "out")
        i += 1

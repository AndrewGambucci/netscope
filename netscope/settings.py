"""User settings: where "home" is on the map. Env vars override the saved config."""
from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass

from netscope import paths
from netscope.logs import log


@dataclass
class Home:
    lat: float = 0.0
    lon: float = 0.0
    label: str = "You"
    is_set: bool = False


class Settings:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._file = paths.data_dir() / "config.json"
        self.home = self._load()

    def _load(self) -> Home:
        home = Home()
        try:
            data = json.loads(self._file.read_text(encoding="utf-8"))
            home = Home(float(data["home_lat"]), float(data["home_lon"]),
                        str(data.get("home_label", "You")), True)
        except (OSError, ValueError, KeyError, TypeError):
            pass
        # Env vars win so real coordinates never need to be committed or saved anywhere.
        try:
            if "NETSCOPE_LAT" in os.environ and "NETSCOPE_LON" in os.environ:
                home.lat = float(os.environ["NETSCOPE_LAT"])
                home.lon = float(os.environ["NETSCOPE_LON"])
                home.is_set = True
            if "NETSCOPE_LABEL" in os.environ:
                home.label = os.environ["NETSCOPE_LABEL"]
        except ValueError:
            log.warning("Ignoring invalid NETSCOPE_LAT / NETSCOPE_LON")
        return home

    def set_home(self, lat: float, lon: float, label: str = "You") -> None:
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            raise ValueError("coordinates out of range")
        with self._lock:
            self.home = Home(lat, lon, label, True)
            try:
                self._file.write_text(
                    json.dumps({"home_lat": lat, "home_lon": lon, "home_label": label}), encoding="utf-8")
            except OSError as e:
                log.warning("Could not save location: %s", e)

    def as_payload(self) -> dict:
        h = self.home
        return {"home_lat": h.lat, "home_lon": h.lon, "home_label": h.label, "home_set": h.is_set}

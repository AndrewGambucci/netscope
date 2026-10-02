"""IP -> location, from a local MMDB database (no per-lookup network calls).

Order of preference:
  1. A MaxMind GeoLite2-City.mmdb the user provided (or fetched with MAXMIND_LICENSE_KEY)
  2. DB-IP "City Lite" - free, no account or key, downloaded automatically on first run
     (CC BY 4.0, https://db-ip.com - attribution is shown in the map footer)
"""
from __future__ import annotations

import datetime as dt
import gzip
import os
import shutil
import ssl
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections import OrderedDict
from collections.abc import Callable
from pathlib import Path

import geoip2.database
import geoip2.errors

from netscope import __version__, paths
from netscope.logs import log

MAXMIND_NAME = "GeoLite2-City.mmdb"
DBIP_NAME = "dbip-city-lite.mmdb"
DBIP_URL = "https://download.db-ip.com/free/dbip-city-lite-{year}-{month:02d}.mmdb.gz"
MAXMIND_URL = ("https://download.maxmind.com/app/geoip_download"
               "?edition_id=GeoLite2-City&license_key={key}&suffix=tar.gz")
STALE_AFTER_DAYS = 45          # DB-IP publishes monthly
CACHE_SIZE = 8192

Progress = Callable[[str], None]


def _ssl_context() -> ssl.SSLContext:
    # python.org builds on macOS ship without a CA bundle; certifi always has one.
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def _open(url: str, timeout: int = 30):
    req = urllib.request.Request(url, headers={"User-Agent": f"NetScope/{__version__}"})
    return urllib.request.urlopen(req, timeout=timeout, context=_ssl_context())


def _validate(path: Path) -> None:
    """Raise if `path` isn't a usable City database."""
    with geoip2.database.Reader(str(path)) as reader:
        reader.city("8.8.8.8")  # AddressNotFound is fine; a wrong DB type raises TypeError


class _CountingReader:
    """File-like wrapper that counts compressed bytes read, for progress reporting."""

    def __init__(self, raw) -> None:
        self._raw = raw
        self.count = 0

    def read(self, n: int = -1) -> bytes:
        data = self._raw.read(n)
        self.count += len(data)
        return data


def _fetch_dbip(dest: Path, progress: Progress | None) -> None:
    today = dt.date.today()
    previous_month = today.replace(day=1) - dt.timedelta(days=1)
    last_error: Exception | None = None
    for d in (today, previous_month):  # the new month's file appears on the 1st; fall back a month
        try:
            resp = _open(DBIP_URL.format(year=d.year, month=d.month))
        except urllib.error.HTTPError as e:
            last_error = e
            continue
        total = int(resp.headers.get("Content-Length") or 0)
        counted = _CountingReader(resp)
        tmp_fd, tmp_name = tempfile.mkstemp(dir=dest.parent, suffix=".part")
        try:
            last_report = 0.0
            with os.fdopen(tmp_fd, "wb") as out, gzip.GzipFile(fileobj=counted) as gz:
                while chunk := gz.read(1 << 20):
                    out.write(chunk)
                    now = time.monotonic()
                    if progress and total and now - last_report > 0.5:
                        progress(f"Downloading location database… {min(99, counted.count * 100 // total)}%")
                        last_report = now
            _validate(Path(tmp_name))
            os.replace(tmp_name, dest)
            return
        finally:
            resp.close()
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
    raise last_error or RuntimeError("DB-IP download failed")


def _fetch_maxmind(dest: Path, key: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / "geolite.tar.gz"
        with _open(MAXMIND_URL.format(key=key), timeout=60) as resp, open(archive, "wb") as f:
            shutil.copyfileobj(resp, f)
        with tarfile.open(archive, "r:gz") as tar:
            member = next((m for m in tar.getmembers() if m.name.endswith(MAXMIND_NAME)), None)
            if member is None or not member.isfile():
                raise RuntimeError("downloaded archive did not contain " + MAXMIND_NAME)
            # Extract just this one file, by content, never trusting archive paths.
            src = tar.extractfile(member)
            staged = Path(tmp) / MAXMIND_NAME
            with open(staged, "wb") as out:
                shutil.copyfileobj(src, out)
        _validate(staged)
        shutil.copyfile(staged, dest)


class GeoDB:
    def __init__(self) -> None:
        self._reader: geoip2.database.Reader | None = None
        self._lock = threading.Lock()
        self._cache: OrderedDict[str, dict | None] = OrderedDict()
        self.path: Path | None = None

    # ── locating / loading ───────────────────────────────────────────────────
    @staticmethod
    def candidates() -> list[Path]:
        data = paths.data_dir()
        found = [data / MAXMIND_NAME,
                 paths.package_dir().parent / MAXMIND_NAME,   # source checkout (legacy location)
                 Path.cwd() / MAXMIND_NAME,
                 data / DBIP_NAME]
        return [p for p in found if p.is_file()]

    @property
    def ready(self) -> bool:
        return self._reader is not None

    def open(self, path: Path) -> bool:
        try:
            reader = geoip2.database.Reader(str(path))
        except Exception as e:
            log.warning("Could not open %s: %s", path, e)
            return False
        with self._lock:
            old, self._reader, self.path = self._reader, reader, path
            self._cache.clear()
        if old:
            old.close()
        log.info("GeoIP database loaded: %s", path)
        return True

    def load_existing(self) -> bool:
        return any(self.open(p) for p in self.candidates())

    # ── obtaining a database ─────────────────────────────────────────────────
    def ensure(self, progress: Progress | None = None) -> bool:
        """Make sure a database is loaded, downloading one if needed. Never raises."""
        if self.load_existing():
            return True
        data = paths.data_dir()
        key = os.environ.get("MAXMIND_LICENSE_KEY", "").strip()
        if key:
            if progress:
                progress("Downloading location database from MaxMind…")
            try:
                _fetch_maxmind(data / MAXMIND_NAME, key)
                if self.open(data / MAXMIND_NAME):
                    return True
            except Exception as e:
                # urllib puts the full URL (with the key) in some messages: log only the type.
                log.warning("MaxMind download failed (%s); trying DB-IP instead", type(e).__name__)
        if progress:
            progress("Downloading location database… 0%")
        try:
            _fetch_dbip(data / DBIP_NAME, progress)
            return self.open(data / DBIP_NAME)
        except Exception as e:
            log.error("Could not download a location database: %s", e)
            return False

    def refresh_if_stale(self) -> None:
        """Quietly update the DB-IP file if it's old. The user's own MaxMind file is left alone."""
        path = self.path
        if not path or path.name != DBIP_NAME:
            return
        if time.time() - path.stat().st_mtime < STALE_AFTER_DAYS * 86400:
            return
        try:
            _fetch_dbip(path, None)
            self.open(path)
        except Exception as e:
            log.info("Location database refresh skipped: %s", e)

    # ── lookup ───────────────────────────────────────────────────────────────
    def lookup(self, ip: str) -> dict | None:
        with self._lock:
            if ip in self._cache:
                self._cache.move_to_end(ip)
                return self._cache[ip]
            reader = self._reader
        if reader is None:
            return None
        try:
            r = reader.city(ip)
            result = None
            if r.location.latitude is not None and r.location.longitude is not None:
                result = {
                    "ip": ip,
                    "lat": r.location.latitude,
                    "lon": r.location.longitude,
                    "city": r.city.name or "",
                    "country": r.country.name or "Unknown",
                    "cc": r.country.iso_code or "",
                }
        except (geoip2.errors.AddressNotFoundError, ValueError):
            result = None
        except Exception as e:  # corrupt record etc. - never take the pipeline down
            log.debug("lookup(%s) failed: %s", ip, e)
            result = None
        with self._lock:
            self._cache[ip] = result
            if len(self._cache) > CACHE_SIZE:
                self._cache.popitem(last=False)
        return result

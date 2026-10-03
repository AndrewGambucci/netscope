"""Where NetScope keeps its files, for a source checkout, a pip install, or a frozen app."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

from netscope import APP_NAME


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def data_dir() -> Path:
    """Per-user writable directory (GeoIP database, config, logs). Created on demand.

    The elevated capture helper may run as a different user (root), so the UI
    process passes its own directory down via NETSCOPE_DATA_DIR."""
    override = os.environ.get("NETSCOPE_DATA_DIR")
    if override:
        path = Path(override)
    elif sys.platform == "win32":
        path = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")) / APP_NAME
        # Microsoft Store Python silently redirects AppData writes into its own package folder.
        # Resolving the (existing) folder gives the real location, so logs and messages point there.
        path.mkdir(parents=True, exist_ok=True)
        path = path.resolve()
    elif sys.platform == "darwin":
        path = Path.home() / "Library" / "Application Support" / APP_NAME
    else:
        path = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / APP_NAME.lower()
    path.mkdir(parents=True, exist_ok=True)
    return path


def package_dir() -> Path:
    """Directory holding templates/, static/ and assets/ (also valid inside a PyInstaller bundle)."""
    if is_frozen():
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent)) / "netscope"
    return Path(__file__).resolve().parent


def private_cache_dir() -> str:
    """A cache directory used only by this OS user.

    Scapy caches parsed data files under ~/.cache; a previous `sudo` run can leave
    that root-owned so a later normal-user `import scapy` crashes. Giving every
    user (root included) their own directory means they can never collide."""
    uid = os.getuid() if hasattr(os, "getuid") else os.environ.get("USERNAME", "user")
    return os.path.join(tempfile.gettempdir(), f"netscope-cache-{uid}")

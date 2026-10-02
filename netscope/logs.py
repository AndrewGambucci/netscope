"""Logging that also works in a windowed (console-less) frozen app, where sys.stderr is None."""
from __future__ import annotations

import logging
import logging.handlers
import sys

from netscope import paths

log = logging.getLogger("netscope")


def setup(verbose: bool = False, to_file: bool = True) -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # legacy Windows consoles are cp1252
        except Exception:
            pass

    log.setLevel(logging.DEBUG if verbose else logging.INFO)
    log.handlers.clear()
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%H:%M:%S")

    if sys.stderr is not None:
        console = logging.StreamHandler(sys.stderr)
        console.setFormatter(fmt)
        log.addHandler(console)
    if not to_file:
        return
    try:
        logfile = logging.handlers.RotatingFileHandler(
            paths.data_dir() / "netscope.log", maxBytes=512_000, backupCount=2, encoding="utf-8"
        )
        logfile.setFormatter(fmt)
        log.addHandler(logfile)
    except OSError:
        pass  # read-only home etc.: console logging is enough

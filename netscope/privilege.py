"""Starting the capture helper with the privileges packet capture needs.

Only the small helper is elevated; the window and web server stay unprivileged.
  macOS    native "NetScope wants to make changes" password dialog (osascript)
  Windows  standard UAC prompt (ShellExecute "runas"), window hidden
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from netscope import paths
from netscope.logs import log


def is_admin() -> bool:
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def helper_args(port: int, token: str) -> list[str]:
    """argv that runs the capture helper, for a source checkout, pip install or frozen app."""
    tail = ["--capture-helper", "--port", str(port), "--token", token]
    # The elevated process starts with a clean environment, so hand over the one setting it needs.
    ignore = os.environ.get("NETSCOPE_IGNORE_CIDRS")
    if ignore is not None:
        tail += ["--ignore-cidrs", ignore]
    if paths.is_frozen():
        return [sys.executable, *tail]
    return [sys.executable, "-m", "netscope", *tail]


_TCC_PROTECTED = ("Desktop", "Documents", "Downloads")


def helper_pythonpath() -> str | None:
    """PYTHONPATH the elevated helper needs, or None when it's frozen (code is inside the app).

    macOS privacy protection (TCC) stops a process started through the admin dialog from reading
    ~/Desktop, ~/Documents and ~/Downloads - even as root - so a checkout cloned there can't be
    imported. In that case a copy of the package is staged in the app's data folder instead.
    (Pip installs and the packaged app live outside those folders and are used in place.)"""
    if paths.is_frozen():
        return None
    package = paths.package_dir()
    if sys.platform == "darwin":
        home = Path.home().resolve()
        if any(package.resolve().is_relative_to(home / name) for name in _TCC_PROTECTED):
            staged = paths.data_dir() / "helper-src"
            shutil.rmtree(staged, ignore_errors=True)
            shutil.copytree(package, staged / "netscope",
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "static", "templates", "assets"))
            return str(staged)
    return str(package.parent)


def _applescript_string(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def macos_script(port: int, token: str) -> str:
    """The AppleScript that runs the helper as root. Split out so it can be unit tested."""
    argv = " ".join(shlex.quote(a) for a in helper_args(port, token))
    env = ""
    pythonpath = helper_pythonpath()
    if pythonpath:
        # root's environment is minimal: make sure it can import this copy of netscope
        env = f"env PYTHONPATH={shlex.quote(pythonpath)} "
    command = f"{env}{argv} >/dev/null 2>&1 &"
    prompt = "NetScope needs permission to watch network connections (it only reads packet headers)."
    return (f"do shell script {_applescript_string(command)} "
            f"with prompt {_applescript_string(prompt)} with administrator privileges")


def launch_helper(port: int, token: str) -> tuple[bool, str]:
    """Start the helper. Returns (started, user-facing error). 'Started' means the process
    was launched; it announces itself over the socket once it's actually capturing."""
    try:
        if is_admin():
            subprocess.Popen(helper_args(port, token), stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
            return True, ""

        if sys.platform == "darwin":
            result = subprocess.run(["osascript", "-e", macos_script(port, token)],
                                    capture_output=True, text=True, timeout=180)
            if result.returncode == 0:
                return True, ""
            if "-128" in result.stderr or "canceled" in result.stderr.lower():
                return False, "Permission was not granted, so live capture is off."
            log.warning("osascript failed: %s", result.stderr.strip())
            return False, "Could not get permission to capture packets."

        if sys.platform == "win32":
            import ctypes
            args = helper_args(port, token)
            cwd = None if paths.is_frozen() else str(paths.package_dir().parent)
            params = subprocess.list2cmdline(args[1:])
            # >32 means success; the elevated process runs hidden (SW_HIDE = 0)
            rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", args[0], params, cwd, 0)
            if rc > 32:
                return True, ""
            return False, "Administrator permission was not granted, so live capture is off."

        return False, "Live capture needs root on this platform. Run NetScope with sudo."
    except subprocess.TimeoutExpired:
        return False, "The permission dialog timed out."
    except Exception as e:  # noqa: BLE001 - surface anything as a friendly message
        log.exception("launch_helper failed")
        return False, f"Could not start the capture helper: {e}"

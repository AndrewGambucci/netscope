"""`netscope --create-shortcut`: put a launcher on the user's Desktop.

For pip / source installs. (The downloadable macOS .app and the Windows installer
ship their own icon and shortcut, so users of those never need this.)
"""
from __future__ import annotations

import plistlib
import shlex
import stat
import subprocess
import sys
from pathlib import Path

from netscope import APP_NAME, __version__, paths

BUNDLE_ID = "io.github.netscope"


def _icon(name: str) -> Path | None:
    icon = paths.package_dir() / "assets" / name
    return icon if icon.is_file() else None


def desktop_dir() -> Path:
    if sys.platform == "win32":
        # Resolve through the shell so OneDrive-redirected desktops work.
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", "[Environment]::GetFolderPath('Desktop')"],
            capture_output=True, text=True, timeout=30)
        if out.returncode == 0 and out.stdout.strip():
            return Path(out.stdout.strip())
    return Path.home() / "Desktop"


def create_macos_app(dest_dir: Path, python: str | None = None) -> Path:
    """Build a minimal NetScope.app that launches this Python environment's NetScope."""
    python = python or sys.executable
    app = dest_dir / f"{APP_NAME}.app"
    macos, resources = app / "Contents" / "MacOS", app / "Contents" / "Resources"
    macos.mkdir(parents=True, exist_ok=True)
    resources.mkdir(parents=True, exist_ok=True)

    plist = {
        "CFBundleName": APP_NAME,
        "CFBundleDisplayName": APP_NAME,
        "CFBundleIdentifier": BUNDLE_ID,
        "CFBundleVersion": __version__,
        "CFBundleShortVersionString": __version__,
        "CFBundlePackageType": "APPL",
        "CFBundleExecutable": APP_NAME,
        "NSHighResolutionCapable": True,
    }
    icon = _icon("icon.icns")
    if icon:
        (resources / "icon.icns").write_bytes(icon.read_bytes())
        plist["CFBundleIconFile"] = "icon"
    with open(app / "Contents" / "Info.plist", "wb") as f:
        plistlib.dump(plist, f)

    launcher = macos / APP_NAME
    launcher.write_text(
        "#!/bin/sh\n"
        f"export PYTHONPATH={shlex.quote(str(paths.package_dir().parent))}${{PYTHONPATH:+:$PYTHONPATH}}\n"
        f"exec {shlex.quote(python)} -m netscope \"$@\"\n")
    launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return app


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def create_windows_shortcut(dest_dir: Path, target: str | None = None, args: str = "") -> Path:
    if target is None:
        python = Path(sys.executable)
        gui = python.with_name("pythonw.exe")             # no console window
        target = str(gui if gui.exists() else python)
        args = "-m netscope"
    link = dest_dir / f"{APP_NAME}.lnk"
    icon = _icon("icon.ico")
    script = (
        "$s = (New-Object -ComObject WScript.Shell).CreateShortcut(" + _ps_quote(str(link)) + ");"
        f"$s.TargetPath = {_ps_quote(target)};"
        f"$s.Arguments = {_ps_quote(args)};"
        f"$s.WorkingDirectory = {_ps_quote(str(Path.home()))};"
        f"$s.Description = {_ps_quote('NetScope - live network traffic map')};"
        + (f"$s.IconLocation = {_ps_quote(str(icon))};" if icon else "")
        + "$s.Save()"
    )
    subprocess.run(["powershell", "-NoProfile", "-Command", script], check=True, timeout=60)
    return link


def create_desktop_shortcut() -> Path:
    dest = desktop_dir()
    dest.mkdir(parents=True, exist_ok=True)
    if sys.platform == "darwin":
        if paths.is_frozen():
            raise RuntimeError("You're already running the NetScope app - drag it to your Desktop or Dock.")
        return create_macos_app(dest)
    if sys.platform == "win32":
        if paths.is_frozen():
            return create_windows_shortcut(dest, target=sys.executable)
        return create_windows_shortcut(dest)
    raise RuntimeError("Desktop shortcuts are only supported on macOS and Windows.")

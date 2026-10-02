# -*- mode: python ; coding: utf-8 -*-
# Build with:  pyinstaller packaging/netscope.spec --noconfirm
# macOS   -> dist/NetScope.app
# Windows -> dist/NetScope/NetScope.exe  (wrapped into an installer by packaging/windows/netscope.iss)
import os
import re
import sys
import tempfile
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

os.environ["XDG_CACHE_HOME"] = tempfile.mkdtemp()   # keep scapy's import-time cache out of ~/.cache

ROOT = Path(SPECPATH).parent
PKG = ROOT / "netscope"
VERSION = re.search(r'__version__ = "([^"]+)"', (PKG / "__init__.py").read_text()).group(1)

icon_file = PKG / "assets" / ("icon.icns" if sys.platform == "darwin" else "icon.ico")
icon = str(icon_file) if icon_file.exists() else None

hiddenimports = (
    ["engineio.async_drivers.threading", "simple_websocket"]
    + collect_submodules("scapy")
    + collect_submodules("webview")
)

a = Analysis(
    [str(ROOT / "packaging" / "launcher.py")],
    pathex=[str(ROOT)],
    datas=[
        (str(PKG / "templates"), "netscope/templates"),
        (str(PKG / "static"), "netscope/static"),
        (str(PKG / "assets"), "netscope/assets"),
    ],
    hiddenimports=hiddenimports,
    excludes=["tkinter", "matplotlib", "numpy", "pytest", "IPython"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="NetScope",
    console=False,          # windowed: no terminal window behind the app
    icon=icon,
)

coll = COLLECT(exe, a.binaries, a.datas, name="NetScope")

if sys.platform == "darwin":
    app = BUNDLE(
        coll,
        name="NetScope.app",
        icon=icon,
        bundle_identifier="io.github.netscope",
        version=VERSION,
        info_plist={
            "CFBundleName": "NetScope",
            "CFBundleDisplayName": "NetScope",
            "CFBundleShortVersionString": VERSION,
            "NSHighResolutionCapable": True,
            "LSMinimumSystemVersion": "11.0",
            "NSHumanReadableCopyright": "MIT License",
        },
    )

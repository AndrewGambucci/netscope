# Contributing

```bash
git clone https://github.com/AndrewGambucci/NetScope && cd NetScope
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest          # no root, no network, no GeoIP database needed
ruff check .
python -m netscope --demo      # try the UI with simulated traffic
python -m netscope             # live capture (asks for permission)
```

## Layout
| Path | Role |
|---|---|
| `netscope/capture.py` | Packet classification + the privileged helper (**only** code that runs elevated) |
| `netscope/privilege.py` | Launching the helper (macOS admin dialog / Windows UAC) |
| `netscope/pipeline.py` | Validate, de-duplicate, geolocate, reverse-DNS, count |
| `netscope/geo.py` | Location database: locate, download, look up |
| `netscope/server.py` | Flask + Socket.IO, helper listener, app state |
| `netscope/templates`, `static` | The UI |
| `packaging/` | PyInstaller spec, macOS `.dmg` script, Windows Inno Setup script, icon generator |

## Building the apps locally
```bash
pip install ".[build]"
python packaging/make_icons.py              # only if netscope/assets/icon.png exists
pyinstaller packaging/netscope.spec --noconfirm
sh packaging/macos/build_dmg.sh             # macOS: dist/NetScope-<version>-macos-<arch>.dmg
```
Releases are built by `.github/workflows/release.yml` when a `v*` tag is pushed.

Please keep changes small, add tests for behaviour changes, and test on the OS you touched.

# Changelog

## Unreleased

- **Windows:** without Npcap, the capture helper reports it straight away instead of briefly showing LIVE.
- **Windows:** with Microsoft Store Python, the startup log shows the real data folder (Windows redirects
  that Python's AppData).
- **Windows:** `--create-shortcut` from a source checkout starts in the checkout folder, so it launches
  without a pip install (macOS already did this).

## 1.0.0

First packaged release.

- **Installable app** for macOS (`.dmg`) and Windows (installer with desktop shortcut), plus `pip install`
  and `netscope --create-shortcut`.
- **Privilege separation:** only a tiny capture helper runs as root/Administrator; the window and
  web server run as the normal user. macOS shows the native password dialog, Windows the UAC prompt.
- **No account or license key needed:** the location database (DB-IP City Lite) downloads
  automatically on first run and refreshes monthly. A MaxMind GeoLite2 file or `MAXMIND_LICENSE_KEY`
  is still honoured.
- Click-to-set your location on the map (saved per user), instead of environment variables only.
- In-app status banner (starting, waiting for permission, live, demo, errors) with retry buttons.
- Multi-homed / VPN machines: every local IPv4 address is used for direction detection.
- **Fixed:** DNS replies from public resolvers were shown as inbound PROBEs.
- **Fixed:** feed values from reverse DNS were inserted into the page unescaped (HTML injection).
- **Fixed:** crash on startup when `~/.cache` was root-owned from a previous `sudo` run.
- **Security:** DNS-rebinding protection (Host header check), restricted WebSocket origins,
  token-authenticated helper channel, bounded caches, Subresource Integrity on Leaflet.
- Windows support: Npcap guidance, UAC elevation, UTF-8 console handling, windowed build with log file.
- CI on macOS and Windows; tagged releases build installers automatically.

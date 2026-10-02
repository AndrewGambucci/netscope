# Third-party notices

NetScope is MIT licensed (see LICENSE). It uses:

- **IP geolocation by [DB-IP](https://db-ip.com)** — "IP to City Lite" database, licensed
  [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Downloaded on first run, not redistributed here.
- **[MaxMind GeoLite2](https://www.maxmind.com)** — optional; used if you provide your own file or license key.
  Its license doesn't allow redistribution, so it is never bundled.
- **Map data © [OpenStreetMap](https://www.openstreetmap.org/copyright) contributors** (ODbL), tiles served by the OSM tile servers
  under their [tile usage policy](https://operations.osmfoundation.org/policies/tiles/).
- [Leaflet](https://leafletjs.com) (BSD-2), [Socket.IO client](https://socket.io) (MIT),
  [Scapy](https://scapy.net) (GPL-2.0), [Flask](https://flask.palletsprojects.com) (BSD-3),
  [Flask-SocketIO](https://flask-socketio.readthedocs.io) (MIT), [pywebview](https://pywebview.flowrl.com) (BSD-3),
  [geoip2](https://github.com/maxmind/GeoIP2-python) (Apache-2.0).
- [Npcap](https://npcap.com) on Windows (separately installed by the user; see its license).

Scapy is GPL-2.0 licensed. NetScope imports it at runtime in the capture helper; if you redistribute
bundled binaries, make sure you comply with Scapy's license terms.

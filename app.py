#!/usr/bin/env python3
"""
NetScope — real-time network traffic visualizer.

Captures new outbound connections and unsolicited inbound probes off the local
network interface, geolocates the remote end against a local MaxMind GeoLite2
database, and streams the results to a live world map over WebSockets.

Run with:  python3 app.py       (macOS/Linux — re-runs itself under sudo as needed)
           python app.py        (Windows — start the terminal as Administrator)

Packet capture needs elevated privileges on every platform. Without a GeoIP
database available, the app falls back to a scripted demo mode so the UI is
still explorable with no setup at all.
"""

import threading
import time
import socket
import os
import sys
import webbrowser
import concurrent.futures
from collections import defaultdict

# ── dependency check ──────────────────────────────────────────────────────────
MISSING = []
try:
    from flask import Flask, render_template_string
    from flask_socketio import SocketIO
except ImportError:
    MISSING.append("flask flask-socketio")

try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY_OK = True
except ImportError:
    MISSING.append("scapy")
    SCAPY_OK = False

try:
    import geoip2.database
    import geoip2.errors
    GEOIP_OK = True
except ImportError:
    MISSING.append("geoip2")
    GEOIP_OK = False

webview = None
try:
    import webview
except ImportError:
    pass

if MISSING:
    print("\n[!] Missing packages. Install them with:")
    print(f"    pip install {' '.join(MISSING)}\n")
    sys.exit(1)

# ── config ────────────────────────────────────────────────────────────────────
GEOIP_DB = "GeoLite2-City.mmdb"          # looked up next to this file
PORT     = 6767

# Where the arcs originate on the map. Defaults to downtown Minneapolis; an
# approximate city-level origin is deliberate, since the point is to show where
# traffic *goes*, not to publish the operator's exact location. Override per-run:
#   NETSCOPE_LAT=47.61 NETSCOPE_LON=-122.33 NETSCOPE_LABEL="You (Seattle)" python3 app.py
HOME_LAT   = float(os.environ.get("NETSCOPE_LAT", "44.9778"))
HOME_LON   = float(os.environ.get("NETSCOPE_LON", "-93.2650"))
HOME_LABEL = os.environ.get("NETSCOPE_LABEL", "You (Minneapolis)")

# If set (a free key from https://www.maxmind.com/en/geolite2/signup) and no
# local GeoLite2-City.mmdb is found, one is downloaded automatically on startup.
MAXMIND_LICENSE_KEY = os.environ.get("MAXMIND_LICENSE_KEY", "")

# How long (seconds) to suppress duplicate events for the same
# remote host + port + direction, so one noisy connection doesn't
# flood the feed with repeat entries.
DEDUP_WINDOW = 20

# Cap on the dedup bookkeeping dict. Without this, a long-running capture
# accumulates one entry per unique (ip, port, direction) forever; expired
# entries are swept once this many keys pile up.
DEDUP_MAX_KEYS = 10_000

# Address prefixes never worth plotting: RFC1918 private space, loopback,
# link-local, multicast, and broadcast. These are either this machine talking to
# itself or LAN chatter, none of which has a meaningful map location.
IGNORE_NETS = [
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "127.", "0.", "169.254.", "224.", "239.", "255.",
]

# Extra individual IPs to drop, on top of the prefixes above. Empty by default —
# a hook for silencing a specific chatty host without editing IGNORE_NETS.
IGNORE_IPS: set[str] = set()

# ── platform / privileges ─────────────────────────────────────────────────────
IS_WINDOWS = os.name == "nt"

def is_elevated() -> bool:
    """True if this process can open a raw capture handle.

    POSIX exposes geteuid(); Windows has no such call, so we ask the shell API
    whether the process is running in the Administrators group instead. Any
    failure is reported as "not elevated" — the cost of a false negative is one
    extra warning line, while a false positive means capture fails later with a
    far more confusing error.
    """
    if IS_WINDOWS:
        try:
            import ctypes
            # getattr, not ctypes.windll directly: the attribute only exists on
            # Windows builds, and a bare reference trips type checkers elsewhere.
            windll = getattr(ctypes, "windll")
            return bool(windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0

def npcap_installed() -> bool:
    """Windows only: whether Scapy found a usable Npcap/WinPcap provider.

    Scapy imports fine without the driver but yields zero interfaces, so the
    interface list is the reliable signal. Always True off Windows, where
    libpcap ships with the OS.
    """
    if not IS_WINDOWS:
        return True
    try:
        from scapy.arch.windows import get_windows_if_list
        return len(get_windows_if_list()) > 0
    except Exception:
        return False

def privilege_hint() -> str:
    """Platform-appropriate instructions for getting capture permissions."""
    if IS_WINDOWS:
        return ("Close this window, right-click your terminal (PowerShell/cmd) and pick\n"
                "    \"Run as administrator\", then run:  python app.py")
    return "Run it with sudo:  sudo python3 app.py"

# ── globals ───────────────────────────────────────────────────────────────────
app       = Flask(__name__)
socketio  = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
geo_reader = None
stats     = defaultdict(int)   # country -> hit count
seen_ips  = {}                 # ip -> geo dict  (simple cache)
rdns_cache: dict[str, str] = {}
_rdns_pool = concurrent.futures.ThreadPoolExecutor(max_workers=8)
_recent_events: dict[tuple, float] = {}   # (remote_ip, port, direction) -> last emitted ts
_local_ips: set[str] = set()

# ── Reverse DNS ───────────────────────────────────────────────────────────────
def rdns_lookup(ip: str) -> str:
    if ip in rdns_cache:
        return rdns_cache[ip]
    try:
        host = _rdns_pool.submit(socket.gethostbyaddr, ip).result(timeout=0.5)[0]
    except Exception:
        host = ""
    rdns_cache[ip] = host
    return host

# ── GeoIP setup ───────────────────────────────────────────────────────────────
def geoip_db_path() -> str:
    """Absolute path to the GeoLite2 database beside this file.

    Resolved from __file__ rather than the working directory so the app behaves
    the same whether launched from its own folder, from elsewhere, or re-executed
    by the sudo relaunch below.
    """
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), GEOIP_DB)

def load_geoip():
    global geo_reader
    db_path = geoip_db_path()
    if not os.path.exists(db_path):
        print(f"\n[!] GeoLite2 database not found at: {db_path}")
        print("    Download it free from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
        print("    Register, download GeoLite2-City.mmdb and put it next to app.py\n")
        print("    Running in DEMO MODE with fake traffic instead.\n")
        return False
    try:
        geo_reader = geoip2.database.Reader(db_path)
        print(f"[+] GeoIP database loaded: {db_path}")
        return True
    except Exception as e:
        print(f"[!] Could not open GeoIP database: {e}")
        return False

def download_geoip(license_key: str) -> bool:
    """Fetch GeoLite2-City.mmdb from MaxMind using the caller's own free
    license key. Only ever runs when the file isn't already present."""
    import tarfile
    import tempfile
    import urllib.request

    url = (
        "https://download.maxmind.com/app/geoip_download"
        f"?edition_id=GeoLite2-City&license_key={license_key}&suffix=tar.gz"
    )
    print("[+] No local GeoLite2 database found — downloading with your MaxMind license key…")
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            archive_path = os.path.join(tmpdir, "geolite.tar.gz")
            urllib.request.urlretrieve(url, archive_path)
            with tarfile.open(archive_path, "r:gz") as tar:
                if hasattr(tarfile, "data_filter"):
                    tar.extractall(tmpdir, filter="data")
                else:
                    tar.extractall(tmpdir)

            found = None
            for root, _, files in os.walk(tmpdir):
                if GEOIP_DB in files:
                    found = os.path.join(root, GEOIP_DB)
                    break
            if not found:
                print("[!] Downloaded archive did not contain GeoLite2-City.mmdb")
                return False

            # shutil.copyfile streams the ~60MB database instead of reading it
            # fully into memory the way read()/write() would.
            import shutil
            shutil.copyfile(found, geoip_db_path())
        print("[+] GeoLite2 database downloaded successfully.")
        return True
    except Exception as e:
        print(f"[!] Failed to download GeoLite2 database: {e}")
        print("    Download it manually from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
        return False

def lookup(ip: str) -> dict | None:
    if ip in seen_ips:
        return seen_ips[ip]
    try:
        r = geo_reader.city(ip)
        if r.location.latitude is None:
            return None
        result = {
            "ip":      ip,
            "lat":     r.location.latitude,
            "lon":     r.location.longitude,
            "city":    r.city.name or "",
            "country": r.country.name or "Unknown",
            "cc":      r.country.iso_code or "",
        }
        seen_ips[ip] = result
        return result
    except Exception:
        seen_ips[ip] = None
        return None

# ── packet sniffer ────────────────────────────────────────────────────────────
# Only meaningful, connection-level events are captured — not every packet on
# the wire. That means:
#   - outbound: the SYN that opens a new TCP connection (i.e. "you requested
#     something from a site"), or a DNS query (i.e. "you looked a hostname up")
#   - inbound:  an unsolicited SYN arriving from a public IP (i.e. something
#     out there is probing/connecting to this machine, not routine reply
#     traffic from a connection we opened)
# Established-connection chatter (ACKs, retransmits, keepalives, streaming
# payload packets) is filtered out at the kernel level via the BPF filter
# below, and repeat events for the same host are suppressed for DEDUP_WINDOW
# seconds so one chatty remote doesn't flood the feed.
SNIFF_FILTER = (
    "(tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn) or (udp and port 53)"
)

def is_private(ip: str) -> bool:
    """Whether an address is local-only and therefore not worth mapping.

    Covers private, loopback, link-local, multicast and broadcast space — all
    the ranges in IGNORE_NETS, not just RFC1918.
    """
    return any(ip.startswith(p) for p in IGNORE_NETS)

def get_local_ips() -> set[str]:
    """Best-effort set of this machine's own addresses, used to tell inbound
    from outbound.

    The UDP 'connection' to 8.8.8.8 sends no packets — it only asks the routing
    table which local address would be used to reach the internet, which is the
    reliable way to find the primary interface's IP. The hostname lookup is a
    fallback that catches some additional configurations.
    """
    ips = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        ips.add(socket.gethostbyname(socket.gethostname()))
    except Exception:
        pass
    return ips

def _is_dupe(remote_ip: str, port: int, direction: str) -> bool:
    """Whether this event repeats one seen within DEDUP_WINDOW seconds."""
    key = (remote_ip, port, direction)
    now = time.time()
    last = _recent_events.get(key)
    if last is not None and now - last < DEDUP_WINDOW:
        return True
    _recent_events[key] = now

    # Entries stay in the dict purely as timestamps, so on a busy link this
    # would grow without bound over a long capture. Anything older than the
    # window can no longer suppress a duplicate, so sweep it.
    if len(_recent_events) > DEDUP_MAX_KEYS:
        cutoff = now - DEDUP_WINDOW
        for k in [k for k, ts in _recent_events.items() if ts < cutoff]:
            del _recent_events[k]
    return False

def process_packet(pkt):
    # A malformed/truncated packet here must never kill the sniff() loop —
    # that would silently stop all capture with no visible error.
    try:
        _handle_packet(pkt)
    except Exception as e:
        print(f"[!] Skipped unparseable packet: {e}")

def _handle_packet(pkt):
    if IP not in pkt:
        return
    src, dst = pkt[IP].src, pkt[IP].dst

    if TCP in pkt:
        flags = pkt[TCP].flags
        if not (flags & 0x02) or flags & 0x10:   # require SYN, reject SYN-ACK/ACK
            return
        dport = pkt[TCP].dport
        proto = "HTTPS" if dport == 443 else ("HTTP" if dport == 80 else "TCP")
        port  = dport
    elif UDP in pkt:
        proto = "DNS"
        port  = 53
    else:
        return

    # Determine direction relative to this machine. Traffic between two
    # remote/private hosts (shouldn't normally reach us) is dropped.
    dst_is_us = dst in _local_ips or is_private(dst)
    src_is_us = src in _local_ips or is_private(src)

    if src_is_us and not dst_is_us:
        direction, remote = "out", dst
    elif dst_is_us and not src_is_us:
        direction, remote = "in", src
    else:
        return

    if is_private(remote) or remote in IGNORE_IPS:
        return
    if _is_dupe(remote, port, direction):
        return

    if direction == "in":
        proto = "PROBE"

    geo = lookup(remote)
    if geo is None:
        return

    stats[geo["country"]] += 1

    payload = {
        **geo,
        "proto":     proto,
        "direction": direction,
        "hostname":  rdns_lookup(remote),
        "src_lat":   HOME_LAT,
        "src_lon":   HOME_LON,
        "ts":        time.time(),
        "top":       sorted(stats.items(), key=lambda x: -x[1])[:8]
    }
    socketio.emit("pkt", payload)

def start_sniffer():
    if not SCAPY_OK or geo_reader is None:
        return
    global _local_ips
    _local_ips = get_local_ips()
    print(f"[+] Local IP(s): {', '.join(_local_ips) or 'unknown'}")
    print("[+] Capturing new connections and inbound probes…")
    try:
        sniff(
            prn=process_packet,
            store=False,
            filter=SNIFF_FILTER,
        )
    except PermissionError:
        # POSIX raises this for a non-root raw socket. Windows usually surfaces
        # the same condition as OSError instead, handled below.
        print(f"\n[!] Permission denied opening the capture device.\n    {privilege_hint()}\n")
    except OSError as e:
        # Covers the Windows "no such device / driver missing" family, where the
        # cause is almost always Npcap rather than privileges.
        if IS_WINDOWS and not npcap_installed():
            print("\n[!] No capture driver found. Scapy needs Npcap on Windows:")
            print("    Install it from https://npcap.com/ (check \"WinPcap API-compatible\n"
                  "    mode\" during setup), then restart this terminal.\n")
        else:
            print(f"\n[!] Could not start capture: {e}\n    {privilege_hint()}\n")
    except Exception as e:
        print(f"[!] Sniffer error: {e}")

# ── demo mode ─────────────────────────────────────────────────────────────────
# Reached whenever live capture isn't possible: no GeoLite2 database, or on
# Windows a missing Npcap driver or a non-elevated terminal.
# Scripted stand-in traffic so the UI is explorable with zero setup. The mix
# includes inbound PROBE entries as well as outbound requests, so demo mode
# exercises both arc directions rather than only showing outbound.
# Hostnames are hardcoded rather than resolved: demo mode must not fire real
# DNS queries, both to stay offline-friendly and to keep the sniffer's own
# traffic out of a live capture running alongside it.
DEMO_TARGETS = [
    {"ip":"8.8.8.8",      "lat":37.42,  "lon":-122.08, "city":"Mountain View",   "country":"United States", "cc":"US","proto":"DNS",   "direction":"out","hostname":"dns.google"},
    {"ip":"104.16.0.1",   "lat":51.51,  "lon":-0.13,   "city":"London",          "country":"United Kingdom","cc":"GB","proto":"HTTPS", "direction":"out","hostname":"cloudflare.com"},
    {"ip":"31.13.72.36",  "lat":48.86,  "lon":2.35,    "city":"Paris",           "country":"France",        "cc":"FR","proto":"HTTPS", "direction":"out","hostname":""},
    {"ip":"52.94.236.248","lat":35.68,  "lon":139.69,  "city":"Tokyo",           "country":"Japan",         "cc":"JP","proto":"TCP",   "direction":"out","hostname":""},
    {"ip":"185.60.218.35","lat":55.75,  "lon":37.62,   "city":"Moscow",          "country":"Russia",        "cc":"RU","proto":"PROBE", "direction":"in", "hostname":""},
    {"ip":"142.250.80.46","lat":-33.87, "lon":151.21,  "city":"Sydney",          "country":"Australia",     "cc":"AU","proto":"HTTPS", "direction":"out","hostname":""},
    {"ip":"13.107.42.14", "lat":47.61,  "lon":-122.33, "city":"Seattle",         "country":"United States", "cc":"US","proto":"TCP",   "direction":"out","hostname":""},
    {"ip":"203.0.113.5",  "lat":22.28,  "lon":114.16,  "city":"Hong Kong",       "country":"Hong Kong",     "cc":"HK","proto":"PROBE", "direction":"in", "hostname":""},
    {"ip":"157.240.22.35","lat":37.77,  "lon":-122.42, "city":"San Francisco",   "country":"United States", "cc":"US","proto":"HTTPS", "direction":"out","hostname":""},
    {"ip":"1.1.1.1",      "lat":-27.46, "lon":153.02,  "city":"Brisbane",        "country":"Australia",     "cc":"AU","proto":"DNS",   "direction":"out","hostname":"one.one.one.one"},
    {"ip":"190.0.68.0",   "lat":-34.60, "lon":-58.38,  "city":"Buenos Aires",    "country":"Argentina",     "cc":"AR","proto":"PROBE", "direction":"in", "hostname":""},
    {"ip":"17.253.144.10","lat":52.37,  "lon":4.89,    "city":"Amsterdam",       "country":"Netherlands",   "cc":"NL","proto":"HTTPS", "direction":"out","hostname":""},
]

_demo_stop = threading.Event()

def run_demo():
    import random
    print("[~] Demo mode: scripted sample traffic (no packets are being captured).")
    i = 0
    # wait() rather than sleep() so the thread can be told to exit promptly.
    while not _demo_stop.wait(random.uniform(0.8, 2.5)):
        t = DEMO_TARGETS[i % len(DEMO_TARGETS)]
        stats[t["country"]] += 1
        payload = {
            **t,
            "src_lat": HOME_LAT,
            "src_lon": HOME_LON,
            "ts":      time.time(),
            "top":     sorted(stats.items(), key=lambda x: -x[1])[:8]
        }
        socketio.emit("pkt", payload)
        i += 1

# ── HTML / JS front-end ───────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetScope</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.min.js"></script>
<style>
  :root {
    --bg:       #03070f;
    --panel:    #070d1a;
    --border:   #0d2040;
    --accent:   #00d4ff;
    --accent2:  #ff6b35;
    --accent3:  #39ff14;
    --dim:      #1a3050;
    --text:     #a8d4f0;
    --textdim:  #3a6080;
    --font-mono: 'Share Tech Mono', monospace;
    --font-head: 'Orbitron', sans-serif;
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-mono);
    height: 100vh;
    overflow: hidden;
    display: flex;
    flex-direction: column;
  }

  /* scanline overlay */
  body::after {
    content:'';
    position:fixed; inset:0;
    background: repeating-linear-gradient(
      0deg, transparent, transparent 2px,
      rgba(0,212,255,0.015) 2px, rgba(0,212,255,0.015) 4px
    );
    pointer-events:none;
    z-index:9999;
  }

  /* ── header ── */
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 20px;
    border-bottom: 1px solid var(--border);
    background: var(--panel);
    flex-shrink: 0;
    position: relative;
    z-index: 100;
  }

  .logo {
    font-family: var(--font-head);
    font-size: 1.4rem;
    font-weight: 900;
    letter-spacing: .15em;
    color: var(--accent);
    text-shadow: 0 0 20px var(--accent), 0 0 40px rgba(0,212,255,0.3);
  }
  .logo span { color: var(--accent2); }

  .status-bar {
    display: flex;
    gap: 24px;
    font-size: .72rem;
    letter-spacing: .08em;
    color: var(--textdim);
  }
  .status-bar .val {
    color: var(--accent3);
    font-weight: bold;
  }
  #status-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    background: var(--accent3);
    display: inline-block;
    margin-right: 6px;
    animation: pulse 1.5s infinite;
  }
  @keyframes pulse {
    0%,100%{ box-shadow: 0 0 4px var(--accent3); opacity:1; }
    50%    { box-shadow: 0 0 12px var(--accent3); opacity:.6; }
  }

  /* ── layout ── */
  .main {
    display: flex;
    flex: 1;
    overflow: hidden;
  }

  /* ── map ── */
  #map {
    flex: 1;
    background: #020810;
  }

  /* leaflet dark tile tweaks */
  .leaflet-tile { filter: brightness(.55) saturate(.6) hue-rotate(190deg); }
  .leaflet-container { background: #020810; }

  /* ── sidebar ── */
  aside {
    width: 290px;
    flex-shrink: 0;
    background: var(--panel);
    border-left: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .panel-title {
    font-family: var(--font-head);
    font-size: .62rem;
    letter-spacing: .18em;
    color: var(--textdim);
    padding: 12px 16px 8px;
    border-bottom: 1px solid var(--border);
    text-transform: uppercase;
  }

  /* live feed */
  #feed {
    flex: 1;
    overflow-y: auto;
    padding: 0;
  }
  #feed::-webkit-scrollbar { width: 3px; }
  #feed::-webkit-scrollbar-track { background: transparent; }
  #feed::-webkit-scrollbar-thumb { background: var(--dim); }

  .feed-item {
    padding: 9px 16px;
    border-bottom: 1px solid rgba(13,32,64,.6);
    animation: fadeIn .25s ease;
    cursor: default;
    transition: background .15s;
  }
  .feed-item:hover { background: rgba(0,212,255,.04); }
  @keyframes fadeIn { from { opacity:0; transform: translateX(8px); } to { opacity:1; transform:none; } }

  .feed-host { font-size: .78rem; color: var(--accent); letter-spacing:.04em; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .feed-meta { font-size: .68rem; color: var(--textdim); margin-top: 2px; display:flex; align-items:center; gap:6px; }
  .feed-meta .country { color: var(--text); }

  .proto-badge {
    display: inline-block;
    font-size: .6rem;
    padding: 1px 5px;
    border-radius: 2px;
    font-family: var(--font-head);
    letter-spacing: .08em;
    margin-left: 6px;
    vertical-align: middle;
  }
  .proto-HTTPS  { background: rgba(0,212,255,.12);  color: var(--accent);  border: 1px solid rgba(0,212,255,.3); }
  .proto-HTTP   { background: rgba(255,107,53,.12); color: var(--accent2); border: 1px solid rgba(255,107,53,.3); }
  .proto-DNS    { background: rgba(57,255,20,.12);  color: var(--accent3); border: 1px solid rgba(57,255,20,.3); }
  .proto-TCP    { background: rgba(168,212,240,.08);color: var(--text);    border: 1px solid rgba(168,212,240,.2); }
  .proto-UDP    { background: rgba(168,212,240,.06);color: var(--textdim); border: 1px solid var(--dim); }
  .proto-OTHER  { background: transparent;          color: var(--textdim); border: 1px solid var(--dim); }
  .proto-PROBE  { background: rgba(255,45,85,.14);  color: #ff2d55;        border: 1px solid rgba(255,45,85,.4); }

  /* top countries */
  #toplist {
    padding: 0 0 8px;
    border-top: 1px solid var(--border);
  }
  .top-row {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 5px 16px;
    font-size: .7rem;
  }
  .top-rank { color: var(--textdim); width: 14px; text-align:right; flex-shrink:0; }
  .top-bar-wrap { flex:1; background: var(--dim); height: 3px; border-radius: 2px; overflow:hidden; }
  .top-bar { height:100%; background: var(--accent); border-radius:2px; transition: width .4s ease; }
  .top-name { color: var(--text); flex: 0 0 110px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .top-count { color: var(--accent); width: 28px; text-align:right; flex-shrink:0; }

  /* counter strip */
  .counters {
    display: flex;
    border-top: 1px solid var(--border);
    flex-shrink: 0;
  }
  .counter {
    flex:1;
    text-align:center;
    padding: 10px 4px;
    border-right: 1px solid var(--border);
  }
  .counter:last-child { border-right: none; }
  .counter-val {
    font-family: var(--font-head);
    font-size: 1.1rem;
    color: var(--accent);
    font-weight: 700;
  }
  .counter-lbl {
    font-size: .55rem;
    color: var(--textdim);
    letter-spacing: .1em;
    margin-top: 1px;
  }
</style>
</head>
<body>

<header>
  <div class="logo">NET<span>SCOPE</span></div>
  <div class="status-bar">
    <span><span id="status-dot"></span><span id="mode-label">CONNECTING…</span></span>
    <span>IPS <span class="val" id="hdr-ips">0</span></span>
    <span>COUNTRIES <span class="val" id="hdr-ctry">0</span></span>
  </div>
</header>

<div class="main">
  <div id="map"></div>

  <aside>
    <div class="panel-title">▸ Live Connections</div>
    <div id="feed"></div>

    <div id="toplist">
      <div class="panel-title">▸ Top Destinations</div>
      <div id="top-rows"></div>
    </div>

    <div class="counters">
      <div class="counter"><div class="counter-val" id="c-pkts" style="font-size:.65rem;letter-spacing:.04em;">—</div><div class="counter-lbl">TOP COUNTRY</div></div>
      <div class="counter"><div class="counter-val" id="c-ips">0</div><div class="counter-lbl">UNIQUE IPS</div></div>
      <div class="counter"><div class="counter-val" id="c-ctry">0</div><div class="counter-lbl">COUNTRIES</div></div>
    </div>
  </aside>
</div>

<script>
// ── map init ──────────────────────────────────────────────────────────────────
const map = L.map('map', {
  center: [20, 0], zoom: 2,
  zoomControl: false,
  attributionControl: false
});

L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
  maxZoom: 18
}).addTo(map);

L.control.zoom({ position: 'topleft' }).addTo(map);

// home marker
const homeIcon = L.divIcon({
  html: `<div style="
    width:12px;height:12px;border-radius:50%;
    background:#39ff14;
    box-shadow:0 0 10px #39ff14,0 0 20px #39ff14;
    border:2px solid #fff;
  "></div>`,
  iconSize:[12,12], iconAnchor:[6,6], className:''
});

const HOME = { lat: {{ home_lat }}, lon: {{ home_lon }} };
L.marker([HOME.lat, HOME.lon], {icon: homeIcon})
  .bindTooltip('{{ home_label }}', {permanent:false, className:'', direction:'right'})
  .addTo(map);

// ── arc drawing ───────────────────────────────────────────────────────────────
const PROTO_COLORS = {
  HTTPS: '#00d4ff', HTTP: '#ff6b35', DNS: '#39ff14',
  TCP:   '#a8d4f0', UDP: '#5a8aaa', OTHER: '#2a5070',
  PROBE: '#ff2d55'
};

// Builds the curved flight-path line between two points.
//
// Two things matter here beyond plain interpolation. First, the shorter way
// between two longitudes may cross the antimeridian — Minneapolis to Tokyo runs
// west across the Pacific, not east across all of Europe and Asia — so the
// endpoint is unwrapped past ±180 and Leaflet is left to wrap it back. Second,
// a straight line reads as a chord on a projected map, so the midpoint is
// lifted perpendicular to the path to bow it into a visible arc.
function greatCirclePoints(lat1, lon1, lat2, lon2, n=60) {
  // Unwrap the destination longitude onto whichever side is actually closer.
  let dLon = lon2 - lon1;
  if (dLon >  180) dLon -= 360;
  if (dLon < -180) dLon += 360;

  const dLat = lat2 - lat1;
  // Bow height scales with path length but is capped, so short hops stay gentle
  // and intercontinental ones don't balloon off the top of the map.
  const dist = Math.hypot(dLat, dLon);
  const bow  = Math.min(dist * 0.15, 20);

  const pts = [];
  for (let i = 0; i <= n; i++) {
    const t = i / n;
    // sin(pi*t) peaks at the midpoint and is zero at both endpoints.
    const lift = Math.sin(Math.PI * t) * bow;
    pts.push([lat1 + dLat * t + lift, lon1 + dLon * t]);
  }
  return pts;
}

function drawArc(srcLat, srcLon, dstLat, dstLon, proto) {
  const color = PROTO_COLORS[proto] || PROTO_COLORS.OTHER;
  const pts   = greatCirclePoints(srcLat, srcLon, dstLat, dstLon);

  // animated dashed polyline
  const line = L.polyline(pts, {
    color, weight: 1.5, opacity: 0,
    dashArray: '6 8', dashOffset: '0'
  }).addTo(map);

  // fade in
  let op = 0;
  const fadeIn = setInterval(() => {
    op += 0.08;
    line.setStyle({ opacity: Math.min(op, 0.75) });
    if (op >= 0.75) clearInterval(fadeIn);
  }, 30);

  // dash animation
  let offset = 0;
  const dash = setInterval(() => {
    offset -= 1;
    line.setStyle({ dashOffset: String(offset) });
  }, 30);

  // destination pulse
  const pulseIcon = L.divIcon({
    html: `<div class="pulse-ring" style="--c:${color}"></div>`,
    iconSize:[16,16], iconAnchor:[8,8], className:''
  });
  const marker = L.marker([dstLat, dstLon], {icon: pulseIcon}).addTo(map);

  // fade out after 6s
  setTimeout(() => {
    clearInterval(dash);
    let o2 = 0.75;
    const fadeOut = setInterval(() => {
      o2 -= 0.05;
      line.setStyle({ opacity: Math.max(o2, 0) });
      if (o2 <= 0) { clearInterval(fadeOut); map.removeLayer(line); }
    }, 40);
    setTimeout(() => { try { map.removeLayer(marker); } catch(e){} }, 800);
  }, 5500);
}

// pulse ring CSS
const style = document.createElement('style');
style.textContent = `
.pulse-ring {
  width:14px; height:14px; border-radius:50%;
  border: 2px solid var(--c, #00d4ff);
  animation: ringPulse 1s ease-out forwards;
  box-shadow: 0 0 6px var(--c,#00d4ff);
}
@keyframes ringPulse {
  0%   { transform:scale(.5); opacity:1; }
  100% { transform:scale(2.5); opacity:0; }
}`;
document.head.appendChild(style);

// ── stats ──────────────────────────────────────────────────────────────────────
let uniqueIPs = new Set(), uniqueCtry = new Set();

let topCountry = '—';

function updateCounters(top) {
  if (top && top.length) topCountry = top[0][0];
  const i = uniqueIPs.size, c = uniqueCtry.size;
  document.getElementById('c-pkts').textContent  = topCountry;
  document.getElementById('c-ips').textContent   = i;
  document.getElementById('c-ctry').textContent  = c;
  document.getElementById('hdr-ips').textContent  = i;
  document.getElementById('hdr-ctry').textContent = c;
}

function updateTopList(top) {
  const max   = top.length ? top[0][1] : 1;
  const wrap  = document.getElementById('top-rows');
  wrap.innerHTML = top.map(([name, cnt], i) => `
    <div class="top-row">
      <span class="top-rank">${i+1}</span>
      <span class="top-name">${esc(name)}</span>
      <div class="top-bar-wrap"><div class="top-bar" style="width:${Math.round(cnt/max*100)}%"></div></div>
      <span class="top-count">${Number(cnt) || 0}</span>
    </div>`).join('');
}

// ── feed ───────────────────────────────────────────────────────────────────────
const feed     = document.getElementById('feed');
const MAX_FEED = 80;

// Every string rendered below originates off-machine. A reverse-DNS hostname in
// particular is chosen by whoever controls the remote IP's PTR record, so a
// hostile host could name itself "<img onerror=...>" and get script execution in
// this dashboard. Escape before interpolating anywhere.
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[c]);
}

// Protocol drives a CSS class name, so restrict it to the known set rather than
// letting arbitrary text into the class attribute.
const KNOWN_PROTOS = ['HTTPS','HTTP','DNS','TCP','UDP','PROBE'];
function protoClass(p) {
  return KNOWN_PROTOS.includes(p) ? p : 'OTHER';
}

function addFeedItem(d) {
  const el = document.createElement('div');
  el.className = 'feed-item';
  const city = d.city ? `${esc(d.city)}, ` : '';
  const hostLine = d.hostname
    ? `<div class="feed-host">${esc(d.hostname)}</div>`
    : `<div class="feed-host" style="color:var(--textdim)">${esc(d.ip)}</div>`;
  el.innerHTML = `
    ${hostLine}
    <div class="feed-meta">
      <span class="proto-badge proto-${protoClass(d.proto)}">${esc(d.proto)}</span>
      <span class="country">${city}${esc(d.country)}</span>
    </div>`;
  feed.prepend(el);
  while (feed.children.length > MAX_FEED) feed.lastChild.remove();
}

// ── socket ─────────────────────────────────────────────────────────────────────
const socket = io();

// The badge must never read LIVE while demo traffic is playing — the whole
// point of the tool is trusting that what's on the map really happened.
const IS_DEMO = {{ 'true' if demo_mode else 'false' }};

socket.on('connect', () => {
  document.getElementById('mode-label').textContent = IS_DEMO ? 'DEMO DATA' : 'LIVE CAPTURE';
});
socket.on('disconnect', () => {
  document.getElementById('mode-label').textContent = 'DISCONNECTED';
});

socket.on('pkt', d => {
  uniqueIPs.add(d.ip);
  uniqueCtry.add(d.country);

  // inbound probes are drawn flowing toward home, not away from it
  if (d.direction === 'in') {
    drawArc(d.lat, d.lon, d.src_lat, d.src_lon, d.proto);
  } else {
    drawArc(d.src_lat, d.src_lon, d.lat, d.lon, d.proto);
  }
  addFeedItem(d);
  updateCounters(d.top);
  if (d.top) updateTopList(d.top);
});
</script>
</body>
</html>"""

# ── routes ────────────────────────────────────────────────────────────────────
# Set once at startup so the UI can label demo traffic honestly.
DEMO_MODE = False

@app.route("/")
def index():
    return render_template_string(
        HTML,
        home_lat=HOME_LAT,
        home_lon=HOME_LON,
        home_label=HOME_LABEL,
        demo_mode=DEMO_MODE,
    )

@app.errorhandler(Exception)
def handle_error(e):
    print(f"[!] Unhandled Flask error: {e}")
    return "Something went wrong loading NetScope. Check the server log for details.", 500

# ── main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("""
  ███╗   ██╗███████╗████████╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
  ██╔██╗ ██║█████╗     ██║   ███████╗██║     ██║   ██║██████╔╝█████╗
  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝
  ██║ ╚████║███████╗   ██║   ███████║╚██████╗╚██████╔╝██║     ███████╗
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
    """)

    # Get a GeoIP database in place before dealing with privileges — downloading
    # needs none, capturing does, and having the file settles whether a capture
    # is even going to be attempted.
    _db_path = geoip_db_path()
    if not os.path.exists(_db_path) and MAXMIND_LICENSE_KEY:
        download_geoip(MAXMIND_LICENSE_KEY)

    _want_capture = os.path.exists(_db_path)
    if not _want_capture:
        # Explain the fallback here rather than leaving the user to guess why the
        # map is showing traffic they didn't generate.
        print(f"[!] No GeoLite2 database found at {_db_path}")
        if MAXMIND_LICENSE_KEY:
            print("    The automatic download didn't succeed — see the error above.")
        else:
            print("    Set MAXMIND_LICENSE_KEY and restart to fetch one automatically:")
            print("      https://www.maxmind.com/en/geolite2/signup")
        print("    Starting in DEMO MODE with scripted sample traffic.\n")

    # Windows: no sudo to re-exec through, and UAC elevation would spawn a
    # detached console the user can't see output in. Warn and continue instead —
    # demo mode still gives them a working UI.
    if _want_capture and IS_WINDOWS:
        if not npcap_installed():
            print("[!] Npcap not detected — live capture needs it on Windows.")
            print("    Install from https://npcap.com/ (enable \"WinPcap API-compatible mode\"),")
            print("    then restart your terminal. Falling back to demo mode for now.\n")
            _want_capture = False
        elif not is_elevated():
            print("[!] Not running as Administrator — live capture will be denied.")
            print(f"    {privilege_hint()}")
            print("    Continuing in demo mode for now.\n")
            _want_capture = False

    # macOS/Linux: re-exec under sudo, preserving the current interpreter (so a
    # virtualenv survives) and the environment (-E, so NETSCOPE_* and
    # MAXMIND_LICENSE_KEY aren't dropped). Skipped in demo mode, where no
    # capture is attempted and root would buy nothing.
    if _want_capture and not IS_WINDOWS and not is_elevated():
        print("[+] Packet capture needs root — relaunching with sudo (you may be prompted for your password)…")
        try:
            os.execvp("sudo", ["sudo", "-E", sys.executable, os.path.abspath(__file__)] + sys.argv[1:])
        except Exception as e:
            print(f"[!] Could not relaunch with sudo automatically: {e}")
            print(f"    {privilege_hint()}")
            sys.exit(1)

    geoip_loaded = load_geoip() if _want_capture else False

    # Check the port before starting any traffic source, so a second instance
    # exits on the conflict instead of first announcing a capture it won't run.
    # Doing it here also keeps EADDRINUSE out of the Werkzeug background thread,
    # where the traceback is easy to miss.
    _probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        _probe.bind(("127.0.0.1", PORT))
    except OSError:
        print(f"[!] Port {PORT} is already in use — NetScope may already be running.")
        print("    Close the other instance, or change PORT at the top of app.py.")
        sys.exit(1)
    finally:
        _probe.close()

    # Live capture when a database loaded, scripted traffic otherwise. Either
    # way the source thread is a daemon, so it dies with the process.
    DEMO_MODE = not geoip_loaded
    source = start_sniffer if geoip_loaded else run_demo
    threading.Thread(target=source, daemon=True).start()

    def serve():
        # allow_unsafe_werkzeug: this is Werkzeug's dev server, but the socket is
        # bound to loopback only and NetScope is a single-user local tool, so the
        # usual "don't serve this publicly" caveat doesn't apply.
        socketio.run(app, host="127.0.0.1", port=PORT, debug=False,
                     use_reloader=False, allow_unsafe_werkzeug=True)

    def wait_for_server(timeout=30.0) -> bool:
        """Poll until Flask accepts connections, rather than guessing with sleep.

        A fixed delay either races the server on a slow machine (blank window) or
        wastes time on a fast one. The timeout is generous because a cold start —
        first import of Scapy, bytecode still being compiled — is slow on older
        hardware, and slow is not the same as broken.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", PORT), timeout=0.25):
                    return True
            except OSError:
                time.sleep(0.1)
        return False

    try:
        if webview is not None:
            # pywebview must own the main thread, so Flask goes to a background one.
            threading.Thread(target=serve, daemon=True).start()
            if not wait_for_server():
                # Not fatal — the server may still be warming up, and the window
                # will connect once it does. Better a slow window than a hard
                # exit on a slow machine.
                print("[!] Server slow to start — opening the window anyway.")
            print(f"[+] Opening desktop window (http://127.0.0.1:{PORT})")
            webview.create_window(
                "NetScope",
                f"http://127.0.0.1:{PORT}",
                width=1400,
                height=900,
                min_size=(900, 600),
            )
            webview.start()
        else:
            print("[i] pywebview not installed — opening in your browser instead.")
            print("    (pip install pywebview for a native desktop window)")

            def open_browser():
                if wait_for_server():
                    webbrowser.open(f"http://127.0.0.1:{PORT}")
            threading.Thread(target=open_browser, daemon=True).start()
            print(f"[+] NetScope running at http://127.0.0.1:{PORT}  (Ctrl+C to stop)")
            serve()
    except KeyboardInterrupt:
        # Ctrl+C during capture is the normal way to quit; exit quietly rather
        # than dumping a traceback over the user's terminal.
        pass
    finally:
        _demo_stop.set()
        _rdns_pool.shutdown(wait=False)
        print("\n[+] NetScope stopped.")

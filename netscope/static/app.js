// NetScope frontend: Leaflet map + Socket.IO feed.
// Everything that came from the network (hostnames from reverse DNS, country
// names) is treated as untrusted and escaped before it touches the DOM.

const $ = id => document.getElementById(id);

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

// ── map ──────────────────────────────────────────────────────────────────────
const map = L.map('map', { center: [20, 0], zoom: 2, zoomControl: false, worldCopyJump: true });
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
  maxZoom: 18,
  attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors · ' +
               'IP geolocation by <a href="https://db-ip.com">DB-IP</a> / <a href="https://www.maxmind.com">MaxMind</a>',
}).addTo(map);
L.control.zoom({ position: 'topleft' }).addTo(map);

const homeIcon = L.divIcon({
  html: '<div style="width:12px;height:12px;border-radius:50%;background:#39ff14;' +
        'box-shadow:0 0 10px #39ff14,0 0 20px #39ff14;border:2px solid #fff;"></div>',
  iconSize: [12, 12], iconAnchor: [6, 6], className: '',
});

let home = { lat: 0, lon: 0, label: 'You', set: false };
let homeMarker = null;

function applySettings(s) {
  home = { lat: s.home_lat, lon: s.home_lon, label: s.home_label, set: s.home_set };
  if (homeMarker) { map.removeLayer(homeMarker); homeMarker = null; }
  if (home.set) {
    homeMarker = L.marker([home.lat, home.lon], { icon: homeIcon }).addTo(map);
    homeMarker.bindTooltip(home.label, { direction: 'right' });
  }
  refreshBanner();
}

// ── arcs ─────────────────────────────────────────────────────────────────────
const PROTO_COLORS = {
  HTTPS: '#00d4ff', HTTP: '#ff6b35', DNS: '#39ff14',
  TCP: '#a8d4f0', UDP: '#5a8aaa', OTHER: '#2a5070', PROBE: '#ff2d55',
};

function arcPoints(lat1, lon1, lat2, lon2, n = 60) {
  // Take the short way around the globe instead of crossing the whole map.
  if (lon2 - lon1 > 180) lon2 -= 360;
  else if (lon1 - lon2 > 180) lon2 += 360;
  const pts = [];
  for (let i = 0; i <= n; i++) {
    const t = i / n;
    pts.push([lat1 + (lat2 - lat1) * t, lon1 + (lon2 - lon1) * t]);
  }
  return pts;
}

function pulseAt(lat, lon, color) {
  const icon = L.divIcon({
    html: `<div class="pulse-ring" style="--c:${color}"></div>`,
    iconSize: [16, 16], iconAnchor: [8, 8], className: '',
  });
  const marker = L.marker([lat, lon], { icon, interactive: false }).addTo(map);
  setTimeout(() => map.removeLayer(marker), 1200);
}

function drawArc(srcLat, srcLon, dstLat, dstLon, proto, pulseLat, pulseLon) {
  const color = PROTO_COLORS[proto] || PROTO_COLORS.OTHER;
  pulseAt(pulseLat, pulseLon, color);
  if (srcLat === null || dstLat === null) return;   // no home location yet: pulse only

  const line = L.polyline(arcPoints(srcLat, srcLon, dstLat, dstLon), {
    color, weight: 1.5, opacity: 0, dashArray: '6 8', interactive: false,
  }).addTo(map);

  let op = 0, offset = 0;
  const fade = setInterval(() => {
    op = Math.min(op + 0.08, 0.75);
    line.setStyle({ opacity: op });
    if (op >= 0.75) clearInterval(fade);
  }, 30);
  const dash = setInterval(() => line.setStyle({ dashOffset: String(--offset) }), 30);

  setTimeout(() => {
    clearInterval(dash);
    let o = 0.75;
    const out = setInterval(() => {
      o -= 0.05;
      line.setStyle({ opacity: Math.max(o, 0) });
      if (o <= 0) { clearInterval(out); map.removeLayer(line); }
    }, 40);
  }, 5500);
}

// ── stats / feed ─────────────────────────────────────────────────────────────
const uniqueIPs = new Set(), uniqueCtry = new Set();
let topCountry = '—';

function updateCounters(top) {
  if (top && top.length) topCountry = top[0][0];
  $('c-pkts').textContent = topCountry;
  $('c-ips').textContent = $('hdr-ips').textContent = uniqueIPs.size;
  $('c-ctry').textContent = $('hdr-ctry').textContent = uniqueCtry.size;
}

function updateTopList(top) {
  const max = top.length ? top[0][1] : 1;
  $('top-rows').innerHTML = top.map(([name, cnt], i) => `
    <div class="top-row">
      <span class="top-rank">${i + 1}</span>
      <span class="top-name">${esc(name)}</span>
      <div class="top-bar-wrap"><div class="top-bar" style="width:${Math.round(cnt / max * 100)}%"></div></div>
      <span class="top-count">${Number(cnt)}</span>
    </div>`).join('');
}

const feed = $('feed');
const MAX_FEED = 80;

function addFeedItem(d) {
  const el = document.createElement('div');
  el.className = 'feed-item';
  const place = [d.city, d.country].filter(Boolean).join(', ');
  const proto = Object.hasOwn(PROTO_COLORS, d.proto) ? d.proto : 'OTHER';
  const host = d.hostname
    ? `<div class="feed-host">${esc(d.hostname)}</div>`
    : `<div class="feed-host" style="color:var(--textdim)">${esc(d.ip)}</div>`;
  el.innerHTML = `${host}
    <div class="feed-meta">
      <span class="proto-badge proto-${proto}">${esc(d.proto)}</span>
      <span class="country">${esc(place)}</span>
    </div>`;
  el.title = `${d.ip}${d.hostname ? '  ' + d.hostname : ''}`;
  feed.prepend(el);
  while (feed.children.length > MAX_FEED) feed.lastChild.remove();
}

// ── status banner ────────────────────────────────────────────────────────────
let status = { mode: 'starting', message: '' };

const MODE_LABEL = { live: 'LIVE', demo: 'DEMO DATA', starting: 'STARTING…', preparing: 'PREPARING…',
                     waiting: 'WAITING FOR PERMISSION…', idle: 'NOT CAPTURING', error: 'ERROR' };
const MODE_CLASS = { live: 'live', demo: 'demo', error: 'error', idle: 'error' };

function action(label, event) {
  return `<button class="btn" data-event="${esc(event)}">${esc(label)}</button> `;
}

function refreshBanner() {
  const m = status.mode;
  const cls = MODE_CLASS[m] || 'busy';
  $('mode-label').textContent = MODE_LABEL[m] || m.toUpperCase();
  $('mode-label').className = 'mode-' + cls;
  $('status-dot').className = cls === 'live' ? '' : cls;

  const parts = [];
  if (status.message) parts.push(esc(status.message));
  if (m === 'live' && !home.set) parts.push('Click “Set location”, then click the map where you are, to draw arcs from your position.');
  if (status.help_url) parts.push(`<a href="${esc(status.help_url)}" target="_blank" rel="noopener">More info</a>`);

  const actions = [];
  if (m === 'idle' || m === 'error') actions.push(action('Enable live capture', 'enable_live'));
  if (m === 'idle' || m === 'error') actions.push(action('Show demo', 'start_demo'));

  const banner = $('banner');
  $('banner-msg').innerHTML = parts.join(' ');
  $('banner-actions').innerHTML = actions.join('');
  banner.classList.toggle('show', parts.length > 0 || actions.length > 0);
  banner.classList.toggle('error', m === 'error' || m === 'idle');
  map.invalidateSize();
}

$('banner-actions').addEventListener('click', e => {
  const ev = e.target.closest('button')?.dataset.event;
  if (ev) socket.emit(ev);
});

// ── set-location mode ────────────────────────────────────────────────────────
const locBtn = $('btn-location');
let picking = false;
function setPicking(on) {
  picking = on;
  document.body.classList.toggle('picking', on);
  locBtn.classList.toggle('active', on);
  locBtn.textContent = on ? 'Click the map…' : 'Set location';
}
locBtn.addEventListener('click', () => setPicking(!picking));
map.on('click', e => {
  if (!picking) return;
  socket.emit('set_home', { lat: e.latlng.lat, lon: e.latlng.wrap().lng });
  setPicking(false);
});
document.addEventListener('keydown', e => { if (e.key === 'Escape') setPicking(false); });

// ── socket ───────────────────────────────────────────────────────────────────
const socket = io();

socket.on('connect', refreshBanner);
socket.on('disconnect', () => {
  status = { mode: 'error', message: 'Lost connection to the NetScope server.' };
  refreshBanner();
});
socket.on('status', s => { status = s; refreshBanner(); });
socket.on('settings', applySettings);

socket.on('pkt', d => {
  uniqueIPs.add(d.ip);
  uniqueCtry.add(d.country);

  const haveHome = home.set;
  if (d.direction === 'in') {
    // inbound probes flow toward home
    drawArc(d.lat, d.lon, haveHome ? home.lat : null, home.lon, d.proto, d.lat, d.lon);
  } else {
    drawArc(haveHome ? home.lat : null, home.lon, d.lat, d.lon, d.proto, d.lat, d.lon);
  }
  addFeedItem(d);
  updateCounters(d.top);
  if (d.top) updateTopList(d.top);
});

refreshBanner();

/**
 * NIDS Dashboard — dashboard.js
 * Handles WebSocket connection, Chart.js charts, alerts, and all UI interactions
 */

// ─── State ────────────────────────────────────────────────────────────────────
const state = {
    socket: null,
    snifferRunning: false,
    feedPaused: false,
    activeFilter: 'ALL',
    alerts: [],
    blacklist: [],
    packetBuffer: [],           // Rolling window for pps calculation
    ppsHistory: Array(60).fill(0),
    protoCount: { TCP: 0, UDP: 0, ICMP: 0 },
    statsRefreshInterval: null,
    toastQueue: [],
    toastVisible: false,
    map: null,
    mapMarkers: {},             // ip → leaflet marker
};

// ─── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    initAuth();
    initClock();
    initCharts();
    initMap();
    connectWebSocket();
    loadAlerts();
    loadBlacklist();
    loadTopIPs();
    initMapper();

    // Periodic refresh
    setInterval(refreshStats, 5000);
    setInterval(loadTopIPs, 10000);
    setInterval(updatePPS, 1000);
    setInterval(refreshMap, 30000);
    setInterval(loadCountryStats, 20000);
});

// ─── Clock ────────────────────────────────────────────────────────────────────
function initClock() {
    function tick() {
        const now = new Date();
        document.getElementById('sys-time').textContent =
            now.toTimeString().slice(0, 8);
    }
    tick();
    setInterval(tick, 1000);
}

// ─── WebSocket ────────────────────────────────────────────────────────────────
function connectWebSocket() {
    state.socket = io({ transports: ['websocket', 'polling'] });

    state.socket.on('connect', () => {
        setConnStatus(true);
        state.socket.emit('request_stats');
        hookScanSocket();
    });

    state.socket.on('disconnect', () => setConnStatus(false));

    state.socket.on('packet', (pkt) => {
        if (!state.feedPaused) addPacketToFeed(pkt);
        state.packetBuffer.push(Date.now());
        updateProtoCount(pkt.protocol);
        refreshProtoChart();
        state.livePacketCount = (state.livePacketCount || 0) + 1;
        document.getElementById('val-packets').textContent = state.livePacketCount.toLocaleString();
    });

    state.socket.on('new_alert', (alert) => {
        prependAlert(alert);
        updateStatCounter('val-threats', null, true);  // pulse, not increment
        showToast(alert);
        refreshStats();
        // Refresh map after short delay to let DB write complete
        setTimeout(refreshMap, 2000);
    });

    state.socket.on('ip_blacklisted', (data) => {
        loadBlacklist();
    });

    state.socket.on('stats_update', (stats) => {
        applyStats(stats);
    });
}

function setConnStatus(online) {
    const pill = document.getElementById('conn-status');
    pill.innerHTML = `<span class="pulse-dot"></span><span>${online ? 'CONNECTED' : 'OFFLINE'}</span>`;
    if (online) pill.classList.add('online');
    else pill.classList.remove('online');
}

// ─── Stats ────────────────────────────────────────────────────────────────────
async function refreshStats() {
    try {
        const r = await fetch('/api/stats');
        const data = await r.json();
        applyStats(data);
    } catch (e) { }
}

function applyStats(data) {
    if (!state.livePacketCount || state.livePacketCount === 0) {
        animateCounter('val-packets', data.packets_today || 0);
    }
    animateCounter('val-threats', data.active_threats || 0);
    animateCounter('val-blocked', data.blacklisted_ips || 0);
    animateCounter('val-total', data.total_alerts || 0);
    updateSnifferPill(data.sniffer_running);
    state.snifferRunning = data.sniffer_running;
}

function animateCounter(id, value) {
    const el = document.getElementById(id);
    if (!el) return;
    const current = parseInt(el.textContent.replace(/,/g, '')) || 0;
    if (current !== value) {
        el.textContent = value.toLocaleString();
        el.classList.add('flash');
        setTimeout(() => el.classList.remove('flash'), 400);
    }
}

// ─── PPS Counter ─────────────────────────────────────────────────────────────
function updatePPS() {
    const now = Date.now();
    const cutoff = now - 1000;
    state.packetBuffer = state.packetBuffer.filter(t => t > cutoff);
    const pps = state.packetBuffer.length;

    // Shift history
    state.ppsHistory.shift();
    state.ppsHistory.push(pps);

    document.getElementById('pps-counter').textContent = `${pps} pkt/s`;
    updateTrafficChart();
}

// ─── Charts ───────────────────────────────────────────────────────────────────
let trafficChart, protoChart;
const chartLabels = Array.from({ length: 60 }, (_, i) => `${60 - i}s`);

function initCharts() {
    const chartDefaults = {
        responsive: true, maintainAspectRatio: false,
        animation: { duration: 200 },
        plugins: { legend: { labels: { color: '#4a9a74', font: { family: "'Share Tech Mono'", size: 11 } } } },
    };

    // Traffic line chart
    const tc = document.getElementById('trafficChart').getContext('2d');
    const gradient = tc.createLinearGradient(0, 0, 0, 200);
    gradient.addColorStop(0, 'rgba(0,255,159,0.25)');
    gradient.addColorStop(1, 'rgba(0,255,159,0)');

    trafficChart = new Chart(tc, {
        type: 'line',
        data: {
            labels: chartLabels,
            datasets: [{
                label: 'Packets/s',
                data: [...state.ppsHistory],
                borderColor: '#00ff9f',
                backgroundColor: gradient,
                borderWidth: 1.5,
                pointRadius: 0,
                fill: true,
                tension: 0.4,
            }]
        },
        options: {
            ...chartDefaults,
            scales: {
                x: { display: false },
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(13,43,43,0.8)' },
                    ticks: { color: '#2a5a44', font: { family: "'Share Tech Mono'", size: 10 } }
                }
            },
            plugins: { legend: { display: false } }
        }
    });

    // Protocol pie chart
    const pc = document.getElementById('protoChart').getContext('2d');
    protoChart = new Chart(pc, {
        type: 'doughnut',
        data: {
            labels: ['TCP', 'UDP', 'ICMP'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: ['rgba(0,191,255,0.7)', 'rgba(255,215,0,0.7)', 'rgba(255,140,0,0.7)'],
                borderColor: ['#00bfff', '#ffd700', '#ff8c00'],
                borderWidth: 1,
            }]
        },
        options: {
            ...chartDefaults,
            cutout: '65%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#4a9a74', font: { family: "'Share Tech Mono'", size: 10 }, padding: 10 }
                }
            }
        }
    });
}

function updateTrafficChart() {
    if (!trafficChart) return;
    trafficChart.data.datasets[0].data = [...state.ppsHistory];
    trafficChart.update('none');
}

function updateProtoCount(protocol) {
    if (state.protoCount[protocol] !== undefined) {
        state.protoCount[protocol]++;
    }
}

function refreshProtoChart() {
    if (!protoChart) return;
    protoChart.data.datasets[0].data = [
        state.protoCount.TCP,
        state.protoCount.UDP,
        state.protoCount.ICMP,
    ];
    protoChart.update('none');
}

// ─── Packet Feed ──────────────────────────────────────────────────────────────
function addPacketToFeed(pkt) {
    const feed = document.getElementById('packet-feed');
    const time = new Date(pkt.timestamp || Date.now()).toTimeString().slice(0, 8);
    const proto = pkt.protocol || 'TCP';

    const line = document.createElement('div');
    line.className = 'pkt-line';
    line.innerHTML = `
    <span class="pkt-time">${time}</span>
    <span class="pkt-proto pkt-${proto}">${proto}</span>
    <span class="pkt-src">${pkt.src_ip || '?'}</span>
    <span class="pkt-port">:${pkt.src_port || '?'}</span>
    <span class="pkt-arrow">→</span>
    <span class="pkt-dst">${pkt.dst_ip || '?'}</span>
    <span class="pkt-port">:${pkt.dst_port || '?'}</span>
    <span class="pkt-size">${pkt.size || 0}B</span>
  `;

    feed.prepend(line);

    // Keep feed from growing too large
    while (feed.children.length > 80) {
        feed.removeChild(feed.lastChild);
    }
}

function toggleFeed() {
    state.feedPaused = !state.feedPaused;
    document.getElementById('feed-toggle').textContent =
        state.feedPaused ? '▶ RESUME' : '■ PAUSE';
}

// ─── Alerts ───────────────────────────────────────────────────────────────────
async function loadAlerts() {
    try {
        const sev = state.activeFilter === 'ALL' ? '' : `?severity=${state.activeFilter}`;
        const r = await fetch(`/api/alerts${sev}`);
        const data = await r.json();
        renderAlerts(data.alerts || []);
    } catch (e) { }
}

function renderAlerts(alerts) {
    const tbody = document.getElementById('alerts-tbody');
    if (!alerts.length) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="6">No alerts yet. Start the sniffer to begin monitoring.</td></tr>';
        return;
    }
    tbody.innerHTML = alerts.map(a => alertRow(a)).join('');
}

function prependAlert(alert) {
    const tbody = document.getElementById('alerts-tbody');
    const emptyRow = tbody.querySelector('.empty-row');
    if (emptyRow) emptyRow.remove();

    const tr = document.createElement('tr');
    tr.id = `alert-${alert.id || Date.now()}`;
    tr.innerHTML = alertRow(alert, true);
    tbody.prepend(tr);

    // Limit rows
    while (tbody.children.length > 100) tbody.removeChild(tbody.lastChild);
}

function alertRow(a, inner = false) {
    const time = new Date(a.timestamp).toTimeString().slice(0, 8);
    const sevClass = `sev-${a.severity}`;
    const row = `
    ${inner ? '' : `<tr id="alert-${a.id}" class="${a.resolved ? 'resolved-row' : ''}">`}
      <td>${time}</td>
      <td><span class="sev-badge sev-${a.severity}">${a.severity}</span></td>
      <td style="color:var(--text-secondary)">${a.threat_type?.replace(/_/g, ' ')?.toUpperCase() || ''}</td>
      <td style="font-family:var(--font-mono);color:var(--red)">${a.src_ip || '—'}</td>
      <td class="desc-cell" title="${a.description || ''}">${a.description || '—'}</td>
      <td>
        <button class="resolve-btn" onclick="resolveAlert(${a.id})">✓ Resolve</button>
      </td>
    ${inner ? '' : '</tr>'}
  `;
    return row;
}

async function resolveAlert(id) {
    if (!id) return;
    try {
        await fetch(`/api/alerts/${id}/resolve`, { method: 'POST' });
        const row = document.getElementById(`alert-${id}`);
        if (row) row.classList.add('resolved-row');
        refreshStats();
    } catch (e) { }
}

function filterAlerts(severity) {
    state.activeFilter = severity;
    document.querySelectorAll('.btn-tag').forEach(b => b.classList.remove('active'));
    event?.target?.classList?.add('active');
    loadAlerts();
}

// ─── Sniffer Control ──────────────────────────────────────────────────────────
async function startSniffer(demoMode = false) {
    try {
        const r = await fetch('/api/sniffer/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ demo_mode: demoMode })
        });
        const data = await r.json();
        if (data.success || data.error === 'Sniffer already running') {
            updateSnifferPill(true);
        }
        showSimResult(`Sniffer started in ${demoMode ? 'DEMO' : 'REAL'} mode`, 'success');
    } catch (e) {
        showSimResult('Failed to start sniffer', 'error');
    }
}

async function stopSniffer() {
    try {
        await fetch('/api/sniffer/stop', { method: 'POST' });
        updateSnifferPill(false);
        state.livePacketCount = 0;  // ← add this line
        showSimResult('Sniffer stopped', 'info');
    } catch (e) { }
}

function updateSnifferPill(running) {
    const pill = document.getElementById('sniffer-pill');
    const startDemo = document.getElementById('btn-start-demo');
    const startReal = document.getElementById('btn-start-real');
    const stop = document.getElementById('btn-stop');

    if (running) {
        pill.innerHTML = '<span class="dot-off"></span><span>SNIFFER ON</span>';
        pill.classList.add('sniffer-on');
        startDemo.classList.add('hidden');
        startReal.classList.add('hidden');
        stop.classList.remove('hidden');
    } else {
        pill.innerHTML = '<span class="dot-off"></span><span>SNIFFER OFF</span>';
        pill.classList.remove('sniffer-on');
        startDemo.classList.remove('hidden');
        startReal.classList.remove('hidden');
        stop.classList.add('hidden');
    }
}

// ─── Top IPs ──────────────────────────────────────────────────────────────────
async function loadTopIPs() {
    try {
        const r = await fetch('/api/top-ips');
        const data = await r.json();
        renderTopIPs(data.top_ips || []);
    } catch (e) { }
}

function renderTopIPs(ips) {
    const el = document.getElementById('top-ips-list');
    if (!ips.length) {
        el.innerHTML = '<div class="empty-msg">Waiting for traffic…</div>';
        return;
    }
    const max = Math.max(...ips.map(ip => ip.count), 1);
    el.innerHTML = ips.map((ip, i) => `
    <div class="ip-entry">
      <span class="ip-rank">#${i + 1}</span>
      <span class="ip-addr">${ip.ip}</span>
      <div class="ip-bar-wrap">
        <div class="ip-bar" style="width:${(ip.count / max * 100).toFixed(0)}%"></div>
      </div>
      <span class="ip-count">${ip.count}</span>
    </div>
  `).join('');
}

// ─── Attack Simulation ────────────────────────────────────────────────────────
async function simulateAttack(type) {
    const srcIp = document.getElementById('sim-src-ip').value ||
        `10.${Math.floor(Math.random() * 254)}.${Math.floor(Math.random() * 254)}.${Math.floor(Math.random() * 254)}`;

    showSimResult(`Launching ${type} simulation from ${srcIp}…`, 'info');

    try {
        const r = await fetch(`/api/simulate/${type}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ source: srcIp })
        });
        const data = await r.json();
        showSimResult(`✓ ${data.message}`, 'success');
        setTimeout(loadAlerts, 1000);
    } catch (e) {
        showSimResult('Simulation failed — is sniffer running?', 'error');
    }
}

function showSimResult(msg, type = 'info') {
    const el = document.getElementById('sim-result');
    el.textContent = msg;
    el.classList.remove('hidden');
    el.style.color = type === 'error' ? 'var(--red)' : type === 'success' ? 'var(--accent)' : 'var(--yellow)';
    setTimeout(() => el.classList.add('hidden'), 4000);
}

// ─── Blacklist ────────────────────────────────────────────────────────────────
async function loadBlacklist() {
    try {
        const r = await fetch('/api/blacklist');
        const data = await r.json();
        renderBlacklist(data.blacklist || []);
    } catch (e) { }
}

function renderBlacklist(entries) {
    const el = document.getElementById('blacklist-entries');
    if (!entries.length) {
        el.innerHTML = '<div class="empty-msg">No IPs blocked</div>';
        return;
    }
    el.innerHTML = entries.map(e => `
    <div class="bl-entry">
      <span class="bl-ip">${e.ip_address}</span>
      <span class="bl-reason">${e.reason || '—'}</span>
      ${e.auto_blocked ? '<span class="bl-auto">AUTO</span>' : ''}
      <button class="bl-del" onclick="removeFromBlacklist(${e.id})">✕</button>
    </div>
  `).join('');
}

async function addToBlacklist() {
    const ip = document.getElementById('bl-ip-input').value.trim();
    if (!ip) return;

    try {
        const r = await fetch('/api/blacklist', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, reason: 'Manual block' })
        });
        const data = await r.json();
        if (data.success) {
            document.getElementById('bl-ip-input').value = '';
            loadBlacklist();
            refreshStats();
        } else {
            alert(data.error || 'Failed to block IP');
        }
    } catch (e) { }
}

async function removeFromBlacklist(id) {
    try {
        await fetch(`/api/blacklist/${id}`, { method: 'DELETE' });
        loadBlacklist();
        refreshStats();
    } catch (e) { }
}

// ─── Toast ────────────────────────────────────────────────────────────────────
function showToast(alert) {
    state.toastQueue.push(alert);
    if (!state.toastVisible) processToastQueue();
}

function processToastQueue() {
    if (!state.toastQueue.length) { state.toastVisible = false; return; }
    state.toastVisible = true;
    const alert = state.toastQueue.shift();

    const toast = document.getElementById('alert-toast');
    document.getElementById('toast-sev').textContent = alert.severity;
    document.getElementById('toast-type').textContent = (alert.threat_type || '').replace(/_/g, ' ').toUpperCase();
    document.getElementById('toast-ip').textContent = `Source: ${alert.src_ip || 'unknown'}`;

    // Color by severity
    const colors = { CRITICAL: 'var(--red)', HIGH: 'var(--orange)', MEDIUM: 'var(--yellow)', LOW: 'var(--blue)' };
    const c = colors[alert.severity] || 'var(--accent)';
    toast.style.borderColor = c;
    document.getElementById('toast-sev').style.color = c;

    toast.classList.remove('hidden');
    setTimeout(() => { closeToast(); setTimeout(processToastQueue, 300); }, 4000);
}

function closeToast() {
    document.getElementById('alert-toast').classList.add('hidden');
}

// ─── Stat counter helper ──────────────────────────────────────────────────────
function updateStatCounter(id, value, pulseOnly = false) {
    const el = document.getElementById(id);
    if (!el) return;
    if (!pulseOnly && value !== null) el.textContent = value.toLocaleString();
    el.classList.add('flash');
    setTimeout(() => el.classList.remove('flash'), 400);
}

// ─── Threat World Map (Leaflet.js) ────────────────────────────────────────────

const SEV_COLORS = {
    CRITICAL: '#ff3e3e',
    HIGH: '#ff8c00',
    MEDIUM: '#ffd700',
    LOW: '#00bfff',
};

function initMap() {
    if (!window.L) return;

    state.map = L.map('threat-map', {
        center: [20, 0],
        zoom: 2,
        minZoom: 1,
        maxZoom: 10,
        zoomControl: true,
        attributionControl: false,
    });

    // Dark tile layer (OpenStreetMap via CartoDB dark)
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        subdomains: 'abcd',
        maxZoom: 19,
    }).addTo(state.map);

    // Attribution in corner
    L.control.attribution({ prefix: false })
        .addAttribution('© <a href="https://carto.com/" style="color:#4a9a74">CARTO</a>')
        .addTo(state.map);

    // Load initial data
    refreshMap();
    loadCountryStats();
}

async function refreshMap() {
    if (!state.map) return;
    try {
        const r = await fetch('/api/geo/threat-map?hours=24');
        const data = await r.json();
        const markers = data.markers || [];

        // Update marker count
        document.getElementById('map-marker-count').textContent = `${markers.length} threats`;

        // Clear old markers
        Object.values(state.mapMarkers).forEach(m => state.map.removeLayer(m));
        state.mapMarkers = {};

        markers.forEach(m => addMapMarker(m));
    } catch (e) { }
}

function addMapMarker(marker) {
    if (!marker.lat || !marker.lng || !state.map) return;

    const color = SEV_COLORS[marker.severity] || SEV_COLORS.LOW;
    const radius = Math.min(6 + (marker.count * 2), 20);

    // Pulsing circle marker
    const icon = L.divIcon({
        className: '',
        html: `
      <div style="position:relative;width:${radius * 2}px;height:${radius * 2}px;">
        <div class="marker-ping" style="
          width:${radius * 2}px;height:${radius * 2}px;
          background:${color};opacity:0.4;top:0;left:0;
        "></div>
        <div style="
          position:absolute;top:50%;left:50%;
          transform:translate(-50%,-50%);
          width:${radius}px;height:${radius}px;
          background:${color};border-radius:50%;
          border:1.5px solid rgba(255,255,255,0.3);
          box-shadow:0 0 8px ${color};
        "></div>
      </div>`,
        iconSize: [radius * 2, radius * 2],
        iconAnchor: [radius, radius],
    });

    const flag = marker.flag || '🌐';
    const types = (marker.threat_types || []).join(', ').replace(/_/g, ' ').toUpperCase();

    const popup = L.popup({ maxWidth: 220 }).setContent(`
    <div class="map-popup-ip">${marker.ip}</div>
    <div class="map-popup-loc">${flag} ${marker.city || ''}${marker.city ? ', ' : ''}${marker.country || 'Unknown'}</div>
    <div class="map-popup-meta">Threats: <b>${marker.count}</b> &nbsp;|&nbsp; ${types || 'UNKNOWN'}</div>
    <div class="map-popup-meta">Last seen: ${new Date(marker.last_seen).toLocaleTimeString()}</div>
    ${marker.isp ? `<div class="map-popup-meta">ISP: ${marker.isp}</div>` : ''}
    <span class="map-popup-sev sev-${marker.severity}">${marker.severity}</span>
  `);

    const leafletMarker = L.marker([marker.lat, marker.lng], { icon })
        .bindPopup(popup)
        .addTo(state.map);

    state.mapMarkers[marker.ip] = leafletMarker;
}

// ─── Country Stats ────────────────────────────────────────────────────────────

async function loadCountryStats() {
    try {
        const r = await fetch('/api/geo/stats');
        const data = await r.json();
        renderCountryStats(data.top_countries || []);
    } catch (e) { }
}

function renderCountryStats(countries) {
    const el = document.getElementById('countries-list');
    if (!countries.length) {
        el.innerHTML = '<div class="empty-msg">No geo data yet — trigger some alerts first</div>';
        return;
    }

    const max = Math.max(...countries.map(c => c.count), 1);
    const barColors = ['#ff3e3e', '#ff8c00', '#ffd700', '#00bfff', '#00ff9f'];

    el.innerHTML = countries.map((c, i) => {
        const pct = ((c.count / max) * 100).toFixed(0);
        const color = barColors[Math.min(i, barColors.length - 1)];
        return `
      <div class="country-entry">
        <span class="ip-rank">#${i + 1}</span>
        <span class="country-name">${c.country}</span>
        <div class="country-bar-wrap">
          <div class="country-bar" style="width:${pct}%;background:${color}"></div>
        </div>
        <span class="country-count">${c.count}</span>
      </div>`;
    }).join('');
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

function initAuth() {
    const token = localStorage.getItem('nids_token');
    if (!token) {
        window.location.href = '/login';
        return;
    }
    const user = JSON.parse(localStorage.getItem('nids_user') || '{}');
    document.getElementById('user-display').textContent = user.display_name || user.username || '?';
    const roleTag = document.getElementById('user-role-tag');
    roleTag.textContent = (user.role || 'analyst').toUpperCase();
    roleTag.className = `role-tag role-${user.role || 'analyst'}`;

    // Hide admin-only controls for analysts
    if (user.role !== 'admin') {
        document.getElementById('btn-start-real')?.classList.add('hidden');
    }
}

function getAuthHeaders() {
    const token = localStorage.getItem('nids_token');
    return token ? { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' } : {};
}

function logout() {
    localStorage.removeItem('nids_token');
    localStorage.removeItem('nids_user');
    window.location.href = '/login';
}

// Patch fetch calls to include auth token
const _origFetch = window.fetch;
window.fetch = function (url, opts = {}) {
    const token = localStorage.getItem('nids_token');
    if (token && typeof url === 'string' && url.startsWith('/api/')) {
        opts.headers = { ...(opts.headers || {}), 'Authorization': `Bearer ${token}` };
    }
    return _origFetch(url, opts);
};

// ─── Network Mapper ───────────────────────────────────────────────────────────

async function initMapper() {
    try {
        const r = await fetch('/api/scan/local-network');
        const data = await r.json();
        const el = document.getElementById('mapper-subnet');
        if (el) el.textContent = data.subnet || '—';
    } catch (e) { }
}

async function startNetworkScan() {
    document.getElementById('scan-progress-wrap').classList.remove('hidden');
    document.getElementById('btn-scan').classList.add('hidden');
    document.getElementById('scan-progress-fill').style.width = '0%';
    document.getElementById('scan-progress-msg').textContent = 'Starting scan…';
    document.getElementById('mapper-results').innerHTML = '';

    try {
        const r = await fetch('/api/scan/network', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });
        const data = await r.json();
        if (!data.success) {
            showMapperError(data.error || 'Scan failed');
        }
    } catch (e) {
        showMapperError('Could not start scan');
    }
}

// Listen for scan progress/complete via WebSocket
function hookScanSocket() {
    if (!state.socket) return;

    state.socket.on('scan_progress', (data) => {
        const fill = document.getElementById('scan-progress-fill');
        const msg = document.getElementById('scan-progress-msg');
        if (fill) fill.style.width = `${data.percent}%`;
        if (msg) msg.textContent = data.message;
    });

    state.socket.on('scan_complete', (data) => {
        document.getElementById('scan-progress-wrap').classList.add('hidden');
        document.getElementById('btn-scan').classList.remove('hidden');
        document.getElementById('scan-progress-fill').style.width = '100%';
        renderMapperResults(data.results || []);
        const el = document.getElementById('mapper-subnet');
        if (el) el.textContent = `${data.hosts_found} hosts on ${data.subnet}`;
    });

    state.socket.on('scan_error', (data) => {
        showMapperError(data.error);
        document.getElementById('btn-scan').classList.remove('hidden');
    });
}

function renderMapperResults(hosts) {
    const el = document.getElementById('mapper-results');
    if (!hosts.length) {
        el.innerHTML = '<div class="empty-msg">No hosts found. Make sure you\'re on a LAN.</div>';
        return;
    }

    const DANGEROUS_PORTS = new Set([21, 23, 135, 139, 445, 3389, 5900]);

    el.innerHTML = hosts.map(host => {
        const ports = (host.open_ports || []).map(p =>
            `<span class="port-tag ${DANGEROUS_PORTS.has(p.port) ? 'dangerous' : ''}"
        title="${p.service}${p.banner ? ': ' + p.banner : ''}">${p.port}/${p.service}</span>`
        ).join('');

        return `
      <div class="host-card">
        <div class="host-card-hdr" onclick="this.nextElementSibling.classList.toggle('hidden')">
          <span class="host-ip">${host.ip}</span>
          <span class="host-name">${host.hostname !== host.ip ? host.hostname : ''}</span>
          <span class="host-vendor">${host.vendor || ''}</span>
          <span class="risk-badge risk-${host.risk}">${host.risk}</span>
          <span style="font-family:var(--font-mono);font-size:0.6rem;color:var(--text-dim)">
            ${(host.open_ports || []).length} ports
          </span>
        </div>
        <div class="host-ports ${!ports ? 'hidden' : ''}">${ports || '<span style="color:var(--text-dim);font-size:0.65rem;font-family:var(--font-mono)">No open ports detected</span>'}</div>
      </div>`;
    }).join('');
}

function showMapperError(msg) {
    document.getElementById('mapper-results').innerHTML =
        `<div class="empty-msg" style="color:var(--red)">⚠ ${msg}</div>`;
    document.getElementById('scan-progress-wrap').classList.add('hidden');
    document.getElementById('btn-scan').classList.remove('hidden');
}

// ─── Auth Download (inject token into link clicks) ─────────────────────────────

function authDownload(link) {
    const token = localStorage.getItem('nids_token');
    if (!token) { logout(); return false; }

    // Fetch with auth header and trigger download manually
    fetch(link.href, { headers: { 'Authorization': `Bearer ${token}` } })
        .then(r => {
            if (r.status === 401) { logout(); return; }
            const cd = r.headers.get('Content-Disposition') || '';
            const match = cd.match(/filename=(.+)/);
            const filename = match ? match[1] : 'nids_export';
            return r.blob().then(blob => ({ blob, filename }));
        })
        .then(({ blob, filename }) => {
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url; a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        })
        .catch(() => {
            const el = document.getElementById('export-msg');
            if (el) { el.textContent = '⚠ Export failed'; el.classList.remove('hidden'); setTimeout(() => el.classList.add('hidden'), 3000); }
        });

    return false; // Prevent default link navigation
}
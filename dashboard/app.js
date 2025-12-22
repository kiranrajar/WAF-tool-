const API_BASE = "/api";
const COUNTRY_COORDS = {
    'US': { x: 20, y: 40 }, 'CN': { x: 80, y: 45 }, 'RU': { x: 75, y: 25 },
    'GB': { x: 47, y: 30 }, 'DE': { x: 50, y: 32 }, 'FR': { x: 48, y: 35 },
    'IN': { x: 72, y: 55 }, 'BR': { x: 33, y: 70 }, 'AU': { x: 88, y: 80 },
    'CA': { x: 20, y: 25 }, 'JP': { x: 90, y: 40 }, 'KP': { x: 86, y: 40 },
    'IR': { x: 65, y: 45 }, 'UA': { x: 58, y: 33 }, 'XX': { x: 50, y: 50 }
};

document.addEventListener('DOMContentLoaded', () => {
    try {
        initCharts();
    } catch (e) {
        console.warn("Chart system standby: UI placeholders active.");
    }
    syncData();
    setInterval(() => {
        syncData().catch(e => console.warn("Sync pulse retry..."));
    }, 2000);

    // Navigation
    document.querySelectorAll('#sidebar-nav a').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const target = link.getAttribute('data-tab');

            document.querySelectorAll('#sidebar-nav a').forEach(l => l.classList.remove('active'));
            link.classList.add('active');

            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            document.getElementById(target).classList.add('active');
        });
    });

    // Configuration Sync
    document.getElementById('save-config')?.addEventListener('click', async () => {
        const config = {
            targetUrl: document.getElementById('cfg-target').value,
            rateLimit: parseInt(document.getElementById('cfg-rate-limit').value),
            riskThreshold: parseFloat(document.getElementById('cfg-threshold').value) / 100,
            blockedCountries: document.getElementById('cfg-geo').value.split(',').map(s => s.trim().toUpperCase()),
            protectionMode: document.getElementById('protection-mode').value
        };

        const res = await fetch(`${API_BASE}/config`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });

        if (res.ok) showToast("✅ Security policy updated and deployed");
    });

    document.getElementById('protection-mode')?.addEventListener('change', () => {
        document.getElementById('save-config').click();
    });

    // Refresh Data
    document.getElementById('refresh-data')?.addEventListener('click', syncData);

    // Modal Logic
    const modal = document.getElementById('sim-modal');
    document.getElementById('open-sim')?.addEventListener('click', () => modal.classList.add('active'));
    document.getElementById('close-sim')?.addEventListener('click', () => modal.classList.remove('active'));

    // Simulator Actions
    document.querySelectorAll('.sim-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const type = btn.getAttribute('data-type');
            const targets = {
                sqli: "/login?user=admin' OR 1=1--",
                xss: "/search?q=<script>alert(1)</script>",
                traversal: "/file?path=../../etc/passwd",
                rce: "/cmd?exec=rm -rf /",
                normal: "/"
            };

            showToast(`🚀 Sending ${type.toUpperCase()} request...`);
            fetch(`http://localhost:3000${targets[type] || '/'}`);
            modal.classList.remove('active');
        });
    });

    // Firewall
    document.getElementById('btn-add-ip').addEventListener('click', async () => {
        const ip = document.getElementById('add-ip-field').value;
        if (ip) {
            showToast(`⚠️ Blacklisting ${ip}...`);
            await fetch(`${API_BASE}/config`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ...currentConfig,
                    blacklist: [...(currentConfig.blacklist || []), ip]
                })
            });
            document.getElementById('add-ip-field').value = '';
            syncData();
        }
    });
});

let currentConfig = {};

async function syncData() {
    try {
        const [logsRes, statsRes] = await Promise.all([
            fetch(`${API_BASE}/logs`),
            fetch(`${API_BASE}/stats`)
        ]);

        const logs = await logsRes.json();
        const stats = await statsRes.json();
        currentConfig = stats.config || {};

        if (stats.total !== undefined) {
            updateUI(logs, stats);
            updateMap(logs);
        }
    } catch (err) {
        console.warn("Retrying engine sync...");
    }
}

function updateUI(logs, stats) {
    const config = stats.config || {};

    // Stats Cards
    const safeSetText = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.innerText = val;
    };

    safeSetText('stat-total', stats.total || 0);
    safeSetText('stat-blocked', stats.blocked || 0);
    safeSetText('stat-risk', (stats.avgRisk || 0).toFixed(3));
    safeSetText('stat-bans', stats.blacklistCount || 0);

    // Config Fields
    if (document.getElementById('save-config') && config) {
        const setVal = (id, v) => {
            const el = document.getElementById(id);
            if (el) el.value = v || '';
        };
        setVal('cfg-target', config.targetUrl);
        setVal('cfg-rate-limit', config.rateLimit);
        setVal('cfg-threshold', Math.round((config.riskThreshold || 0.5) * 100));
        setVal('cfg-geo', config.blockedCountries?.join(', '));
        setVal('protection-mode', config.protectionMode);
    }

    // Table
    const tbody = document.getElementById('log-body');
    const recent = [...logs].slice(0, 12);
    tbody.innerHTML = recent.map(log => `
        <tr>
            <td>${log.time}</td>
            <td>${log.ip}</td>
            <td><span style="font-size: 1.2rem; margin-right: 5px;">${getFlag(log.country)}</span> ${log.country}</td>
            <td title="${log.url}">${log.url.substring(0, 25)}${log.url.length > 25 ? '...' : ''}</td>
            <td>
                <span class="fingerprint-tag ${log.isBot ? 'tag-bot' : 'tag-human'}">
                    ${log.isBot ? (log.botInfo || 'Automated') : 'Browser'}
                </span>
            </td>
            <td><span style="color: ${log.type === 'Normal' ? 'var(--text-muted)' : 'var(--warning)'}">${log.type}</span></td>
            <td>
                <span class="risk-dot" style="background: ${getRiskColor(log.risk)}"></span>
                ${(log.risk * 100).toFixed(1)}%
            </td>
            <td><span class="status-tag ${log.status === 'Blocked' ? 'tag-blocked' : 'tag-allowed'}">${log.status}</span></td>
        </tr>
    `).join('');

    // Charts
    updateCharts(logs, stats);

    // Firewall
    const blacklistElem = document.getElementById('blacklist-view');
    blacklistElem.innerHTML = config.blacklist.map(ip => `
        <div class="ip-item">
            <span>${ip}</span>
            <button class="btn" style="padding: 4px 12px; font-size: 0.75rem;" onclick="unblock('${ip}')">Remove</button>
        </div>
    `).join('');

    // Threat Intelligence
    updateThreatIntel(stats);

    // Geo Stats
    updateGeoStats(logs);

    // Notifications
    checkForNewAnomalies(logs);
}

function updateThreatIntel(stats) {
    const threats = stats.threats || {};
    const total = Object.values(threats).reduce((a, b) => a + b, 0) || 1;

    // Update counts and bars
    updateThreatBar('sqli', threats['SQL Injection'] || 0, total);
    updateThreatBar('xss', threats['XSS'] || 0, total);
    updateThreatBar('path', threats['Path Traversal'] || 0, total);
    updateThreatBar('rce', threats['WebShell/RCE'] || 0, total);

    // Timeline stats
    const blocked = Object.values(threats).reduce((a, b) => a + b, 0);
    document.getElementById('attacks-hour').innerText = blocked;
    document.getElementById('attacks-day').innerText = blocked;
    document.getElementById('peak-time').innerText = new Date().toLocaleTimeString().substring(0, 5);
}

function updateThreatBar(id, count, total) {
    const countElem = document.getElementById(`${id}-count`);
    const barElem = document.getElementById(`${id}-bar`);
    if (countElem) countElem.innerText = count;
    if (barElem) barElem.style.width = `${(count / total) * 100}%`;
}

function updateGeoStats(logs) {
    const geoCount = {};
    logs.forEach(log => {
        if (log.type !== 'Normal') {
            geoCount[log.country] = (geoCount[log.country] || 0) + 1;
        }
    });

    const geoStatsElem = document.getElementById('geo-stats');
    if (!geoStatsElem) return;

    const sortedCountries = Object.entries(geoCount)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 6);

    geoStatsElem.innerHTML = sortedCountries.map(([country, count]) => `
        <div class="geo-item">
            <span class="geo-country">${getFlag(country)} ${country}</span>
            <span class="geo-count">${count} Threats</span>
        </div>
    `).join('') || '<div class="geo-item"><span class="geo-country">No global threats detected</span></div>';
}

function getRiskColor(risk) {
    if (risk > 0.8) return 'var(--danger)';
    if (risk > 0.5) return 'var(--warning)';
    return 'var(--success)';
}

function getFlag(country) {
    const flags = { 'US': '🇺🇸', 'CN': '🇨🇳', 'RU': '🇷🇺', 'BR': '🇧🇷', 'DE': '🇩🇪', 'IN': '🇮🇳', 'JP': '🇯🇵', 'GB': '🇬🇧', 'FR': '🇫🇷', 'NL': '🇳🇱' };
    return flags[country] || '🌐';
}

function initCharts() {
    const vEl = document.getElementById('velocityChart');
    if (vEl) {
        const velocityCtx = vEl.getContext('2d');
        velocityChart = new Chart(velocityCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Risk Score',
                    data: [],
                    borderColor: '#58a6ff',
                    backgroundColor: 'rgba(88, 166, 255, 0.1)',
                    borderWidth: 2,
                    pointRadius: 0,
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { min: 0, max: 1, grid: { color: '#21262d' }, ticks: { color: '#8b949e' } },
                    x: { display: false }
                },
                plugins: { legend: { display: false } }
            }
        });
    }

    const vecEl = document.getElementById('vectorChart');
    if (vecEl) {
        const vectorCtx = vecEl.getContext('2d');
        vectorChart = new Chart(vectorCtx, {
            type: 'radar',
            data: {
                labels: ['SQLi', 'XSS', 'Traversal', 'WebShell', 'Anomaly'],
                datasets: [{
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: 'rgba(248, 81, 73, 0.2)',
                    borderColor: '#f85149',
                    pointBackgroundColor: '#f85149',
                    pointBorderColor: '#fff',
                    pointHoverBackgroundColor: '#fff',
                    pointHoverBorderColor: '#f85149'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    r: {
                        angleLines: { color: '#30363d' },
                        grid: { color: '#30363d' },
                        pointLabels: { color: '#8b949e', font: { size: 11 } },
                        ticks: { display: false }
                    }
                }
            }
        });
    }
}

function updateCharts(logs, stats) {
    if (velocityChart) {
        const recent = logs.slice(-30);
        velocityChart.data.labels = recent.map(l => l.time);
        velocityChart.data.datasets[0].data = recent.map(l => l.risk);
        velocityChart.update('none');
    }

    if (vectorChart) {
        const threatProfile = [
            stats.threats['SQL Injection'] || 0,
            stats.threats['XSS'] || 0,
            stats.threats['Path Traversal'] || 0,
            stats.threats['WebShell/RCE'] || 0,
            stats.threats['Anomaly / Threat'] || 0
        ];
        vectorChart.data.datasets[0].data = threatProfile;
        vectorChart.update('none');
    }
}

let lastLogCount = 0;
function checkForNewAnomalies(logs) {
    if (logs.length > lastLogCount) {
        const latest = logs[logs.length - 1];
        if (latest.status === "Blocked") {
            showToast(`🚨 Security Event: Blocked ${latest.type} from ${latest.ip}`);
        }
        lastLogCount = logs.length;
    }
}

async function unblock(ip) {
    await fetch(`${API_BASE}/unblock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
    });
    syncData();
}

function showToast(msg) {
    const area = document.getElementById('toast-area');
    const t = document.createElement('div');
    t.className = 'toast';
    t.innerText = msg;
    area.appendChild(t);
    setTimeout(() => t.remove(), 4000);
}
function updateMap(logs) {
    const mapContainer = document.getElementById('threat-map');
    if (!mapContainer) return;

    // Pulse Map Stats
    if (document.getElementById('map-critical')) {
        document.getElementById('map-critical').innerText = logs.filter(l => l.status === "Blocked" && l.risk >= 0.8).length;
        document.getElementById('map-anomalies').innerText = logs.filter(l => l.status === "Blocked" && l.risk < 0.8).length;
    }

    const now = Date.now();
    const recentBlocks = logs.filter(l => l.status === "Blocked" && (now - l.timestamp < 15000));

    recentBlocks.forEach(log => {
        const id = `ping-${log.timestamp}`;
        if (document.getElementById(id)) return;

        const pos = COUNTRY_COORDS[log.country] || COUNTRY_COORDS['US'];
        const ping = document.createElement('div');
        ping.className = 'attack-ping';
        ping.id = id;
        ping.style.left = `${pos.x}%`;
        ping.style.top = `${pos.y}%`;

        mapContainer.appendChild(ping);
        setTimeout(() => ping.remove(), 2500);
    });
}

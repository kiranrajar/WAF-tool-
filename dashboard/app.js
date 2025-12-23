const API_BASE = "/api";
const COUNTRY_COORDS = {
    'US': { x: 22, y: 35 }, 'CN': { x: 78, y: 38 }, 'RU': { x: 70, y: 20 },
    'GB': { x: 46, y: 28 }, 'DE': { x: 49, y: 30 }, 'FR': { x: 47, y: 32 },
    'IN': { x: 70, y: 45 }, 'BR': { x: 32, y: 70 }, 'AU': { x: 85, y: 75 },
    'CA': { x: 20, y: 20 }, 'JP': { x: 88, y: 38 }, 'KP': { x: 83, y: 38 },
    'KR': { x: 83, y: 39 }, 'IR': { x: 62, y: 40 }, 'UA': { x: 55, y: 30 },
    'PK': { x: 67, y: 42 }, 'SA': { x: 58, y: 48 }, 'ZA': { x: 55, y: 80 },
    'EG': { x: 55, y: 40 }, 'NG': { x: 48, y: 55 }, 'MX': { x: 18, y: 45 },
    'ID': { x: 80, y: 60 }, 'TR': { x: 58, y: 35 }, 'IT': { x: 50, y: 34 },
    'ES': { x: 45, y: 35 }, 'NL': { x: 48, y: 29 }, 'SE': { x: 51, y: 22 },
    'NO': { x: 49, y: 22 }, 'FI': { x: 54, y: 20 }, 'DK': { x: 49, y: 28 },
    'PL': { x: 52, y: 30 }, 'RO': { x: 56, y: 33 }, 'GR': { x: 55, y: 37 },
    'Unknown': { x: 50, y: 95 }
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
        const btn = document.getElementById('save-config');
        const originalText = btn.innerText;
        btn.innerText = "Saving...";
        btn.disabled = true;

        const getCheck = (id) => document.getElementById(id)?.checked ?? true;

        const config = {
            targetUrl: document.getElementById('cfg-target').value, // Allow empty or custom
            rateLimit: parseInt(document.getElementById('cfg-rate-limit').value) || 100,
            riskThreshold: parseFloat(document.getElementById('cfg-threshold').value) / 100,
            blockedCountries: document.getElementById('cfg-geo').value.split(',').map(s => s.trim().toUpperCase()).filter(s => s.length === 2),
            protectionMode: document.getElementById('cfg-mode') ? document.getElementById('cfg-mode').value : 'blocking',
            modules: {
                sqli: getCheck('mod-sqli'),
                xss: getCheck('mod-xss'),
                pathTraversal: getCheck('mod-path'),
                rce: getCheck('mod-rce'),
                bot: getCheck('mod-bot')
            }
        };

        try {
            const res = await fetch(`${API_BASE}/config`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config)
            });

            if (res.ok) {
                showToast("✅ Global configuration updated and modules hot-reloaded");
                syncData(); // Refresh UI to confirm persistence
            } else {
                showToast("❌ Failed to save configuration");
            }
        } catch (e) {
            showToast("❌ Network Error: Could not save config");
        } finally {
            btn.innerText = originalText;
            btn.disabled = false;
        }
    });

    // Sync Protection Mode Dropdowns
    const headerMode = document.getElementById('protection-mode');
    const settingMode = document.getElementById('cfg-mode');

    if (headerMode && settingMode) {
        headerMode.addEventListener('change', () => {
            settingMode.value = headerMode.value;
            document.getElementById('save-config').click();
        });
        settingMode.addEventListener('change', () => {
            headerMode.value = settingMode.value;
            // distinct from save, just sync UI until save clicked? 
            // actually user expects save on settings page usually manually, but header is quick toggle
        });
    }

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
                anomaly: "/api/check?token=$$$$$$$$$$$$$$$$^^^^^^^^^^^^^^^^^^^^@@@@@@@@@@",
                normal: "/"
            };

            showToast(`🚀 Sending ${type.toUpperCase()} request...`);
            // Use relative path so it hits the same origin (works for Vercel & Proxy)
            fetch(targets[type] || '/');
            modal.classList.remove('active');
        });
    });

    // Red Team: Carpet Bomb
    document.getElementById('carpet-bomb-btn')?.addEventListener('click', async () => {
        const modal = document.getElementById('sim-modal');
        modal.classList.remove('active');
        showToast("🔥 Initiating Carpet Bomb Attack Sequence...");

        const vectors = ['sqli', 'xss', 'traversal', 'rce', 'anomaly'];
        const targets = {
            sqli: ["/login?user=admin' OR 1=1--", "/product?id=1; DROP TABLE users"],
            xss: ["/search?q=<script>alert(1)</script>", "/user/<img src=x onerror=alert(1)>"],
            traversal: ["/file?path=../../etc/passwd", "/d/..%2f..%2fwindows%2fwin.ini"],
            rce: ["/cmd?exec=rm -rf /", "/api/ping?host=127.0.0.1|whoami"],
            anomaly: ["/api/check?token=$$$$$$$$$$$$", "/v1/auth?key=invalid_hex_string_overflow"]
        };

        for (let i = 0; i < 50; i++) {
            // Randomly select vector
            const vector = vectors[Math.floor(Math.random() * vectors.length)];
            const payload = targets[vector][Math.floor(Math.random() * targets[vector].length)];

            // Fire and Forget (don't await response to simulate concurrent flood)
            fetch(payload).catch(e => { });

            // Small random delay (50-150ms) to look like a script
            await new Promise(r => setTimeout(r, Math.floor(Math.random() * 100) + 50));

            if (i % 10 === 0) showToast(`🔥 Flooding... Request ${i}/50`);
        }
        showToast("✅ Red Team Exercise Complete");
        syncData();
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

async function syncData(syncInputs = false) {
    try {
        const res = await fetch(`${API_BASE}/stats`);
        const stats = await res.json();

        currentConfig = stats.config || {};
        const logs = stats.recentLogs || [];

        if (stats.total !== undefined) {
            updateUI(logs, stats, syncInputs);
            updateMap(logs, stats);
        }
    } catch (err) {
        console.warn("Retrying engine sync...");
    }
}



function updateUI(logs, stats, syncInputs) {
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

    // Config Fields (Only update when explicitly requested)
    if (syncInputs && document.getElementById('save-config') && config) {
        const setVal = (id, v) => {
            const el = document.getElementById(id);
            if (el) el.value = v || '';
        };
        // Default true if missing or undefined in config, but handle UI existence check
        const setCheck = (id, v) => {
            const el = document.getElementById(id);
            if (el) el.checked = v !== false;
        };

        setVal('cfg-target', config.targetUrl);
        setVal('cfg-rate-limit', config.rateLimit);
        setVal('cfg-threshold', Math.round((config.riskThreshold || 0.5) * 100));
        setVal('cfg-geo', config.blockedCountries?.join(', '));
        // Try both new and old IDs
        if (document.getElementById('protection-mode')) setVal('protection-mode', config.protectionMode);
        if (document.getElementById('cfg-mode')) setVal('cfg-mode', config.protectionMode);

        const modules = config.modules || {};
        setCheck('mod-sqli', modules.sqli);
        setCheck('mod-xss', modules.xss);
        setCheck('mod-path', modules.pathTraversal);
        setCheck('mod-rce', modules.rce);
        setCheck('mod-bot', modules.bot);
    }

    // Table
    const tbody = document.getElementById('log-body');
    const recent = [...logs].slice(0, 12);
    tbody.innerHTML = recent.map(log => {
        const url = log.url || '/';
        const displayUrl = url.length > 25 ? url.substring(0, 22) + '...' : url;
        const payload = log.payload || '-';
        const displayPayload = payload.length > 20 ? payload.substring(0, 17) + '...' : payload;
        const riskScore = typeof log.risk === 'number' ? (log.risk * 100).toFixed(1) : '0.0';

        return `
        <tr>
            <td>${log.time || '--:--'}</td>
            <td>${log.ip || '0.0.0.0'}</td>
            <td><span style="font-size: 1.2rem; margin-right: 5px;">${getFlag(log.country)}</span> ${log.country || 'Unknown'}</td>
            <td title="${url}">${displayUrl}</td>
            <td title="${payload.replace(/"/g, '&quot;')}" class="payload-cell">${displayPayload}</td>
            <td>
                <span class="fingerprint-tag ${log.isBot ? 'tag-bot' : 'tag-human'}">
                    ${log.isBot ? 'Automated' : 'Browser'}
                </span>
            </td>
            <td><span style="color: ${log.type === 'Normal' ? 'var(--text-muted)' : 'var(--warning)'}">${log.type || 'Normal'}</span></td>
            <td>
                <span class="risk-dot" style="background: ${getRiskColor(log.risk || 0)}"></span>
                ${riskScore}%
            </td>
            <td><span class="status-tag ${log.status === 'Blocked' ? 'tag-blocked' : 'tag-allowed'}">${log.status || 'Allowed'}</span></td>
        </tr>
    `}).join('');

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
    updateThreatIntel(logs, stats);

    // Geo Stats
    updateGeoStats(logs);

    // Notifications
    checkForNewAnomalies(logs);
}

function updateThreatIntel(logs, stats) {
    if (!stats || !stats.threats) return;

    const t = stats.threats;
    const counts = {
        xss: t['XSS'] || 0,
        sqli: t['SQL Injection'] || 0,
        path: t['Path Traversal'] || 0,
        rce: t['WebShell/RCE'] || 0,
        anomaly: t['ML Anomaly Detection'] || 0
    };

    const total = stats.blocked || 1;

    // Update counts and bars
    const updateBar = (id, count) => {
        const el = document.getElementById(id + '-count');
        const bar = document.getElementById(id + '-bar');
        if (el) el.innerText = count;
        if (bar) bar.style.width = Math.min(100, (count / total) * 100) + '%';
    };

    updateBar('xss', counts.xss);
    updateBar('sqli', counts.sqli);
    updateBar('path', counts.path);
    updateBar('rce', counts.rce);
    updateBar('anomaly', counts.anomaly);


    // Timeline stats
    const blocked = stats.blocked || 0;

    // Last Hour vs 24H (Approximation based on available logs - usually recent 500)
    // Note: logs are just the last N in memory/file, so we just show total visible log stats
    const safeText = (id, txt) => { if (document.getElementById(id)) document.getElementById(id).innerText = txt; };
    safeText('attacks-hour', blocked);
    safeText('attacks-day', blocked); // Since logs are transient in this demo, just equal for now
    safeText('peak-time', new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }));
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
            stats.threats['ML Anomaly Detection'] || 0
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
function updateMap(logs, stats) {
    const mapContainer = document.getElementById('threat-map');
    if (!mapContainer) return;

    // Pulse Map Stats (Using accurate backend counters)
    // Pulse Map Stats
    if (document.getElementById('map-critical') && stats) {
        document.getElementById('map-critical').innerText = stats.mapCritical || 0;
        document.getElementById('map-anomalies').innerText = stats.mapAnomalies || 0;

        // Hide loader if data is synced
        const loader = document.querySelector('.map-placeholder');
        if (loader) loader.style.display = 'none';
    }

    const now = Date.now();
    // Only show blocks from last 60 seconds to keep map active but relevant
    const recentBlocks = logs.filter(l => l.status === "Blocked" && (now - l.timestamp < 60000));

    recentBlocks.forEach(log => {
        const id = `ping-${log.timestamp}`;
        if (document.getElementById(id)) return;

        // Default to PK or US if unknown, or random slight jitter
        const basePos = COUNTRY_COORDS[log.country] || COUNTRY_COORDS['US'] || { x: 50, y: 50 };
        // Add random jitter so dots don't stack perfectly
        const jitterX = (Math.random() - 0.5) * 2;
        const jitterY = (Math.random() - 0.5) * 2;

        const ping = document.createElement('div');
        ping.className = 'attack-ping';
        ping.id = id;
        ping.style.left = `${basePos.x + jitterX}%`;
        ping.style.top = `${basePos.y + jitterY}%`;

        // Tooltip
        ping.title = `${log.ip} (${log.country})\n${log.type}`;

        mapContainer.appendChild(ping);
        // Remove after animation
        setTimeout(() => ping.remove(), 3000);
    });
}

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

let currentConfig = {};
let velocityChart, vectorChart;

document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    syncData(true);

    // Auto-poll logs and stats every 2 seconds
    setInterval(() => syncData(), 2000);

    // Navigation Logic
    document.querySelectorAll('#sidebar-nav a').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const tabId = link.getAttribute('data-tab');

            // Switch Menu
            document.querySelectorAll('#sidebar-nav a').forEach(l => l.classList.remove('active'));
            link.classList.add('active');

            // Switch Tab
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            document.getElementById(tabId)?.classList.add('active');

            // Update Title
            const titles = {
                'dashboard': 'Security Enterprise Control',
                'intelligence': 'Threat Intelligence Hub',
                'firewall': 'Active Barrier Management',
                'settings': 'Core Propulsion Settings'
            };
            document.getElementById('page-title').innerText = titles[tabId] || 'Command Center';
        });
    });

    // Modal Control
    document.getElementById('open-simulator')?.addEventListener('click', () => {
        document.getElementById('sim-modal').classList.add('active');
    });
    document.getElementById('close-sim')?.addEventListener('click', () => {
        document.getElementById('sim-modal').classList.remove('active');
    });

    // Force Refresh
    document.getElementById('force-refresh')?.addEventListener('click', () => {
        showToast("🔄 Force Synchronizing with Engine...");
        syncData(true);
    });

    // Save Settings
    document.getElementById('save-config')?.addEventListener('click', async () => {
        const payload = {
            targetUrl: document.getElementById('cfg-target').value,
            rateLimit: parseInt(document.getElementById('cfg-rate-limit')?.value || 100),
            riskThreshold: parseInt(document.getElementById('cfg-threshold').value) / 100,
            protectionMode: document.getElementById('cfg-mode').value,
            modules: {
                sqli: document.getElementById('mod-sqli').checked,
                xss: document.getElementById('mod-xss').checked,
                pathTraversal: document.getElementById('mod-path').checked,
                rce: document.getElementById('mod-rce').checked,
                bot: document.getElementById('mod-bot').checked
            }
        };

        try {
            const res = await fetch(`${API_BASE}/config`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            if (res.ok) showToast("✅ Configuration deployed to AEGIS Cloud");
        } catch (e) {
            showToast("❌ Connection Failure during deployment");
        }
    });

    // Add To Blacklist
    document.getElementById('btn-add-ip')?.addEventListener('click', async () => {
        const ip = document.getElementById('add-ip-field').value;
        if (ip) {
            showToast(`🛡️ Blacklisting IP: ${ip}`);
            await fetch(`${API_BASE}/config`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ...currentConfig, blacklist: [...(currentConfig.blacklist || []), ip] })
            });
            document.getElementById('add-ip-field').value = '';
            syncData();
        }
    });

    // Red Team Exercise
    document.getElementById('carpet-bomb-btn')?.addEventListener('click', async () => {
        document.getElementById('sim-modal').classList.remove('active');
        showToast("🔥 Initiating High-Velocity Carpet Bomb Attack...");

        const vectors = ['sqli', 'xss', 'traversal', 'rce', 'anomaly'];
        const attackPaths = {
            sqli: ["/api/v1/auth?u=admin' OR 1=1--", "/products?id=1; DROP TABLE logs"],
            xss: ["/search?q=<script>alert('pwned')</script>", "/user/profile?bio=<img src=x onerror=alert(1)>"],
            traversal: ["/static/../../etc/passwd", "/download?file=..%2f..%2fconfig.env"],
            rce: ["/cmd?exec=whoami;ls", "/v1/shell?run=bash -i"],
            anomaly: ["/api/check?token=$$%FF%00", "/data/binary/overflow_test_raw_payload"]
        };

        for (let i = 0; i < 40; i++) {
            const v = vectors[Math.floor(Math.random() * vectors.length)];
            const path = attackPaths[v][Math.floor(Math.random() * attackPaths[v].length)];
            fetch(path).catch(e => { });
            await new Promise(r => setTimeout(r, 100)); // Delay to simulate real traffic
        }
        showToast("✅ Attack Sequence Complete");
    });
});

async function syncData(syncInputs = false) {
    try {
        const res = await fetch(`${API_BASE}/stats`);
        const stats = await res.json();

        currentConfig = stats.config || {};
        const logs = stats.recentLogs || [];

        updateUI(logs, stats, syncInputs);
        updateMap(logs, stats);
    } catch (err) {
        console.warn("Retrying engine sync...");
    }
}

function updateUI(logs, stats, syncInputs) {
    // Stats Cards
    const safeSet = (id, val) => { if (document.getElementById(id)) document.getElementById(id).innerText = val; };
    safeSet('stat-total', stats.total || 0);
    safeSet('stat-blocked', stats.blocked || 0);
    safeSet('stat-risk', (stats.avgRisk || 0).toFixed(3));
    safeSet('stat-bans', stats.blacklistCount || 0);

    // Sync Fields if needed
    if (syncInputs && currentConfig) {
        const s = (id, v) => { if (document.getElementById(id)) document.getElementById(id).value = v || ''; };
        const c = (id, v) => { if (document.getElementById(id)) document.getElementById(id).checked = !!v; };

        s('cfg-target', currentConfig.targetUrl);
        s('cfg-mode', currentConfig.protectionMode);
        s('cfg-rate-limit', currentConfig.rateLimit || 100);
        s('cfg-threshold', Math.round((currentConfig.riskThreshold || 0.88) * 100));

        const m = currentConfig.modules || {};
        c('mod-sqli', m.sqli);
        c('mod-xss', m.xss);
        c('mod-path', m.pathTraversal);
        c('mod-rce', m.rce);
        c('mod-bot', m.bot);
    }

    // Traffic Table
    const tbody = document.getElementById('log-body');
    if (tbody) {
        tbody.innerHTML = logs.slice(0, 12).map(log => `
            <tr>
                <td>${log.time || '--:--'}</td>
                <td>${log.ip || '0.0.0.0'}</td>
                <td><span style="font-size: 1.2rem;">${getFlag(log.country)}</span> ${log.country}</td>
                <td title="${log.url}">${(log.url || '/').substring(0, 20)}...</td>
                <td class="payload-cell">${(log.payload || '-').substring(0, 15)}...</td>
                <td><span class="fingerprint-tag ${log.isBot ? 'tag-bot' : 'tag-human'}">${log.isBot ? 'Script' : 'Browser'}</span></td>
                <td>${log.type}</td>
                <td>
                    <span class="risk-dot" style="background: ${getRiskColor(log.risk)}"></span>
                    ${(log.risk * 100).toFixed(1)}%
                </td>
                <td><span class="status-tag ${log.status === 'Blocked' ? 'tag-blocked' : 'tag-allowed'}">${log.status}</span></td>
            </tr>
        `).join('');
    }

    // Threat Intel Tab Updates
    updateThreatIntel(stats);
    updateGeoStats(stats.geoStats || {});
    updateCharts(logs, stats);
}

function updateThreatIntel(stats) {
    const t = stats.threats || {};
    const total = stats.blocked || 1;

    const map = {
        'sqli': 'SQL Injection',
        'xss': 'XSS',
        'path': 'Path Traversal',
        'rce': 'WebShell/RCE',
        'anomaly': 'ML Anomaly Detection',
        'bot': 'Automated Bot/Script',
        'honey': 'WAF Honeypot Trap',
        'infra': 'Blacklisted IP'
    };

    Object.entries(map).forEach(([id, name]) => {
        let count = t[name] || 0;
        if (id === 'anomaly' && t['Anomaly Detected']) count += t['Anomaly Detected'];

        const el = document.getElementById(`${id}-count`);
        const bar = document.getElementById(`${id}-bar`);
        if (el) el.innerText = count;
        if (bar) bar.style.width = Math.min(100, (count / total) * 100) + '%';
    });

    const safeSet = (id, val) => { if (document.getElementById(id)) document.getElementById(id).innerText = val; };
    safeSet('attacks-hour', Math.floor(stats.blocked * 0.4)); // Simulate temporal distribution
    safeSet('attacks-day', stats.blocked);
    safeSet('peak-time', new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }));
}

function updateGeoStats(geo) {
    const geoElem = document.getElementById('geo-stats');
    if (!geoElem) return;

    const entries = Object.entries(geo).sort((a, b) => b[1] - a[1]).slice(0, 5);
    geoElem.innerHTML = entries.map(([country, count]) => `
        <div class="geo-item">
            <span class="geo-country">${getFlag(country)} ${country}</span>
            <span class="geo-count">${count} Threats</span>
        </div>
    `).join('') || '<div class="geo-item"><span>Global Perimeter Secure</span></div>';
}

function updateMap(logs, stats) {
    const map = document.getElementById('threat-map');
    if (!map) return;

    // Hide loader
    const loader = map.querySelector('.map-placeholder');
    if (loader) loader.style.display = 'none';

    // Show recent block pulses
    const recentBlocks = logs.filter(l => l.status === "Blocked").slice(0, 5);
    recentBlocks.forEach(log => {
        const id = `ping-${log.ip}-${log.timestamp}`;
        if (document.getElementById(id)) return;

        const pos = COUNTRY_COORDS[log.country] || { x: 50, y: 50 };
        const ping = document.createElement('div');
        ping.className = 'attack-ping';
        ping.id = id;
        ping.style.left = `${pos.x}%`;
        ping.style.top = `${pos.y}%`;
        map.appendChild(ping);
        setTimeout(() => ping.remove(), 2500);
    });
}

function initCharts() {
    const ctxV = document.getElementById('velocityChart')?.getContext('2d');
    const ctxT = document.getElementById('vectorChart')?.getContext('2d');
    if (!ctxV || !ctxT) return;

    velocityChart = new Chart(ctxV, {
        type: 'line',
        data: { labels: [], datasets: [{ label: 'Threat Flow', data: [], borderColor: '#3b82f6', tension: 0.4, fill: true, backgroundColor: 'rgba(59, 130, 246, 0.1)' }] },
        options: { responsive: true, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, grid: { color: '#23282e' } }, x: { grid: { display: false } } } }
    });

    vectorChart = new Chart(ctxT, {
        type: 'doughnut',
        data: { labels: ['SQLi', 'XSS', 'RCE', 'Other'], datasets: [{ data: [0, 0, 0, 0], backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6', '#10b981'], borderWidth: 0 }] },
        options: { responsive: true, plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8' } } }, cutout: '70%' }
    });
}

function updateCharts(logs, stats) {
    if (!velocityChart || !vectorChart) return;

    // Update Velocity (Traffic per timeframe)
    const labels = logs.slice(0, 10).reverse().map(l => l.time);
    const data = logs.slice(0, 10).reverse().map(l => l.risk * 100);
    velocityChart.data.labels = labels;
    velocityChart.data.datasets[0].data = data;
    velocityChart.update('none');

    // Update Vector Profile
    const t = stats.threats || {};
    vectorChart.data.datasets[0].data = [t['SQL Injection'] || 0, t['XSS'] || 0, t['WebShell/RCE'] || 0, t['ML Anomaly Detection'] || 0];
    vectorChart.update('none');
}

function getRiskColor(risk) {
    if (risk > 0.8) return '#ef4444';
    if (risk > 0.5) return '#f59e0b';
    return '#10b981';
}

function getFlag(country) {
    const flags = { 'US': '🇺🇸', 'CN': '🇨🇳', 'RU': '🇷🇺', 'GB': '🇬🇧', 'IN': '🇮🇳', 'PK': '🇵🇰', 'DE': '🇩🇪', 'FR': '🇫🇷', 'JP': '🇯🇵', 'KR': '🇰🇷', 'Unknown': '🏳️' };
    return flags[country] || '🏳️';
}

function showToast(msg) {
    const area = document.getElementById('toast-area');
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerText = msg;
    area.appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
}

// SIMULATOR HELPER
window.testAttack = (type) => {
    const vectors = {
        sqli: "/search?q=' OR 1=1 --",
        xss: "/search?q=<script>alert(1)</script>",
        traversal: "/etc/passwd",
        rce: "/cmd?exec=whoami",
        anomaly: "/api/check?payload=%00%FF%00%AA"
    };
    showToast(`🚀 Launching Simulated ${type.toUpperCase()} Attack...`);
    fetch(vectors[type]).catch(e => { });
};

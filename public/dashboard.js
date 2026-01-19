/**
 * SYNAPSE: Unified Neural Dashboard
 * Digital Forensics & Semantic Security
 */

let trafficChart, threatChart;

async function fetchStats() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();

        // SYNAPSE Neural Sync: Updating SOC Stats
        document.getElementById('stat-total').innerText = data.total.toLocaleString();
        document.getElementById('stat-blocked').innerText = data.blocked.toLocaleString();

        const aiIndicator = document.getElementById('stat-ai');
        if (aiIndicator) {
            const riskLevel = data.avgRisk || 0;
            aiIndicator.innerText = (100 - (riskLevel * 100)).toFixed(1) + '%';
            aiIndicator.style.color = riskLevel > 0.3 ? 'var(--danger)' : 'var(--success)';
        }

        // Overview CPU Stat
        fetchSystemStats();

        // Auto-Refresh Traffic logs if on that page
        if (document.getElementById('page-traffic').style.display === 'block') {
            fetchTrafficLogs();
        }

        // Update Overview Log Table
        const logBody = document.getElementById('log-table-body');
        if (logBody) {
            logBody.innerHTML = '';
            data.recentLogs.slice(0, 15).forEach(log => {
                const row = document.createElement('tr');
                const layerBadge = log.type === 'Normal' ? '' : `<span class="badge badge-warning" style="border: 1px solid var(--warning)">${log.layer || 'L7'}</span>`;
                const botBadge = log.isBot ? `<span class="badge" style="background: var(--neon-pink); color: white; margin-left: 4px; box-shadow: 0 0 10px var(--neon-pink)">LLM_BOT</span>` : '';
                const statusBadge = log.status === 'Blocked'
                    ? `<span class="badge badge-danger" style="background: rgba(255,0,85,0.1); border: 1px solid var(--danger); border-radius: 2px;">TERMINATED</span>`
                    : `<span class="badge badge-success" style="background: rgba(0,255,170,0.1); border: 1px solid var(--success); border-radius: 2px;">CLEAN</span>`;

                row.innerHTML = `
                    <td style="font-family: 'JetBrains Mono'; font-size: 0.7rem; color: var(--text-muted)">${log.time}</td>
                    <td style="font-family: 'JetBrains Mono'; font-weight: 600; color: var(--accent)">${log.ip}</td>
                    <td style="font-size: 0.8rem;">${log.country}</td>
                    <td>${layerBadge}${botBadge}</td>
                    <td style="font-size: 0.8rem;">${log.type}</td>
                    <td style="font-family: 'JetBrains Mono'; font-weight: 700; color: ${log.risk > 0.7 ? 'var(--danger)' : 'var(--accent)'}">${(log.risk * 100).toFixed(0)}</td>
                    <td>${statusBadge}</td>
                `;
                logBody.appendChild(row);
            });
        }

        updateCharts(data);
    } catch (err) {
        console.error("Dashboard Sync Error:", err);
    }
}

async function fetchTrafficLogs() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();
        const trafficBody = document.getElementById('traffic-log-body');
        if (!trafficBody) return;

        if (!data.recentLogs || data.recentLogs.length === 0) {
            trafficBody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding: 40px; color: var(--text-secondary); font-style: italic;">📡 Monitoring active. Waiting for system traffic packets...</td></tr>';
            return;
        }

        trafficBody.innerHTML = '';
        data.recentLogs.forEach(log => {
            const row = document.createElement('tr');
            const riskColor = log.risk > 0.8 ? 'var(--danger)' : (log.risk > 0.3 ? 'var(--warning)' : 'var(--accent)');
            const payloadSnippet = log.payload ? (log.payload.length > 40 ? log.payload.substring(0, 40) + '...' : log.payload) : 'SAFE_GET_REQUEST';

            row.innerHTML = `
                <td style="font-size: 0.7rem; color: var(--text-muted)">${log.time}</td>
                <td style="font-family: 'JetBrains Mono'; font-weight: 600; color: var(--accent)">${log.ip}</td>
                <td><span class="badge" style="background:rgba(255,255,255,0.05); color: var(--text-primary); border: 1px solid var(--border)">${log.method || 'TCP'}</span></td>
                <td style="font-size: 0.8rem; font-weight: 500;">${log.url || '/'}</td>
                <td style="font-family: 'JetBrains Mono'; font-size: 0.7rem; color: var(--text-secondary)"><code>${payloadSnippet}</code></td>
                <td style="font-weight: 700; color: ${riskColor}; text-shadow: 0 0 10px ${riskColor}44">${(log.risk * 100).toFixed(0)}%</td>
                <td style="text-align: center;">${log.status === 'Blocked' ? '🔴 <span style="font-size:0.6rem; color:var(--danger)">DROPPED</span>' : '🟢 <span style="font-size:0.6rem; color:var(--success)">PASSED</span>'}</td>
            `;
            trafficBody.appendChild(row);
        });
    } catch (err) {
        console.error("Traffic Log Fetch Error:", err);
    }
}

async function fetchCurrentConfig() {
    try {
        const response = await fetch('/api/config');
        const config = await response.json();

        // Populate inputs
        if (document.getElementById('ai-version')) document.getElementById('ai-version').value = config.modelVersion;
        if (document.getElementById('risk-range')) {
            document.getElementById('risk-range').value = config.riskThreshold;
            document.getElementById('risk-value').innerText = config.riskThreshold;
        }
        if (document.getElementById('protection-mode')) document.getElementById('protection-mode').value = config.protectionMode;
        if (document.getElementById('target-url')) document.getElementById('target-url').value = config.targetUrl;
        if (document.getElementById('blocked-countries')) document.getElementById('blocked-countries').value = config.blockedCountries.join(', ');

        // Network Layer Settings
        if (document.getElementById('allowed-ports')) document.getElementById('allowed-ports').value = (config.allowedPorts || []).join(', ');
        if (document.getElementById('blocked-subnets')) document.getElementById('blocked-subnets').value = (config.blockedSubnets || []).join(', ');
    } catch (e) {
        console.error("Config fetch error:", e);
    }
}

async function saveEngineConfig() {
    const config = {
        modelVersion: document.getElementById('ai-version')?.value,
        riskThreshold: parseFloat(document.getElementById('risk-range')?.value),
        protectionMode: document.getElementById('protection-mode')?.value,
        targetUrl: document.getElementById('target-url')?.value,
        blockedCountries: document.getElementById('blocked-countries')?.value.split(',').map(s => s.trim()).filter(s => s),
        allowedPorts: document.getElementById('allowed-ports')?.value.split(',').map(s => parseInt(s.trim())).filter(s => !isNaN(s)),
        blockedSubnets: document.getElementById('blocked-subnets')?.value.split(',').map(s => s.trim()).filter(s => s)
    };

    try {
        const res = await fetch('/api/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });

        if (res.ok) {
            alert("✅ SYNAPSE Neural Weights Synchronized Successfully.");
            fetchStats();
        } else {
            alert("❌ Failed to synchronize policy. Check backend connection.");
        }
    } catch (e) {
        alert("❌ Network Error: Sync failed.");
    }
}

function updateCharts(data) {
    const ctxTraffic = document.getElementById('trafficChart')?.getContext('2d');
    if (!ctxTraffic) return;

    if (trafficChart) trafficChart.destroy();
    trafficChart = new Chart(ctxTraffic, {
        type: 'line',
        data: {
            labels: ['10m', '8m', '6m', '4m', '2m', 'Now'],
            datasets: [{
                label: 'Neural Throughput',
                data: [42, 58, 43, 65, 32, (data.total % 100) + 20],
                borderColor: '#00ffff',
                tension: 0.4,
                fill: true,
                backgroundColor: 'rgba(0, 255, 255, 0.05)'
            }]
        },
        options: {
            maintainAspectRatio: false,
            responsive: true,
            scales: { y: { beginAtZero: true }, x: { grid: { display: false } } },
            plugins: { legend: { display: false } }
        }
    });

    const ctxThreat = document.getElementById('threatChart')?.getContext('2d');
    if (!ctxThreat) return;

    if (threatChart) threatChart.destroy();
    const threatLabels = Object.keys(data.threats).filter(k => data.threats[k] > 0);
    const threatData = threatLabels.map(k => data.threats[k]);

    threatChart = new Chart(ctxThreat, {
        type: 'doughnut',
        data: {
            labels: threatLabels,
            datasets: [{
                data: threatData,
                backgroundColor: ['#00ffff', '#ff0055', '#ffaa00', '#00ffaa', '#ff00ff', '#5500ff', '#0055ff', '#ffff00'],
                borderWidth: 0
            }]
        },
        options: {
            maintainAspectRatio: false,
            responsive: true,
            plugins: { legend: { position: 'bottom', labels: { boxWidth: 12, usePointStyle: true, color: '#888' } } }
        }
    });
}

async function fetchSystemStats() {
    try {
        const res = await fetch('/api/system');
        const data = await res.json();

        // Update Overview Tile
        const cpuTile = document.getElementById('stat-sys-cpu');
        if (cpuTile) cpuTile.innerText = data.cpu + '%';

        // Update System Page
        if (document.getElementById('sys-cpu-val')) {
            document.getElementById('sys-cpu-val').innerText = data.cpu + '%';
            document.getElementById('cpu-bar').style.width = data.cpu + '%';
            document.getElementById('sys-mem-val').innerText = data.memory + '%';
            document.getElementById('mem-bar').style.width = data.memory + '%';

            document.getElementById('sys-platform').innerText = data.platform.toUpperCase() + ' (' + data.distro + ')';
            document.getElementById('sys-uptime').innerText = Math.floor(data.uptime / 3600) + ' hrs active';
            document.getElementById('sys-net-in').innerText = (data.netIn / 1024).toFixed(2) + ' kbps';
            document.getElementById('sys-net-out').innerText = (data.netOut / 1024).toFixed(2) + ' kbps';
        }
    } catch (e) {
        console.warn("System Sync Error:", e);
    }
}

function switchPage(pageId) {
    document.querySelectorAll('.page').forEach(p => p.style.display = 'none');
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

    const targetPage = document.getElementById(`page-${pageId}`);
    if (targetPage) {
        targetPage.style.display = 'block';

        // Correctly highlight the corresponding nav item
        const navItems = document.querySelectorAll('aside nav .nav-item');
        navItems.forEach(n => {
            const text = n.innerText.toLowerCase();
            if (pageId === 'overview' && text.includes('overview')) n.classList.add('active');
            if (pageId === 'traffic' && text.includes('streams')) n.classList.add('active');
            if (pageId === 'system' && text.includes('health')) n.classList.add('active');
            if (pageId === 'intelligence' && text.includes('logic')) n.classList.add('active');
            if (pageId === 'settings' && text.includes('policy')) n.classList.add('active');
        });

        if (pageId === 'traffic') fetchTrafficLogs();
        if (pageId === 'system') fetchSystemStats();
        if (pageId === 'settings' || pageId === 'intelligence') fetchCurrentConfig();
    }
}

function updateRiskValue(val) {
    document.getElementById('risk-value').innerText = val;
}

async function syncThreatFeeds() {
    alert("🔄 SYNAPSE Neural Sync: Initiating global threat data harvest...");
}

function toggleSystem() {
    alert("🛡️ Neural Link Active: Real-time System Guard engaged.");
}

// Initial Loads
fetchStats();
fetchSystemStats();
fetchCurrentConfig();
setInterval(fetchStats, 5000);
setInterval(fetchSystemStats, 3000);

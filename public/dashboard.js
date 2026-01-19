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

        document.getElementById('stat-db').innerText = data.threats['OSI Layer 3'] || data.blacklistCount || 0;

        // Update Log Table
        const logBody = document.getElementById('log-table-body');
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

        updateCharts(data);
    } catch (err) {
        console.error("Dashboard Sync Error:", err);
    }
}

function updateCharts(data) {
    // Traffic Chart (Mocked history for visual impact)
    const ctxTraffic = document.getElementById('trafficChart').getContext('2d');
    if (trafficChart) trafficChart.destroy();
    trafficChart = new Chart(ctxTraffic, {
        type: 'line',
        data: {
            labels: ['10m', '8m', '6m', '4m', '2m', 'Now'],
            datasets: [{
                label: 'Neural Throughput',
                data: [42, 58, 43, 65, 32, (data.total % 100) + 20], // Hybrid real-time trend
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

    // Threat Chart
    const ctxThreat = document.getElementById('threatChart').getContext('2d');
    if (threatChart) threatChart.destroy();
    const threatLabels = Object.keys(data.threats).filter(k => data.threats[k] > 0);
    const threatData = threatLabels.map(k => data.threats[k]);

    threatChart = new Chart(ctxThreat, {
        type: 'doughnut',
        data: {
            labels: threatLabels,
            datasets: [{
                data: threatData,
                backgroundColor: ['#6366f1', '#ef4444', '#f59e0b', '#22c55e', '#8b5cf6'],
                borderWidth: 0
            }]
        },
        options: {
            maintainAspectRatio: false,
            responsive: true,
            plugins: { legend: { position: 'bottom', labels: { boxWidth: 12, usePointStyle: true } } }
        }
    });
}

function switchPage(pageId) {
    document.querySelectorAll('.page').forEach(p => p.style.display = 'none');
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

    document.getElementById(`page-${pageId}`).style.display = 'block';
    // Mark nav item active
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(n => {
        if (n.innerText.toLowerCase().includes(pageId)) n.classList.add('active');
    });
}

function updateRiskValue(val) {
    document.getElementById('risk-value').innerText = val;
}

async function syncThreatFeeds() {
    alert("🔄 Triggering Global Threat Feed Sync...");
    // Future: Call API to trigger backend sync
}

// Initial Sync
fetchStats();
setInterval(fetchStats, 5000);

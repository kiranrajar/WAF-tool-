/**
 * AEGIS Enterprise Dashboard Logic
 * Professional SOC Implementation
 */

let trafficChart, threatChart;

async function fetchStats() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();

        // Update Stats
        document.getElementById('stat-total').innerText = data.total.toLocaleString();
        document.getElementById('stat-blocked').innerText = data.blocked.toLocaleString();
        document.getElementById('stat-db').innerText = data.threats['OSI Layer 3'] || data.blacklistCount || 0;

        // Update Log Table
        const logBody = document.getElementById('log-table-body');
        logBody.innerHTML = '';

        data.recentLogs.slice(0, 10).forEach(log => {
            const row = document.createElement('tr');
            const layerBadge = log.type === 'Normal' ? '' : `<span class="badge badge-warning">${log.layer || 'L7'}</span>`;
            const botBadge = log.isBot ? `<span class="badge badge-info" style="background: var(--primary); color: white; margin-left: 4px;">BOT</span>` : '';
            const statusBadge = log.status === 'Blocked'
                ? `<span class="badge badge-danger">Blocked</span>`
                : `<span class="badge badge-success">Allowed</span>`;

            row.innerHTML = `
                <td style="font-family: 'JetBrains Mono'; font-size: 0.75rem;">${log.time}</td>
                <td style="font-weight: 600;">${log.ip}</td>
                <td>${log.country}</td>
                <td>${layerBadge}${botBadge}</td>
                <td>${log.type}</td>
                <td style="font-weight: 700; color: ${log.risk > 0.7 ? 'var(--danger)' : 'var(--text-secondary)'}">${(log.risk * 100).toFixed(0)}%</td>
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
                label: 'Requests',
                data: [12, 19, 3, 5, 2, 15], // Mock trend
                borderColor: '#6366f1',
                tension: 0.4,
                fill: true,
                backgroundColor: 'rgba(99, 102, 241, 0.1)'
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

const express = require('express');
const axios = require('axios');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');

const app = express();
const PORT = 3000;
const LOG_FILE = path.join(__dirname, 'logs.json');
const CONFIG_FILE = path.join(__dirname, 'config.json');

// Real-world signatures: SQLi, XSS, Path Traversal, WebShells
const SIGNATURES = {
    'SQL Injection': [
        /UNION\s+SELECT/i, /OR\s+1=1/i, /admin'--/i, /DROP\s+TABLE/i,
        /SLEEP\(\d+\)/i, /BENCHMARK\(/i, /information_schema/i
    ],
    'XSS': [
        /<script.*?>/i, /javascript:/i, /onerror=/i, /onload=/i,
        /eval\(/i, /alert\(/i, /document\.cookie/i
    ],
    'Path Traversal': [
        /\.\.\//, /%2e%2e%2f/i, /\/etc\/passwd/i, /\/windows\/system32/i, /boot\.ini/i
    ],
    'WebShell/RCE': [
        /cmd\.exe/i, /bin\/sh/i, /bin\/bash/i, /passthru\(/i, /exec\(/i, /system\(/i, /shell_exec\(/i
    ]
};

// Mock Geo-IP data
const COUNTRIES = ['US', 'CN', 'RU', 'BR', 'DE', 'IN', 'JP', 'GB', 'FR', 'NL'];
function getMockGeo() {
    return COUNTRIES[Math.floor(Math.random() * COUNTRIES.length)];
}

// Initialize config if it doesn't exist
if (!fs.existsSync(CONFIG_FILE)) {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify({
        blacklist: [],
        whitelist: ['127.0.0.1', '::1'],
        rateLimit: 15,
        autoBlockThreshold: 0.92,
        reputationThreshold: -50 // Score drops on attacks
    }, null, 2));
}

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, '../dashboard')));

const ipReputation = {};

setInterval(() => {
    // Decay reputation penalty over time (recovery)
    for (let ip in ipReputation) {
        if (ipReputation[ip] < 0) ipReputation[ip] += 1;
    }
}, 300000); // Every 5 mins

function calculateEntropy(text) {
    if (!text) return 0;
    const len = text.length;
    const freq = {};
    for (let char of text) freq[char] = (freq[char] || 0) + 1;
    let entropy = 0;
    for (let char in freq) {
        const p = freq[char] / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

function extractFeatures(payload) {
    const decoded = decodeURIComponent(payload);
    const length = decoded.length;
    const specCount = (decoded.match(/[',<>"();[\]{}!@#$%^&*+-=/\\|_]/g) || []).length;
    const specDensity = length > 0 ? specCount / length : 0;

    // Pattern matches
    let sqli = 0, xss = 0, trauma = 0, rce = 0;
    SIGNATURES['SQL Injection'].forEach(p => { if (p.test(decoded)) sqli++; });
    SIGNATURES['XSS'].forEach(p => { if (p.test(decoded)) xss++; });
    SIGNATURES['Path Traversal'].forEach(p => { if (p.test(decoded)) trauma++; });
    SIGNATURES['WebShell/RCE'].forEach(p => { if (p.test(decoded)) rce++; });

    const encodedChars = (payload.match(/%/g) || []).length;
    const entropy = calculateEntropy(decoded);

    return [length, specDensity, sqli + trauma, xss + rce, encodedChars, entropy];
}

function logRequest(ip, url, risk, status, type, country) {
    const logs = JSON.parse(fs.readFileSync(LOG_FILE));
    const newLog = {
        time: new Date().toLocaleTimeString(),
        timestamp: Date.now(),
        ip,
        url,
        risk: parseFloat(risk.toFixed(3)),
        status,
        type,
        country
    };
    logs.push(newLog);
    if (logs.length > 500) logs.shift();
    fs.writeFileSync(LOG_FILE, JSON.stringify(logs, null, 2));
}

// Global WAF Engine
app.use(async (req, res, next) => {
    const ip = req.ip.replace('::ffff:', '');
    if (req.url.startsWith('/api/') || req.url === '/' || req.url.includes('.')) return next();

    const config = JSON.parse(fs.readFileSync(CONFIG_FILE));

    // 1. CIDR / IP Blacklist
    if (config.blacklist.includes(ip)) {
        return res.status(403).json({ error: "Access Denied by Firewall" });
    }

    // 2. Reputation Check
    const rep = ipReputation[ip] || 0;
    if (rep < config.reputationThreshold) {
        logRequest(ip, req.url, 1.0, "Blocked", "Reputation Ban", getMockGeo());
        return res.status(403).json({ error: "Source Reputation Critical" });
    }

    const payload = req.url + JSON.stringify(req.body || "");
    const features = extractFeatures(payload);
    const country = getMockGeo();

    let risk = 0.5;
    let status = "Allowed";
    let type = "Normal";

    try {
        const mlRes = await axios.post("http://localhost:8000/score", { features });
        risk = mlRes.data.risk;

        // Final Classification Logic
        const detectedType = Object.keys(SIGNATURES).find(category =>
            SIGNATURES[category].some(pattern => pattern.test(decodeURIComponent(payload)))
        );

        if (detectedType) type = detectedType;
        else if (risk > 0.7) type = "Anomaly / Threat";

        // Decision Engine
        if (risk > 0.88 || detectedType) {
            status = "Blocked";
            ipReputation[ip] = (ipReputation[ip] || 0) - 20; // Hit reputation

            // Persistent Auto-Block
            if (ipReputation[ip] < config.reputationThreshold && !config.whitelist.includes(ip)) {
                if (!config.blacklist.includes(ip)) {
                    config.blacklist.push(ip);
                    fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
                }
            }
        }
    } catch (err) {
        // Safe-mode Fallback
        const quickCheck = Object.keys(SIGNATURES).some(c =>
            SIGNATURES[c].some(p => p.test(decodeURIComponent(payload)))
        );
        if (quickCheck) { status = "Blocked"; risk = 0.95; type = "Rule-Match"; }
    }

    logRequest(ip, req.url, risk, status, type, country);

    if (status === "Blocked") {
        return res.status(403).json({ error: "ML-WAF Blocked This Request", risk_score: risk });
    }

    next();
});

// Admin APIs
app.get('/api/logs', (req, res) => res.json(JSON.parse(fs.readFileSync(LOG_FILE))));
app.get('/api/config', (req, res) => res.json(JSON.parse(fs.readFileSync(CONFIG_FILE))));
app.get('/api/stats', (req, res) => {
    const logs = JSON.parse(fs.readFileSync(LOG_FILE));
    const config = JSON.parse(fs.readFileSync(CONFIG_FILE));
    res.json({
        total: logs.length,
        blocked: logs.filter(l => l.status === "Blocked").length,
        allowed: logs.filter(l => l.status === "Allowed").length,
        avgRisk: logs.length > 0 ? logs.reduce((acc, l) => acc + l.risk, 0) / logs.length : 0,
        threats: logs.reduce((acc, l) => {
            if (l.type !== "Normal") acc[l.type] = (acc[l.type] || 0) + 1;
            return acc;
        }, {}),
        blacklistCount: config.blacklist.length
    });
});
app.post('/api/unblock', (req, res) => {
    const { ip } = req.body;
    const config = JSON.parse(fs.readFileSync(CONFIG_FILE));
    config.blacklist = config.blacklist.filter(i => i !== ip);
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
    if (ipReputation[ip]) delete ipReputation[ip];
    res.json({ success: true });
});

app.listen(PORT, () => console.log(`WAF Engine v2.5 Online at http://localhost:${PORT}`));

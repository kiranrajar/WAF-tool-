require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const geoip = require('geoip-lite');
const UAParser = require('ua-parser-js');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();
const PORT = process.env.PORT || 3000;
const TARGET_URL = process.env.TARGET_URL || 'https://httpbin.org';
const LOG_FILE = path.join(__dirname, 'logs.json');
const BLACKLIST_FILE = path.join(__dirname, 'blacklist.json');
const REPUTATION_FILE = path.join(__dirname, 'reputation.json');

// Initialize files
if (!fs.existsSync(LOG_FILE)) fs.writeFileSync(LOG_FILE, JSON.stringify([]));
if (!fs.existsSync(BLACKLIST_FILE)) fs.writeFileSync(BLACKLIST_FILE, JSON.stringify([]));
if (!fs.existsSync(REPUTATION_FILE)) fs.writeFileSync(REPUTATION_FILE, JSON.stringify({}));

app.use(cors());
app.use(bodyParser.json());

// Disable caching for all static files
app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Surrogate-Control', 'no-store');
    next();
});

// Serve static files BEFORE WAF middleware
app.use(express.static(path.join(__dirname, '../dashboard')));

// Attack signatures
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

    let sqli = 0, xss = 0, trauma = 0, rce = 0;
    SIGNATURES['SQL Injection'].forEach(p => { if (p.test(decoded)) sqli++; });
    SIGNATURES['XSS'].forEach(p => { if (p.test(decoded)) xss++; });
    SIGNATURES['Path Traversal'].forEach(p => { if (p.test(decoded)) trauma++; });
    SIGNATURES['WebShell/RCE'].forEach(p => { if (p.test(decoded)) rce++; });

    const encodedChars = (payload.match(/%/g) || []).length;
    const entropy = calculateEntropy(decoded);

    return [length, specDensity, sqli + trauma, xss + rce, encodedChars, entropy];
}

function detectBot(userAgent) {
    const botPatterns = [/bot/i, /crawler/i, /spider/i, /scraper/i, /curl/i, /wget/i];
    return botPatterns.some(pattern => pattern.test(userAgent));
}

function logRequest(logData) {
    try {
        const logs = JSON.parse(fs.readFileSync(LOG_FILE));
        logs.push({
            time: new Date().toLocaleTimeString(),
            timestamp: Date.now(),
            ...logData
        });
        if (logs.length > 500) logs.shift();
        fs.writeFileSync(LOG_FILE, JSON.stringify(logs, null, 2));
    } catch (err) {
        console.error('Error logging:', err);
    }
}

function getReputation(ip) {
    try {
        const reps = JSON.parse(fs.readFileSync(REPUTATION_FILE));
        return reps[ip] || { score: 0, attacks: 0 };
    } catch {
        return { score: 0, attacks: 0 };
    }
}

function updateReputation(ip, change) {
    try {
        const reps = JSON.parse(fs.readFileSync(REPUTATION_FILE));
        if (!reps[ip]) reps[ip] = { score: 0, attacks: 0 };
        reps[ip].score += change;
        reps[ip].attacks += (change < 0 ? 1 : 0);
        reps[ip].lastUpdate = Date.now();
        fs.writeFileSync(REPUTATION_FILE, JSON.stringify(reps, null, 2));
        return reps[ip];
    } catch (err) {
        console.error('Error updating reputation:', err);
        return { score: 0, attacks: 0 };
    }
}

function addToBlacklist(ip, reason) {
    try {
        const blacklist = JSON.parse(fs.readFileSync(BLACKLIST_FILE));
        if (!blacklist.find(b => b.ip === ip)) {
            blacklist.push({ ip, reason, added: new Date().toISOString() });
            fs.writeFileSync(BLACKLIST_FILE, JSON.stringify(blacklist, null, 2));
            console.log(`🚫 IP ${ip} blacklisted: ${reason}`);
        }
    } catch (err) {
        console.error('Error adding to blacklist:', err);
    }
}

// WAF Middleware - ONLY for non-static routes
app.use(async (req, res, next) => {
    const startTime = Date.now();
    const ip = req.ip.replace('::ffff:', '');
    const userAgent = req.get('user-agent') || 'Unknown';

    // Skip API routes only (static files already served above)
    if (req.url.startsWith('/api/') || req.url === '/health') {
        return next();
    }

    try {
        // GeoIP
        const geo = geoip.lookup(ip);
        const country = geo ? geo.country : 'XX';

        // Bot detection
        const isBot = detectBot(userAgent);
        const uaParser = new UAParser(userAgent);
        const browser = uaParser.getBrowser();

        // Blacklist check
        const blacklist = JSON.parse(fs.readFileSync(BLACKLIST_FILE));
        if (blacklist.some(b => b.ip === ip)) {
            console.log(`🚫 Blocked blacklisted IP: ${ip}`);
            return res.status(403).json({ error: 'Access Denied' });
        }

        // Reputation check
        const reputation = getReputation(ip);
        if (reputation.score < -50) {
            console.log(`🚫 Blocked low reputation IP: ${ip} (score: ${reputation.score})`);
            return res.status(403).json({ error: 'Access denied due to reputation' });
        }

        const payload = req.url + JSON.stringify(req.body || "");
        const features = extractFeatures(payload);

        let risk = 0.5;
        let status = "Allowed";
        let type = "Normal";

        // ML Detection
        try {
            const mlRes = await axios.post("http://localhost:8000/score", { features }, { timeout: 5000 });
            risk = mlRes.data.risk;
        } catch (err) {
            console.warn('⚠️  ML API unavailable, using rules only');
        }

        // Signature detection
        const detectedType = Object.keys(SIGNATURES).find(category =>
            SIGNATURES[category].some(pattern => pattern.test(decodeURIComponent(payload)))
        );

        if (detectedType) {
            type = detectedType;
        } else if (risk > 0.7) {
            type = "Anomaly / Threat";
        }

        // Decision
        if (risk > 0.88 || detectedType) {
            status = "Blocked";
            const updatedRep = updateReputation(ip, -20);

            console.log(`🚨 ATTACK DETECTED: ${type} from ${ip} (risk: ${(risk * 100).toFixed(1)}%)`);

            if (updatedRep.score < -50) {
                addToBlacklist(ip, `Auto-blocked: ${type} (${updatedRep.attacks} attacks)`);
            }
        }

        // Log
        logRequest({
            ip,
            country,
            url: req.url,
            method: req.method,
            userAgent: browser.name || userAgent.substring(0, 50),
            risk: parseFloat(risk.toFixed(3)),
            status,
            type,
            responseTime: Date.now() - startTime,
            isBot
        });

        if (status === "Blocked") {
            return res.status(403).json({
                error: "🛡️ Blocked by AEGIS Shield",
                risk_score: risk.toFixed(3),
                threat_type: type,
                incident_id: Math.random().toString(36).substring(7).toUpperCase()
            });
        }

        // IMPORTANT: Move to proxy only if not a dashboard/API route
        if (req.url.startsWith('/api/') || req.url === '/health' || req.headers.referer?.includes('/dashboard')) {
            return next();
        }

        next();
    } catch (err) {
        console.error('WAF error:', err);
        next();
    }
});

// Reverse Proxy Implementation
app.use('/', (req, res, next) => {
    // Skip proxy for Dashboard and Internal APIs
    if (req.url.startsWith('/api/') || req.url === '/health' || req.url.includes('style.css') || req.url.includes('app.js')) {
        return next();
    }

    createProxyMiddleware({
        target: TARGET_URL,
        changeOrigin: true,
        onProxyReq: (proxyReq, req, res) => {
            // Forward headers correctly
            proxyReq.setHeader('X-Protected-By', 'AEGIS-Shield-WAF');
        }
    })(req, res, next);
});

// API Endpoints
app.get('/api/logs', (req, res) => {
    const logs = JSON.parse(fs.readFileSync(LOG_FILE));
    res.json(logs);
});

app.get('/api/stats', (req, res) => {
    const logs = JSON.parse(fs.readFileSync(LOG_FILE));
    const blacklist = JSON.parse(fs.readFileSync(BLACKLIST_FILE));

    res.json({
        total: logs.length,
        blocked: logs.filter(l => l.status === "Blocked").length,
        allowed: logs.filter(l => l.status === "Allowed").length,
        avgRisk: logs.length > 0 ? logs.reduce((acc, l) => acc + l.risk, 0) / logs.length : 0,
        threats: logs.reduce((acc, l) => {
            if (l.type !== "Normal") acc[l.type] = (acc[l.type] || 0) + 1;
            return acc;
        }, {}),
        blacklistCount: blacklist.length
    });
});

app.get('/api/config', (req, res) => {
    const blacklist = JSON.parse(fs.readFileSync(BLACKLIST_FILE));
    res.json({ blacklist: blacklist.map(b => b.ip) });
});

app.post('/api/unblock', (req, res) => {
    const { ip } = req.body;
    const blacklist = JSON.parse(fs.readFileSync(BLACKLIST_FILE));
    const filtered = blacklist.filter(b => b.ip !== ip);
    fs.writeFileSync(BLACKLIST_FILE, JSON.stringify(filtered, null, 2));
    console.log(`✓ IP ${ip} removed from blacklist`);
    res.json({ success: true });
});

app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        version: '3.0.0',
        uptime: process.uptime(),
        timestamp: new Date().toISOString()
    });
});

app.listen(PORT, () => {
    console.log('\n🛡️  ═══════════════════════════════════════════════════════');
    console.log('   AEGIS Shield v3.0 - Production WAF');
    console.log('   ═══════════════════════════════════════════════════════');
    console.log(`   🌐 Dashboard:  http://localhost:${PORT}/`);
    console.log(`   📊 API Stats:  http://localhost:${PORT}/api/stats`);
    console.log(`   🏥 Health:     http://localhost:${PORT}/health`);
    console.log('   ═══════════════════════════════════════════════════════');
    console.log('   ✓ GeoIP Detection: Enabled');
    console.log('   ✓ Bot Detection: Enabled');
    console.log('   ✓ ML Engine: Ready');
    console.log('   ✓ Reputation System: Active');
    console.log('   ═══════════════════════════════════════════════════════\n');
});

module.exports = app;

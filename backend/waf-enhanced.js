const express = require('express');
const axios = require('axios');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const geoip = require('geoip-lite');
const useragent = require('express-useragent');
const { createProxyMiddleware } = require('http-proxy-middleware');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');
const { Log, Blacklist, Reputation } = require('./models');

const app = express();
const PORT = process.env.PORT || 3000;
const TARGET_URL = process.env.TARGET_URL || 'http://localhost:5000'; // Default to our target app
const MONGODB_URI = process.env.MONGODB_URI;
const DISCORD_WEBHOOK = process.env.DISCORD_WEBHOOK;

// Apex Alert System
async function sendSOCAlert(data) {
    console.log(`📡 [SOC ALERT] ${data.type} detected from ${data.ip} (${data.country})`);
    if (DISCORD_WEBHOOK) {
        try {
            await axios.post(DISCORD_WEBHOOK, {
                embeds: [{
                    title: `🛡️ AEGIS Shield: Critical Alert`,
                    color: 15548997, // Red
                    fields: [
                        { name: "Event Type", value: data.type, inline: true },
                        { name: "IP Address", value: data.ip, inline: true },
                        { name: "Country", value: data.country, inline: true },
                        { name: "Risk Score", value: `${(data.risk * 100).toFixed(1)}%`, inline: true },
                        { name: "Payload", value: `\`\`\`${data.payload?.substring(0, 100) || 'N/A'}\`\`\`` }
                    ],
                    timestamp: new Date().toISOString()
                }]
            });
        } catch (err) {
            console.error('❌ Failed to send Discord alert');
        }
    }
}

// Connect to MongoDB
if (MONGODB_URI) {
    mongoose.connect(MONGODB_URI)
        .then(() => console.log('✅ Connected to MongoDB Atlas'))
        .catch(err => console.error('❌ MongoDB Connection Error:', err));
}

const LOG_FILE = path.join(__dirname, 'logs.json');
const BLACKLIST_FILE = path.join(__dirname, 'blacklist.json');
const CONFIG_FILE = path.join(__dirname, 'config.json');

// Initialize files if not exists
if (!fs.existsSync(LOG_FILE)) fs.writeFileSync(LOG_FILE, JSON.stringify([]));
if (!fs.existsSync(BLACKLIST_FILE)) fs.writeFileSync(BLACKLIST_FILE, JSON.stringify([]));
if (!fs.existsSync(CONFIG_FILE)) {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify({
        blockedCountries: ['CN', 'RU', 'KP'],
        rateLimit: 100,
        riskThreshold: 0.88,
        protectionMode: 'blocking',
        targetUrl: 'http://localhost:5000'
    }));
}

app.use(cors());
app.use(useragent.express());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Rate Limiting (DDoS Protection)
const limiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: (req) => {
        const config = JSON.parse(fs.readFileSync(CONFIG_FILE));
        return config.rateLimit || 100;
    },
    message: { error: "Too many requests. AEGIS DDoS Protection active." },
    standardHeaders: true,
    legacyHeaders: false,
});

// Serve static files (Dashboard)
app.use('/dashboard', express.static(path.join(__dirname, '../dashboard')));

// Custom Block Page Helper
function getBlockPage(ip, reason, incidentId) {
    return `
        <html>
        <head>
            <title>403 Forbidden - AEGIS Shield</title>
            <style>
                body { background: #0d1117; color: #c9d1d9; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
                .container { background: #161b22; border: 1px solid #30363d; padding: 40px; border-radius: 12px; max-width: 600px; text-align: center; box-shadow: 0 8px 32px rgba(0,0,0,0.4); }
                .icon { font-size: 64px; color: #f85149; margin-bottom: 20px; }
                h1 { font-size: 24px; color: #f85149; margin-bottom: 10px; }
                p { line-height: 1.6; color: #8b949e; }
                .meta { margin-top: 30px; font-family: monospace; font-size: 12px; color: #484f58; background: #0d1117; padding: 15px; border-radius: 6px; text-align: left; }
                .footer { margin-top: 40px; font-size: 14px; color: #58a6ff; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="icon">🛡️</div>
                <h1>Access Denied by AEGIS Shield</h1>
                <p>Your request was flagged as a potential security threat and has been blocked by our automated systems.</p>
                <div class="meta">
                    [SYSTEM_LOG]<br>
                    IP: ${ip}<br>
                    CAUSE: ${reason}<br>
                    INCIDENT_ID: ${incidentId}<br>
                    TIME: ${new Date().toISOString()}
                </div>
                <div class="footer">Protected by AEGIS Shield Enterprise Security</div>
            </div>
        </body>
        </html>
    `;
}

// Attack signatures
const SIGNATURES = {
    'SQL Injection': [/UNION\s+SELECT/i, /OR\s+1=1/i, /admin'--/i, /DROP\s+TABLE/i, /SLEEP\(\d+\)/i, /BENCHMARK\(/i, /information_schema/i],
    'XSS': [/<script.*?>/i, /javascript:/i, /onerror=/i, /onload=/i, /eval\(/i, /alert\(/i, /document\.cookie/i],
    'Path Traversal': [/\.\.\//, /%2e%2e%2f/i, /\/etc\/passwd/i, /\/windows\/system32/i, /boot\.ini/i],
    'WebShell/RCE': [/cmd\.exe/i, /bin\/sh/i, /bin\/bash/i, /passthru\(/i, /exec\(/i, /system\(/i, /shell_exec\(/i]
};

function calculateEntropy(text) {
    if (!text) return 0;
    const len = text.length;
    const freq = {};
    for (const char of text) freq[char] = (freq[char] || 0) + 1;
    let entropy = 0;
    for (const char in freq) {
        const p = freq[char] / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

function extractFeatures(req) {
    const payload = req.url + JSON.stringify(req.body || "") + JSON.stringify(req.query || "");
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

// Bot Detection Fingerprinting
function getFingerprintRisk(req) {
    let risk = 0;
    const ua = req.headers['user-agent'] || '';

    // 1. Check for common headless browser markers
    if (ua.includes('Headless') || ua.includes('Puppeteer') || ua.includes('Playwright')) risk += 0.5;

    // 2. Check for missing common headers usually present in real browsers
    if (!req.headers['accept-language']) risk += 0.2;
    if (!req.headers['accept']) risk += 0.1;

    // 3. Check for scripting languages as browsers
    if (ua.includes('python-requests') || ua.includes('Go-http-client') || ua.includes('node-fetch')) risk += 0.4;

    return risk;
}

async function logRequest(logData) {
    try {
        if (MONGODB_URI) {
            await Log.create({ time: new Date().toLocaleTimeString(), ...logData });
        } else {
            const logs = JSON.parse(fs.readFileSync(LOG_FILE));
            logs.push({ time: new Date().toLocaleTimeString(), timestamp: Date.now(), ...logData });
            if (logs.length > 500) logs.shift();
            fs.writeFileSync(LOG_FILE, JSON.stringify(logs, null, 2));
        }
    } catch (err) {
        console.error('Error logging:', err);
    }
}

// Core WAF Engine (Global Inspection)
app.use(async (req, res, next) => {
    // 1. Basic Setup
    const startTime = Date.now();
    const ip = req.ip.replace('::ffff:', '').replace('127.0.0.1', '8.8.8.8'); // Local dev override for GeoIP
    const config = JSON.parse(fs.readFileSync(CONFIG_FILE));
    const geo = geoip.lookup(ip);
    const country = geo ? geo.country : 'XX';

    // 2. Internal Route Check
    if (req.url.startsWith('/api/') || req.url.startsWith('/dashboard') || req.url === '/health') {
        return next();
    }

    // 3. Honeypot Check (Apex Mastery Traps)
    const honeyPaths = ['/.env', '/admin_setup', '/wp-admin', '/phpmyadmin', '/backup.zip'];
    if (honeyPaths.some(p => req.url.includes(p))) {
        console.log(`🪤 Honeypot Triggered! IP: ${ip} touched ${req.url}`);

        const blacklist = JSON.parse(fs.readFileSync(BLACKLIST_FILE));
        if (!blacklist.find(b => b.ip === ip)) {
            blacklist.push({ ip, reason: `WAF Honeypot: ${req.url}`, timestamp: Date.now() });
            fs.writeFileSync(BLACKLIST_FILE, JSON.stringify(blacklist, null, 2));
        }

        sendSOCAlert({
            type: "Honeypot Triggered (Auto-Blacklisted)",
            ip, country, risk: 1.0, payload: `Accessed sensitive path: ${req.url}`
        });

        return res.status(403).send(getBlockPage(ip, "WAF Honeypot Activated", "HONEY-TRAP"));
    }

    try {
        // 4. Global Blacklist Check
        const blacklist = JSON.parse(fs.readFileSync(BLACKLIST_FILE));
        if (blacklist.some(b => b.ip === ip)) {
            return res.status(403).send(getBlockPage(ip, "IP Permanently Blacklisted", "B-LIST"));
        }

        // 5. Geo-Blocking
        if (config.blockedCountries.includes(country)) {
            console.log(`🚫 Geo-Blocked: ${ip} from ${country}`);
            return res.status(403).send(getBlockPage(ip, "Geo-Location Blocked", "GEO-" + country));
        }

        // 4. ML & Signature Inspection & Fingerprinting
        const features = extractFeatures(req);
        const botRisk = getFingerprintRisk(req);
        let risk = 0.5 + botRisk;
        let type = botRisk > 0.4 ? "Automated Bot/Script" : "Normal";

        // Try ML Engine
        try {
            const mlRes = await axios.post("http://localhost:8000/score", { features }, { timeout: 2000 });
            risk = (mlRes.data.risk + botRisk) / 1.5; // Merge bot risk with ML anomaly score
        } catch (err) {
            // Fallback to heuristic
            risk = (features[1] * 2 + (features[2] + features[3]) * 0.5 + features[5] * 0.1 + botRisk) / 3;
        }

        // Signature check
        const payload = req.url + JSON.stringify(req.body);
        const decodedPayload = decodeURIComponent(payload);
        const detectedType = Object.keys(SIGNATURES).find(cat =>
            SIGNATURES[cat].some(p => p.test(decodedPayload))
        );

        if (detectedType) {
            type = detectedType;
            risk = 1.0;
        }

        let status = "Allowed";
        if ((risk > config.riskThreshold || detectedType) && config.protectionMode === 'blocking') {
            status = "Blocked";
            sendSOCAlert({ type, ip, country, risk, payload: payload.substring(0, 100) });
            console.log(`🚨 ATTACK DETECTED: ${type} from ${ip} (Risk: ${risk.toFixed(3)})`);
        }

        // Log results
        logRequest({
            ip, country, url: req.url, method: req.method,
            userAgent: req.useragent.browser || 'Unknown',
            risk: parseFloat(risk.toFixed(3)), status, type,
            responseTime: Date.now() - startTime,
            isBot: req.useragent.isBot
        });

        if (status === "Blocked") {
            const incidentId = Math.random().toString(36).substring(7).toUpperCase();
            return res.status(403).send(getBlockPage(ip, type, incidentId));
        }

        next();
    } catch (err) {
        console.error('WAF Process Error:', err);
        next();
    }
});

// Primary Reverse Proxy with Dynamic Target
app.use('/', limiter, (req, res, next) => {
    // Skip if internal
    if (req.url.startsWith('/api/') || req.url.startsWith('/dashboard') || req.url === '/health') {
        return next();
    }

    const config = JSON.parse(fs.readFileSync(CONFIG_FILE));
    const dynamicTarget = config.targetUrl || TARGET_URL;

    createProxyMiddleware({
        target: dynamicTarget,
        changeOrigin: true,
        secure: false, // For local self-signed certs
        ws: true, // Support WebSockets
        xfwd: true, // Forward headers
        onProxyRes: (proxyRes, req, res) => {
            // Inject Honeypot Link into HTML responses
            if (proxyRes.headers['content-type']?.includes('text/html')) {
                const originalWrite = res.write;
                const originalEnd = res.end;
                let body = '';

                res.write = function (chunk) { body += chunk; };
                res.end = function (chunk) {
                    if (chunk) body += chunk;
                    // Inject a hidden honeypot link before </body>
                    const honeyLink = '<a href="/admin_setup" style="display:none;" aria-hidden="true">Admin Panel</a>';
                    body = body.replace('</body>', `${honeyLink}</body>`);

                    res.setHeader('content-length', Buffer.byteLength(body));
                    originalWrite.call(res, body);
                    originalEnd.call(res);
                };
            }
        },
        onProxyReq: (proxyReq, req, res) => {
            proxyReq.setHeader('X-Protected-By', 'AEGIS-Shield-v3');
            proxyReq.setHeader('X-Real-IP', req.ip);
            // Ensure host header matches target for external sites
            if (dynamicTarget.includes('http')) {
                const targetHost = new URL(dynamicTarget).host;
                proxyReq.setHeader('host', targetHost);
            }
        },
        onError: (err, req, res) => {
            console.error('Proxy Error:', err.message);
            res.status(502).send(`
                <div style="font-family: sans-serif; padding: 50px; text-align: center; background: #0d1117; color: #c9d1d9; height: 100vh;">
                    <h1 style="color: #f85149;">502 Bad Gateway</h1>
                    <p>AEGIS Shield: Could not reach the destination server [${dynamicTarget}].</p>
                    <p style="color: #8b949e; font-size: 0.9em;">Check if the Target URL in your dashboard is correct and online.</p>
                </div>
            `);
        }
    })(req, res, next);
});

// Admin API
app.get('/api/stats', (req, res) => {
    const logs = JSON.parse(fs.readFileSync(LOG_FILE));
    const blacklist = JSON.parse(fs.readFileSync(BLACKLIST_FILE));
    const config = JSON.parse(fs.readFileSync(CONFIG_FILE));

    const blocked = logs.filter(l => l.status === "Blocked").length;
    const threats = logs.reduce((acc, l) => {
        if (l.type !== "Normal") acc[l.type] = (acc[l.type] || 0) + 1;
        return acc;
    }, {});

    res.json({
        total: logs.length,
        blocked,
        allowed: logs.length - blocked,
        avgRisk: logs.length > 0 ? logs.reduce((acc, l) => acc + l.risk, 0) / logs.length : 0,
        threats,
        blacklistCount: blacklist.length,
        config
    });
});

app.get('/api/logs', (req, res) => {
    const logs = JSON.parse(fs.readFileSync(LOG_FILE));
    res.json(logs.reverse().slice(0, 100));
});

app.get('/api/config', (req, res) => {
    const config = JSON.parse(fs.readFileSync(CONFIG_FILE));
    const blacklist = JSON.parse(fs.readFileSync(BLACKLIST_FILE));
    res.json({ ...config, blacklist: blacklist.map(b => b.ip) });
});

app.post('/api/config', (req, res) => {
    const newConfig = req.body;
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(newConfig, null, 2));
    res.json({ success: true });
});

app.post('/api/unblock', (req, res) => {
    const { ip } = req.body;
    const blacklist = JSON.parse(fs.readFileSync(BLACKLIST_FILE));
    const filtered = blacklist.filter(b => b.ip !== ip);
    fs.writeFileSync(BLACKLIST_FILE, JSON.stringify(filtered, null, 2));
    res.json({ success: true });
});

app.get('/health', (req, res) => res.json({ status: 'active', version: '3.1.0-PROD' }));

app.listen(PORT, () => {
    console.log(`\n🛡️  AEGIS SHIELD v3.1 PROFESSIONAL WAF STARTED`);
    console.log(`🌐 Proxy Listening:    http://localhost:${PORT}`);
    console.log(`📊 Security Dashboard: http://localhost:${PORT}/dashboard`);
    console.log(`🎯 Target Application: ${TARGET_URL}\n`);
});

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
const { Log, Blacklist, Reputation, Config } = require('./models');

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

// Environment adaptation for Vercel (Read-Only FS)
const IS_VERCEL = process.env.VERCEL || process.env.vercel;
const DATA_DIR = IS_VERCEL ? '/tmp' : __dirname;

const LOG_FILE = path.join(DATA_DIR, 'logs.json');
const BLACKLIST_FILE = path.join(DATA_DIR, 'blacklist.json');
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');

// Initialize files if not exists (or copy to /tmp in Vercel)
const DEFAULT_CONFIG = {
    blockedCountries: ['CN', 'RU', 'KP'],
    rateLimit: 100,
    riskThreshold: 0.88,
    protectionMode: 'blocking',
    targetUrl: 'http://books.toscrape.com',
    modules: {
        sqli: true,
        xss: true,
        pathTraversal: true,
        rce: true,
        bot: true
    }
};

async function initDataFiles() {
    if (!fs.existsSync(LOG_FILE)) fs.writeFileSync(LOG_FILE, JSON.stringify([]));
    if (!fs.existsSync(BLACKLIST_FILE)) fs.writeFileSync(BLACKLIST_FILE, JSON.stringify([]));

    if (MONGODB_URI) {
        try {
            const exists = await Config.findOne({ id: 'global' });
            if (!exists) {
                await Config.create({ id: 'global', ...DEFAULT_CONFIG });
                console.log("✅ Initialized Default Config in MongoDB");
            }
        } catch (e) { console.error("DB Init Error:", e); }
    }

    if (!fs.existsSync(CONFIG_FILE)) {
        fs.writeFileSync(CONFIG_FILE, JSON.stringify(DEFAULT_CONFIG));
    }
}


initDataFiles();

app.use(cors());
app.use(useragent.express());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Rate Limiting (DDoS Protection)
const limiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: (req) => {
        try {
            if (fs.existsSync(CONFIG_FILE)) {
                const config = JSON.parse(fs.readFileSync(CONFIG_FILE));
                return config.rateLimit || 100;
            }
        } catch (e) { }
        return 100;
    },
    message: { error: "Too many requests. AEGIS DDoS Protection active." },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.url.startsWith('/api/') || req.url.startsWith('/dashboard') || req.url === '/health'
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
            await Log.create({ time: new Date().toLocaleTimeString('en-US', { timeZone: 'Asia/Karachi' }), ...logData });
        } else {
            // Re-read file to ensure we have latest data (in case of concurrent lambdas, though loose consistency)
            let logs = [];
            if (fs.existsSync(LOG_FILE)) {
                logs = JSON.parse(fs.readFileSync(LOG_FILE));
            }
            logs.push({ time: new Date().toLocaleTimeString('en-US', { timeZone: 'Asia/Karachi' }), timestamp: Date.now(), ...logData });
            if (logs.length > 500) logs.shift();
            fs.writeFileSync(LOG_FILE, JSON.stringify(logs, null, 2));
        }
    } catch (err) {
        console.error('Error logging:', err);
    }
}

// Core WAF Engine (Global Inspection)
app.use(async (req, res, next) => {
    // Initialize data files if missing (crucial for serverless cold starts)
    initDataFiles();

    // 1. Basic Setup
    const startTime = Date.now();
    // Vercel/Proxy IP Handling
    const ip = req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0] : (req.connection.remoteAddress || req.ip);
    // If testing locally (::1), map to a random public IP for testing geo features, else keep it
    const cleanIp = (ip === '::1' || ip === '127.0.0.1') ? '103.244.175.10' : ip.replace('::ffff:', ''); // 103... is a Pakistan IP example for testing

    let config = DEFAULT_CONFIG;
    try {
        if (MONGODB_URI) {
            const dbConfig = await Config.findOne({ id: 'global' }).lean();
            if (dbConfig) config = dbConfig;
        } else if (fs.existsSync(CONFIG_FILE)) {
            config = JSON.parse(fs.readFileSync(CONFIG_FILE));
        }
    } catch (e) { }

    // Country Detection: Vercel Header -> GeoIP -> Default
    let country = req.headers['x-vercel-ip-country'];
    if (!country) {
        const geo = geoip.lookup(cleanIp);
        country = geo ? geo.country : 'US'; // Default to US if unknown
    }

    // Capture Payload for logging
    const currentPayload = req.method + " " + req.url + (Object.keys(req.body || {}).length ? " " + JSON.stringify(req.body) : "");

    // 2. Lockdown Mode Check (ZoneAlarm Style "Internet Lock")
    if (config.protectionMode === 'lockdown' && !req.url.startsWith('/api/') && !req.url.startsWith('/dashboard')) {
        await logRequest({ ip: cleanIp, country, method: req.method, url: req.url, type: 'Manual Lockdown', risk: 1.0, status: 'Blocked', payload: currentPayload, isBot: false });
        return res.status(403).send("<h1>🛡️ SYSTEM LOCKDOWN ACTIVE</h1><p>All traffic is currently suspended by the administrator.</p>");
    }

    // 3. Internal Route Check
    if (req.url.startsWith('/api/') || req.url.startsWith('/dashboard') || req.url === '/health') {
        return next();
    }

    let status = "Allowed";
    let type = "Normal";
    let risk = 0.0;

    try {
        // 0. Trusted Zone (Whitelist) - ZoneAlarm "Trusted" Concept
        const whitelist = config.whitelist || [];
        if (whitelist.includes(cleanIp)) {
            status = "Trusted";
            type = "Whitelisted IP";
            risk = 0.0;
            // Bypass all other checks
        }

        // 3. Honeypot Check
        const honeyPaths = ['/.env', '/admin_setup', '/wp-admin', '/phpmyadmin', '/backup.zip'];
        if (status === "Allowed" && honeyPaths.some(p => req.url.includes(p))) {
            status = "Blocked";
            type = "WAF Honeypot Trap";
            risk = 1.0;
            updateReputation(cleanIp, -50); // Massive penalty

            const blacklist = JSON.parse(fs.readFileSync(BLACKLIST_FILE));
            if (!blacklist.find(b => b.ip === cleanIp)) {
                blacklist.push({ ip: cleanIp, reason: `WAF Honeypot: ${req.url}`, timestamp: Date.now() });
                fs.writeFileSync(BLACKLIST_FILE, JSON.stringify(blacklist, null, 2));
            }
            sendSOCAlert({ type, ip: cleanIp, country, risk, payload: req.url });
        }

        // 4. Global Blacklist Check
        if (status === "Allowed") {
            const blacklist = JSON.parse(fs.readFileSync(BLACKLIST_FILE));
            if (blacklist.some(b => b.ip === cleanIp)) {
                status = "Blocked";
                type = "Blacklisted IP";
                risk = 1.0;
            }
        }

        // 5. Geo-Blocking
        if (status === "Allowed" && config.blockedCountries.includes(country)) {
            status = "Blocked";
            type = `Geo-Blocked (${country})`;
            risk = 1.0;
        }

        // 6. ML & Signature Inspection
        if (status === "Allowed") {
            // Default modules if missing (backward compatibility)
            const modules = config.modules || { sqli: true, xss: true, pathTraversal: true, rce: true, bot: true };

            const features = extractFeatures(req);
            let botRisk = 0;

            if (modules.bot) {
                botRisk = getFingerprintRisk(req);
            }

            risk = 0.5 + botRisk;
            type = (modules.bot && botRisk > 0.4) ? "Automated Bot/Script" : "Normal";

            // Heuristic Discovery (ZoneAlarm Style Heuristic)
            risk = (features[1] * 2 + (features[2] + features[3]) * 0.5 + features[5] * 0.1 + botRisk) / 3;

            const payload = req.url + (req.body && Object.keys(req.body).length ? JSON.stringify(req.body) : "");
            const decodedPayload = decodeURIComponent(payload);

            const moduleMap = {
                'SQL Injection': modules.sqli,
                'XSS': modules.xss,
                'Path Traversal': modules.pathTraversal,
                'WebShell/RCE': modules.rce
            };

            const detectedType = Object.keys(SIGNATURES).find(cat => {
                // Skip if module is disabled
                if (moduleMap[cat] === false) return false;
                return SIGNATURES[cat].some(p => p.test(decodedPayload));
            });

            if (detectedType) {
                type = detectedType;
                risk = 1.0;
            }

            if ((risk > config.riskThreshold || detectedType) && config.protectionMode === 'blocking') {
                status = "Blocked";
                if (!detectedType) type = "ML Anomaly Detection"; // Differentiate ML blocks from signatures
                console.log(`🚨 BLOCKING: ${type} from ${cleanIp} (Risk: ${risk.toFixed(3)})`);
                sendSOCAlert({ type, ip: cleanIp, country, risk, payload: payload.substring(0, 100) });
            }
        }



        // 7. Log results (await to ensure persistence in serverless)
        await logRequest({
            ip: cleanIp, country, url: req.url, method: req.method,
            userAgent: req.headers['user-agent'] || 'Unknown',
            risk: parseFloat(risk.toFixed(3)), status, type,
            responseTime: Date.now() - startTime,
            isBot: req.isBot || false,
            payload: currentPayload // Use the captured payload
        });

        if (status === "Blocked") {
            const incidentId = Math.random().toString(36).substring(7).toUpperCase();
            console.log(`🚨 BLOCKING: ${type} from ${cleanIp} (Incident: ${incidentId})`);

            if (config.protectionMode === 'stealth') {
                console.log("👻 STEALTH MODE: Dropping connection silently.");
                // Important difference: We log it as "Blocked" but technically it's "Dropped"
                // destroy() kills the TCP socket. The client gets ERR_CONNECTION_RESET or timeout.
                return req.destroy();
            }

            return res.status(403).send(getBlockPage(cleanIp, type, incidentId));
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

    let config = {};
    try {
        if (fs.existsSync(CONFIG_FILE)) config = JSON.parse(fs.readFileSync(CONFIG_FILE));
    } catch (e) { }

    const dynamicTarget = config.targetUrl; // Trust the config file explicit value

    if (!dynamicTarget) {
        // Only if config is broken/missing, fallback to sensible default for safety
        // But for proxy middleware we probably need strictly valid URL. 
        // If user cleared it, we might error out or show a "Not Configured" page.
        // For now, let's just default to internal app if absolutely nothing provided.
    }

    createProxyMiddleware({
        target: dynamicTarget || TARGET_URL, // Fallback purely for startup safety
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
            // Disable compression so we can inject content safely
            proxyReq.removeHeader('accept-encoding');

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
app.get('/api/stats', async (req, res) => {
    try {
        let logs = [], blacklist = [], config = {};

        if (MONGODB_URI) {
            logs = await Log.find().lean();
            blacklist = await Blacklist.find().lean();
            const dbConfig = await Config.findOne({ id: 'global' }).lean();
            config = dbConfig || DEFAULT_CONFIG;
        } else {
            await initDataFiles(); // Ensure files exist
            logs = JSON.parse(fs.readFileSync(LOG_FILE, 'utf8'));
            blacklist = JSON.parse(fs.readFileSync(BLACKLIST_FILE, 'utf8'));
            config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
        }

        const blocked = logs.filter(l => l.status === "Blocked").length;

        // Accurate Map Stats calculated from full historical logs
        const mapCritical = logs.filter(l => l.status === "Blocked" && (l.risk >= 0.8 || (l.type && l.type.includes('Honeypot')))).length;
        const mapAnomalies = logs.filter(l => l.status === "Blocked" && (l.risk < 0.8 && (!l.type || !l.type.includes('Honeypot')))).length;

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
            mapCritical,
            mapAnomalies,
            blacklistCount: blacklist.length,
            config
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to read data" });
    }
});

app.get('/api/logs', async (req, res) => {
    try {
        if (MONGODB_URI) {
            const logs = await Log.find().sort({ timestamp: -1 }).limit(50);
            return res.json(logs);
        }
        initDataFiles();
        const logs = JSON.parse(fs.readFileSync(LOG_FILE, 'utf8'));
        res.json(logs.reverse().slice(0, 50));
    } catch (err) {
        res.json([]);
    }
});

app.get('/api/config', async (req, res) => {
    try {
        await initDataFiles();
        let config = DEFAULT_CONFIG;
        let blacklistIps = [];

        if (MONGODB_URI) {
            const dbConfig = await Config.findOne({ id: 'global' }).lean();
            if (dbConfig) config = dbConfig;
            const bl = await Blacklist.find().lean();
            blacklistIps = bl.map(b => b.ip);
        } else {
            if (fs.existsSync(CONFIG_FILE)) config = JSON.parse(fs.readFileSync(CONFIG_FILE));
            const blacklist = JSON.parse(fs.readFileSync(BLACKLIST_FILE));
            blacklistIps = blacklist.map(b => b.ip);
        }
        res.json({ ...config, blacklist: blacklistIps });
    } catch (e) { res.status(500).send("Config Error"); }
});

app.post('/api/config', async (req, res) => {
    try {
        const newConfig = req.body;
        console.log("⚙️  Received Configuration Update:", JSON.stringify(newConfig));

        if (MONGODB_URI) {
            await Config.updateOne({ id: 'global' }, { $set: newConfig }, { upsert: true });
        } else {
            fs.writeFileSync(CONFIG_FILE, JSON.stringify(newConfig, null, 2));
        }

        // If there's blacklist in body and we have DB, sync it
        if (newConfig.blacklist && MONGODB_URI) {
            for (const ip of newConfig.blacklist) {
                await Blacklist.updateOne({ ip }, { ip, reason: "Manual Block" }, { upsert: true });
            }
        }

        res.json({ success: true, message: "Configuration saved successfully" });
    } catch (e) {
        console.error("Config Save Error:", e);
        res.status(500).send("Write Error");
    }
});

app.post('/api/unblock', async (req, res) => {
    try {
        const { ip } = req.body;
        if (MONGODB_URI) {
            await Blacklist.deleteOne({ ip });
        }

        // Also update local file for redundancy/UI consistency
        if (fs.existsSync(BLACKLIST_FILE)) {
            const blacklist = JSON.parse(fs.readFileSync(BLACKLIST_FILE));
            const filtered = blacklist.filter(b => b.ip !== ip);
            fs.writeFileSync(BLACKLIST_FILE, JSON.stringify(filtered, null, 2));
        }

        res.json({ success: true });
    } catch (e) { res.status(500).send("Write Error"); }
});



app.get('/health', (req, res) => res.json({ status: 'active', version: '3.1.0-PROD', environment: IS_VERCEL ? 'Vercel Serverless' : 'Hosted' }));

// Only listen if not in serverless mode (Vercel exports the app)
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`\n🛡️  AEGIS SHIELD v3.1 PROFESSIONAL WAF STARTED`);
        console.log(`🌐 Proxy Listening:    http://localhost:${PORT}`);
        console.log(`📊 Security Dashboard: http://localhost:${PORT}/dashboard`);
        console.log(`🎯 Target Application: ${TARGET_URL}\n`);
    });
}



module.exports = app;

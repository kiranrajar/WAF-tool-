const express = require('express');
/*
 * SYNAPSE: Enterprise-Grade Neural WAF
 * Advanced AI-Powered Security Platform
 */
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

// Industry-Grade Modular Core
const AIEngine = require('./core/ai-engine');
const MultiLayerInspector = require('./core/osi-layer');
const threatIntelligence = require('./intelligence/threat-feeds');
const botMitigation = require('./core/bot-mitigation');
const schemaValidator = require('./core/schema-validator');


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
                    title: `🧠 SYNAPSE: Critical Neural Alert`,
                    color: 15548997, // Red
                    fields: [
                        { name: "Threat Vector", value: data.type, inline: true },
                        { name: "Source Core IP", value: data.ip, inline: true },
                        { name: "Origin", value: data.country, inline: true },
                        { name: "Risk Index", value: `${(data.risk * 100).toFixed(1)}%`, inline: true },
                        { name: "Neural Payload", value: `\`\`\`${data.payload?.substring(0, 100) || 'N/A'}\`\`\`` }
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
    try {
        if (!fs.existsSync(LOG_FILE)) fs.writeFileSync(LOG_FILE, ""); // Initialize as empty file
        if (!fs.existsSync(BLACKLIST_FILE)) fs.writeFileSync(BLACKLIST_FILE, JSON.stringify([]));

        // Sync with global threat databases on startup (Commercial feature)
        threatIntelligence.synchronize();

        if (MONGODB_URI && mongoose.connection.readyState === 1) {
            const exists = await Config.findOne({ id: 'global' });
            if (!exists) {
                await Config.create({ id: 'global', ...DEFAULT_CONFIG });
                console.log("✅ Initialized Default Config in MongoDB");
            }
        }

        if (!fs.existsSync(CONFIG_FILE)) {
            fs.writeFileSync(CONFIG_FILE, JSON.stringify(DEFAULT_CONFIG));
        }
    } catch (e) {
        console.warn("Init Files Warning:", e.message);
    }
}



initDataFiles();

app.use(cors());
app.use(useragent.express());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const limiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: (req) => {
        try {
            // Use currentConfig if available (synced by middleware), else try disk
            const config = (typeof currentConfigGlobal !== 'undefined') ? currentConfigGlobal : DEFAULT_CONFIG;
            return config.rateLimit || 100;
        } catch (e) { }
        return 100;
    },
    message: { error: "Too many requests. AEGIS DDoS Protection active." },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
        const isControlApi = ['/api/stats', '/api/config', '/api/logs', '/api/unblock', '/health'].some(p => req.url === p || req.url.startsWith(p + '?'));
        const isDashboard = req.url.startsWith('/dashboard') || req.url === '/dashboard';
        const isStatic = /\.(js|css|png|jpg|jpeg|gif|ico|svg)$/.test(req.url);
        return isControlApi || isDashboard || isStatic;
    }
});

let currentConfigGlobal = DEFAULT_CONFIG; // Cache for the limiter

// --- COMMERCIAL FEATURE: Bot Verification Route ---
app.post('/api/verify-human', bodyParser.urlencoded({ extended: true }), (req, res) => {
    const { token, ts, redirect, fp } = req.body;
    const ip = req.ip.replace('::ffff:', '');

    if (botMitigation.verifyToken(token, ts)) {
        botMitigation.recordVerification(ip);
        console.log(`🤖 [BOT MITIGATION] Humanity verified for IP: ${ip} | FP: ${fp}`);
        return res.redirect(redirect || '/');
    }
    res.status(403).send("<h1>Verification Failed</h1><p>Cryptographic proof invalid.</p>");
});


// Serve static files (Dashboard)
app.use('/dashboard', express.static(path.join(__dirname, '../public')));
app.use(express.static(path.join(__dirname, '../public')));

// Custom Block Page Helper
function getBlockPage(ip, reason, incidentId) {
    return `
        <html>
        <head>
            <title>403 Forbidden - SYNAPSE</title>
            <style>
                body { background: #050505; color: #e0e0e0; font-family: 'JetBrains Mono', monospace; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
                .container { background: #0c0c0c; border: 1px solid #1a1a1a; padding: 40px; border-radius: 4px; max-width: 600px; text-align: center; box-shadow: 0 0 30px rgba(0,255,255,0.05); }
                .icon { font-size: 64px; color: #00ffff; margin-bottom: 20px; text-shadow: 0 0 20px rgba(0,255,255,0.3); }
                h1 { font-size: 20px; color: #00ffff; margin-bottom: 10px; letter-spacing: 2px; }
                p { line-height: 1.6; color: #888; font-size: 14px; }
                .meta { margin-top: 30px; font-family: monospace; font-size: 11px; color: #444; background: #020202; padding: 15px; border-radius: 2px; text-align: left; border-left: 2px solid #00ffff; }
                .footer { margin-top: 40px; font-size: 12px; color: #333; letter-spacing: 1px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="icon">🧠</div>
                <h1>NEURAL LINK BLOCKED BY SYNAPSE</h1>
                <p>Anomalous activity detected. Request terminated by active neural defense protocols.</p>
                <div class="meta">
                    [NEURAL_LOG_ENTRY]<br>
                    IP_ORIGIN: ${ip}<br>
                    VECTOR: ${reason}<br>
                    INCIDENT_REF: ${incidentId}<br>
                    TIMESTAMP: ${new Date().toISOString()}
                </div>
                <div class="footer">SYSTEM STATUS: ACTIVE | SYNAPSE NEURAL DEFENSE v3.1</div>
            </div>
        </body>
        </html>
    `;
}

// Core WAF Engine (Global Inspection)

async function logRequest(logData) {
    try {
        const timestamp = Date.now();
        const timeStr = new Date().toLocaleTimeString('en-US', { timeZone: 'Asia/Karachi' });
        const fullLog = { time: timeStr, timestamp, ...logData };

        if (MONGODB_URI && mongoose.connection.readyState === 1) {
            await Log.create(fullLog);
        } else {
            // Use append-only NDJSON for robustness
            fs.appendFileSync(LOG_FILE, JSON.stringify(fullLog) + '\n');
        }
    } catch (err) {
        console.error('Error logging:', err);
    }
}

// Core WAF Engine (Global Inspection)
// Core WAF Engine (Global Inspection)
app.use(async (req, res, next) => {
    // 0. Skip WAF for exactly dashboard assets and internal control APIs
    const isControlApi = ['/api/stats', '/api/config', '/api/logs', '/api/unblock', '/health'].some(p => req.url === p || req.url.startsWith(p + '?'));
    const isDashboard = req.url.startsWith('/dashboard') || req.url === '/dashboard';
    const isStatic = /\.(js|css|png|jpg|jpeg|gif|ico|svg)$/.test(req.url);

    if (isControlApi || isDashboard || isStatic) {
        return next();
    }

    // 1. Setup & Config
    const startTime = Date.now();
    let config = { ...DEFAULT_CONFIG };
    try {
        if (MONGODB_URI && mongoose.connection.readyState === 1) {
            const dbConfig = await Config.findOne({ id: 'global' }).lean();
            if (dbConfig) config = { ...DEFAULT_CONFIG, ...dbConfig };
        } else if (fs.existsSync(CONFIG_FILE)) {
            const fileConfig = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
            config = { ...DEFAULT_CONFIG, ...fileConfig };
        }
    } catch (e) {
        console.error("Config Loading Error:", e.message);
    }

    currentConfigGlobal = config;

    // Initialize Components
    const aiEngine = new AIEngine(config.modelVersion || 'v2.0');
    const inspector = new MultiLayerInspector(config);

    // 2. Layer 3/4 Inspection (Network & Transport)
    const netCheck = inspector.inspectNetwork(req);
    const cleanIp = netCheck.ip;

    if (netCheck.blocked) {
        await logRequest({ ip: cleanIp, country: 'Unknown', method: req.method, url: req.url, type: netCheck.reason, risk: 1.0, status: 'Blocked', layer: netCheck.layer });
        return res.status(403).send(getBlockPage(cleanIp, netCheck.reason, 'OSI-L3-BLOCK'));
    }

    // Country Detection
    let country = req.headers['x-vercel-ip-country'];
    if (!country) {
        const geo = geoip.lookup(cleanIp);
        country = geo ? geo.country : 'US';
    }

    const currentPayload = req.method + " " + req.url + (Object.keys(req.body || {}).length ? " " + JSON.stringify(req.body) : "");

    // 3. Static Threat Database Check (Commercial Intelligence)
    if (threatIntelligence.isThreat(cleanIp)) {
        await logRequest({ ip: cleanIp, country, method: req.method, url: req.url, type: 'Static Intelligence Match', risk: 1.0, status: 'Blocked', layer: 'Layer 3 (Global Feed)' });
        return res.status(403).send(getBlockPage(cleanIp, 'Detected in Global Threat Database', 'INTEL-BLOCK'));
    }

    // 4. Lockdown Mode Check
    if (config.protectionMode === 'lockdown') {
        await logRequest({ ip: cleanIp, country, method: req.method, url: req.url, type: 'Manual Lockdown', risk: 1.0, status: 'Blocked', payload: currentPayload, isBot: false });
        return res.status(403).send("<h1>🛡️ SYSTEM LOCKDOWN ACTIVE</h1><p>All traffic is currently suspended by the administrator.</p>");
    }

    let status = "Allowed";
    let type = "Normal";
    let risk = 0.0;
    let detectedLayer = "Layer 7";
    let isBotDetected = false;

    try {
        // 5. Blacklist Check
        let blacklist = [];
        try {
            if (fs.existsSync(BLACKLIST_FILE)) {
                blacklist = JSON.parse(fs.readFileSync(BLACKLIST_FILE, 'utf8') || '[]');
            }
        } catch (e) { }

        if (blacklist.some(b => b.ip === cleanIp)) {
            status = "Blocked";
            type = "Local Blacklist";
            risk = 1.0;
            detectedLayer = "Layer 3";
        }

        // 6. Geo-Blocking
        if (status === "Allowed" && config.blockedCountries.includes(country)) {
            status = "Blocked";
            type = `Geo-Blocked (${country})`;
            risk = 1.0;
            detectedLayer = "Layer 3";
        }

        // 7. Layer 7 (Application) - AI & Signature Inspection
        if (status === "Allowed") {
            // A. Schema Validation
            const schemaCheck = schemaValidator.validate(req);
            if (!schemaCheck.valid) {
                status = "Blocked";
                type = "API Schema Violation";
                risk = 0.9;
                detectedLayer = "Layer 7 (API)";
                console.warn(`🛡️ [SCHEMA GUARD] ${schemaCheck.reason} for ${req.path}`);
            }

            // B. Core App Check
            if (status === "Allowed") {
                const appCheck = inspector.inspectApplication(req, aiEngine);

                // C. Active Bot Challenge logic (Commercial Mitigation)
                const isVerifiedHuman = botMitigation.isVerified(cleanIp);
                if (appCheck.risk > 0.4 && !isVerifiedHuman && !isStatic) {
                    console.log(`🌀 [BOT CHALLENGE] Redirecting suspicious IP: ${cleanIp}`);
                    return res.send(botMitigation.generateChallengePage(req.url));
                }

                if (appCheck.blocked) {
                    status = "Blocked";
                    type = appCheck.reason;
                    risk = appCheck.risk;
                    isBotDetected = !!appCheck.isBot;
                    detectedLayer = appCheck.layer || "Layer 7";
                }
            }
        }

        // 8. Final Logging
        await logRequest({
            ip: cleanIp, country, url: req.url, method: req.method,
            userAgent: req.headers['user-agent'] || 'Unknown',
            risk: parseFloat(risk.toFixed(3)), status, type,
            layer: detectedLayer,
            isBot: isBotDetected,
            responseTime: Date.now() - startTime,
            payload: currentPayload
        });

        if (status === "Blocked") {
            const incidentId = Math.random().toString(36).substring(7).toUpperCase();
            if (config.protectionMode === 'stealth') {
                if (res.socket) res.socket.destroy();
                else res.destroy();
                return;
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
    // Skip if internal or static
    const isControlApi = ['/api/stats', '/api/config', '/api/logs', '/api/unblock', '/health'].some(p => req.url === p || req.url.startsWith(p + '?'));
    const isDashboard = req.url.startsWith('/dashboard') || req.url === '/dashboard';
    const isStatic = /\.(js|css|png|jpg|jpeg|gif|ico|svg)$/.test(req.url);

    if (isControlApi || isDashboard || isStatic) {
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
        let total = 0, blocked = 0;
        let threats = { 'SQL Injection': 0, 'XSS': 0, 'Path Traversal': 0, 'WebShell/RCE': 0, 'ML Anomaly Detection': 0 };
        let geoStats = {};

        // Helper to ensure we have a connection or wait a bit (Vercel cold start)
        if (MONGODB_URI && mongoose.connection.readyState !== 1) {
            await new Promise(r => setTimeout(r, 800)); // Wait for connection
        }

        if (MONGODB_URI && mongoose.connection.readyState === 1) {
            // High-performance counts
            total = await Log.countDocuments();
            blocked = await Log.countDocuments({ status: "Blocked" });

            // Get threat breakdown
            const threatStats = await Log.aggregate([
                { $match: { type: { $ne: "Normal" } } },
                { $group: { _id: "$type", count: { $sum: 1 } } }
            ]);
            threatStats.forEach(t => { threats[t._id] = t.count; });

            // Geo stats aggregation
            const gStats = await Log.aggregate([
                { $match: { status: "Blocked" } },
                { $group: { _id: "$country", count: { $sum: 1 } } },
                { $sort: { count: -1 } },
                { $limit: 10 }
            ]);
            gStats.forEach(g => { geoStats[g._id] = g.count; });

            const bl = await Blacklist.find().lean();
            blacklist = bl;
            const dbConfig = await Config.findOne({ id: 'global' }).lean();
            config = dbConfig || DEFAULT_CONFIG;

            logs = await Log.find().sort({ timestamp: -1 }).limit(50).lean();
        } else {
            await initDataFiles();
            const logContent = fs.readFileSync(LOG_FILE, 'utf8');
            logs = logContent.split('\n').filter(l => l.trim()).map(l => JSON.parse(l));
            blacklist = JSON.parse(fs.readFileSync(BLACKLIST_FILE, 'utf8') || '[]');
            config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8') || '[]');
            total = logs.length;
            blocked = logs.filter(l => l.status === "Blocked").length;
            logs.forEach(l => {
                if (l.type !== "Normal") threats[l.type] = (threats[l.type] || 0) + 1;
                if (l.status === "Blocked") geoStats[l.country] = (geoStats[l.country] || 0) + 1;
            });
        }

        res.json({
            total, blocked, allowed: total - blocked,
            avgRisk: logs.length > 0 ? logs.reduce((acc, l) => acc + l.risk, 0) / logs.length : 0,
            threats, geoStats,
            blacklistCount: blacklist.length,
            config,
            recentLogs: logs.map(l => ({ ...l, id: l._id })) // Ensure ID for mapping
        });
    } catch (err) {
        console.error("Stats API Error:", err);
        res.status(500).json({ error: "Failed to read data" });
    }
});

app.get('/api/logs', async (req, res) => {
    try {
        if (MONGODB_URI && mongoose.connection.readyState === 1) {
            const logs = await Log.find().sort({ timestamp: -1 }).limit(50).lean();
            return res.json(logs);
        }
        await initDataFiles();
        const logContent = fs.readFileSync(LOG_FILE, 'utf8');
        const logs = logContent.split('\n').filter(l => l.trim()).map(l => JSON.parse(l));
        res.json([...logs].reverse().slice(0, 50));
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
        console.log("⚙️  Saving Configuration Update...");

        if (MONGODB_URI && mongoose.connection.readyState === 1) {
            // Update MongoDB primarily
            await Config.updateOne({ id: 'global' }, { $set: newConfig }, { upsert: true });
        }

        // Always try to update local cache file for the current instance's fast-path
        try {
            fs.writeFileSync(CONFIG_FILE, JSON.stringify(newConfig, null, 2));
        } catch (err) {
            console.warn("Local config cache save failed (expected on Vercel serverless):", err.message);
        }

        // Fast-path for Blacklist sync
        if (newConfig.blacklist && MONGODB_URI && mongoose.connection.readyState === 1) {
            // Only update DB if they actually changed
            const existing = await Blacklist.find().lean();
            const existingIps = existing.map(b => b.ip);

            const newIps = newConfig.blacklist.filter(ip => !existingIps.includes(ip));
            if (newIps.length > 0) {
                await Blacklist.insertMany(newIps.map(ip => ({ ip, reason: "Manual Block" })));
            }
        }

        res.json({ success: true, message: "Configuration persistent in Cloud" });
    } catch (e) {
        console.error("Config Save Error:", e);
        res.status(500).json({ success: false, error: e.message });
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

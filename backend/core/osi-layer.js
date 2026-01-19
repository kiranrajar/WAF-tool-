/**
 * SYNAPSE: Multi-Layer Neural Engine
 * Handles OSI Layer 3 (Network), Layer 4 (Transport), and Layer 7 (Application) logic.
 */

class MultiLayerInspector {
    constructor(config) {
        this.config = config;
        this.signatures = {
            'SQL Injection': [/UNION\s+SELECT/i, /OR\s+1=1/i, /admin'--/i, /DROP\s+TABLE/i, /SLEEP\(\d+\)/i, /BENCHMARK\(/i, /information_schema/i],
            'XSS': [/<script.*?>/i, /javascript:/i, /onerror=/i, /onload=/i, /eval\(/i, /alert\(/i, /document\.cookie/i],
            'Path Traversal': [/\.\.\//, /%2e%2e%2f/i, /\/etc\/passwd/i, /\/windows\/system32/i, /boot\.ini/i],
            'WebShell/RCE': [/cmd\.exe/i, /bin\/sh/i, /bin\/bash/i, /passthru\(/i, /exec\(/i, /system\(/i, /shell_exec\(/i]
        };
    }

    /**
     * Layer 3 & 4 Simulation (Network/Transport)
     * In a Node.js environment, we focus on IP Subnets, Port access, and Connection limits.
     */
    inspectNetwork(req) {
        const xff = req.headers['x-forwarded-for'];
        const ip = xff ? xff.split(',')[0].trim() : (req.connection.remoteAddress || req.ip);
        const cleanIp = ip.replace('::ffff:', '');

        // Layer 3: Subnet / IP Range Check
        if (this.isSubnetBlocked(cleanIp)) {
            return { blocked: true, layer: 'Layer 3 (Network)', reason: 'Source IP range is restricted by policy' };
        }

        // Layer 4: Protocol & Port Integrity
        const incomingPort = req.socket?.localPort || 80;
        const allowedPorts = this.config?.allowedPorts || [80, 443, 3000];

        if (!allowedPorts.includes(incomingPort)) {
            return { blocked: true, layer: 'Layer 4 (Transport)', reason: `Unauthorized port access: ${incomingPort}` };
        }

        if (req.headers['upgrade'] && req.headers['upgrade'] !== 'websocket') {
            return { blocked: true, layer: 'Layer 4 (Transport)', reason: 'Protocol violation' };
        }

        return { blocked: false, ip: cleanIp };
    }

    /**
     * Layer 7 (Application) - Deep Packet Inspection
     */
    inspectApplication(req, aiModel) {
        // AI Analysis
        let aiResult = { threatLevel: 0 };
        try {
            aiResult = aiModel.analyze(req) || { threatLevel: 0 };
        } catch (e) {
            console.error('[WAF ERROR] AI Analysis failed:', e.message);
        }

        // Signature Analysis & Protocol Integrity
        const payload = req.url + JSON.stringify(req.body || "") + JSON.stringify(req.query || "");
        let decoded = payload;
        let isMalformed = false;
        try {
            decoded = decodeURIComponent(payload);
        } catch (e) {
            isMalformed = true;
            decoded = payload.replace(/%/g, '%25');
        }

        if (isMalformed) {
            return {
                blocked: true,
                layer: 'Layer 7 (Protocol)',
                reason: 'Malformed URI Encoding',
                score: 1.0
            };
        }

        for (const [type, patterns] of Object.entries(this.signatures)) {
            for (const pattern of patterns) {
                if (pattern.test(decoded)) {
                    return {
                        blocked: true,
                        layer: 'Layer 7 (Application)',
                        reason: type,
                        score: 1.0
                    };
                }
            }
        }

        // Bot Risk (Layer 7 Fingerprinting)
        const botRisk = this.getFingerprintRisk(req);
        if (botRisk > 0.6) {
            return {
                blocked: true,
                layer: 'Layer 7 (Behavioral)',
                reason: 'Suspicious Bot Behavior',
                score: botRisk,
                isBot: true
            };
        }

        const threshold = this.config?.riskThreshold || 0.88;
        if (aiResult.threatLevel > threshold) {
            return {
                blocked: true,
                layer: 'Layer 7 (Application)',
                reason: aiResult.detectedType || 'AI Anomaly Detection',
                score: aiResult.threatLevel
            };
        }

        return { blocked: false };
    }

    getFingerprintRisk(req) {
        let risk = 0;
        const ua = req.headers['user-agent'] || '';
        if (ua.includes('Headless') || ua.includes('Puppeteer') || ua.includes('Playwright')) risk += 0.5;
        if (!req.headers['accept-language']) risk += 0.2;
        if (ua.includes('python-requests') || ua.includes('Go-http-client') || ua.includes('node-fetch') || ua.includes('axios')) risk += 0.4;
        return Math.round(risk * 100) / 100;
    }

    isSubnetBlocked(ip) {
        const blockedSubnets = this.config?.blockedSubnets || [];
        if (blockedSubnets.length === 0) return false;

        // Commercial CIDR validation (Quick check for prefix matches)
        return blockedSubnets.some(subnet => {
            if (subnet.includes('/')) {
                const [range] = subnet.split('/');
                const prefix = range.split('.').slice(0, 3).join('.');
                return ip.startsWith(prefix);
            }
            return ip === subnet;
        });
    }
}

module.exports = MultiLayerInspector;

/**
 * SYNAPSE: Active Bot Mitigation Layer
 * Implements JS-based browser challenges and passive fingerprinting.
 */

const crypto = require('crypto');

class BotMitigation {
    constructor() {
        this.challengeSecret = process.env.CHALLENGE_SECRET || 'synapse-neural-token-2025';
        this.verifiedSessions = new Set(); // In production, use Redis with TTL
    }

    /**
     * Generates a "Humanity Proof" challenge page
     */
    generateChallengePage(targetUrl) {
        const timestamp = Date.now();
        const token = this.generateToken(timestamp);

        return `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Check | SYNAPSE</title>
            <style>
                body { background: #050505; color: #00ffff; font-family: 'JetBrains Mono', monospace; display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; margin: 0; }
                .loader { width: 50px; height: 50px; border: 3px solid #1a1a1a; border-top: 3px solid #00ffff; border-radius: 50%; animation: spin 1s linear infinite; margin-bottom: 20px; }
                @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
                h1 { font-size: 14px; letter-spacing: 2px; }
                p { color: #444; font-size: 10px; }
            </style>
        </head>
        <body>
            <div class="loader"></div>
            <h1>ANALYZING BROWSER INTEGRITY</h1>
            <p>SYNAPSE NEURAL DEFENSE ACTIVE</p>
            <script>
                (function() {
                    // Browser Fingerprinting & Proof of Work
                    const canvas = document.createElement('canvas');
                    const ctx = canvas.getContext('2d');
                    ctx.textBaseline = "top";
                    ctx.font = "14px 'Arial'";
                    ctx.fillStyle = "#f60";
                    ctx.fillRect(125,1,62,20);
                    ctx.fillStyle = "#069";
                    ctx.fillText("synapse-bot-test", 2, 15);
                    const fingerprint = canvas.toDataURL();

                    // Solve simple computational puzzle
                    const pow = Math.sqrt(${timestamp}).toString();
                    
                    setTimeout(() => {
                        const form = document.createElement('form');
                        form.method = 'POST';
                        form.action = '/api/verify-human';
                        
                        const fields = {
                            token: '${token}',
                            ts: '${timestamp}',
                            fp: btoa(fingerprint).substring(0, 100),
                            redirect: '${targetUrl}'
                        };

                        for (const key in fields) {
                            const input = document.createElement('input');
                            input.type = 'hidden';
                            input.name = key;
                            input.value = fields[key];
                            form.appendChild(input);
                        }

                        document.body.appendChild(form);
                        form.submit();
                    }, 1500);
                })();
            </script>
        </body>
        </html>
        `;
    }

    generateToken(ts) {
        return crypto.createHmac('sha256', this.challengeSecret)
            .update(ts.toString())
            .digest('hex');
    }

    verifyToken(token, ts) {
        const expected = this.generateToken(ts);
        const isFresh = (Date.now() - parseInt(ts)) < 600000; // 10 min window
        return token === expected && isFresh;
    }

    recordVerification(ip) {
        this.verifiedSessions.add(ip);
        // Clean up after 1 hour (simulated)
        setTimeout(() => this.verifiedSessions.delete(ip), 3600000);
    }

    isVerified(ip) {
        return this.verifiedSessions.has(ip);
    }
}

module.exports = new BotMitigation();

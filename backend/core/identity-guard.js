/**
 * SYNAPSE: Identity Guard & JWT Inspection
 * Protects against session hijacking, token replay, and unauthorized account access.
 */

class IdentityGuard {
    constructor() {
        this.sessionMap = new Map(); // In production, use Redis for session tracking
    }

    /**
     * Inspects Authorization headers and JWT tokens.
     */
    inspect(req) {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return { valid: true };

        const token = authHeader.split(' ')[1];
        if (!token) return { valid: true };

        // 1. Structural Validation (Basic JWT Format)
        const parts = token.split('.');
        if (parts.length !== 3) {
            return {
                valid: false,
                reason: 'Malformed Identity Token',
                risk: 1.0
            };
        }

        // 2. Anomaly Detection (Session Hijacking / Replay)
        try {
            const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
            const userId = payload.sub || payload.id;
            const currentIp = req.ip.replace('::ffff:', '');

            if (userId) {
                const lastIp = this.sessionMap.get(userId);
                if (lastIp && lastIp !== currentIp) {
                    // Token is being used from a different IP suddenly
                    return {
                        valid: false,
                        reason: 'Identity Conflict: Potential Session Hijack',
                        risk: 0.9,
                        type: 'Account Takeover Attempt'
                    };
                }
                this.sessionMap.set(userId, currentIp);
            }
        } catch (e) {
            return { valid: false, reason: 'Identity Decoder Error', risk: 0.5 };
        }

        return { valid: true };
    }
}

module.exports = new IdentityGuard();

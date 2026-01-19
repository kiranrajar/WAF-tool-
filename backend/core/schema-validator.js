/**
 * SYNAPSE: API Schema Guard
 * Enforces strict request structure validation for protected API endpoints.
 */

class SchemaValidator {
    constructor() {
        // Commercial implementations would load these from a DB or YAML
        this.protectedRoutes = {
            '/api/login': {
                method: 'POST',
                requiredFields: ['username', 'password'],
                types: { username: 'string', password: 'string' }
            },
            '/api/update-profile': {
                method: 'POST',
                requiredFields: ['id', 'email'],
                types: { id: 'number', email: 'string' }
            }
        };
    }

    validate(req) {
        const route = this.protectedRoutes[req.path];
        if (!route) return { valid: true }; // Not a strictly guarded route

        if (req.method !== route.method) {
            return { valid: false, reason: `Invalid HTTP Method. Expected ${route.method}` };
        }

        const body = req.body || {};

        // 1. Check for missing fields
        for (const field of route.requiredFields) {
            if (!(field in body)) {
                return { valid: false, reason: `Missing required field: ${field}` };
            }
        }

        // 2. Type validation (Basic Schema Enforcement)
        for (const [field, type] of Object.entries(route.types)) {
            if (typeof body[field] !== type) {
                return { valid: false, reason: `Type Mismatch for ${field}. Expected ${type}, got ${typeof body[field]}` };
            }
        }

        // 3. Size Inspection (Commercial standard)
        if (JSON.stringify(body).length > 2000) {
            return { valid: false, reason: 'Payload exceeds allowed scale' };
        }

        return { valid: true };
    }
}

module.exports = new SchemaValidator();

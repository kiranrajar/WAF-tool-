/**
 * SYNAPSE: Neural Detection Engine (v3.1)
 * Supports Model Versioning and Adaptive Weighting
 */

const fs = require('fs');
const path = require('path');

class AIEngine {
    constructor(version = 'v1.0') {
        this.version = version;
        this.modelPath = path.join(__dirname, `../models/${version}/weights.json`);
        this.weights = this.loadModel(version);
    }

    loadModel(version) {
        const defaultWeights = {
            v1: { specDensityWeight: 2.5, entropyWeight: 0.8 },
            v2: { specDensityWeight: 3.1, entropyWeight: 1.1 }
        };

        // Attempt specialized model loading from trained assets
        try {
            const customPath = path.join(__dirname, `../models/${version}/weights.json`);
            if (fs.existsSync(customPath)) {
                console.log(`🧠 [AI Engine] Loading Optimized Model: ${version}`);
                const data = JSON.parse(fs.readFileSync(customPath, 'utf8'));
                return data;
            }
        } catch (e) {
            console.warn(`⚠️ [AI Engine] Custom model ${version} load failed, using fallback.`);
        }

        const vKey = (typeof version === 'string' && version.startsWith('v1')) ? 'v1' : 'v2';
        return defaultWeights[vKey] || defaultWeights.v2;
    }

    calculateEntropy(text) {
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

    analyze(req) {
        const payload = req.url + JSON.stringify(req.body || "") + JSON.stringify(req.query || "");
        let decoded = payload;
        try {
            decoded = decodeURIComponent(payload);
        } catch (e) {
            decoded = payload.replace(/%/g, '%25');
        }

        // Feature Extraction (The "Input Layer")
        const length = decoded.length;
        const specCount = (decoded.match(/[',<>"();[\]{}!@#$%^&*+-=/\\|_]/g) || []).length;
        const specDensity = length > 0 ? specCount / length : 0;
        const entropy = this.calculateEntropy(decoded);

        // Weighted Inference (The "Hidden Layer" Simulation)
        let score = (specDensity * this.weights.specDensityWeight) +
            (entropy * this.weights.entropyWeight);

        // Normalize Score (0 to 1)
        score = Math.tanh(score / 5); // Using Tanh for smooth squashing

        return {
            threatLevel: score,
            modelVersion: this.version,
            features: { length, specDensity, entropy }
        };
    }
}

module.exports = AIEngine;

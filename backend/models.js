const mongoose = require('mongoose');

const logSchema = new mongoose.Schema({
    time: String,
    timestamp: { type: Number, default: Date.now },
    ip: String,
    country: String,
    url: String,
    method: String,
    userAgent: String,
    risk: Number,
    status: String,
    type: String,
    responseTime: Number,
    isBot: Boolean,
    payload: String
});

const blacklistSchema = new mongoose.Schema({
    ip: { type: String, unique: true },
    reason: String,
    added: { type: Date, default: Date.now }
});

const reputationSchema = new mongoose.Schema({
    ip: { type: String, unique: true },
    score: { type: Number, default: 0 },
    attacks: { type: Number, default: 0 },
    lastUpdate: { type: Number, default: Date.now }
});

const configSchema = new mongoose.Schema({
    id: { type: String, default: 'global' },
    targetUrl: String,
    rateLimit: Number,
    riskThreshold: Number,
    blockedCountries: [String],
    protectionMode: String,
    modules: {
        sqli: Boolean,
        xss: Boolean,
        pathTraversal: Boolean,
        rce: Boolean,
        bot: Boolean
    }
});

module.exports = {
    Log: mongoose.model('Log', logSchema),
    Blacklist: mongoose.model('Blacklist', blacklistSchema),
    Reputation: mongoose.model('Reputation', reputationSchema),
    Config: mongoose.model('Config', configSchema)
};

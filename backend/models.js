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
    isBot: Boolean
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

module.exports = {
    Log: mongoose.model('Log', logSchema),
    Blacklist: mongoose.model('Blacklist', blacklistSchema),
    Reputation: mongoose.model('Reputation', reputationSchema)
};

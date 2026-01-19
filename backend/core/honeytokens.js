/**
 * SYNAPSE: Advanced Honeytoken Engine
 * Implements digital deception traps to catch automated bots and scrapers.
 */

class HoneytokenEngine {
    constructor() {
        this.traps = [
            '/admin_login',
            '/wp-login.php',
            '/.env',
            '/config.php',
            '/backup.sql',
            '/phpmyadmin',
            '/.git/config'
        ];
    }

    /**
     * Checks if a request path is a designated honeytoken trap.
     */
    isTrap(path) {
        return this.traps.some(trap => path.toLowerCase().includes(trap));
    }

    /**
     * Injects hidden honeytokens into HTML responses.
     * This is an advanced "Deception" layer.
     */
    injectHoney(html) {
        if (typeof html !== 'string') return html;

        const traps = [
            '<a href="/admin_login" style="display:none" aria-hidden="true">Management Portal</a>',
            '<!-- Security Trace: /backup.sql -->',
            '<link rel="prefetch" href="/.env" />'
        ];

        // Inject before the closing body tag
        return html.replace('</body>', `${traps.join('\n')}\n</body>`);
    }
}

module.exports = new HoneytokenEngine();

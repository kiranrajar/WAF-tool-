const axios = require('axios');
const { spawn } = require('child_process');
const path = require('path');

async function runTests() {
    console.log('🚀 Starting WAF Test Suite...');

    // Start the WAF server
    const server = spawn('node', ['waf-enhanced.js'], {
        cwd: __dirname,
        env: { ...process.env, PORT: 3005, TARGET_URL: 'http://example.com' }
    });

    server.stdout.on('data', (data) => {
        console.log(`[Server] ${data}`);
    });

    server.stderr.on('data', (data) => {
        console.error(`[Server Error] ${data}`);
    });

    // Wait for server to start
    await new Promise(r => setTimeout(r, 2000));

    const baseUrl = 'http://localhost:3005';

    const testCases = [
        { name: 'Normal Request', url: '/', expected: 200 },
        { name: 'SQL Injection', url: '/?id=1%20OR%201=1', expected: 403 },
        { name: 'XSS', url: '/?q=%3Cscript%3Ealert(1)%3C/script%3E', expected: 403 },
        { name: 'Path Traversal', url: '/../../etc/passwd', expected: 403 },
        { name: 'Malformed URI', url: '/%G1', expected: 403 },
        { name: 'Health Check', url: '/health', expected: 200 }
    ];

    let passed = 0;
    for (const tc of testCases) {
        try {
            console.log(`\n🧪 Testing: ${tc.name} (${tc.url})`);
            const res = await axios.get(baseUrl + tc.url, { validateStatus: false });
            if (res.status === tc.expected) {
                console.log(`✅ Passed (Status: ${res.status})`);
                passed++;
            } else {
                console.error(`❌ Failed (Expected: ${tc.expected}, Got: ${res.status})`);
                console.error(`[Detail] Response Body snippet: ${res.data.toString().substring(0, 200)}`);
            }
        } catch (err) {
            console.error(`❌ Error testing ${tc.name}:`, err.message);
        }
    }

    console.log(`\n📊 Results: ${passed}/${testCases.length} tests passed.`);

    // Cleanup
    server.kill();
    process.exit(passed === testCases.length ? 0 : 1);
}

runTests();

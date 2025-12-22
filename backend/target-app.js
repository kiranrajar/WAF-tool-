const express = require('express');
const bodyParser = require('body-parser');

const app = express();
const PORT = 5000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// A vulnerable database simulation
const USERS = [
    { id: 1, username: 'admin', password: 'password123', secret: 'FLAG{WAF_BYPASS_SUCCESS}' },
    { id: 2, username: 'user', password: 'user123', secret: 'Nice try!' }
];

app.get('/', (req, res) => {
    res.send(`
        <html>
        <head>
            <title>Target Application - Vulnerable App</title>
            <style>
                body { font-family: sans-serif; padding: 50px; background: #f0f2f5; }
                .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); max-width: 400px; margin: auto; }
                h1 { color: #1a73e8; }
                input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 4px; }
                button { background: #1a73e8; color: white; border: none; padding: 10px; width: 100%; border-radius: 4px; cursor: pointer; }
            </style>
        </head>
        <body>
            <div class="card">
                <h1>Target Login</h1>
                <p>Wait... is this app protected by AEGIS?</p>
                <form action="/login" method="POST">
                    <input type="text" name="username" placeholder="Username">
                    <input type="password" name="password" placeholder="Password">
                    <button type="submit">Login</button>
                </form>
                <div style="margin-top: 20px;">
                    <h3>Search Products</h3>
                    <form action="/search" method="GET">
                        <input type="text" name="q" placeholder="Search...">
                        <button type="submit">Search</button>
                    </form>
                </div>
            </div>
        </body>
        </html>
    `);
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    // VULNERABILITY: This is just a simulation but let's make it look real
    const user = USERS.find(u => u.username === username && u.password === password);
    if (user) {
        res.send(`<h1>Welcome ${user.username}</h1><p>Your secret: ${user.secret}</p>`);
    } else {
        res.send('<h1>Login Failed</h1>');
    }
});

app.get('/search', (req, res) => {
    const query = req.query.q;
    // VULNERABILITY: XSS
    res.send(`<h1>Search Results</h1><p>You searched for: ${query}</p>`);
});

app.listen(PORT, () => {
    console.log(`🎯 Target Application running on http://localhost:${PORT}`);
    console.log(`🛡️  Protected by AEGIS Shield when accessed through Port 3000`);
});

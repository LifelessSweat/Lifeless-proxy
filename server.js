const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Configurations via Environment Variables (Set these securely in Render)
const PROXY_PASSWORD = process.env.PROXY_PASSWORD || "MySuperSecretPassword123";
// Provide a comma-separated list of IPs to block (e.g., "192.168.1.1,203.0.113.5")
const BANNED_IPS = (process.env.BANNED_IPS || "").split(',').map(ip => ip.trim());

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// 1. IP Blocker Middleware
app.use((req, res, next) => {
    // Extract client IP, accounting for Render's reverse proxy headers
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    
    if (BANNED_IPS.includes(clientIp)) {
        console.log(`[SECURITY] Blocked request from banned IP: ${clientIp}`);
        return res.status(403).send('Access Denied: Your IP address is restricted.');
    }
    next();
});

// Simple In-Memory Session Object (For demonstration; resets on server restart)
let authenticatedSessions = new Set();

// 2. Simple Gateway HTML UI
app.get('/', (req, res) => {
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Private Proxy Gateway</title>
            <style>
                body { font-family: Arial, sans-serif; background: #121212; color: #fff; text-align: center; padding-top: 50px; }
                input, button { padding: 10px; font-size: 16px; margin: 10px; border-radius: 4px; border: none; }
                input[type="text"] { width: 300px; }
                button { background: #007bff; color: white; cursor: pointer; }
                .info { color: #888; font-size: 12px; }
            </style>
        </head>
        <body>
            <h2>Private Access Proxy</h2>
            <p class="info">Your IP: ${clientIp}</p>
            <form action="/login" method="POST">
                <input type="password" name="password" placeholder="Enter Access Password" required><br>
                <button type="submit">Authenticate</button>
            </form>
        </body>
        </html>
    `);
});

// 3. Login Authentication Route
app.post('/login', (req, res) => {
    const { password } = req.body;
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    if (password === PROXY_PASSWORD) {
        authenticatedSessions.add(clientIp);
        return res.send(`
            <html>
            <body style="background:#121212; color:#fff; font-family:Arial; text-align:center; padding-top:50px;">
                <h3>Authenticated Successfully!</h3>
                <p>To browse a site, use the URL format: <code>/proxy/https/example.com</code></p>
                <input type="text" id="targetUrl" placeholder="example.com" style="padding:10px; width:250px;">
                <button onclick="go()" style="padding:10px; background:#28a745; color:white; border:none; cursor:pointer;">Go</button>
                <script>
                    function go() {
                        let url = document.getElementById('targetUrl').value.replace(/^(https?:\\/\\/)?/, '');
                        window.location.href = '/proxy/https/' + url;
                    }
                </script>
            </body>
            </html>
        `);
    } else {
        res.status(401).send('Incorrect Password.');
    }
});

// 4. Secure Dynamic Proxy Engine Route
app.use('/proxy/:protocol/:domain(*)', (req, res, next) => {
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    // Check if the user has authenticated their IP session
    if (!authenticatedSessions.has(clientIp)) {
        return res.status(403).send('Unauthorized: Please authenticate at the home directory first.');
    }

    const { protocol, domain } = req.params;
    const targetTarget = `${protocol}://${domain}`;

    // Create dynamic runtime proxy handler
    const dynamicProxy = createProxyMiddleware({
        target: targetTarget,
        changeOrigin: true,
        followRedirects: true,
        pathRewrite: (path, req) => {
            // Strips the internal proxy naming path out before querying the actual site
            return path.replace(`/proxy/${protocol}/${domain}`, '');
        },
        onError: (err, req, res) => {
            res.status(500).send('Proxy error encountered mapping target resource.');
        }
    });

    dynamicProxy(req, res, next);
});

app.listen(PORT, () => {
    console.log(`Secure Proxy running on port ${PORT}`);
});

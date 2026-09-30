const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const BANNED_IPS = new Set((process.env.BANNED_IPS || "").split(',').map(ip => ip.trim()));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Token Management Mechanics
function generateToken(ip) {
    const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: ip, exp: Math.floor(Date.now() / 1000) + (3600 * 3) })).toString('base64url');
    const signature = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${payload}`).digest('base64url');
    return `${header}.${payload}.${signature}`;
}

function verifyToken(token, expectedIp) {
    if (!token) return false;
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    const [header, payload, signature] = parts;
    const expectedSignature = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${payload}`).digest('base64url');
    if (signature !== expectedSignature) return false;
    try {
        const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString());
        return decoded.exp > Math.floor(Date.now() / 1000) && decoded.sub === expectedIp;
    } catch { return false; }
}

// Firewall Core
app.use((req, res, next) => {
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
    if (BANNED_IPS.has(clientIp)) {
        return res.status(403).send('ERR_CONNECTION_REFUSED');
    }
    next();
});

// Serve the Innocent Decoy Frontend App
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Inside Dashboard Interface Route (Triggered from Blank Box Click Action)
app.get('/initialize-vault-session', (req, res) => {
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
    const secureToken = generateToken(clientIp);
    
    res.cookie('__Secure-Tunnel-Auth', secureToken, { httpOnly: true, secure: true, sameSite: 'strict' });
    
    res.send(`
        <html>
        <head>
            <title>Internal Console</title>
            <style>
                body { background:#0d1117; color:#58a6ff; font-family:monospace; text-align:center; padding-top:100px; }
                input, button { background:#161b22; color:#c9d1d9; border:1px solid #30363d; padding:12px; font-size:16px; margin:10px; border-radius:6px; }
                button { cursor:pointer; color:#58a6ff; font-weight:bold; }
            </style>
        </head>
        <body>
            <h3>Pipeline Console Established Successfully</h3>
            <p>Input target external network domain destination below to construct reverse map mapping layer.</p>
            <input type="text" id="target" placeholder="example.com" style="width:300px;">
            <button onclick="launch()">Map Pipeline</button>
            <script>
                function launch() {
                    let d = document.getElementById('target').value.replace(/^(https?:\\/\\/)?/, '');
                    window.location.href = '/pipeline/https/' + d;
                }
                // Backup panic hotkey inside proxy environment mapping canvas
                document.addEventListener('keydown', (e) => {
                    if(e.key.toLowerCase() === 'c' && e.ctrlKey) { window.location.href = "https://google.com"; }
                });
            </script>
        </body>
        </html>
    `);
});

// Dynamic Core Pipeline Proxy Engine Route
app.use('/pipeline/:protocol/:domain(*)', (req, res, next) => {
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
    const cookies = req.headers.cookie ? Object.fromEntries(req.headers.cookie.split('; ').map(c => c.split('='))) : {};
    const token = cookies['__Secure-Tunnel-Auth'];

    if (!verifyToken(token, clientIp)) {
        return res.status(403).send('Authentication missing or invalid token signature mapping credentials.');
    }

    const { protocol, domain } = req.params;
    
    createProxyMiddleware({
        target: `${protocol}://${domain}`,
        changeOrigin: true,
        followRedirects: true,
        pathRewrite: (path) => path.replace(`/pipeline/${protocol}/${domain}`, ''),
        on: {
            proxyReq: (pReq) => {
                pReq.removeHeader('x-forwarded-for');
                pReq.removeHeader('via');
                pReq.setHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36');
            },
            proxyRes: (pRes) => {
                if (pRes.headers['location']) {
                    let loc = pRes.headers['location'];
                    const match = loc.match(/^(https?):\/\/(.*)/);
                    if (match) pRes.headers['location'] = `/pipeline/${match[1]}/${match[2]}`;
                }
            }
        },
        onError: (err, req, res) => res.status(502).send('Host connection timeout error payload mapping index.')
    })(req, res, next);
});

app.listen(PORT, () => console.log(`Stealth active on port ${PORT}`));

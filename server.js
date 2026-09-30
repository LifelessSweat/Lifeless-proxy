const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
// Change this "Seed" on Render to whatever you want. This forms the base of your moving password.
const MASTER_SEED = process.env.MASTER_SEED || "LifelessSystemDefaultSeed123!"; 

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// 1. Math Module: Computes the 24-Hour Active Password based on date tracking
function getDailyPassword() {
    const today = new Date().toISOString().split('T')[0]; // Format: YYYY-MM-DD
    const hash = crypto.createHash('sha256')
        .update(MASTER_SEED + today)
        .digest('hex');
    
    // Returns a distinct, easy-to-read 8 character key that shifts every single day
    return "LP-" + hash.substring(0, 8).toUpperCase();
}

// Print the active token to server backend console on startup for verification
console.log(`[SYSTEM INITIALIZATION] Today's active key is: ${getDailyPassword()}`);

// Token Session Engine
function generateToken(ip) {
    const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: ip, exp: Math.floor(Date.now() / 1000) + 14400 })).toString('base64url');
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

// Serve the Lunar Front-End Layout
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Authentication Endpoint Processing
app.post('/login', (req, res) => {
    const { password } = req.body;
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
    const currentTargetKey = getDailyPassword();

    if (password === currentTargetKey) {
        const secureToken = generateToken(clientIp);
        res.cookie('__Lifeless-Tunnel-Auth', secureToken, { httpOnly: true, secure: true, sameSite: 'strict' });
        
        // Return browser panel dashboard matching Lunar v2 Crimson Theme
        return res.send(`
            <html>
            <head>
                <title>Lifeless Console</title>
                <style>
                    body { background:#0a0a0c; color:#ff3333; font-family:monospace; text-align:center; padding-top:100px; margin:0; }
                    .wrapper { background:#121216; border:1px solid #990000; padding:40px; display:inline-block; border-radius:12px; box-shadow:0 0 20px rgba(255,51,51,0.1); }
                    input, button { background:#1a1a22; color:#f5f5f7; border:1px solid #2e2e38; padding:14px; font-size:16px; margin:10px; border-radius:6px; }
                    input:focus { outline:none; border-color:#ff3333; }
                    button { cursor:pointer; color:#ff3333; font-weight:bold; border-color:#990000; text-transform:uppercase; }
                    button:hover { background:#ff3333; color:white; }
                </style>
            </head>
            <body>
                <div class="wrapper">
                    <h3>[ PI-LINE TERMINAL READY ]</h3>
                    <p style="color:#8a8a93; font-size:12px;">Proxy session active. Target destination maps inside custom frame logic.</p>
                    <input type="text" id="target" placeholder="destinationurl.com" style="width:320px;" autocomplete="off">
                    <button onclick="launch()">Tunnel</button>
                </div>
                <script>
                    function launch() {
                        let d = document.getElementById('target').value.replace(/^(https?:\\/\\/)?/, '');
                        window.location.href = '/pipeline/https/' + d;
                    }
                    document.addEventListener('keydown', (e) => {
                        if(e.key.toLowerCase() === 'c' && e.altKey) { window.location.href = "https://google.com"; }
                    });
                </script>
            </body>
            </html>
        `);
    } else {
        res.status(401).send(`
            <body style="background:#0a0a0c; color:#ff3333; font-family:monospace; text-align:center; padding-top:100px;">
                <h3>ACCESS DENIED: KEY SIGNATURE INVALID</h3>
                <p style="color:#8a8a93;"><a href="/" style="color:#ff3333;">Return to Gateway</a></p>
            </body>
        `);
    }
});

// Dynamic Core Pipeline Proxy Engine Route
app.use('/pipeline/:protocol/:domain(*)', (req, res, next) => {
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
    const cookies = req.headers.cookie ? Object.fromEntries(req.headers.cookie.split('; ').map(c => c.split('='))) : {};
    const token = cookies['__Lifeless-Tunnel-Auth'];

    if (!verifyToken(token, clientIp)) {
        return res.status(403).send('Pipeline access verification failed: Invalid signature authentication lifecycle.');
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
                    if (match) pRes.headers['location'] = `/pipeline/${match}/${match}`;
                }
            }
        },
        onError: (err, req, res) => res.status(502).send('Remote core mapping pipe dropped runtime sync stream.')
    })(req, res, next);
});

app.listen(PORT, () => console.log(`Lifeless Engine routing active on container port ${PORT}`));

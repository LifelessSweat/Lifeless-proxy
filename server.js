const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Security Keys Configuration
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
// Change this "MASTER_SEED" in your Render Environment Variables to customize your daily passwords
const MASTER_SEED = process.env.MASTER_SEED || "LifelessSystemDefaultSeed123!"; 
const BANNED_IPS = new Set((process.env.BANNED_IPS || "").split(',').map(ip => ip.trim()));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// 1. Core Password Rotation Module (Generates a new token daily at midnight UTC)
function getDailyPassword() {
    const today = new Date().toISOString().split('T')[0]; // Format: YYYY-MM-DD
    const hash = crypto.createHash('sha256')
        .update(MASTER_SEED + today)
        .digest('hex');
    
    // Returns a unique 8-character key prefixed with LP- (e.g., LP-A3B8D9F2)
    return "LP-" + hash.substring(0, 8).toUpperCase();
}

// Print the active token to your Render backend logs on startup
console.log(`[SYSTEM INITIALIZATION] Today's active key is: ${getDailyPassword()}`);

// 2. Cryptographic JWT Session Handlers
function generateToken(ip) {
    const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: ip, exp: Math.floor(Date.now() / 1000) + 14400 })).toString('base64url'); // Valid for 4 Hours
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

// 3. Hardware IP Firewall Filter
app.use((req, res, next) => {
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
    if (BANNED_IPS.has(clientIp)) {
        return res.status(403).send('ERR_CONNECTION_REFUSED');
    }
    next();
});

// 4. Serve the Main Entrance Panel (index.html)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// 5. Authentication Processing & Dashboard Delivery (URL Locking Interface)
app.post('/login', (req, res) => {
    const { password } = req.body;
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
    const currentTargetKey = getDailyPassword();

    if (password === currentTargetKey) {
        const secureToken = generateToken(clientIp);
        res.cookie('__Lifeless-Tunnel-Auth', secureToken, { httpOnly: true, secure: true, sameSite: 'strict' });
        
        // Return the dashboard containing the URL-Locking Viewport Engine
        return res.send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Lifeless Console // Active</title>
                <style>
                    body, html { margin: 0; padding: 0; width: 100%; height: 100%; overflow: hidden; background: #0a0a0c; font-family: monospace; }
                    
                    /* Top Navigation Control Strip (Lunar v2 Aesthetic) */
                    .omnibar { 
                        display: flex; align-items: center; background: #121216; 
                        border-bottom: 1px solid #990000; padding: 10px 20px; box-sizing: border-box; 
                        height: 55px; transition: margin-top 0.3s ease;
                    }
                    .brand { color: #ff3333; font-weight: bold; font-size: 14px; margin-right: 20px; letter-spacing: 1px; }
                    input#target { 
                        flex-grow: 1; background: #1a1a22; color: #f5f5f7; 
                        border: 1px solid #2e2e38; padding: 10px 14px; font-size: 14px; 
                        border-radius: 6px; font-family: monospace; 
                    }
                    input#target:focus { outline: none; border-color: #ff3333; }
                    
                    .btn-group { display: flex; gap: 8px; margin-left: 12px; }
                    button { 
                        background: #1a1a22; color: #ff3333; border: 1px solid #990000; 
                        padding: 10px 16px; font-weight: bold; 
                        border-radius: 6px; cursor: pointer; text-transform: uppercase; 
                    }
                    button:hover { background: #ff3333; color: white; }
                    
                    /* Dynamic Main Screen Viewer */
                    .viewport-container { width: 100%; height: calc(100% - 55px); background: #fff; position: relative; }
                    iframe#proxyViewport { width: 100%; height: 100%; border: none; margin: 0; padding: 0; }
                    
                    /* Hidden/Full-Screen adjustments toggle */
                    .fullscreen-active .omnibar { margin-top: -55px; }
                    .fullscreen-active .viewport-container { height: 100%; }
                    
                    #toggleIndicator {
                        position: absolute; top: 10px; right: 20px; background: rgba(18,18,22,0.8);
                        color: #ff3333; border: 1px solid #990000; padding: 5px 10px; font-size: 11px;
                        border-radius: 4px; cursor: pointer; z-index: 9999; display: none;
                    }
                </style>
            </head>
            <body>

                <!-- Top Menu Panel -->
                <div class="omnibar" id="topBar">
                    <div class="brand">LIFELESS//V2</div>
                    <input type="text" id="target" placeholder="Enter target site destination (e.g., wikipedia.org)..." autocomplete="off">
                    <div class="btn-group">
                        <button onclick="tunnelSite()">Tunnel</button>
                        <button onclick="toggleBar(true)" style="border-color:#333;color:#8a8a93;">Hide UI</button>
                    </div>
                </div>

                <!-- Hidden UI Restore Pin -->
                <div id="toggleIndicator" onclick="toggleBar(false)">Show Bar</div>

                <!-- Website Frame Port -->
                <div class="viewport-container" id="viewBox">
                    <iframe id="proxyViewport" src="about:blank"></iframe>
                </div>

                <script>
                    function tunnelSite() {
                        let input = document.getElementById('target').value.trim();
                        if(!input) return;

                        let cleanUrl = input.replace(/^(https?:\\/\\/)?/, '');
                        
                        // Updates the internal viewport reference link directly
                        // This allows you to browse without mutating your top browser URL address bar
                        document.getElementById('proxyViewport').src = '/pipeline/https/' + cleanUrl;
                    }

                    function toggleBar(hide) {
                        if(hide) {
                            document.body.classList.add('fullscreen-active');
                            document.getElementById('toggleIndicator').style.display = 'block';
                        } else {
                            document.body.classList.remove('fullscreen-active');
                            document.getElementById('toggleIndicator').style.display = 'none';
                        }
                    }

                    document.getElementById('target').addEventListener('keypress', function (e) {
                        if (e.key === 'Enter') { tunnelSite(); }
                    });

                    // Anti-Tracking Emergency Panic Key Combo (Press G + C keys simultaneously)
                    let keysPressed = {};
                    document.addEventListener('keydown', (e) => {
                        keysPressed[e.key.toLowerCase()] = true;
                        if (keysPressed['g'] && keysPressed['c']) {
                            window.location.replace("https://google.com");
                        }
                    });
                    document.addEventListener('keyup', (e) => { delete keysPressed[e.key.toLowerCase()]; });
                </script>
            </body>
            </html>
        `);
    } else {
        res.status(401).send(`
            <body style="background:#0a0a0c; color:#ff3333; font-family:monospace; text-align:center; padding-top:100px;">
                <h3>ACCESS DENIED: DYNAMIC SECURITY TOKEN INVALID</h3>
                <p style="color:#8a8a93;"><a href="/" style="color:#ff3333;">Return to Gateway Entrance</a></p>
            </body>
        `);
    }
});

// 6. Dynamic Reverse-Proxy Pipeline Distribution Engine
app.use('/pipeline/:protocol/:domain(*)', (req, res, next) => {
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
    const cookies = req.headers.cookie ? Object.fromEntries(req.headers.cookie.split('; ').map(c => c.split('='))) : {};
    const token = cookies['__Lifeless-Tunnel-Auth'];

    if (!verifyToken(token, clientIp)) {
        return res.status(403).send('Pipeline link distribution rejected: Invalid authorization signature cycle.');
    }

    const { protocol, domain } = req.params;
createProxyMiddleware({
target: ${protocol}://${domain},
changeOrigin: true,
followRedirects: true,
pathRewrite: (path) => path.replace(/pipeline/${protocol}/${domain}, ''),
on: {
proxyReq: (pReq) => {
// Wipe identifiable networking logs from upstream web hosts
pReq.removeHeader('x-forwarded-for');
pReq.removeHeader('via');
pReq.setHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36');
},
proxyRes: (pRes) => {
// Intercept server redirections and latch them within our internal proxy pipeline format
if (pRes.headers['location']) {
let loc = pRes.headers['location'];
const match = loc.match(/^(https?)://(.*)/);
if (match) pRes.headers['location'] = /pipeline/${match[1]}/${match[2]};
}
}
},
onError: (err, req, res) => res.status(502).send('Gateway Error: Remote data pipeline sync interface dropped out.')
})(req, res, next);
});
app.listen(PORT, () => console.log(Lifeless Proxy Kernel Engine listening securely on port ${PORT}));

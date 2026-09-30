// 6. Upgraded Dynamic Reverse-Proxy Pipeline with Header Stripping & WebSockets
const proxyServer = app.use('/pipeline/:protocol/:domain(*)', (req, res, next) => {
    const clientIp = req.headers['x-forwarded-for']?.split(',').trim() || req.socket.remoteAddress;
    const cookies = req.headers.cookie ? Object.fromEntries(req.headers.cookie.split('; ').map(c => c.split('='))) : {};
    const token = cookies['__Lifeless-Tunnel-Auth'];

    if (!verifyToken(token, clientIp)) {
        return res.status(403).send('Pipeline link distribution rejected: Invalid authorization signature cycle.');
    }

    const { protocol, domain } = req.params;
    
    createProxyMiddleware({
        target: `${protocol}://${domain}`,
        changeOrigin: true,
        followRedirects: true,
        ws: true, // <--- ENABLE WEBSOCKETS: Allows persistent data streams
        pathRewrite: (path) => path.replace(`/pipeline/${protocol}/${domain}`, ''),
        on: {
            proxyReq: (pReq) => {
                // Wipe identifiable tracking logs
                pReq.removeHeader('x-forwarded-for');
                pReq.removeHeader('via');
                pReq.setHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36');
            },
            proxyRes: (pRes) => {
                // <--- LUNAR STRATEGY: Delete anti-iframe blocks right before they hit your browser
                delete pRes.headers['x-frame-options'];
                delete pRes.headers['content-security-policy'];
                delete pRes.headers['content-security-policy-report-only'];

                // Intercept server redirections
                if (pRes.headers['location']) {
                    let loc = pRes.headers['location'];
                    const match = loc.match(/^(https?):\/\/(.*)/);
                    if (match) pRes.headers['location'] = `/pipeline/${match}/${match}`;
                }
            }
        },
        onError: (err, req, res) => res.status(502).send('Gateway Error: Remote data pipeline sync interface dropped out.')
    })(req, res, next);
});

// Bind the Express server to variable so we can handle raw WebSocket connections natively
const server = app.listen(PORT, () => console.log(`Lifeless Proxy Kernel Engine listening securely on port ${PORT}`));

// Intercept top-level protocol upgrade requests (e.g. Chat/Sync tools)
server.on('upgrade', (req, socket, head) => {
    console.log('[WEBSOCKET CONNECTION] Upstream protocol upgrade requested.');
});

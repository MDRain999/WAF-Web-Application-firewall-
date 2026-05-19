// ==========================================
// NEXUS ENTERPRISE WAF - Complete Backend
// ==========================================
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// ==========================================
// STATE
// ==========================================
const state = {
    total: 2459802,
    blocked: 142095,
    bw: 84.2,
    latency: 1.2
};

let burpProxyActive = false;
let burpLogs = ['> Proxy Offline', '> Click Start Proxy to begin...'];

const eventRules = [
    { name: 'SQLi - Union Select', act: 'Blocked', badge: 'badge-red' },
    { name: 'XSS - Script Tag', act: 'Blocked', badge: 'badge-red' },
    { name: 'Rate Limit (Ncell Gateway)', act: 'Throttled', badge: 'badge-blue' },
    { name: 'Bad Bot (Scraper)', act: 'Blocked', badge: 'badge-red' }
];

let nextRuleId = 5;
let wafRulesets = [
    { id:1, enabled:true, name:'OWASP Top 10 Core Rules', description:'Protects against SQLi, XSS, LFI, RFI, and other common vulnerabilities.', action:'Block', count:482, category:'owasp', isCustom:false },
    { id:2, enabled:true, name:'Bad Bot Protection', description:'Blocks known malicious user agents, scrapers, and automated scanning tools.', action:'Challenge (Captcha)', count:1024, category:'bots', isCustom:false },
    { id:3, enabled:false, name:'Rate Limiting (Strict)', description:'Limits requests to 100 per minute per IP to mitigate DoS and brute forcing.', action:'Block', count:1, category:'owasp', isCustom:false },
    { id:4, enabled:true, name:'Custom: Block Admin Path', description:'Blocks access to /admin/* from non-internal IP ranges.', action:'Block', count:1, category:'custom', isCustom:true }
];

// ==========================================
// WAF RULESETS API
// ==========================================
app.get('/api/rulesets', (req, res) => {
    let filtered = [...wafRulesets];
    const { category, q } = req.query;
    if (category && category !== 'all') filtered = filtered.filter(r => r.category === category);
    if (q) filtered = filtered.filter(r => r.name.toLowerCase().includes(q.toLowerCase()) || r.description.toLowerCase().includes(q.toLowerCase()));
    res.json(filtered);
});

app.patch('/api/rulesets/:id/toggle', (req, res) => {
    const rule = wafRulesets.find(r => r.id === parseInt(req.params.id));
    if (!rule) return res.status(404).json({ error: 'Rule not found' });
    rule.enabled = !rule.enabled;
    res.json(rule);
});

app.patch('/api/rulesets/:id', (req, res) => {
    const rule = wafRulesets.find(r => r.id === parseInt(req.params.id));
    if (!rule) return res.status(404).json({ error: 'Rule not found' });
    if (req.body.action) rule.action = req.body.action;
    res.json(rule);
});

app.post('/api/rulesets', (req, res) => {
    const { name, description } = req.body;
    if (!name) return res.status(400).json({ error: 'Name is required' });
    const newRule = { id: nextRuleId++, enabled: true, name: `Custom: ${name}`, description: description || 'Custom rule created by admin.', action: 'Block', count: 1, category: 'custom', isCustom: true };
    wafRulesets.push(newRule);
    res.status(201).json(newRule);
});

app.delete('/api/rulesets/:id', (req, res) => {
    const rule = wafRulesets.find(r => r.id === parseInt(req.params.id));
    if (!rule) return res.status(404).json({ error: 'Rule not found' });
    if (!rule.isCustom) return res.status(403).json({ error: 'Cannot delete managed rulesets' });
    wafRulesets = wafRulesets.filter(r => r.id !== rule.id);
    res.json({ deleted: true, id: rule.id });
});

// ==========================================
// BURP SUITE API
// ==========================================
app.post('/api/burp/start', (req, res) => {
    burpProxyActive = true;
    burpLogs = ['> Listening on 127.0.0.1:8080', '> Waiting for incoming traffic...', `[${new Date().toLocaleTimeString()}] > Intercept is ON`];
    res.json({ status: 'active', message: 'Proxy started' });
});

app.post('/api/burp/stop', (req, res) => {
    burpProxyActive = false;
    burpLogs.push(`[${new Date().toLocaleTimeString()}] > Intercept is OFF`);
    res.json({ status: 'inactive', message: 'Proxy stopped' });
});

app.get('/api/burp/logs', (req, res) => {
    if (burpProxyActive && Math.random() > 0.3) {
        const methods = ['GET', 'POST', 'OPTIONS', 'PUT'];
        const method = methods[Math.floor(Math.random() * methods.length)];
        const paths = ['/login', '/api/v1/users', '/admin/dashboard', '/search?q=test', '/api/session'];
        const p = paths[Math.floor(Math.random() * paths.length)];
        burpLogs.push(`[${new Date().toLocaleTimeString()}] Intercepted ${method} ${p}`);
        if (burpLogs.length > 15) burpLogs.shift();
    }
    res.json({ logs: burpLogs, isActive: burpProxyActive });
});

// ==========================================
// SQLMAP API
// ==========================================
app.post('/api/sqlmap/scan', (req, res) => {
    res.json({
        command: 'sqlmap -u "http://target/api?id=1" --random-agent --level 3',
        lines: [
            `[*] starting @ ${new Date().toLocaleTimeString()}`,
            '[+] testing connection to the target URL',
            '[!] WAF/IPS identified: Nexus Enterprise WAF',
            '[*] checking if the target is vulnerable to SQL injection',
            '[*] testing evasion techniques (e.g. BETWEEN, RANDOMCASE)',
            '[-] target URL appears to be NOT injectable (blocked by WAF)'
        ]
    });
});

// ==========================================
// WAFW00F API
// ==========================================
app.post('/api/wafw00f/analyze', (req, res) => {
    res.json({
        command: 'wafw00f https://edge.nexus.local',
        lines: [
            '[+] Checking for WAF presence...',
            '[+] Sending crafted HTTP requests to trigger WAF...',
            '[+] Analyzing server response headers and body...',
            '[+] WAF detected: Nexus Enterprise WAF',
            '[+] Reason: Proprietary block page pattern match (HTTP 403)'
        ]
    });
});

// ==========================================
// PAYLOAD SANDBOX API
// ==========================================
app.post('/api/sandbox/fire', (req, res) => {
    const { payload } = req.body;
    if (!payload || !payload.trim()) return res.status(400).json({ error: 'No payload' });
    const isSQLi = /('|--|union|select|insert|update|delete|drop)/i.test(payload);
    const isXSS = /(<script|javascript:|onerror=|onload=|<img|<svg)/i.test(payload);
    const isLFI = /(\.\.\/|\.\.\\|etc\/passwd|boot\.ini)/i.test(payload);
    if (isSQLi) return res.json({ blocked: true, rule: 'SQL Injection (OWASP CRS 942)', severity: 'critical' });
    if (isXSS) return res.json({ blocked: true, rule: 'Cross-Site Scripting (OWASP CRS 941)', severity: 'high' });
    if (isLFI) return res.json({ blocked: true, rule: 'Local File Inclusion (OWASP CRS 930)', severity: 'critical' });
    return res.json({ blocked: false, rule: null, severity: 'none' });
});

// ==========================================
// RECENT ALERTS API
// ==========================================
app.get('/api/alerts', (req, res) => {
    const now = new Date();
    res.json([
        { severity: 'critical', msg: 'SQLi burst detected from NTC gateway - 48 payloads blocked in 12s', src: 'KTM-DC-01', timestamp: now.toISOString() },
        { severity: 'high', msg: 'Bot traffic spike from Pokhara edge - 1,200 req/min from 3 IPs', src: 'PKR-Edge-02', timestamp: new Date(now - 120000).toISOString() },
        { severity: 'medium', msg: 'Admin path probe from external IP 103.94.x.x - 6 attempts blocked', src: 'KTM-DC-01', timestamp: new Date(now - 480000).toISOString() },
        { severity: 'low', msg: 'LAL-DC-03 load threshold warning - CPU at 78%, scaling recommended', src: 'LAL-DC-03', timestamp: new Date(now - 900000).toISOString() }
    ]);
});

// ==========================================
// THREAT ORIGIN API
// ==========================================
app.get('/api/threat-origin', (req, res) => {
    res.json({
        summary: { uniqueIPs: 1842, countries: 6, autoBlocked: 312 },
        origins: [
            { name: 'China', pct: 34, count: 626 },
            { name: 'Russia', pct: 22, count: 405 },
            { name: 'United States', pct: 16, count: 295 },
            { name: 'India', pct: 12, count: 221 },
            { name: 'Brazil', pct: 9, count: 166 },
            { name: 'Others', pct: 7, count: 129 }
        ]
    });
});

// ==========================================
// GENERATE REPORT API
// ==========================================
app.get('/api/report', (req, res) => {
    res.json({
        generatedAt: new Date().toISOString(),
        summary: { totalRequests: state.total.toLocaleString(), threatsBlocked: state.blocked.toLocaleString(), bandwidth: `${state.bw.toFixed(1)} GB`, avgLatency: `${state.latency.toFixed(1)} ms` },
        topThreats: [
            { type: 'SQL Injection', count: Math.floor(state.blocked * 0.45), percentage: '45%' },
            { type: 'Cross-Site Scripting', count: Math.floor(state.blocked * 0.25), percentage: '25%' },
            { type: 'Path Traversal', count: Math.floor(state.blocked * 0.15), percentage: '15%' },
            { type: 'Rate Limit Exceeded', count: Math.floor(state.blocked * 0.10), percentage: '10%' },
            { type: 'Bad Bot', count: Math.floor(state.blocked * 0.05), percentage: '5%' }
        ],
        activeRules: wafRulesets.filter(r => r.enabled).length,
        totalRules: wafRulesets.length,
        status: 'Operational'
    });
});

// ==========================================
// REAL-TIME (Socket.io)
// ==========================================
function generateEvent() {
    const rule = eventRules[Math.floor(Math.random() * eventRules.length)];
    const ip = `${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`;
    const dts = ['KTM-DC-01', 'PKR-Edge-02', 'LAL-DC-03'];
    const dest = dts[Math.floor(Math.random() * dts.length)];
    return { time: new Date().toLocaleTimeString([], { hour12: false }), ip, ruleName: rule.name, dest, action: rule.act, badge: rule.badge };
}

io.on('connection', (socket) => {
    console.log(`[Socket.io] Client connected: ${socket.id}`);
    socket.emit('metrics-update', state);
    const initial = []; for (let i = 0; i < 6; i++) initial.push(generateEvent());
    socket.emit('initial-events', initial);
    socket.on('disconnect', () => console.log(`[Socket.io] Disconnected: ${socket.id}`));
});

setInterval(() => {
    state.total += Math.floor(Math.random() * 50);
    state.latency = 1.1 + Math.random() * 0.3;
    if (Math.random() > 0.6) {
        state.blocked += Math.floor(Math.random() * 3 + 1);
        state.bw += 0.01;
        io.emit('new-event', generateEvent());
    }
    io.emit('metrics-update', state);
}, 2000);

// ==========================================
// FALLBACK
// ==========================================
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

const PORT = 3000;
server.listen(PORT, () => {
    console.log(`\n  Nexus Enterprise WAF Backend`);
    console.log(`  Running on http://localhost:${PORT}\n`);
});

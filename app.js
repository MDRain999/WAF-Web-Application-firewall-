// ==========================================
// NEXUS ENTERPRISE WAF - Elite Dashboard Logic
// ==========================================

// --- WAF RULESETS DATA STORE ---
let nextRuleId = 5;
let wafRulesets = [
    { id:1, enabled:true, name:'OWASP Top 10 Core Rules', description:'Protects against SQLi, XSS, LFI, RFI, and other common vulnerabilities.', action:'Block', count:482, category:'owasp', isCustom:false },
    { id:2, enabled:true, name:'Bad Bot Protection', description:'Blocks known malicious user agents, scrapers, and automated scanning tools.', action:'Challenge (Captcha)', count:1024, category:'bots', isCustom:false },
    { id:3, enabled:false, name:'Rate Limiting (Strict)', description:'Limits requests to 100 per minute per IP to mitigate DoS and brute forcing.', action:'Block', count:1, category:'owasp', isCustom:false },
    { id:4, enabled:true, name:'Custom: Block Admin Path', description:'Blocks access to /admin/* from non-internal IP ranges.', action:'Block', count:1, category:'custom', isCustom:true }
];
let activeFilter = 'all';
let searchQuery = '';

function getFilteredRules() {
    return wafRulesets.filter(r => {
        const matchCat = activeFilter === 'all' || r.category === activeFilter;
        const matchSearch = !searchQuery || r.name.toLowerCase().includes(searchQuery) || r.description.toLowerCase().includes(searchQuery);
        return matchCat && matchSearch;
    });
}

function renderRulesTable() {
    const tbody = document.getElementById('rules-table-body');
    if (!tbody) return;
    const filtered = getFilteredRules();
    const actions = ['Block', 'Log Only', 'Challenge (Captcha)'];
    tbody.innerHTML = filtered.map(r => {
        const toggleOn = r.enabled;
        const toggleCls = toggleOn ? 'bg-primary/20 border-primary/50 hover:bg-primary/30' : 'bg-white/5 border-white/10 hover:bg-white/10';
        const dotCls = toggleOn ? 'bg-primary right-0.5' : 'bg-zinc-500 left-0.5';
        const nameCls = toggleOn ? 'text-white' : 'text-zinc-500';
        const descCls = toggleOn ? 'text-zinc-400' : 'text-zinc-600';
        const countCls = toggleOn ? '' : 'text-zinc-600';
        const selDisabled = toggleOn ? '' : 'disabled';
        const selTextCls = toggleOn ? 'text-white focus:border-primary' : 'text-zinc-500';
        const customBadge = r.isCustom ? ' <span class="badge badge-blue">Custom</span>' : '';
        const deleteBtn = r.isCustom ? `<button data-delete-id="${r.id}" class="text-zinc-600 hover:text-red-400 transition p-1" title="Delete"><svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg></button>` : '';
        const opts = actions.map(a => `<option ${a===r.action?'selected':''}>${a}</option>`).join('');
        return `<tr class="table-row group"><td class="px-6 py-4"><div data-toggle-id="${r.id}" class="w-8 h-4 ${toggleCls} rounded-full relative cursor-pointer border transition-colors"><div class="w-3 h-3 ${dotCls} rounded-full absolute top-0.5 shadow"></div></div></td><td class="px-6 py-4 ${nameCls} font-medium flex items-center gap-2">${r.name}${customBadge}</td><td class="px-6 py-4 ${descCls} truncate max-w-xs">${r.description}</td><td class="px-6 py-4"><select data-action-id="${r.id}" class="bg-black/50 border border-white/10 rounded px-2 py-1 text-xs ${selTextCls} focus:outline-none" ${selDisabled}>${opts}</select></td><td class="px-6 py-4 text-right font-mono tabular-nums ${countCls}">${r.count.toLocaleString()}</td><td class="px-6 py-4 text-right">${deleteBtn}</td></tr>`;
    }).join('');
    attachRulesListeners();
}

function attachRulesListeners() {
    document.querySelectorAll('[data-toggle-id]').forEach(el => {
        el.addEventListener('click', () => {
            const id = parseInt(el.dataset.toggleId);
            const rule = wafRulesets.find(r => r.id === id);
            if (rule) { rule.enabled = !rule.enabled; renderRulesTable(); }
        });
    });
    document.querySelectorAll('[data-action-id]').forEach(el => {
        el.addEventListener('change', () => {
            const id = parseInt(el.dataset.actionId);
            const rule = wafRulesets.find(r => r.id === id);
            if (rule) { rule.action = el.value; }
        });
    });
    document.querySelectorAll('[data-delete-id]').forEach(el => {
        el.addEventListener('click', () => {
            const id = parseInt(el.dataset.deleteId);
            const rule = wafRulesets.find(r => r.id === id);
            if (rule && rule.isCustom) { wafRulesets = wafRulesets.filter(r => r.id !== id); renderRulesTable(); }
        });
    });
}

document.addEventListener('DOMContentLoaded', () => {
    // Tab filters
    document.querySelectorAll('.rules-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.rules-tab').forEach(t => { t.classList.remove('text-white','bg-white/10','rounded','shadow-sm'); t.classList.add('text-zinc-500'); });
            tab.classList.remove('text-zinc-500'); tab.classList.add('text-white','bg-white/10','rounded','shadow-sm');
            activeFilter = tab.dataset.cat;
            renderRulesTable();
        });
    });
    // Search
    const searchInput = document.getElementById('rules-search');
    if (searchInput) { searchInput.addEventListener('input', () => { searchQuery = searchInput.value.toLowerCase(); renderRulesTable(); }); }
    // Create custom rule
    const createBtn = document.getElementById('create-rule-btn');
    if (createBtn) {
        createBtn.addEventListener('click', () => {
            const name = prompt('Rule name (e.g. Block /uploads):');
            if (!name) return;
            const desc = prompt('Description:') || 'Custom rule created by admin.';
            wafRulesets.push({ id: nextRuleId++, enabled: true, name: `Custom: ${name}`, description: desc, action: 'Block', count: 1, category: 'custom', isCustom: true });
            renderRulesTable();
        });
    }
    renderRulesTable();
});

const state = {
    total: 2459802,
    blocked: 142095,
    bw: 84.2,
    latency: 1.2
};

const dom = {
    total: document.getElementById('m-total'),
    blocked: document.getElementById('m-blocked'),
    bw: document.getElementById('m-bw'),
    latency: document.getElementById('m-latency'),
    table: document.getElementById('event-table')
};

let sparkData1 = Array.from({length: 12}, () => Math.random() * 10);
let sparkData2 = Array.from({length: 12}, () => Math.random() * 5);
let sparkData3 = Array.from({length: 12}, () => Math.random() * 20);
let sparkCharts = [];
let trafficChartInst = null;
let vectorChartInst = null;

document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    populateVectors();
    populateAlerts();
    populateOrigin();
    seedTable();
    setupNavigation();
    updateDOM();
    setInterval(tickData, 2000);
});

function setupNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    const views = document.querySelectorAll('.view-section');
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = item.getAttribute('data-target');
            navItems.forEach(n => { n.classList.remove('bg-white/10', 'text-white'); n.classList.add('text-zinc-400'); });
            item.classList.remove('text-zinc-400');
            item.classList.add('bg-white/10', 'text-white');
            views.forEach(v => { v.classList.remove('block'); v.classList.add('hidden'); });
            const targetView = document.getElementById(targetId);
            if(targetView) { targetView.classList.remove('hidden'); targetView.classList.add('block'); }
        });
    });
}

function updateDOM() {
    dom.total.innerText = state.total.toLocaleString();
    dom.blocked.innerText = state.blocked.toLocaleString();
    dom.bw.innerHTML = `${state.bw.toFixed(1)} <span class="text-sm font-normal text-zinc-500">GB</span>`;
    dom.latency.innerHTML = `${state.latency.toFixed(1)} <span class="text-sm font-normal text-zinc-500">ms</span>`;
    const rate = ((state.blocked / state.total) * 100).toFixed(2);
    const rateEl = document.getElementById('m-threat-rate');
    if (rateEl) rateEl.textContent = `${rate}% of total traffic`;
    const p99El = document.getElementById('m-p99');
    if (p99El) p99El.textContent = (state.latency * 2 + Math.random() * 0.5).toFixed(1);
}

function initCharts() {
    Chart.defaults.color = '#8F8F8F';
    Chart.defaults.font.family = "'Inter', sans-serif";
    Chart.defaults.plugins.tooltip.backgroundColor = 'rgba(10, 10, 11, 0.9)';
    Chart.defaults.plugins.tooltip.borderColor = 'rgba(255,255,255,0.1)';
    Chart.defaults.plugins.tooltip.borderWidth = 1;
    Chart.defaults.plugins.tooltip.padding = 12;
    Chart.defaults.plugins.tooltip.titleColor = '#EDEDED';
    Chart.defaults.plugins.tooltip.bodyColor = '#a1a1aa';
    Chart.defaults.plugins.tooltip.cornerRadius = 8;
    Chart.defaults.plugins.tooltip.displayColors = false;

    const sparkConfig = (ctxId, data, color) => {
        const ctx = document.getElementById(ctxId).getContext('2d');
        const grad = ctx.createLinearGradient(0, 0, 0, 32);
        grad.addColorStop(0, color.replace('1)', '0.3)'));
        grad.addColorStop(1, color.replace('1)', '0)'));
        return new Chart(ctx, {
            type: 'line',
            data: { labels: Array.from({length: 12}, (_, i) => i), datasets: [{ data: data, borderColor: color, borderWidth: 2, tension: 0.4, pointRadius: 0, fill: true, backgroundColor: grad }] },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false }, tooltip: { enabled: false } }, scales: { x: { display: false }, y: { display: false, min: 0 } }, animation: { duration: 0 } }
        });
    };
    sparkCharts.push(sparkConfig('spark1', sparkData1, 'rgba(74, 222, 128, 1)'));
    sparkCharts.push(sparkConfig('spark2', sparkData2, 'rgba(248, 113, 113, 1)'));
    sparkCharts.push(sparkConfig('spark3', sparkData3, 'rgba(161, 161, 170, 1)'));

    const ctxTraffic = document.getElementById('trafficChart').getContext('2d');
    const gradLegit = ctxTraffic.createLinearGradient(0, 0, 0, 300);
    gradLegit.addColorStop(0, 'rgba(79, 70, 229, 0.3)');
    gradLegit.addColorStop(1, 'rgba(79, 70, 229, 0.0)');
    trafficChartInst = new Chart(ctxTraffic, {
        type: 'line',
        data: { labels: Array.from({length: 24}, (_, i) => `${i.toString().padStart(2, '0')}:00`), datasets: [
            { label: 'Allowed Traffic', data: Array.from({length: 24}, () => Math.floor(Math.random() * 5000 + 3000)), borderColor: '#4F46E5', backgroundColor: gradLegit, borderWidth: 2, tension: 0.4, fill: true, pointRadius: 0, pointHitRadius: 20 },
            { label: 'Blocked Events', data: Array.from({length: 24}, () => Math.floor(Math.random() * 500 + 50)), borderColor: '#ef4444', borderWidth: 2, tension: 0.4, fill: false, pointRadius: 0, pointHitRadius: 20, borderDash: [4, 4] },
            { label: 'Challenged', data: Array.from({length: 24}, () => Math.floor(Math.random() * 200 + 20)), borderColor: '#fb923c', borderWidth: 2, tension: 0.4, fill: false, pointRadius: 0, pointHitRadius: 20, borderDash: [6, 3] }
        ]},
        options: { responsive: true, maintainAspectRatio: false, interaction: { mode: 'index', intersect: false }, plugins: { legend: { display: false } }, scales: { y: { grid: { color: 'rgba(255,255,255,0.05)', drawBorder: false }, border: { dash: [4,4] } }, x: { grid: { display: false }, ticks: { maxTicksLimit: 12 } } } }
    });

    const ctxVector = document.getElementById('vectorChart').getContext('2d');
    vectorChartInst = new Chart(ctxVector, {
        type: 'doughnut',
        data: { labels: ['SQL Injection', 'XSS', 'Path Traversal', 'Rate Limit Exceeded', 'Bad Bot'], datasets: [{ data: [45, 25, 15, 10, 5], backgroundColor: ['#ef4444', '#f59e0b', '#8b5cf6', '#4F46E5', '#3f3f46'], borderWidth: 2, borderColor: '#0A0A0B', hoverOffset: 4 }] },
        options: { responsive: true, maintainAspectRatio: false, cutout: '80%', plugins: { legend: { display: false } } }
    });
}

function populateVectors() {
    const data = [
        { label: 'SQL Injection', val: 45, col: 'bg-red-500' },
        { label: 'Cross-Site Scripting', val: 25, col: 'bg-yellow-500' },
        { label: 'Path Traversal', val: 15, col: 'bg-purple-500' },
        { label: 'Rate Limit Exceeded', val: 10, col: 'bg-primary' },
        { label: 'Bad Bot', val: 5, col: 'bg-zinc-600' },
    ];
    const container = document.getElementById('vector-legend');
    container.innerHTML = data.map(item => `<div class="flex items-center gap-3 text-xs"><span class="w-2 h-2 rounded-full ${item.col} flex-shrink-0"></span><span class="text-zinc-400 w-32 truncate">${item.label}</span><div class="flex-1 bg-white/5 h-1.5 rounded-full overflow-hidden"><div class="${item.col} h-full rounded-full" style="width:${item.val}%"></div></div><span class="font-mono text-white w-8 text-right">${item.val}%</span></div>`).join('');
}

function populateAlerts() {
    const alertStart = new Date();
    const alerts = [
        { severity: 'critical', color: 'red', msg: 'SQLi burst detected from NTC gateway - 48 payloads blocked in 12s', src: 'KTM-DC-01', time: alertStart },
        { severity: 'high', color: 'orange', msg: 'Bot traffic spike from Pokhara edge - 1,200 req/min from 3 IPs', src: 'PKR-Edge-02', time: new Date(alertStart - 120000) },
        { severity: 'medium', color: 'yellow', msg: 'Admin path probe from external IP 103.94.x.x - 6 attempts blocked', src: 'KTM-DC-01', time: new Date(alertStart - 480000) },
        { severity: 'low', color: 'blue', msg: 'LAL-DC-03 load threshold warning - CPU at 78%, scaling recommended', src: 'LAL-DC-03', time: new Date(alertStart - 900000) }
    ];
    const feed = document.getElementById('alerts-feed');
    const colors = { red: 'border-red-500/30 bg-red-500/5', orange: 'border-orange-500/30 bg-orange-500/5', yellow: 'border-yellow-500/30 bg-yellow-500/5', blue: 'border-blue-500/30 bg-blue-500/5' };
    const dotColors = { red: 'bg-red-500', orange: 'bg-orange-500', yellow: 'bg-yellow-500', blue: 'bg-blue-500' };
    feed.innerHTML = alerts.map((a, i) => `<div class="border-l-2 ${colors[a.color]} rounded-r-md px-4 py-3"><div class="flex justify-between items-start"><div class="flex items-start gap-2"><span class="w-1.5 h-1.5 rounded-full ${dotColors[a.color]} mt-1.5 flex-shrink-0"></span><p class="text-xs text-zinc-300">${a.msg}</p></div><span class="text-[10px] text-zinc-500 font-mono flex-shrink-0 ml-3" ${i===0?'id="first-alert-time"':''}>${i===0?'just now':formatTimeAgo(a.time)}</span></div><p class="text-[10px] text-zinc-600 mt-1 ml-4">${a.src} · ${a.severity.toUpperCase()}</p></div>`).join('');
    // Live timer for first alert
    setInterval(() => {
        const el = document.getElementById('first-alert-time');
        if (el) { const secs = Math.floor((Date.now() - alertStart.getTime()) / 1000); el.textContent = secs < 60 ? `${secs}s ago` : `${Math.floor(secs/60)}m ago`; }
    }, 1000);
}

function formatTimeAgo(date) {
    const secs = Math.floor((Date.now() - date.getTime()) / 1000);
    if (secs < 60) return `${secs}s ago`;
    return `${Math.floor(secs / 60)}m ago`;
}

function populateOrigin() {
    const countries = [
        { name: 'China', pct: 34, count: 626 },
        { name: 'Russia', pct: 22, count: 405 },
        { name: 'United States', pct: 16, count: 295 },
        { name: 'India', pct: 12, count: 221 },
        { name: 'Brazil', pct: 9, count: 166 },
        { name: 'Others', pct: 7, count: 129 }
    ];
    const container = document.getElementById('origin-bars');
    container.innerHTML = countries.map(c => `<div class="flex items-center gap-3 text-xs"><span class="text-zinc-400 w-24 truncate">${c.name}</span><div class="flex-1 bg-white/5 h-1.5 rounded-full overflow-hidden"><div class="bg-primary h-full rounded-full" style="width:${c.pct}%"></div></div><span class="font-mono text-zinc-300 w-16 text-right">${c.count.toLocaleString()} IPs</span></div>`).join('');
}

const rules = [
    { name: 'SQLi - Union Select', act: 'Blocked', badge: 'badge-red' },
    { name: 'XSS - Script Tag', act: 'Blocked', badge: 'badge-red' },
    { name: 'Rate Limit (Ncell Gateway)', act: 'Throttled', badge: 'badge-blue' },
    { name: 'Bad Bot (Scraper)', act: 'Blocked', badge: 'badge-red' }
];

function generateRow(isInitial = false) {
    const rule = rules[Math.floor(Math.random() * rules.length)];
    const ip = `${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`;
    const dts = ['KTM-DC-01', 'PKR-Edge-02', 'LAL-DC-03'];
    const dest = dts[Math.floor(Math.random() * dts.length)];
    const time = new Date();
    if (isInitial) time.setMinutes(time.getMinutes() - Math.floor(Math.random() * 60));
    const timeStr = time.toLocaleTimeString([], { hour12: false });
    return `<tr class="table-row group"><td class="px-6 py-3 text-zinc-400 group-hover:text-zinc-300">${timeStr}</td><td class="px-6 py-3 text-white">${ip}</td><td class="px-6 py-3 text-zinc-300 font-sans text-xs">${rule.name}</td><td class="px-6 py-3 text-zinc-400 group-hover:text-white">${dest}</td><td class="px-6 py-3 text-right"><span class="badge ${rule.badge}">${rule.act}</span></td></tr>`;
}

function seedTable() { let rows = ''; for(let i=0; i<6; i++) rows += generateRow(true); dom.table.innerHTML = rows; }

function tickData() {
    state.total += Math.floor(Math.random() * 50);
    sparkData1.shift(); sparkData1.push(Math.random() * 10);
    sparkData2.shift(); sparkData2.push(Math.random() * 5);
    sparkData3.shift(); sparkData3.push(Math.random() * 20);
    sparkCharts.forEach(c => c.update());
    if(Math.random() > 0.6) {
        state.blocked += Math.floor(Math.random() * 3 + 1);
        state.bw += 0.01;
        dom.table.insertAdjacentHTML('afterbegin', generateRow());
        if(dom.table.children.length > 8) dom.table.removeChild(dom.table.lastElementChild);
    }
    state.latency = 1.1 + Math.random() * 0.3;
    updateDOM();
}

// --- BURP SUITE SIMULATION ---
let burpPollingInterval = null;
let burpLogsData = ["> Proxy Offline", "> Click Start Proxy to begin..."];
document.addEventListener('DOMContentLoaded', () => {
    const burpBtn = document.getElementById('burp-proxy-btn');
    const burpLogs = document.getElementById('burp-logs-container');
    if(burpBtn && burpLogs) {
        burpBtn.addEventListener('click', () => {
            const isStarting = burpBtn.innerText === 'Start Proxy';
            if(isStarting) {
                burpBtn.innerText = 'Stop Proxy';
                burpBtn.classList.replace('text-orange-400', 'text-red-400');
                burpBtn.classList.replace('bg-orange-500/20', 'bg-red-500/20');
                burpBtn.classList.replace('hover:bg-orange-500/30', 'hover:bg-red-500/30');
                burpLogsData = ["> Listening on 127.0.0.1:8080", "> Waiting for incoming traffic...", `[${new Date().toLocaleTimeString()}] > Intercept is ON`];
                renderBurpLogs();
                burpPollingInterval = setInterval(simulateBurpTraffic, 2000);
            } else {
                burpBtn.innerText = 'Start Proxy';
                burpBtn.classList.replace('text-red-400', 'text-orange-400');
                burpBtn.classList.replace('bg-red-500/20', 'bg-orange-500/20');
                burpBtn.classList.replace('hover:bg-red-500/30', 'hover:bg-orange-500/30');
                burpLogsData.push(`[${new Date().toLocaleTimeString()}] > Intercept is OFF`);
                renderBurpLogs();
                clearInterval(burpPollingInterval);
            }
        });
    }
    function simulateBurpTraffic() {
        if(Math.random() > 0.4) {
            const methods = ['GET', 'POST', 'OPTIONS'];
            const method = methods[Math.floor(Math.random() * methods.length)];
            const paths = ['/login', '/api/v1/users', '/admin/dashboard', '/search?q=test'];
            const p = paths[Math.floor(Math.random() * paths.length)];
            burpLogsData.push(`[${new Date().toLocaleTimeString()}] Intercepted <span class="text-white">${method} ${p}</span>`);
            if(burpLogsData.length > 15) burpLogsData.shift();
            renderBurpLogs();
        }
    }
    function renderBurpLogs() { if(!burpLogs) return; burpLogs.innerHTML = burpLogsData.join('<br>'); burpLogs.scrollTop = burpLogs.scrollHeight; }
});

// --- PAYLOAD SANDBOX ---
document.addEventListener('DOMContentLoaded', () => {
    const fireBtn = document.getElementById('sandbox-fire-btn');
    const payloadInput = document.getElementById('sandbox-payload-input');
    const responseContainer = document.getElementById('sandbox-response');
    if(fireBtn && payloadInput && responseContainer) {
        fireBtn.addEventListener('click', () => {
            const payload = payloadInput.value.trim();
            if(!payload) return;
            fireBtn.innerText = 'Analyzing...'; fireBtn.disabled = true;
            responseContainer.innerHTML = `<svg class="w-8 h-8 text-primary animate-spin mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg><p class="text-xs text-primary animate-pulse">Running signature engine...</p>`;
            setTimeout(() => {
                fireBtn.innerText = 'Fire Payload'; fireBtn.disabled = false;
                const isSQLi = /('|--|union|select|insert|update|delete|drop)/i.test(payload);
                const isXSS = /(<script|javascript:|onerror=|onload=)/i.test(payload);
                if (isSQLi || isXSS) {
                    const ruleName = isSQLi ? 'SQL Injection (OWASP CRS 942)' : 'Cross-Site Scripting (OWASP CRS 941)';
                    responseContainer.innerHTML = `<div class="absolute inset-0 bg-red-500/10"></div><svg class="w-8 h-8 text-red-500 mb-2 relative z-10" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg><h4 class="text-white font-bold text-sm relative z-10">Payload Blocked</h4><p class="text-[10px] text-red-400 font-mono mt-1 relative z-10">${ruleName}</p>`;
                } else {
                    responseContainer.innerHTML = `<div class="absolute inset-0 bg-green-500/10"></div><svg class="w-8 h-8 text-green-500 mb-2 relative z-10" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg><h4 class="text-white font-bold text-sm relative z-10">Payload Allowed</h4><p class="text-[10px] text-green-400 font-mono mt-1 relative z-10">No malicious signatures detected</p>`;
                }
            }, 1200);
        });
    }
});

// --- SQLMAP SIMULATION ---
document.addEventListener('DOMContentLoaded', () => {
    const sqlmapBtn = document.getElementById('sqlmap-btn');
    const sqlmapLogs = document.getElementById('sqlmap-logs');
    if (sqlmapBtn && sqlmapLogs) {
        sqlmapBtn.addEventListener('click', () => {
            sqlmapBtn.innerText = 'Scanning...'; sqlmapBtn.disabled = true;
            sqlmapLogs.innerHTML = `<span class="text-blue-400">sqlmap -u "http://target/api?id=1" --random-agent --level 3</span><br>[*] starting @ ${new Date().toLocaleTimeString()}<br>`;
            const lines = ['[+] testing connection to the target URL','[!] WAF/IPS identified: Nexus Enterprise WAF','[*] checking if the target is vulnerable to SQL injection','[*] testing evasion techniques (e.g. BETWEEN, RANDOMCASE)','[-] target URL appears to be NOT injectable (blocked by WAF)'];
            let delay = 800;
            lines.forEach((line, index) => { setTimeout(() => { sqlmapLogs.innerHTML += line + '<br>'; sqlmapLogs.scrollTop = sqlmapLogs.scrollHeight; if (index === lines.length - 1) { sqlmapBtn.innerText = 'Run Scan'; sqlmapBtn.disabled = false; } }, delay); delay += 700 + Math.random() * 500; });
        });
    }
});

// --- WAFW00F SIMULATION ---
document.addEventListener('DOMContentLoaded', () => {
    const wafw00fBtn = document.getElementById('wafw00f-btn');
    const wafw00fLogs = document.getElementById('wafw00f-logs');
    if (wafw00fBtn && wafw00fLogs) {
        wafw00fBtn.addEventListener('click', () => {
            wafw00fBtn.innerText = 'Analyzing...'; wafw00fBtn.disabled = true;
            wafw00fLogs.innerHTML = `<span class="text-purple-400">wafw00f https://edge.nexus.local</span><br>`;
            const lines = ['[+] Checking for WAF presence...','[+] Sending crafted HTTP requests to trigger WAF...','[+] Analyzing server response headers and body...','<span class="text-green-400 font-bold">[+] WAF detected: Nexus Enterprise WAF</span>','[+] Reason: Proprietary block page pattern match (HTTP 403)'];
            let delay = 600;
            lines.forEach((line, index) => { setTimeout(() => { wafw00fLogs.innerHTML += line + '<br>'; wafw00fLogs.scrollTop = wafw00fLogs.scrollHeight; if (index === lines.length - 1) { wafw00fBtn.innerText = 'Analyze'; wafw00fBtn.disabled = false; } }, delay); delay += 800 + Math.random() * 400; });
        });
    }
});

// --- GENERATE REPORT ---
document.addEventListener('DOMContentLoaded', () => {
    const reportBtn = document.getElementById('generate-report-btn');
    if(reportBtn) {
        reportBtn.addEventListener('click', () => {
            reportBtn.innerText = 'Generating...'; reportBtn.disabled = true;
            setTimeout(() => {
                const w = window.open('', '_blank');
                w.document.write(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Nexus WAF Report</title><style>@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Inter',sans-serif;background:#0a0a0b;color:#e4e4e7;padding:40px}.c{max-width:800px;margin:0 auto}.hd{border-bottom:1px solid rgba(255,255,255,0.1);padding-bottom:24px;margin-bottom:32px}.hd h1{font-size:24px;font-weight:600;color:white}.hd p{font-size:13px;color:#71717a;margin-top:4px}.bg{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:500;background:rgba(16,185,129,0.15);color:#10b981}.st{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:32px}.sc{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);border-radius:8px;padding:16px}.sc .l{font-size:11px;color:#71717a;text-transform:uppercase;letter-spacing:0.5px}.sc .v{font-size:22px;font-weight:600;color:white;margin-top:4px}table{width:100%;border-collapse:collapse;margin-top:16px}th,td{text-align:left;padding:10px 16px;border-bottom:1px solid rgba(255,255,255,0.05);font-size:13px}th{color:#71717a;font-weight:500;font-size:11px;text-transform:uppercase;letter-spacing:0.5px}td{color:#d4d4d8}.s{margin-bottom:32px}.s h2{font-size:16px;font-weight:600;color:white;margin-bottom:12px}.pb{background:#4F46E5;color:white;border:none;padding:8px 16px;border-radius:6px;font-size:13px;cursor:pointer;float:right}.pb:hover{background:#4338ca}@media print{.pb{display:none}body{background:white;color:#18181b}.sc{border-color:#e4e4e7}th{color:#52525b}td{color:#27272a}.hd h1,.s h2{color:#18181b}}</style></head><body><div class="c"><div class="hd"><button class="pb" onclick="window.print()">Print / Export PDF</button><h1>🛡️ Nexus WAF Security Report</h1><p>Generated: ${new Date().toLocaleString()} | Status: <span class="bg">Operational</span> | OWASP CRS: v3.3.2</p></div><div class="st"><div class="sc"><div class="l">Total Requests</div><div class="v">${state.total.toLocaleString()}</div></div><div class="sc"><div class="l">Threats Blocked</div><div class="v">${state.blocked.toLocaleString()}</div></div><div class="sc"><div class="l">Bandwidth</div><div class="v">${state.bw.toFixed(1)} GB</div></div><div class="sc"><div class="l">Avg Latency</div><div class="v">${state.latency.toFixed(1)} ms</div></div></div><div class="s"><h2>Top Threat Vectors</h2><table><thead><tr><th>Threat Type</th><th>Count</th><th>Percentage</th></tr></thead><tbody><tr><td>SQL Injection</td><td>${Math.floor(state.blocked*0.45).toLocaleString()}</td><td>45%</td></tr><tr><td>Cross-Site Scripting</td><td>${Math.floor(state.blocked*0.25).toLocaleString()}</td><td>25%</td></tr><tr><td>Path Traversal</td><td>${Math.floor(state.blocked*0.15).toLocaleString()}</td><td>15%</td></tr><tr><td>Rate Limit Exceeded</td><td>${Math.floor(state.blocked*0.10).toLocaleString()}</td><td>10%</td></tr><tr><td>Bad Bot</td><td>${Math.floor(state.blocked*0.05).toLocaleString()}</td><td>5%</td></tr></tbody></table></div><div class="s"><h2>WAF Configuration</h2><table><thead><tr><th>Metric</th><th>Value</th></tr></thead><tbody><tr><td>Active Rules</td><td>3 / 4</td></tr><tr><td>OWASP Core Ruleset</td><td>v3.3.2</td></tr><tr><td>System Status</td><td>Operational</td></tr></tbody></table></div></div></body></html>`);
                w.document.close();
                reportBtn.innerText = 'Generate Report'; reportBtn.disabled = false;
            }, 500);
        });
    }
});

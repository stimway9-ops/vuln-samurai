/**
 * VulnSamurai — Node.js Frontend
 * Japanese Samurai Light Theme
 */

const http   = require('http');
const https  = require('https');
const fs     = require('fs');
const path   = require('path');
const qs     = require('querystring');
const url    = require('url');
const crypto = require('crypto');

const PORT           = process.env.PORT         || 3000;
const BACKEND_URL    = process.env.BACKEND_URL  || 'http://backend:8000';
const SESSION_SECRET = process.env.SESSION_SECRET || 'changeme';

const sessions = new Map();
function newSession() { return crypto.randomBytes(32).toString('hex'); }
function getSession(req) {
  const m = (req.headers.cookie||'').match(/vs_session=([a-f0-9]+)/);
  if (!m) return null;
  return sessions.get(m[1]) || null;
}
function setSession(res, sid, data) {
  sessions.set(sid, data);
  res.setHeader('Set-Cookie', `vs_session=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400`);
}
function clearSession(res, sid) {
  if (sid) sessions.delete(sid);
  res.setHeader('Set-Cookie', 'vs_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
}

function apiRequest(method, endpoint, body, token) {
  return new Promise((resolve, reject) => {
    const parsed   = new URL(BACKEND_URL + endpoint);
    const isHttps  = parsed.protocol === 'https:';
    const lib      = isHttps ? https : http;
    const postData = body ? JSON.stringify(body) : null;
    const options  = {
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + (parsed.search || ''),
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(postData ? { 'Content-Length': Buffer.byteLength(postData) } : {}),
        ...(token    ? { 'Authorization': `Bearer ${token}` } : {}),
      },
    };
    const req = lib.request(options, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on('error', reject);
    if (postData) req.write(postData);
    req.end();
  });
}

const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Noto+Serif+JP:wght@300;400;700&family=Zen+Kaku+Gothic+New:wght@400;700&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --ink:#1a1208;--ink2:#3d2e1a;--muted:#7a6a58;
  --paper:#faf6f0;--paper2:#f2ebe0;--paper3:#e8ddd0;
  --crimson:#9b1a2a;--crimson2:#c42535;
  --gold:#b8860b;--gold2:#d4a017;
  --jade:#2d6a4f;
  --border:rgba(90,60,30,0.18);--border2:rgba(90,60,30,0.35);
  --shadow:rgba(26,18,8,0.12);
  --font:'Zen Kaku Gothic New',sans-serif;
  --serif:'Noto Serif JP',serif;
}
body{font-family:var(--font);background:var(--paper);color:var(--ink);min-height:100vh;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;background-image:repeating-linear-gradient(0deg,transparent,transparent 40px,rgba(90,60,30,0.025) 40px,rgba(90,60,30,0.025) 41px),repeating-linear-gradient(90deg,transparent,transparent 40px,rgba(90,60,30,0.015) 40px,rgba(90,60,30,0.015) 41px);pointer-events:none;z-index:0}
body::after{content:'';position:fixed;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,var(--crimson),var(--gold),var(--crimson));z-index:999}
.navbar{position:sticky;top:0;z-index:100;background:rgba(250,246,240,0.96);backdrop-filter:blur(8px);border-bottom:1px solid var(--border2);box-shadow:0 2px 12px var(--shadow);display:flex;justify-content:space-between;align-items:center;padding:0 40px;height:62px}
.navbar-brand{display:flex;align-items:center;gap:12px;text-decoration:none}
.navbar-brand img{height:32px}
.navbar-brand span{font-family:var(--serif);font-size:1.2rem;font-weight:700;color:var(--crimson);letter-spacing:3px;text-transform:uppercase}
.navbar-brand .jp{font-size:0.72rem;color:var(--muted);letter-spacing:2px;font-family:var(--serif);font-weight:300;display:block;margin-top:-2px}
.navbar-links{display:flex;gap:2px;align-items:center}
.navbar-links a{color:var(--ink2);text-decoration:none;font-weight:700;letter-spacing:1px;text-transform:uppercase;font-size:0.78rem;padding:7px 16px;border-radius:2px;border:1px solid transparent;transition:all 0.2s;position:relative}
.navbar-links a::after{content:'';position:absolute;bottom:4px;left:16px;right:16px;height:1px;background:var(--crimson);transform:scaleX(0);transition:transform 0.2s}
.navbar-links a:hover{color:var(--crimson)}.navbar-links a:hover::after{transform:scaleX(1)}
.navbar-links a.active{color:var(--crimson);border-color:var(--border);background:var(--paper2)}
.navbar-links a.logout{color:var(--muted);font-size:0.72rem}.navbar-links a.logout:hover{color:var(--crimson2)}
.nav-divider{width:1px;height:20px;background:var(--border2);margin:0 8px}
.page{position:relative;z-index:1}
.container{width:92%;max-width:1160px;margin:44px auto}
.section-title{font-family:var(--serif);font-size:0.78rem;font-weight:400;letter-spacing:3px;text-transform:uppercase;color:var(--crimson);margin-bottom:16px;display:flex;align-items:center;gap:12px}
.section-title::before{content:'⚔';font-size:0.9rem;color:var(--gold)}
.section-title::after{content:'';flex:1;height:1px;background:linear-gradient(90deg,var(--border2),transparent)}
.scan-wrap{background:var(--paper2);border:1px solid var(--border2);border-top:3px solid var(--crimson);border-radius:2px;padding:28px 32px;margin-bottom:36px;box-shadow:0 4px 20px var(--shadow);position:relative}
.scan-wrap::before{content:'侍';position:absolute;top:10px;right:20px;font-family:var(--serif);font-size:3rem;color:var(--crimson);opacity:0.06;line-height:1}
.scan-row{display:flex;gap:12px;align-items:center}
.scan-input{flex:1;background:var(--paper);border:1px solid var(--border2);border-radius:2px;padding:12px 18px;color:var(--ink);font-family:'Courier New',monospace;font-size:0.9rem;outline:none;transition:border-color 0.2s,box-shadow 0.2s}
.scan-input:focus{border-color:var(--crimson);box-shadow:0 0 0 3px rgba(155,26,42,0.08)}
.scan-input::placeholder{color:var(--muted)}
.btn{position:relative;display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:12px 28px;background:var(--crimson);color:#fff;border:none;border-radius:2px;font-family:var(--font);font-size:0.8rem;font-weight:700;letter-spacing:2px;text-transform:uppercase;cursor:pointer;overflow:hidden;transition:transform 0.15s,box-shadow 0.2s,background 0.2s;box-shadow:0 4px 12px rgba(155,26,42,0.3);text-decoration:none;white-space:nowrap}
.btn::before{content:'';position:absolute;top:0;left:-100%;width:100%;height:100%;background:linear-gradient(90deg,transparent,rgba(255,255,255,0.15),transparent);transition:left 0.4s ease}
.btn:hover::before{left:100%}.btn:hover{background:var(--crimson2);transform:translateY(-1px);box-shadow:0 6px 20px rgba(155,26,42,0.35)}.btn:active{transform:translateY(0)}
.btn-scan{animation:pulse-crimson 3s ease-out infinite}
@keyframes pulse-crimson{0%{box-shadow:0 4px 12px rgba(155,26,42,0.3),0 0 0 0 rgba(155,26,42,0.3)}60%{box-shadow:0 4px 12px rgba(155,26,42,0.3),0 0 0 10px rgba(155,26,42,0)}100%{box-shadow:0 4px 12px rgba(155,26,42,0.3),0 0 0 0 rgba(155,26,42,0)}}
.btn-gold{background:var(--gold);box-shadow:0 4px 12px rgba(184,134,11,0.3)}.btn-gold:hover{background:var(--gold2);box-shadow:0 6px 20px rgba(184,134,11,0.35)}
.progress-wrap{margin-top:18px;display:none}.progress-wrap.active{display:block}
.progress-label{font-size:0.75rem;font-family:var(--serif);color:var(--muted);margin-bottom:6px;display:flex;justify-content:space-between;letter-spacing:1px}
.progress-bar-outer{height:4px;background:var(--paper3);border-radius:2px;overflow:hidden}
.progress-bar-inner{height:100%;background:linear-gradient(90deg,var(--crimson),var(--gold));border-radius:2px;transition:width 0.6s ease;width:0%}
.engine-badge{display:inline-block;padding:2px 8px;border-radius:2px;font-size:0.7rem;font-weight:700;letter-spacing:1px;text-transform:uppercase;font-family:'Courier New',monospace;background:var(--paper3);border:1px solid var(--border2);color:var(--ink2)}
.msg-success{margin-top:14px;padding:10px 16px;background:rgba(45,106,79,0.08);border-left:3px solid var(--jade);border-radius:0 2px 2px 0;color:var(--jade);font-size:0.85rem;font-family:'Courier New',monospace}
.msg-error{margin-top:14px;padding:10px 16px;background:rgba(155,26,42,0.06);border-left:3px solid var(--crimson);border-radius:0 2px 2px 0;color:var(--crimson);font-size:0.85rem}
.cards{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:32px}
.card{flex:1;min-width:180px;background:var(--paper2);border:1px solid var(--border);border-radius:2px;padding:22px 24px;box-shadow:0 2px 8px var(--shadow);position:relative;overflow:hidden;transition:transform 0.2s,box-shadow 0.2s}
.card:hover{transform:translateY(-2px);box-shadow:0 6px 16px var(--shadow)}
.card::before{content:'';position:absolute;top:0;left:0;width:100%;height:3px;background:var(--border)}
.card.high::before{background:var(--crimson)}.card.medium::before{background:var(--gold)}.card.low::before{background:var(--jade)}
.card::after{position:absolute;bottom:4px;right:10px;font-family:var(--serif);font-size:2.4rem;opacity:0.05;color:var(--ink);line-height:1}
.card.high::after{content:'危';color:var(--crimson);opacity:0.08}.card.medium::after{content:'警';color:var(--gold);opacity:0.08}.card.low::after{content:'安';color:var(--jade);opacity:0.08}
.card-label{font-size:0.68rem;font-weight:700;letter-spacing:2.5px;text-transform:uppercase;color:var(--muted);margin-bottom:8px;font-family:var(--serif)}
.card-value{font-size:2.4rem;font-weight:700;color:var(--ink);line-height:1;font-family:var(--serif)}
.card.high .card-value{color:var(--crimson)}.card.medium .card-value{color:var(--gold)}.card.low .card-value{color:var(--jade)}
.stat-box{background:var(--paper2);border:1px solid var(--border);border-radius:2px;padding:24px 28px;margin-bottom:28px;box-shadow:0 2px 8px var(--shadow)}
.table{width:100%;border-collapse:collapse;font-size:0.88rem}
.table th{background:var(--paper3);color:var(--ink2);font-size:0.68rem;font-weight:700;letter-spacing:2px;text-transform:uppercase;padding:10px 16px;text-align:left;border-bottom:2px solid var(--crimson);font-family:var(--serif)}
.table td{padding:11px 16px;border-bottom:1px solid var(--border);color:var(--ink);vertical-align:middle}
.table tr:last-child td{border-bottom:none}.table tr:hover td{background:rgba(90,60,30,0.04)}
.badge{display:inline-block;padding:3px 10px;border-radius:2px;font-size:0.68rem;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;font-family:'Courier New',monospace}
.badge.high{background:rgba(155,26,42,0.1);color:var(--crimson);border:1px solid rgba(155,26,42,0.3)}
.badge.medium{background:rgba(184,134,11,0.1);color:var(--gold);border:1px solid rgba(184,134,11,0.3)}
.badge.low{background:rgba(45,106,79,0.1);color:var(--jade);border:1px solid rgba(45,106,79,0.3)}
.badge.info{background:rgba(90,60,30,0.08);color:var(--muted);border:1px solid var(--border2)}
.badge.completed,.badge.done{background:rgba(45,106,79,0.1);color:var(--jade);border:1px solid rgba(45,106,79,0.3)}
.badge.running,.badge.pending{background:rgba(184,134,11,0.1);color:var(--gold);border:1px solid rgba(184,134,11,0.3)}
.badge.failed{background:rgba(155,26,42,0.1);color:var(--crimson);border:1px solid rgba(155,26,42,0.3)}
.pill{font-family:'Courier New',monospace;font-size:0.8rem;background:var(--paper3);border:1px solid var(--border2);padding:2px 8px;border-radius:2px;color:var(--ink2)}
.login-wrap{min-height:calc(100vh - 62px);display:flex;align-items:center;justify-content:center;padding:40px 16px;background-image:url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none'%3E%3Cg fill='%23b8860b' fill-opacity='0.04'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E")}
.form-box{background:var(--paper);border:1px solid var(--border2);border-top:3px solid var(--crimson);border-radius:2px;padding:40px 44px;width:100%;max-width:420px;box-shadow:0 8px 40px var(--shadow);position:relative}
.form-box::before{content:'武';position:absolute;top:12px;right:18px;font-family:var(--serif);font-size:2.8rem;color:var(--crimson);opacity:0.07;line-height:1}
.form-box h3{text-align:center;color:var(--crimson);font-family:var(--serif);font-size:1.3rem;letter-spacing:3px;text-transform:uppercase;margin-bottom:6px;font-weight:700}
.form-box .jp-sub{text-align:center;color:var(--muted);font-family:var(--serif);font-size:0.72rem;letter-spacing:2px;margin-bottom:28px}
.form-divider{height:1px;background:var(--border2);margin:28px 0;position:relative}
.form-divider::after{content:'✦';position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);background:var(--paper);padding:0 8px;color:var(--gold);font-size:0.65rem}
.form-sub{font-size:0.7rem;color:var(--muted);letter-spacing:2px;text-transform:uppercase;margin-bottom:14px;font-family:var(--serif)}
label{font-size:0.7rem;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:var(--muted);display:block;margin-bottom:5px;font-family:var(--serif)}
input[type=text],input[type=password],input[type=url]{width:100%;padding:11px 14px;background:var(--paper2);border:1px solid var(--border2);border-radius:2px;color:var(--ink);font-family:'Courier New',monospace;font-size:0.9rem;outline:none;margin-bottom:16px;transition:border-color 0.2s,box-shadow 0.2s}
input[type=text]:focus,input[type=password]:focus,input[type=url]:focus{border-color:var(--crimson);box-shadow:0 0 0 3px rgba(155,26,42,0.08);background:var(--paper)}
.search{padding:8px 14px;background:var(--paper2);border:1px solid var(--border2);border-radius:2px;color:var(--ink);font-family:'Courier New',monospace;font-size:0.85rem;outline:none;width:300px;margin-bottom:16px;transition:border-color 0.2s}
.search:focus{border-color:var(--crimson)}
.log-row.INFO td{color:var(--ink2)}.log-row.WARN td{color:var(--gold)}.log-row.ERROR td{color:var(--crimson)}
.scroll-divider{text-align:center;margin:8px 0 28px;color:var(--gold);font-size:0.7rem;letter-spacing:6px;font-family:var(--serif);opacity:0.6}
@keyframes fade-up{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
.fade-up{animation:fade-up 0.4s ease forwards;opacity:0}
.fade-up:nth-child(1){animation-delay:0.05s}.fade-up:nth-child(2){animation-delay:0.1s}.fade-up:nth-child(3){animation-delay:0.15s}.fade-up:nth-child(4){animation-delay:0.2s}
`;

function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function sevClass(s){if(!s)return 'info';const l=s.toLowerCase();if(l==='high'||l==='critical')return 'high';if(l==='medium'||l==='moderate')return 'medium';if(l==='low')return 'low';return 'info'}

function navbar(active='',session=null){
  const links=[['/', 'Dashboard'],['/report','Reports'],['/logs','Logs']];
  return `<nav class="navbar">
  <a class="navbar-brand" href="/">
    <img src="/static/logo.svg" alt="VulnSamurai">
    <div><span>VulnSamurai</span><span class="jp">脆弱性侍</span></div>
  </a>
  <div class="navbar-links">
    ${links.map(([href,label])=>`<a href="${href}"${active===label?' class="active"':''}>${label}</a>`).join('')}
    <div class="nav-divider"></div>
    ${session?`<a href="/logout" class="logout">⛩ ${esc(session.username)}</a>`:`<a href="/login"${active==='Login'?' class="active"':''}>Login</a>`}
  </div>
</nav>`;
}

function shell(title,body,activeNav='',session=null){
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} — VulnSamurai</title><style>${CSS}</style></head><body>${navbar(activeNav,session)}<div class="page">${body}</div></body></html>`;
}

function pageDashboard(scan=null,message='',error='',session=null){
  const summary=scan?.summary||{high:0,medium:0,low:0,info:0,total:0};
  const vulns=scan?.vulnerabilities||[];
  const payloads=scan?.payloads||[];
  const scanStatus=scan?.status||'';
  const activeScanId=scan?.id||'';
  const empty=`<tr><td colspan="5" style="color:var(--muted);text-align:center;padding:24px;font-family:var(--serif);letter-spacing:2px">— Nothing detected yet —</td></tr>`;
  const vulnRows=vulns.length?vulns.map(v=>`<tr><td>${esc(v.name)}</td><td><span class="badge ${sevClass(v.severity)}">${esc(v.severity)}</span></td><td><span class="engine-badge">${esc(v.engine)}</span></td><td>${esc(v.recommendation)}</td></tr>`).join(''):empty;
  const payloadRows=payloads.length?payloads.map(p=>`<tr><td>${esc(p.vulnerability)}</td><td><span class="pill">${esc(p.payload)}</span></td><td><span class="badge ${sevClass(p.result_severity)}">${esc(p.result)}</span></td><td><span class="engine-badge">${esc(p.engine)}</span></td><td>${esc(p.description)}</td></tr>`).join(''):empty;
  return shell('Dashboard',`
<div class="container">
  <div class="scan-wrap fade-up">
    <div class="section-title">Begin the Hunt</div>
    <form id="scanForm" action="/scan" method="POST">
      <div class="scan-row">
        <input class="scan-input" type="url" name="url" placeholder="https://target.example.com" required>
        <button class="btn btn-scan" type="submit" id="scanBtn">⚔ Start Scan</button>
      </div>
    </form>
    <div class="progress-wrap${activeScanId&&scanStatus==='running'?' active':''}" id="progressWrap">
      <div class="progress-label"><span style="font-family:var(--serif);letter-spacing:1px">Running: <strong id="currentEngine">—</strong></span><span id="pctLabel">0%</span></div>
      <div class="progress-bar-outer"><div class="progress-bar-inner" id="progressBar"></div></div>
    </div>
    ${message?`<div class="msg-success">✓ ${esc(message)}</div>`:''}
    ${error?`<div class="msg-error">✗ ${esc(error)}</div>`:''}
  </div>
  <div class="scroll-divider">— 武 —</div>
  <div class="section-title">Threat Summary</div>
  <div class="cards">
    <div class="card high fade-up"><div class="card-label">High</div><div class="card-value" id="cHigh">${summary.high}</div></div>
    <div class="card medium fade-up"><div class="card-label">Medium</div><div class="card-value" id="cMed">${summary.medium}</div></div>
    <div class="card low fade-up"><div class="card-label">Low</div><div class="card-value" id="cLow">${summary.low}</div></div>
    <div class="card fade-up"><div class="card-label">Total</div><div class="card-value" id="cTotal">${summary.total}</div></div>
  </div>
  <div class="stat-box">
    <div class="section-title">Vulnerabilities Found</div>
    <table class="table"><thead><tr><th>Vulnerability</th><th>Severity</th><th>Engine</th><th>Recommendation</th></tr></thead><tbody>${vulnRows}</tbody></table>
  </div>
  <div class="stat-box">
    <div class="section-title">Triggered Payloads</div>
    <table class="table"><thead><tr><th>Vulnerability</th><th>Payload</th><th>Result</th><th>Engine</th><th>Description</th></tr></thead><tbody>${payloadRows}</tbody></table>
  </div>
</div>
<script>
const SCAN_ID=${JSON.stringify(activeScanId)};let polling=false;
function updateSummary(s){document.getElementById('cHigh').textContent=s.high||0;document.getElementById('cMed').textContent=s.medium||0;document.getElementById('cLow').textContent=s.low||0;document.getElementById('cTotal').textContent=s.total||0}
function updateProgress(data){document.getElementById('progressWrap').classList.add('active');const pct=data.progress||0;document.getElementById('progressBar').style.width=pct+'%';document.getElementById('pctLabel').textContent=pct+'%';document.getElementById('currentEngine').textContent=data.current_engine||'—';if(data.summary)updateSummary(data.summary)}
async function pollStatus(){if(!SCAN_ID||polling)return;polling=true;const interval=setInterval(async()=>{try{const res=await fetch('/api/scans/'+SCAN_ID+'/status');const data=await res.json();updateProgress(data);if(data.status==='done'||data.status==='failed'){clearInterval(interval);polling=false;setTimeout(()=>window.location.href='/?scan='+SCAN_ID,800)}}catch(e){clearInterval(interval);polling=false}},2000)}
if(SCAN_ID&&'${scanStatus}'==='running')pollStatus();
document.getElementById('scanForm').addEventListener('submit',function(){document.getElementById('scanBtn').disabled=true;document.getElementById('progressWrap').classList.add('active')});
</script>`,'Dashboard',session);
}

function pageLogin(error=''){
  return shell('Login',`
<div class="login-wrap"><div class="form-box">
  <h3>⚔ VulnSamurai</h3>
  <p class="jp-sub">脆弱性侍 — Security Testing</p>
  <div class="form-sub">Sign In</div>
  <form action="/login" method="POST">
    <label>Username</label><input type="text" name="username" placeholder="samurai" required>
    <label>Password</label><input type="password" name="password" placeholder="••••••" required>
    <button class="btn" style="width:100%" type="submit">Enter the Dojo</button>
  </form>
  <div class="form-divider"></div>
  <div class="form-sub">Register New Account</div>
  <form action="/register" method="POST">
    <label>Username</label><input type="text" name="username" placeholder="newsamurai" required>
    <label>Email</label><input type="text" name="email" placeholder="user@example.com" required>
    <label>Password</label><input type="password" name="password" placeholder="••••••" required>
    <button class="btn btn-gold" style="width:100%" type="submit">Join the Clan</button>
  </form>
  ${error?`<div class="msg-error" style="margin-top:14px">${esc(error)}</div>`:''}
</div></div>`,'Login');
}

function pageLogs(logs=[],session=null){
  const rows=logs.length?logs.map(l=>`<tr class="log-row ${esc(l.event_type)}"><td style="font-family:'Courier New',monospace;font-size:0.8rem">${l.timestamp?new Date(l.timestamp).toLocaleString():'—'}</td><td><span class="badge ${l.event_type==='INFO'?'low':l.event_type==='WARN'?'medium':'high'}">${esc(l.event_type)}</span></td><td style="font-family:'Courier New',monospace;font-size:0.82rem">${esc(l.message)}</td><td style="font-family:'Courier New',monospace;font-size:0.8rem">${esc(l.ip_address||'—')}</td></tr>`).join(''):`<tr><td colspan="4" style="color:var(--muted);text-align:center;padding:24px;font-family:var(--serif);letter-spacing:2px">— Scroll is empty —</td></tr>`;
  return shell('Logs',`
<div class="container">
  <div class="section-title">Battle Records</div>
  <input class="search" type="text" id="logSearch" placeholder="Filter records..." oninput="filterLogs(this.value)">
  <div class="stat-box"><table class="table"><thead><tr><th>Timestamp</th><th>Level</th><th>Message</th><th>IP</th></tr></thead><tbody id="logBody">${rows}</tbody></table></div>
</div>
<script>function filterLogs(v){document.querySelectorAll('#logBody tr').forEach(r=>{r.style.display=r.textContent.toLowerCase().includes(v.toLowerCase())?'':'none'})}</script>`,'Logs',session);
}

function pageReports(reports=[],session=null){
  const rows=reports.length?reports.map(r=>`<tr><td><span class="pill">${esc(r.id?.slice(-8)||'—')}</span></td><td>${esc(r.name||'—')}</td><td style="font-family:'Courier New',monospace;font-size:0.82rem">${r.generated_at?new Date(r.generated_at).toLocaleDateString():'—'}</td><td style="font-family:var(--serif)">${esc(String(r.findings||0))}</td><td><span class="badge ${sevClass(r.status)}">${esc(r.status||'—')}</span></td></tr>`).join(''):`<tr><td colspan="5" style="color:var(--muted);text-align:center;padding:24px;font-family:var(--serif);letter-spacing:2px">— No battle reports yet —</td></tr>`;
  return shell('Reports',`
<div class="container">
  <div class="section-title">Battle Reports</div>
  <div class="stat-box"><table class="table"><thead><tr><th>Report ID</th><th>Name</th><th>Date</th><th>Findings</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table></div>
</div>`,'Reports',session);
}

const MIME={'.svg':'image/svg+xml','.jpg':'image/jpeg','.jpeg':'image/jpeg','.webp':'image/webp','.png':'image/png'};
function readBody(req){return new Promise((resolve,reject)=>{let data='';req.on('data',c=>data+=c);req.on('end',()=>resolve(qs.parse(data)));req.on('error',reject)})}
function respond(res,status,html){res.writeHead(status,{'Content-Type':'text/html; charset=utf-8'});res.end(html)}
function redirect(res,loc){res.writeHead(302,{Location:loc});res.end()}

const server=http.createServer(async(req,res)=>{
  const parsed=url.parse(req.url);
  const pathname=parsed.pathname;
  const method=req.method.toUpperCase();
  const session=getSession(req);

  if(pathname.startsWith('/static/')){
    const fp=path.join(__dirname,pathname);const ext=path.extname(fp);
    try{const data=fs.readFileSync(fp);res.writeHead(200,{'Content-Type':MIME[ext]||'application/octet-stream'});return res.end(data)}
    catch{res.writeHead(404);return res.end('Not found')}
  }

  if(pathname.startsWith('/api/')){
    const apiPath=pathname.replace('/api','');
    if(!session){res.writeHead(401);return res.end('{"error":"Unauthorized"}')}
    try{const result=await apiRequest('GET',apiPath,null,session.access_token);res.writeHead(result.status,{'Content-Type':'application/json'});return res.end(JSON.stringify(result.body))}
    catch{res.writeHead(502);return res.end('{}')}
  }

  if(pathname==='/'&&method==='GET'){
    const params=new URLSearchParams(parsed.query||'');const scanId=params.get('scan');let scan=null;
    if(scanId&&session){try{const r=await apiRequest('GET',`/scans/${scanId}`,null,session.access_token);if(r.status===200)scan=r.body}catch{}}
    return respond(res,200,pageDashboard(scan,'','',session));
  }

   if(pathname==='/scan'&&method==='POST'){
     // Auto-login with default credentials if not authenticated
     if(!session){
       // Try to login with default credentials
       const loginBody = {username: 'samurai', password: 'samurai'};
       try {
         const loginRes = await apiRequest('POST', '/auth/login', loginBody);
         if(loginRes.status === 200){
           const sid = newSession();
           setSession(res, sid, {access_token: loginRes.body.access_token, refresh_token: loginRes.body.refresh_token, username: 'samurai'});
           // Continue with scan using the session
           const body = await readBody(req);
           const r = await apiRequest('POST', '/scans', {url: body.url}, loginRes.body.access_token);
           if(r.status===202) return redirect(res, `/?scan=${r.body.scan_id}`);
           return respond(res, 200, pageDashboard(null, '', 'Failed to start scan.', {username: 'samurai'}));
         }
       } catch(e) {
         // If login fails, proceed without auth (scans endpoint is public anyway)
       }
     }
     const body = await readBody(req);
     const token = session ? session.access_token : null;
     try{const r=await apiRequest('POST','/scans',{url:body.url},token);if(r.status===202)return redirect(res,`/?scan=${r.body.scan_id}`);return respond(res,200,pageDashboard(null,'','Failed to start scan.',session))}
     catch{return respond(res,200,pageDashboard(null,'','Backend unreachable.',session))}
  }

  if(pathname==='/login'&&method==='GET'){if(session)return redirect(res,'/');return respond(res,200,pageLogin())}

  if(pathname==='/login'&&method==='POST'){
    const body=await readBody(req);
    try{const r=await apiRequest('POST','/auth/login',{username:body.username,password:body.password});
      if(r.status===200){const sid=newSession();setSession(res,sid,{access_token:r.body.access_token,refresh_token:r.body.refresh_token,username:body.username});return redirect(res,'/')}
      return respond(res,401,pageLogin('Invalid credentials'))}
    catch{return respond(res,500,pageLogin('Backend unreachable.'))}
  }

  if(pathname==='/register'&&method==='POST'){
    const body=await readBody(req);
    try{const r=await apiRequest('POST','/auth/register',{username:body.username,email:body.email,password:body.password});if(r.status===201)return redirect(res,'/login');return respond(res,409,pageLogin(r.body?.detail||'Registration failed'))}
    catch{return respond(res,500,pageLogin('Backend unreachable.'))}
  }

  if(pathname==='/logout'&&method==='GET'){
    const m=(req.headers.cookie||'').match(/vs_session=([a-f0-9]+)/);
    clearSession(res,m?.[1]);return redirect(res,'/login');
  }

  if(pathname==='/report'&&method==='GET'){
    let reports=[];
    if(session){try{const r=await apiRequest('GET','/reports',null,session.access_token);if(r.status===200)reports=r.body}catch{}}
    return respond(res,200,pageReports(reports,session));
  }

  if(pathname==='/logs'&&method==='GET'){
    let logs=[];
    if(session){try{const r=await apiRequest('GET','/logs',null,session.access_token);if(r.status===200)logs=r.body}catch{}}
    return respond(res,200,pageLogs(logs,session));
  }

  respond(res,404,shell('404',`
    <div class="container" style="text-align:center;padding-top:80px">
      <div style="font-family:var(--serif);font-size:5rem;color:var(--crimson);opacity:0.3;margin-bottom:16px">四〇四</div>
      <div class="section-title" style="justify-content:center">Path Not Found</div>
      <p style="color:var(--muted);margin:16px 0 28px;font-family:var(--serif);letter-spacing:2px">The path <code>${esc(pathname)}</code> leads nowhere.</p>
      <a href="/" class="btn">Return to the Dojo</a>
    </div>`));
});

server.listen(PORT,()=>{
  console.log('\x1b[33m╔══════════════════════════════════════╗');
  console.log('║   ⚔  VulnSamurai  脆弱性侍           ║');
  console.log(`║   http://localhost:${PORT}              ║`);
  console.log('╚══════════════════════════════════════╝\x1b[0m');
});

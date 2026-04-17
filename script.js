/**
 * PhishGuard AI v2.0 — script.js
 * Shared JS: API calls, history, rendering, audio, toggles
 * API endpoint: POST http://127.0.0.1:5000/api/scan
 */
'use strict';

const API_SCAN   = 'http://127.0.0.1:5000/api/scan';
const API_HEALTH = 'http://127.0.0.1:5000/api/health';
const TIMEOUT_MS = 10000;
const HISTORY_KEY = 'pg_history_v2';
const TOGGLE_KEY  = 'pg_realtime';
const MAX_HIST    = 20;

// ── Utility ──────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

function normalise(raw) {
  let s = (raw || '').trim();
  if (!s) return null;
  if (!/^https?:\/\//i.test(s)) s = 'https://' + s;
  try { const u = new URL(s); return u.hostname.includes('.') ? s : null; }
  catch { return null; }
}

// ── localStorage ─────────────────────────────────────────────────────────────
function getHistory() {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]'); }
  catch { return []; }
}
function pushHistory(entry) {
  try {
    let h = getHistory().filter(e => e.url !== entry.url);
    h.unshift({ url: String(entry.url), prediction: Number(entry.prediction),
      result: String(entry.result), confidence: Number(entry.confidence),
      reasons: entry.reasons || [], time: new Date().toISOString() });
    if (h.length > MAX_HIST) h = h.slice(0, MAX_HIST);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(h));
  } catch(e) { console.warn('[PG] localStorage:', e); }
}
function clearHistory() { localStorage.removeItem(HISTORY_KEY); }

function getToggle() { return localStorage.getItem(TOGGLE_KEY) !== 'off'; }
function setToggle(v) { localStorage.setItem(TOGGLE_KEY, v ? 'on' : 'off'); }

// ── Backend health ────────────────────────────────────────────────────────────
let _healthTimer = null;
async function checkHealth() {
  const dot = $('navDot'), lbl = $('navStatus');
  if (!dot && !lbl) return;
  async function ping() {
    const c = new AbortController();
    const t = setTimeout(() => c.abort(), 3000);
    try {
      const r = await fetch(API_HEALTH, { signal: c.signal });
      clearTimeout(t);
      if (r.ok) {
        const j = await r.json().catch(() => ({}));
        if (dot) { dot.className = 'nav-dot online'; }
        if (lbl) { lbl.textContent = 'ONLINE'; lbl.title = 'Model: ' + (j.model || '?'); }
      } else throw new Error();
    } catch {
      clearTimeout(t);
      if (dot) dot.className = 'nav-dot offline';
      if (lbl) lbl.textContent = 'OFFLINE';
    }
  }
  await ping();
  if (_healthTimer) clearInterval(_healthTimer);
  _healthTimer = setInterval(ping, 30000);
}

// ── Alert sound ───────────────────────────────────────────────────────────────
function beep() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    [880,620,880,520].forEach((f, i) => {
      const o = ctx.createOscillator(), g = ctx.createGain();
      o.connect(g); g.connect(ctx.destination);
      o.type = 'square';
      const t = ctx.currentTime + i * 0.13;
      o.frequency.setValueAtTime(f, t);
      g.gain.setValueAtTime(0, t);
      g.gain.linearRampToValueAtTime(0.18, t + .02);
      g.gain.linearRampToValueAtTime(0, t + .1);
      o.start(t); o.stop(t + .13);
    });
  } catch(e) { /* no audio */ }
}

// ── Core scan ─────────────────────────────────────────────────────────────────
async function runScan(raw) {
  const url = normalise(raw);
  if (!url) {
    showError('Invalid URL — example: https://suspicious-site.com');
    return;
  }

  const btn = $('scanBtn');
  hideError(); hideResult();
  showLoader(true);
  if (btn) { btn.disabled = true; btn.textContent = 'SCANNING...'; }

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(API_SCAN, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
      signal: ctrl.signal,
    });
    clearTimeout(timer);

    if (!res.ok) {
      let msg = `Server error ${res.status}`;
      try { const b = await res.json(); if (b.error) msg = b.error; } catch {}
      throw new Error(msg);
    }

    const data = await res.json();
    if (data.prediction === undefined || !data.result) throw new Error('Unexpected server response.');

    pushHistory({ url: data.url || url, prediction: data.prediction,
      result: data.result, confidence: data.confidence, reasons: data.reasons });

    renderResult(data);
    if (typeof window._afterScan === 'function') window._afterScan(data);

  } catch(err) {
    clearTimeout(timer);
    if (err.name === 'AbortError') {
      showError('Request timed out (10 s) — is the backend running?  →  python app.py');
    } else if (err instanceof TypeError || /fetch|network|failed|load failed/i.test(err.message)) {
      showError('⚡ Backend not reachable — run: cd backend && python app.py  (port 5000)');
    } else {
      showError(err.message || 'Unknown error — check the console (F12).');
    }
    hideResult();
  } finally {
    showLoader(false);
    if (btn) { btn.disabled = false; btn.textContent = 'SCAN NOW'; }
  }
}

// ── Render result ─────────────────────────────────────────────────────────────
function renderResult(data) {
  const rw = $('resultWrap');
  if (!rw) return;

  const phish = Number(data.prediction) === 1;
  const pct   = Math.min(100, Math.round(Number(data.confidence) * 100));
  const cls   = phish ? 'danger' : 'safe';
  const color = phish ? 'var(--danger)' : 'var(--safe)';

  _s('resultIcon',    el => { el.textContent = phish ? '☠️' : '✅'; el.className = 'result-icon-box ' + cls; });
  _s('resultVerdict', el => { el.textContent = data.result || (phish ? 'PHISHING' : 'SAFE'); el.className = 'result-verdict ' + cls; });
  _s('resultUrl',     el => { el.textContent = data.url || '—'; el.title = data.url || ''; });
  _s('rsPred',        el => { el.textContent = phish ? 'PHISHING (1)' : 'SAFE (0)'; el.style.color = color; });
  _s('rsConf',        el => { el.textContent = pct + '%'; el.style.color = color; });
  _s('confPct',       el => { el.textContent = pct + '%'; el.style.color = color; });

  // Double-RAF for bar animation
  const animBar = id => _s(id, el => {
    el.style.transition = 'none'; el.style.width = '0%'; el.style.background = color;
    requestAnimationFrame(() => requestAnimationFrame(() => {
      el.style.transition = 'width 1s cubic-bezier(.4,0,.2,1)';
      el.style.width = pct + '%';
    }));
  });
  animBar('confFill');

  // Reasons
  _s('reasonsList', el => {
    if (phish && data.reasons && data.reasons.length) {
      el.style.display = 'block';
      el.innerHTML = data.reasons.map(r =>
        `<div class="reason-item"><div class="reason-dot"></div>${esc(r)}</div>`
      ).join('');
    } else {
      el.style.display = 'none';
      el.innerHTML = '';
    }
  });

  _s('warnBanner', el => { el.style.display = phish ? 'block' : 'none'; });
  _s('emailStatus', el => {
    if (phish) {
      el.style.display = 'block';
      el.textContent = data.email_sent ? '📧 Alert email sent to admin' : '⏳ Email on cooldown';
      el.style.color = data.email_sent ? 'var(--safe)' : 'var(--warn)';
    } else { el.style.display = 'none'; }
  });

  rw.style.display = 'block'; // reveal after all DOM writes
  if (phish) beep();
}

// ── UI helpers ────────────────────────────────────────────────────────────────
function _s(id, fn) { const el = $(id); if (el) fn(el); }
function showLoader(v) { _s('loaderWrap', el => { el.style.display = v ? 'flex' : 'none'; }); }
function hideResult()  { _s('resultWrap', el => { el.style.display = 'none'; }); }
function showError(m)  { _s('errorMsg', el => { el.innerHTML = '⚠ ' + esc(m); el.style.display = 'block'; }); }
function hideError()   { _s('errorMsg', el => { el.style.display = 'none'; }); }

// ── Nav active state ──────────────────────────────────────────────────────────
function setActive(page) {
  document.querySelectorAll('.nav-links a').forEach(a => {
    a.classList.remove('active');
    const h = a.getAttribute('href') || '';
    if ((page === 'index'   && (h.includes('index') || h === './')) ||
        (page === 'history' &&  h.includes('history')) ||
        (page === 'about'   &&  h.includes('about'))  ||
        (page === 'contact' &&  h.includes('contact'))) {
      a.classList.add('active');
    }
  });
}

// ── Wire scan page inputs (called explicitly from index.html) ─────────────────
function initScan() {
  const btn   = $('scanBtn');
  const input = $('urlInput');
  if (!btn || !input || btn._wired) return;
  btn._wired = true;
  btn.addEventListener('click', () => runScan(input.value));
  input.addEventListener('keydown', e => { if (e.key === 'Enter') runScan(input.value); });
  input.addEventListener('input', hideError);
}

// ── Real-time toggle ──────────────────────────────────────────────────────────
function initToggle() {
  const chk = $('rtToggle');
  if (!chk) return;
  chk.checked = getToggle();
  chk.addEventListener('change', () => {
    setToggle(chk.checked);
    const lbl = $('rtLabel');
    if (lbl) lbl.textContent = chk.checked ? 'Real-Time Protection: ON' : 'Real-Time Protection: OFF';
  });
}

// DOMContentLoaded fallback
document.addEventListener('DOMContentLoaded', () => {
  const btn = $('scanBtn'), input = $('urlInput');
  if (btn && input && !btn._wired) {
    btn._wired = true;
    btn.addEventListener('click', () => runScan(input.value));
    input.addEventListener('keydown', e => { if (e.key === 'Enter') runScan(input.value); });
    input.addEventListener('input', hideError);
  }
});

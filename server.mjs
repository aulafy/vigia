// Vigía — 24/7 watch over your clients' sites: uptime, TLS, exploited vulnerabilities (CISA KEV),
// vulnerable dependencies (OSV) and end-of-life software (endoflife.date). Zero dependencies.
import http from 'node:http';
import fs from 'node:fs';
import tls from 'node:tls';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as L from './lib.mjs';
import { messages } from './i18n.mjs';

const DIR = path.dirname(fileURLToPath(import.meta.url));
const DATA = path.join(DIR, 'data');
fs.mkdirSync(DATA, { recursive: true });

// Minimal .env loader (real environment variables win)
try {
  for (const l of fs.readFileSync(path.join(DIR, '.env'), 'utf8').split('\n')) {
    const m = l.match(/^\s*([A-Z_]+)\s*=\s*(.*?)\s*$/);
    if (m && m[2] && !process.env[m[1]]) process.env[m[1]] = m[2];
  }
} catch {}
const {
  PORT = 4848, HOST = '127.0.0.1', DASH_PASS, VIGIA_LANG = 'en',
  NTFY_TOPIC, NTFY_SERVER = 'https://ntfy.sh', NTFY_TOKEN, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, WEBHOOK_URL,
  HEARTBEAT_URL, PUBLIC_URL, ACK_SECRET, DIGEST_HOUR = '9', DIGEST_TZ = process.env.TZ_DIGEST || 'Europe/Madrid',
} = process.env;
const INV = process.env.VIGIA_INV || path.join(DATA, 'inventory.json');
const STATE_F = process.env.VIGIA_STATE || path.join(DATA, 'state.json');
const T = messages(VIGIA_LANG);
const REPEAT_P1_MS = 10 * 60_000;
const UA = { 'user-agent': 'vigia/0.3 (+https://github.com/aulafy/vigia)' };
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);

if (!fs.existsSync(INV)) fs.copyFileSync(path.join(DIR, 'inventory.example.json'), INV);

let state = { alerts: {}, status: {}, kev: { seen: [], seeded: false }, osv: {}, feeds: {}, scanned: {} };
try { state = { ...state, ...JSON.parse(fs.readFileSync(STATE_F, 'utf8')) }; } catch {}
// Atomic write: a crash mid-write cannot corrupt the state file
const save = () => { fs.writeFileSync(STATE_F + '.tmp', JSON.stringify(state, null, 1)); fs.renameSync(STATE_F + '.tmp', STATE_F); };

// Re-read on every cycle, so editing the inventory needs no restart
let lastInvErr = '';
function inventory({ includePaused = false } = {}) {
  let res;
  try { res = L.loadInventory(JSON.parse(fs.readFileSync(INV, 'utf8'))); }
  catch (e) { res = { assets: [], errors: [`${INV}: ${e.message}`] }; }
  const err = res.errors.join('; ');
  if (err && err !== lastInvErr) log('inventory:', err);
  lastInvErr = err;
  return includePaused ? res.assets : res.assets.filter(a => !a.paused);
}

async function getJSON(url, opts = {}) {
  const r = await fetch(url, { headers: UA, signal: AbortSignal.timeout(30_000), ...opts });
  if (!r.ok) throw new Error(`${url} → HTTP ${r.status}`);
  return r.json();
}

// ---------- Notifications ----------
const ackUrl = key => PUBLIC_URL && ACK_SECRET
  ? `${PUBLIC_URL.replace(/\/$/, '')}/api/ack?key=${encodeURIComponent(key)}&sig=${L.signAck(key, ACK_SECRET)}` : null;

async function notify(prio, title, body, key) {
  if (prio === 'P3') return;
  const urgent = prio === 'P1', ack = key && urgent ? ackUrl(key) : null;
  log(`[${prio}] ${title} — ${body}`);
  const post = (url, payload, headers = {}) => fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(payload), signal: AbortSignal.timeout(15_000) })
    .then(r => { if (!r.ok) throw new Error(`${new URL(url).host} HTTP ${r.status}`); });
  const jobs = [];
  if (NTFY_TOPIC) jobs.push(post(NTFY_SERVER, {
    topic: NTFY_TOPIC, title: `${prio} ${title}`, message: body, priority: urgent ? 5 : 4, tags: [urgent ? 'rotating_light' : 'warning'],
    ...(ack && { actions: [{ action: 'http', label: T.ack, url: ack, method: 'POST', clear: true }] }),
  }, NTFY_TOKEN ? { authorization: `Bearer ${NTFY_TOKEN}` } : {}));
  if (TELEGRAM_BOT_TOKEN && TELEGRAM_CHAT_ID) jobs.push(post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
    chat_id: TELEGRAM_CHAT_ID, text: `${urgent ? '🚨' : '⚠️'} ${prio} ${title}\n${body}${ack ? `\n\n${T.ack}: ${ack}` : ''}`, link_preview_options: { is_disabled: true },
  }));
  if (WEBHOOK_URL) jobs.push(post(WEBHOOK_URL, { prio, title, body, key, ackUrl: ack }));
  (await Promise.allSettled(jobs)).forEach(r => r.status === 'rejected' && log('notify error:', r.reason?.message));
}

// ---------- Alert lifecycle ----------
// Assets in their first scan of a given kind: findings are stored silently and summarised in one message.
const onboarding = {}; // kind -> Set(assetId)
const inOnboarding = (key, asset) => Object.entries(onboarding).some(([k, s]) => key.startsWith(k + ':') && s.has(asset));

// raise: create an alert (deduplicated by key); an unacknowledged P1 is re-sent every 10 minutes
function raise(key, prio, title, body, asset) {
  const now = Date.now(), a = state.alerts[key];
  if (!a) {
    state.alerts[key] = { key, prio, title, body, asset, first: now, sentAt: now, ack: false };
    if (inOnboarding(key, asset)) state.alerts[key].ack = prio !== 'P1'; // P1s still ring
    else notify(prio, title, body, key);
  } else {
    Object.assign(a, { title, body });
    if (a.prio === 'P1' && !a.ack && now - a.sentAt > REPEAT_P1_MS) { a.sentAt = now; notify(prio, T.repeat(title), body, key); }
  }
}

function resolve(key, msg, { quiet = false } = {}) {
  const a = state.alerts[key];
  if (!a) return;
  delete state.alerts[key];
  if (!quiet && a.prio !== 'P3') notify('P2', T.recovered(a.title), msg || '');
}

// Close alerts of one kind that the latest complete scan no longer reports
function prune(kind, assetIds, foundKeys, msg) {
  for (const a of Object.values(state.alerts))
    if (a.key.startsWith(kind + ':') && assetIds.has(a.asset) && !foundKeys.has(a.key)) resolve(a.key, msg, { quiet: a.prio !== 'P1' });
}

function onboard(inv, kind, fn) {
  const fresh = new Set(inv.filter(a => !state.scanned[`${kind}:${a.id}`]).map(a => a.id));
  const t0 = Date.now();
  onboarding[kind] = fresh;
  return fn().then(() => {
    delete onboarding[kind];
    if (!fresh.size) return;
    for (const id of fresh) state.scanned[`${kind}:${id}`] = Date.now(); // only after a complete scan
    const found = Object.values(state.alerts).filter(a => fresh.has(a.asset) && a.key.startsWith(kind + ':') && a.first >= t0);
    if (!found.length) return;
    const c = { P1: 0, P2: 0, P3: 0 };
    found.forEach(a => c[a.prio]++);
    const names = inv.filter(a => found.some(x => x.asset === a.id)).map(a => `${a.client}/${a.name}`).join(', ');
    notify(c.P1 ? 'P1' : 'P2', T.onboard(kind, found.length), T.onboardBody(names, c));
  }, e => { delete onboarding[kind]; throw e; });
}

// ---------- Uptime + TLS (every 60 s) ----------
const tlsDays = host => new Promise(res => {
  const s = tls.connect(443, host, { servername: host, timeout: 8000 }, () => {
    const c = s.getPeerCertificate(); s.end();
    res(c?.valid_to ? Math.floor((new Date(c.valid_to) - Date.now()) / 864e5) : null);
  });
  s.on('error', () => res(null));
  s.on('timeout', () => { s.destroy(); res(null); });
});

async function checkAsset(a) {
  const st = state.status[a.id] ||= { ok: true, fails: 0 };
  const t0 = Date.now();
  let ok = false, code = 0, why = '';
  try {
    const r = await fetch(a.url || `https://${a.domain}`, { redirect: 'follow', signal: AbortSignal.timeout(a.timeoutMs || 10_000), headers: UA });
    code = r.status; ok = code < 400;
    if (ok && a.expect) { if (!(await r.text()).includes(a.expect)) { ok = false; why = T.expectMissing(a.expect); } }
    else await r.body?.cancel();
    if (!ok && !why) why = `HTTP ${code}`;
  } catch (e) { why = e.cause?.code || e.name || e.message; }
  Object.assign(st, { ms: Date.now() - t0, code, checkedAt: Date.now() });
  const key = `down:${a.id}`;
  if (ok) { st.fails = 0; st.ok = true; resolve(key, T.up(a, st.ms)); }
  else {
    st.fails++; st.ok = false;
    if (st.fails >= (a.failThreshold || 2)) raise(key, L.downPriority(a.criticality), T.down(a), T.downBody(a, why, st.fails), a.id);
  }
  // TLS once per hour
  if (a.domain && (!st.tlsAt || Date.now() - st.tlsAt > 3600_000)) {
    st.tlsAt = Date.now(); st.tlsDays = await tlsDays(a.domain);
    const k = `tls:${a.id}`, p = st.tlsDays === null ? null : L.tlsPriority(st.tlsDays);
    // a site that is down already has a down: alert, do not duplicate it
    if (st.tlsDays === null) { if (st.ok) raise(k, 'P2', T.tlsUnreadable(a), T.tlsUnreadableBody(a), a.id); }
    else if (p) raise(k, p, T.tlsExpiring(a, st.tlsDays), a.domain, a.id);
    else resolve(k, T.tlsRenewed);
  }
}

// ---------- CISA KEV (every 15 min) ----------
let kevSet = new Set();
async function checkKEV(inv) {
  const j = await getJSON('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
  kevSet = new Set(j.vulnerabilities.map(v => v.cveID));
  const seen = new Set(state.kev.seen), first = !state.kev.seeded, recent = Date.now() - 14 * 864e5;
  for (const v of j.vulnerabilities) {
    if (seen.has(v.cveID)) continue;
    seen.add(v.cveID);
    if (first && new Date(v.dateAdded) < recent) continue; // first run: only the last 14 days
    for (const a of inv) for (const s of a.stack)
      if (L.kevMatches(v, s)) raise(`kev:${v.cveID}:${a.id}`, L.kevPriority(a.criticality), T.kev(v), T.kevBody(a, s, v), a.id);
  }
  state.kev = { seen: [...seen], seeded: true };
}

// ---------- OSV: exact dependency versions (every 30 min) ----------
async function osvDetails(id) {
  return state.osv[id] ||= await getJSON(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`).then(x => ({
    sev: (x.database_specific?.severity || '').toUpperCase().replace('MODERATE', 'MEDIUM'),
    cves: [id, ...(x.aliases || [])].filter(z => z.startsWith('CVE-')),
    sum: x.summary || (x.details || '').slice(0, 160) || id,
  }));
}

async function checkOSV(inv) {
  const q = [];
  for (const a of inv) for (const s of a.stack) if (s.ecosystem && s.name && s.version) q.push({ a, s });
  const found = new Set();
  for (let i = 0; i < q.length; i += 100) {
    const chunk = q.slice(i, i + 100);
    const r = await getJSON('https://api.osv.dev/v1/querybatch', {
      method: 'POST', headers: { ...UA, 'content-type': 'application/json' },
      body: JSON.stringify({ queries: chunk.map(({ s }) => ({ package: { name: s.name, ecosystem: s.ecosystem }, version: s.version })) }),
    });
    for (let k = 0; k < chunk.length; k++) for (const v of r.results[k]?.vulns || []) {
      const { a, s } = chunk[k], d = await osvDetails(v.id);
      const inKev = d.cves.some(c => kevSet.has(c)), key = `osv:${v.id}:${a.id}:${s.name}`;
      found.add(key);
      raise(key, L.osvPriority({ sev: d.sev, inKev, criticality: a.criticality }), T.osv(a, s, v.id, inKev), T.osvBody(a, d), a.id);
    }
  }
  prune('osv', new Set(q.map(x => x.a.id)), found, T.osvFixed);
}

// ---------- End of life (every 6 h) ----------
async function checkEOL(inv) {
  const cache = {}, found = new Set(), scanned = new Set();
  let complete = true;
  for (const a of inv) for (const s of a.stack) {
    if (!s.eol || !s.version) continue;
    scanned.add(a.id);
    const cycles = cache[s.eol] ??= await getJSON(`https://endoflife.date/api/${encodeURIComponent(s.eol)}.json`).catch(e => { log('eol', s.eol, e.message); return null; });
    if (!Array.isArray(cycles)) { complete = false; continue; }
    const c = L.matchCycle(cycles, s.version), days = L.eolDays(c), p = L.eolPriority(days, a.criticality);
    if (!p) continue;
    const k = `eol:${a.id}:${s.eol}`;
    found.add(k);
    if (days < 0) raise(k, p, T.eolPast(a, s), T.eolPastBody(a, s, c), a.id);
    else raise(k, p, T.eolSoon(a, s, days), a.name, a.id);
  }
  if (complete) prune('eol', scanned, found, '');
}

// ---------- Scheduler ----------
const every = (name, ms, fn) => {
  let busy = false;
  const run = async () => {
    if (busy) return;
    busy = true;
    try { await fn(inventory()); state.feeds[name] = Date.now(); state.feeds[name + 'Err'] = null; }
    catch (e) { log(name, 'error:', e.message); state.feeds[name + 'Err'] = e.message; }
    busy = false;
    save();
  };
  run(); setInterval(run, ms);
};
every('uptime', 60_000, inv => Promise.all(inv.map(checkAsset)));
every('kev', 15 * 60_000, checkKEV);
setTimeout(() => every('osv', 30 * 60_000, inv => onboard(inv, 'osv', () => checkOSV(inv))), 15_000); // after KEV is loaded
setTimeout(() => every('eol', 6 * 3600_000, inv => onboard(inv, 'eol', () => checkEOL(inv))), 30_000);

// Watch the watcher: a feed that misses ~3 cycles is a blind spot
const STALE = { kev: 60 * 60_000, osv: 2 * 3600_000, eol: 24 * 3600_000 };
every('health', 60_000, async () => {
  for (const [f, max] of Object.entries(STALE)) {
    const t = state.feeds[f];
    if (t && Date.now() - t > max) raise(`feed:${f}`, 'P2', T.feedStale(f), T.feedStaleBody(Math.round((Date.now() - t) / 60_000), state.feeds[f + 'Err']), null);
    else if (t) resolve(`feed:${f}`, T.feedOk(f));
  }
  // Drop alerts of assets removed from the inventory
  const ids = new Set(inventory({ includePaused: true }).map(a => a.id));
  for (const a of Object.values(state.alerts)) if (a.asset && !ids.has(a.asset)) delete state.alerts[a.key];
  // Heartbeat to an external service (healthchecks.io, Better Stack…): if Vigía dies, that service alerts you
  if (HEARTBEAT_URL) await fetch(HEARTBEAT_URL, { signal: AbortSignal.timeout(10_000) }).catch(e => log('heartbeat error:', e.message));
});

// Daily digest: new P3s + open, unacknowledged P2s
every('digest', 5 * 60_000, async () => {
  const { day, hour } = L.localClock(DIGEST_TZ);
  if (hour < +DIGEST_HOUR || state.feeds.digestDay === day) return;
  state.feeds.digestDay = day;
  const since = Date.now() - 864e5, all = Object.values(state.alerts);
  const p3 = all.filter(a => a.prio === 'P3' && a.first > since), p2 = all.filter(a => a.prio === 'P2' && !a.ack);
  if (!p3.length && !p2.length) return;
  const top = [...p2, ...p3].slice(0, 8).map(a => `• ${a.prio} ${a.title}`).join('\n');
  notify('P2', T.digest(p2.length, p3.length), top + (p2.length + p3.length > 8 ? `\n${T.more}` : ''));
});

// ---------- Dashboard + API ----------
const authHeader = DASH_PASS ? 'Basic ' + Buffer.from('vigia:' + DASH_PASS).toString('base64') : null;
const escHtml = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  const json = (o, c = 200) => { res.writeHead(c, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
  const html = (s, c = 200) => { res.writeHead(c, { 'content-type': 'text/html; charset=utf-8' }); res.end(s); };

  if (u.pathname === '/healthz') return json({ ok: true, feeds: state.feeds });

  // Signed acknowledge link from a notification: GET shows a confirm button (link previews cannot ack), POST acks
  const key = u.searchParams.get('key'), signed = L.verifyAck(key, u.searchParams.get('sig'), ACK_SECRET);
  if (u.pathname === '/api/ack' && signed) {
    if (req.method === 'POST') { if (state.alerts[key]) state.alerts[key].ack = true; save(); return req.headers.accept?.includes('text/html') ? html(`<p>${escHtml(T.acked)}</p>`) : json({ ok: true }); }
    const a = state.alerts[key];
    return html(`<!doctype html><meta name="viewport" content="width=device-width"><body style="font:16px system-ui;padding:24px">
      <p><b>${escHtml(a ? `${a.prio} ${a.title}` : key)}</b></p><p>${escHtml(a?.body || '')}</p>
      <form method="post"><button style="font-size:18px;padding:12px 20px">${escHtml(T.ack)}</button></form>`);
  }

  if (authHeader && req.headers.authorization !== authHeader) { res.writeHead(401, { 'www-authenticate': 'Basic realm="Vigia"' }); return res.end('unauthorized'); }

  if (u.pathname === '/api/state') return json({
    lang: VIGIA_LANG, inventory: inventory({ includePaused: true }), status: state.status, alerts: Object.values(state.alerts), feeds: state.feeds,
    notify: { ntfy: !!NTFY_TOPIC, telegram: !!TELEGRAM_BOT_TOKEN, webhook: !!WEBHOOK_URL, heartbeat: !!HEARTBEAT_URL, phoneAck: !!(PUBLIC_URL && ACK_SECRET) },
  });
  if (u.pathname === '/api/ack' && req.method === 'POST') { if (state.alerts[key]) state.alerts[key].ack = true; save(); return json({ ok: true }); }
  if (u.pathname === '/api/test' && req.method === 'POST') { await notify('P1', T.testTitle, T.testBody, 'test'); return json({ ok: true }); }
  if (u.pathname === '/') return html(fs.readFileSync(path.join(DIR, 'index.html')));
  json({ error: 'not found' }, 404);
}).listen(PORT, HOST, () => {
  const ch = [NTFY_TOPIC && 'ntfy', TELEGRAM_BOT_TOKEN && 'telegram', WEBHOOK_URL && 'webhook'].filter(Boolean).join('+') || 'NONE (console only)';
  log(`Vigía on http://${HOST}:${PORT} — alerts: ${ch} — heartbeat: ${HEARTBEAT_URL ? 'yes' : 'NO'} — phone ack: ${PUBLIC_URL && ACK_SECRET ? 'yes' : 'no'}`);
  if (!['127.0.0.1', 'localhost', '::1'].includes(HOST) && !DASH_PASS) log('WARNING: dashboard exposed without DASH_PASS');
});

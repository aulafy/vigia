// Vigía — 24/7 watch over your clients' sites: uptime, TLS, exploited vulnerabilities (CISA KEV),
// vulnerable dependencies (OSV) and end-of-life software (endoflife.date). Zero dependencies.
import http from 'node:http';
import fs from 'node:fs';
import tls from 'node:tls';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Resolver } from 'node:dns/promises';
import crypto from 'node:crypto';
import * as L from './lib.mjs';
import { createAlerts } from './alerts.mjs';
import { validateAsset, validateWindow, inWindow } from './public/validate.js';
import * as AI from './ai.mjs';
import { messages } from './i18n.mjs';
import { renderReport, previousMonth, monthRange } from './report.mjs';

const DIR = path.dirname(fileURLToPath(import.meta.url));
const DATA = path.join(DIR, 'data');
fs.mkdirSync(DATA, { recursive: true });

// Minimal .env loader (real environment variables win; quotes are stripped).
// VIGIA_ENV_FILE points elsewhere (tests and the demo use an empty one, so they never reach your real channels).
try {
  for (const l of fs.readFileSync(process.env.VIGIA_ENV_FILE ?? path.join(DIR, '.env'), 'utf8').split('\n')) {
    const kv = L.parseEnvLine(l);
    if (kv && kv[1] && !process.env[kv[0]]) process.env[kv[0]] = kv[1];
  }
} catch {}
const {
  PORT = 4848, HOST = '127.0.0.1', DASH_PASS, VIGIA_LANG = 'en',
  NTFY_TOPIC, NTFY_SERVER = 'https://ntfy.sh', NTFY_TOKEN, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, WEBHOOK_URL,
  HEARTBEAT_URL, PUBLIC_URL, ACK_SECRET, DIGEST_HOUR = '9', DIGEST_TZ = process.env.TZ_DIGEST || 'Europe/Madrid',
  DNS_SERVERS = '1.1.1.1,8.8.8.8', HEARTBEAT_FAIL_URL, CHECKIN_SECRET, CANARY_DAYS = '7', CANARY_ACK_HOURS = '24',
  CONNECTIVITY_URLS = 'https://www.cloudflare.com/cdn-cgi/trace,https://1.1.1.1/', CHECKIN_ALLOW_MASTER = 'false', DASH_HOSTS = '',
  ALLOW_NO_PASSWORD = 'false', ACK_LINK_DAYS = '7', EDGE_VERSION_DAYS = '60', ADVISORY_MAX_AGE_DAYS = '45',
  EPSS_P1 = '0.5', EPSS_P2 = '0.1', EPSS_URL = 'https://api.first.org/data/v1/epss', ADVISORY_FEED_URLS = '', REPORT_BRAND = '',
  OLLAMA_MODEL = '', OLLAMA_URL = 'http://127.0.0.1:11434', OLLAMA_TIMEOUT_S = '120',
  WORDFENCE_API_KEY, WORDFENCE_HOURS = '6', WORDFENCE_URL = 'https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production',
} = process.env;
const INV = process.env.VIGIA_INV || path.join(DATA, 'inventory.json');
const STATE_F = process.env.VIGIA_STATE || path.join(DATA, 'state.json');
const T = messages(VIGIA_LANG);
const VERSION = JSON.parse(fs.readFileSync(path.join(DIR, 'package.json'), 'utf8')).version;
const UA = { 'user-agent': `vigia/${VERSION} (+https://github.com/aulafy/vigia)` };
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);
const START = Date.now();

// `node server.mjs key <asset-id>` prints the per-asset check-in key to install on that asset's servers
if (process.argv[2] === 'key') {
  if (!CHECKIN_SECRET || !process.argv[3]) { console.error('usage: CHECKIN_SECRET=… node server.mjs key <asset-id>'); process.exit(2); }
  console.log(L.deriveKey(CHECKIN_SECRET, process.argv[3]));
  process.exit(0);
}

if (!fs.existsSync(INV)) fs.copyFileSync(path.join(DIR, 'inventory.example.json'), INV);

// domain / dns / web hold the baselines that change alerts compare against
let state = { alerts: {}, status: {}, kev: { seen: [], seeded: false }, osv: {}, feeds: {}, scanned: {}, domain: {}, dns: {}, web: {},
  channels: {}, chain: null, canary: {}, backups: {}, adv: {}, epss: {}, history: [], avail: {}, groups: {}, coverage: {}, replay: {}, edgeSeen: {}, maintenance: [] };
if (fs.existsSync(STATE_F)) {
  try { state = { ...state, ...JSON.parse(fs.readFileSync(STATE_F, 'utf8')) }; }
  catch (e) {
    // keep the broken file for forensics instead of silently starting over
    const bad = `${STATE_F}.corrupt-${Date.now()}`;
    fs.renameSync(STATE_F, bad);
    log(`WARNING: ${STATE_F} unreadable (${e.message}), moved to ${bad}; starting with empty state`);
  }
}
// Durable write: temp file + fsync + rename + fsync of the folder, so neither a crash nor a power cut leaves half a file
function writeAtomic(file, data) {
  const tmp = `${file}.tmp`, fd = fs.openSync(tmp, 'w');
  try { fs.writeSync(fd, data); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(tmp, file);
  try { const d = fs.openSync(path.dirname(file), 'r'); try { fs.fsyncSync(d); } finally { fs.closeSync(d); } } catch {} // not supported everywhere
}
let saveErr = null;
function save() {
  try { writeAtomic(STATE_F, JSON.stringify(state)); if (saveErr) log('state is being saved again'); saveErr = null; }
  catch (e) { if (!saveErr) log('CANNOT SAVE STATE:', e.message); saveErr = e.message; }
}

// Inventories pushed by collectors live in their own file: they can be large and only change on a push
const PUSHED_F = process.env.VIGIA_PUSHED || path.join(DATA, 'pushed.json');
let pushed = {}, pushedVer = 0;
try { pushed = JSON.parse(fs.readFileSync(PUSHED_F, 'utf8')); } catch {}
const savePushed = () => { pushedVer++; try { writeAtomic(PUSHED_F, JSON.stringify(pushed)); } catch (e) { log('cannot save pushed inventory:', e.message); saveErr = e.message; } };

// Edits to inventory.json apply without a restart: the file is re-read when it changes (or after a push).
// A file that does not parse never empties the inventory: the last good copy stays in use and a P2 says so.
const inv$ = { key: null, assets: [], errors: [], broken: null };
function inventory({ includePaused = false } = {}) {
  let mtime = 0;
  try { mtime = fs.statSync(INV).mtimeMs; } catch {}
  const key = `${mtime}:${pushedVer}`;
  if (inv$.key !== key) {
    inv$.key = key;
    try {
      const res = L.loadInventory(JSON.parse(fs.readFileSync(INV, 'utf8')));
      for (const a of res.assets) if (pushed[a.id]?.stack) a.stack = L.dedupeStack([...a.stack, ...pushed[a.id].stack]);
      if (res.errors.join() !== inv$.errors.join() && res.errors.length) log('inventory:', res.errors.join('; '));
      Object.assign(inv$, { assets: res.assets, errors: res.errors, broken: null });
    } catch (e) {
      if (!inv$.broken) log(`inventory: ${INV}: ${e.message} — keeping the last valid inventory`);
      inv$.broken = e.message;
    }
  }
  return includePaused ? inv$.assets : inv$.assets.filter(a => !a.paused);
}

// Read at most `max` bytes of a response and drop the rest: a huge or endless page must not exhaust memory
async function readCapped(r, max = 3_000_000) {
  const reader = r.body?.getReader();
  if (!reader) return '';
  const chunks = [];
  let size = 0;
  try { while (size < max) { const { done, value } = await reader.read(); if (done) break; chunks.push(value); size += value.length; } }
  finally { reader.cancel().catch(() => {}); }
  return Buffer.concat(chunks).subarray(0, max).toString('utf8');
}

// Coverage: a check that keeps failing for one asset (or one feed) is a blind spot, even when the rest of the run succeeds
const COVER_AFTER = 3;
function cover(kind, id, ok, err, asset = null, label = id) {
  const k = `${kind}:${id}`, c = state.coverage[k] ||= { fails: 0 };
  if (ok) { if (c.fails) resolve(`cover:${k}`, T.coverageOk(kind, label)); Object.assign(c, { fails: 0, okAt: Date.now(), err: null }); return; }
  Object.assign(c, { fails: c.fails + 1, err: String(err || '').slice(0, 200), failAt: Date.now() });
  if (c.fails >= COVER_AFTER) raise(`cover:${k}`, 'P2', T.coverage(kind, label), T.coverageBody(c.err, c.fails, c.okAt), asset);
}

async function getJSON(url, opts = {}) {
  const r = await fetch(url, { headers: UA, signal: AbortSignal.timeout(30_000), ...opts });
  if (!r.ok) throw new Error(`${url} → HTTP ${r.status}`);
  return r.json();
}

// ---------- Notifications ----------
// Acknowledge links are bound to one alert instance (its creation time) and expire, so a leaked link cannot silence a future alert
function ackUrl(key) {
  const first = alerts.firstOf(key);
  if (!PUBLIC_URL || !ACK_SECRET || first == null) return null;
  const exp = Date.now() + +ACK_LINK_DAYS * 864e5;
  return `${PUBLIC_URL.replace(/\/$/, '')}/api/ack?key=${encodeURIComponent(key)}&f=${first}&e=${exp}&sig=${L.signAck(L.ackPayload(key, first, exp), ACK_SECRET)}`;
}

// Each channel: retried, and checked for real delivery (not just HTTP 200)
async function deliver(name, url, payload, headers = {}) {
  return L.retry(async () => {
    const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(payload), signal: AbortSignal.timeout(15_000) });
    const body = await r.json().catch(() => null);
    if (!L.deliveryOk(name, r.status, body)) throw new Error(`${name}: HTTP ${r.status}${body?.description ? ` ${body.description}` : body?.error ? ` ${body.error}` : ''}`);
  });
}

function channels(prio, title, body, ack) {
  const urgent = prio === 'P1';
  title = L.clip(title, 250); body = L.clip(body, 3500);
  return [
    NTFY_TOPIC && ['ntfy', () => deliver('ntfy', NTFY_SERVER, {
      topic: NTFY_TOPIC, title: `${prio} ${title}`, message: body, priority: urgent ? 5 : 4, tags: [urgent ? 'rotating_light' : 'warning'],
      ...(ack && { actions: [{ action: 'http', label: T.ack, url: ack, method: 'POST', clear: true }] }),
    }, NTFY_TOKEN ? { authorization: `Bearer ${NTFY_TOKEN}` } : {})],
    TELEGRAM_BOT_TOKEN && TELEGRAM_CHAT_ID && ['telegram', () => deliver('telegram', `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
      chat_id: TELEGRAM_CHAT_ID, text: `${urgent ? '🚨' : '⚠️'} ${prio} ${title}\n${body}${ack ? `\n\n${T.ack}: ${ack}` : ''}`, link_preview_options: { is_disabled: true },
    })],
    WEBHOOK_URL && ['webhook', () => deliver('webhook', WEBHOOK_URL, { prio, title, body, key: ack ? new URL(ack).searchParams.get('key') : null, ackUrl: ack })],
  ].filter(Boolean);
}
const channelCount = () => channels('P2', '', '').length;

// Last resort when no channel works: tell the external heartbeat service, which alerts you by its own means
const FAIL_URL = L.heartbeatFailUrl(HEARTBEAT_URL, HEARTBEAT_FAIL_URL);
let lastBroken = '';
async function failHeartbeat(reason) {
  if (!FAIL_URL) { if (reason !== lastBroken) log('ALERT CHAIN BROKEN and no heartbeat configured:', reason); lastBroken = reason; return; }
  await fetch(FAIL_URL, { method: 'POST', body: `Vigía: ${reason}`, signal: AbortSignal.timeout(10_000) }).catch(e => log('heartbeat /fail error:', e.message));
}

async function notify(prio, title, body, key) {
  if (prio === 'P3') return { sent: 0, failed: 0, total: 0 };
  const ack = key && key !== 'test' ? ackUrl(key) : null;
  log(`[${prio}] ${title} — ${body}`);
  const list = channels(prio, title, body, ack);
  if (!list.length) return { sent: 0, failed: 0, total: 0 };
  const results = await Promise.allSettled(list.map(([, send]) => send()));
  const failed = [];
  results.forEach((r, i) => {
    const name = list[i][0], ch = state.channels[name] ||= {};
    if (r.status === 'fulfilled') Object.assign(ch, { ok: true, lastOk: Date.now(), err: null });
    else { Object.assign(ch, { ok: false, lastFail: Date.now(), err: r.reason?.message }); failed.push(name); log('notify error:', r.reason?.message); }
  });
  if (failed.length === list.length) {
    state.chain = { ok: false, at: Date.now(), err: failed.map(n => state.channels[n].err).join('; ') };
    await failHeartbeat(`all alert channels failed — ${state.chain.err}`);
    return { sent: 0, failed: failed.length, total: list.length, errors: failed.map(n => state.channels[n].err) };
  }
  state.chain = { ok: true, at: Date.now() };
  // channel alerts go out through the channels that still work (raise deduplicates, so no loop)
  for (const [name] of list) {
    if (failed.includes(name)) raise(`channel:${name}`, 'P2', T.channelDown(name), T.channelDownBody(state.channels[name].err), null);
    else if (state.alerts[`channel:${name}`]) resolve(`channel:${name}`, T.channelOk(name));
  }
  return { sent: list.length - failed.length, failed: failed.length, total: list.length };
}

// ---------- Alert lifecycle (alerts.mjs: raise, escalate, group, deliver, retry) ----------
// Maintenance windows mute notifications for the assets they cover (an "all" window also mutes Vigía's own alerts)
const assetById = id => inv$.assets.find(a => a.id === id);
const muted = assetId => (assetId ? inWindow(state.maintenance, assetById(assetId) || { id: assetId }) : (state.maintenance || []).some(w => w.all && Date.parse(w.from) <= Date.now() && Date.now() < Date.parse(w.to)));
const alerts = createAlerts({ state, T, notify, applyAccept: L.applyAccept, save, isMuted: muted });
const { raise, resolve, send, onboard, histNote } = alerts;
const ackAlert = key => alerts.ack(key);
const monthOf = (t = Date.now()) => L.localClock(DIGEST_TZ, new Date(t)).day.slice(0, 7);

// Close alerts of one kind that the latest complete scan no longer reports
function prune(kind, assetIds, foundKeys, msg) {
  for (const a of Object.values(state.alerts))
    if (a.key.startsWith(kind + ':') && assetIds.has(a.asset) && !foundKeys.has(a.key)) resolve(a.key, msg, { quiet: a.prio !== 'P1' });
}

// ---------- Uptime + TLS (every 60 s) ----------
const tlsDays = (host, port = 443) => new Promise(res => {
  const s = tls.connect(port, host, { servername: net.isIP(host) ? undefined : host, timeout: 8000 }, () => {
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
    if (ok && a.expect) { if (!(await readCapped(r)).includes(a.expect)) { ok = false; why = T.expectMissing(a.expect); } }
    else await r.body?.cancel();
    if (!ok && !why) why = `HTTP ${code}`;
  } catch (e) { why = e.cause?.code || e.name || e.message; }
  Object.assign(st, { ms: Date.now() - t0, code, checkedAt: Date.now() });
  if (!muted(a.id)) { const av = ((state.avail[a.id] ||= {})[monthOf()] ||= [0, 0]); av[0]++; if (ok) av[1]++; }
  const key = `down:${a.id}`;
  st.lastProbeOk = ok;
  if (ok) { st.fails = 0; st.ok = true; resolve(key, T.up(a, st.ms)); }
  else {
    st.fails++;
    if (st.fails >= (a.failThreshold || 2)) { st.ok = false; raise(key, L.downPriority(a.criticality), T.down(a), T.downBody(a, why, st.fails), a.id); }
  }
  // TLS once per hour, on the host actually served (url) or the domain
  const tu = a.url?.startsWith('https://') ? new URL(a.url) : null, tlsHost = tu ? tu.hostname : a.url ? null : a.domain, tlsPort = +(tu?.port || 443);
  if (tlsHost && (!st.tlsAt || Date.now() - st.tlsAt > 3600_000)) {
    st.tlsAt = Date.now(); st.tlsDays = (await tlsDays(tlsHost, tlsPort)) ?? (await tlsDays(tlsHost, tlsPort)); // one retry: a blip is not an alert
    const k = `tls:${a.id}`, p = st.tlsDays === null ? null : L.tlsPriority(st.tlsDays);
    // a site that is down already has a down: alert, do not duplicate it
    if (st.tlsDays === null) { if (st.ok) raise(k, 'P2', T.tlsUnreadable(a), T.tlsUnreadableBody({ ...a, domain: tlsHost }), a.id); }
    else if (p) raise(k, p, T.tlsExpiring(a, st.tlsDays), tlsHost, a.id);
    else resolve(k, T.tlsRenewed);
  }
}

// ---------- CISA KEV (every 15 min) ----------
let kevSet = new Set();
async function checkKEV(inv) {
  const j = await getJSON('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
  kevSet = new Set(j.vulnerabilities.map(v => v.cveID));
  const seen = new Set(state.kev.seen), first = !state.kev.seeded, checked = state.kev.checked || {};
  const hit = (v, a, s) => raise(`kev:${v.cveID}:${a.id}`, s.edge ? 'P1' : L.kevPriority(a.criticality), T.kev(v),
    `${T.kevBody(a, s, v)}${s.edge ? ` ${T.huntHint}` : ''}${(v.notes || '').match(/https?:\/\/[^\s;]+/)?.[0] ? ` ${(v.notes || '').match(/https?:\/\/[^\s;]+/)[0]}` : ''}`,
    a.id, null, { term: L.kevTerm(s), ...(s.edge && { dev: `${a.id}:${s.edgeIndex}` }) });
  // 1. entries added since the last run, against every asset
  for (const v of j.vulnerabilities) {
    if (seen.has(v.cveID)) continue;
    seen.add(v.cveID);
    if (!first) for (const a of inv) for (const s of a.stack) if (L.kevMatches(v, s)) hit(v, a, s);
  }
  // 2. assets and products Vigía has not checked yet, against the last 90 days of the catalogue
  //    (name-only matching: older entries are mostly patched and would be noise; OSV/Wordfence cover exact versions)
  const recent = j.vulnerabilities.filter(v => Date.now() - new Date(v.dateAdded) < 90 * 864e5);
  for (const a of inv) {
    const done = new Set(checked[a.id] || []), current = new Set(a.stack.map(L.kevTerm).filter(Boolean));
    for (const s of a.stack) {
      const term = L.kevTerm(s);
      if (!term || done.has(term)) continue;
      for (const v of recent) if (L.kevMatches(v, s)) hit(v, a, s);
      done.add(term);
    }
    // a product removed and added back later is checked again; its old alerts close quietly
    checked[a.id] = [...done].filter(t => current.has(t));
    for (const al of Object.values(state.alerts)) if (al.key.startsWith('kev:') && al.asset === a.id && al.term && !current.has(al.term)) resolve(al.key, '', { quiet: true });
  }
  state.kev = { seen: [...seen], seeded: true, checked };
}

// ---------- OSV: exact dependency versions (every 30 min) ----------
// Cached for a week (severity gets revised); a failed fetch never aborts the scan and is not cached
async function osvDetails(id) {
  const c = state.osv[id];
  if (c && Date.now() - (c.at || 0) < 7 * 864e5) return c;
  try {
    const x = await getJSON(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`);
    return state.osv[id] = {
      at: Date.now(), sev: (x.database_specific?.severity || '').toUpperCase().replace('MODERATE', 'MEDIUM'),
      cves: [id, ...(x.aliases || [])].filter(z => z.startsWith('CVE-')), sum: x.summary || (x.details || '').slice(0, 160) || id,
    };
  } catch (e) { log('osv detail', id, e.message); return c || { sev: '', cves: id.startsWith('CVE-') ? [id] : [], sum: id }; }
}

// querybatch answers at most 1,000 vulnerabilities per package (3,000 per batch): follow next_page_token to the end
async function osvBatch(queries) {
  const out = queries.map(() => []);
  let todo = queries.map((q, i) => ({ i, q }));
  for (let page = 0; todo.length && page < 50; page++) {
    const r = await getJSON('https://api.osv.dev/v1/querybatch', { method: 'POST', headers: { ...UA, 'content-type': 'application/json' }, body: JSON.stringify({ queries: todo.map(t => t.q) }) });
    const next = [];
    todo.forEach((t, k) => { const res = r.results?.[k] || {}; out[t.i].push(...(res.vulns || [])); if (res.next_page_token) next.push({ i: t.i, q: { ...t.q, page_token: res.next_page_token } }); });
    todo = next;
  }
  if (todo.length) throw new Error('OSV kept paginating beyond 50 pages');
  return out;
}

async function checkOSV(inv) {
  // Each package version is queried once, however many assets share it (pushed inventories make this matter)
  const uses = new Map(), assets = new Set();
  for (const a of inv) for (const s of a.stack) if (s.ecosystem && s.name && s.version) {
    const k = `${s.ecosystem}\0${s.name}\0${s.version}`;
    if (!uses.has(k)) uses.set(k, { s, users: [] });
    uses.get(k).users.push(a);
    assets.add(a.id);
  }
  const q = [...uses.values()], found = new Set();
  for (let i = 0; i < q.length; i += 500) {
    const chunk = q.slice(i, i + 500);
    const results = await osvBatch(chunk.map(({ s }) => ({ package: { name: s.name, ecosystem: s.ecosystem }, version: s.version })));
    const ids = [...new Set(results.flatMap(vs => vs.map(v => v.id)))];
    const details = Object.fromEntries((await L.pool(ids, 8, osvDetails)).map((d, i) => [ids[i], d]));
    for (let k = 0; k < chunk.length; k++) for (const v of results[k]) {
      const { s, users } = chunk[k], d = details[v.id], inKev = d.cves.some(c => kevSet.has(c));
      for (const a of users) {
        const key = `osv:${v.id}:${a.id}:${s.name}`;
        found.add(key);
        raise(key, L.osvPriority({ sev: d.sev, inKev, criticality: a.criticality }), T.osv(a, s, v.id, inKev), T.osvBody(a, d), a.id);
      }
    }
  }
  prune('osv', assets, found, T.osvFixed);
}

// ---------- WordPress core, plugins and themes: Wordfence Intelligence v3 (match every 30 min, feed every 6 h) ----------
const WF_F = process.env.VIGIA_WORDFENCE || path.join(DATA, 'wordfence.json');
let wf = { at: 0, idx: null };
try { wf = JSON.parse(fs.readFileSync(WF_F, 'utf8')); } catch {}

async function wordfenceIndex() {
  if (wf.idx && Date.now() - wf.at < +WORDFENCE_HOURS * 3600_000) return wf.idx;
  let feed;
  try {
    const r = await fetch(WORDFENCE_URL, {
      headers: { ...UA, authorization: `Bearer ${WORDFENCE_API_KEY}` }, signal: AbortSignal.timeout(180_000),
    });
    if (!r.ok) { await r.body?.cancel(); throw new Error(`Wordfence feed HTTP ${r.status}${r.status === 401 ? ' (check WORDFENCE_API_KEY)' : ''}`); }
    feed = await r.json();
  } catch (e) {
    // a briefly unreachable feed is not a blind spot yet: keep matching with the cached copy for up to a day
    if (wf.idx && Date.now() - wf.at < 864e5) { log('wordfence refresh failed, using cached feed:', e.message); return wf.idx; }
    throw e;
  }
  wf = { at: Date.now(), idx: L.indexWordfence(feed) };
  fs.writeFileSync(WF_F + '.tmp', JSON.stringify(wf)); fs.renameSync(WF_F + '.tmp', WF_F);
  log(`wordfence: ${Object.keys(wf.idx).length} components indexed`);
  return wf.idx;
}

async function checkWordPress(inv) {
  const users = inv.filter(a => a.stack.some(s => s.wp && s.version));
  if (!users.length) return resolve('wp:nokey', '', { quiet: true });
  if (!WORDFENCE_API_KEY) return raise('wp:nokey', 'P3', T.wpNoKey, T.wpNoKeyBody(users.length), null);
  resolve('wp:nokey', '', { quiet: true });
  const idx = await wordfenceIndex(), found = new Set();
  for (const a of users) for (const it of a.stack.filter(s => s.wp && s.version)) for (const v of L.wpMatches(idx, it)) {
    const inKev = !!v.cve && kevSet.has(v.cve), key = `wp:${v.id}:${a.id}:${L.wpKey(it)}`;
    found.add(key);
    raise(key, L.wpPriority({ score: v.score, title: v.title, inKev, criticality: a.criticality }), T.wp(a, it, v, inKev), T.wpBody(a, it, v), a.id);
  }
  prune('wp', new Set(users.map(a => a.id)), found, T.wpFixed);
}

// ---------- Edge devices (every 15 min): vendor advisories, exposed management interface, portal certificate ----------
const FEEDS = {
  fortinet: 'https://filestore.fortinet.com/fortiguard/rss/ir.xml',
  paloalto: 'https://security.paloaltonetworks.com/rss.xml',
  cisco: 'https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml',
  incibe: 'https://www.incibe.es/incibe-cert/alerta-temprana/avisos/feed',
  // researchers who publish in-the-wild exploitation and scanning waves against edge devices, read for every device
  volexity: 'https://www.volexity.com/feed/',
  watchtowr: 'https://labs.watchtowr.com/rss/',
  greynoise: 'https://www.greynoise.io/blog/rss.xml',
  rapid7: 'https://www.rapid7.com/blog/rss/',
  // "name=url,name=url" replaces or adds feeds (mirrors, or another CERT)
  ...Object.fromEntries(ADVISORY_FEED_URLS.split(',').map(x => x.trim().split(/=(.*)/s)).filter(([k, v]) => k && v)),
};
const RESEARCH = ['volexity', 'watchtowr', 'greynoise', 'rapid7'];
const SOURCE = { fortinet: 'Fortinet PSIRT', paloalto: 'Palo Alto PSIRT', cisco: 'Cisco PSIRT', incibe: 'INCIBE-CERT', volexity: 'Volexity', watchtowr: 'watchTowr Labs', greynoise: 'GreyNoise', rapid7: 'Rapid7' };
const shortHash = x => crypto.createHash('sha1').update(String(x)).digest('hex').slice(0, 12);

// Reachability only: does anything complete a TCP (and for https, TLS) handshake at the address you declared?
function reachable(url, timeout = 8000) {
  return new Promise(res => {
    let u; try { u = new URL(url); } catch { return res(false); }
    const port = +u.port || (u.protocol === 'https:' ? 443 : 80), host = u.hostname.replace(/^\[|\]$/g, '');
    const opts = { host, port, timeout, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false };
    const s = u.protocol === 'https:' ? tls.connect(opts, () => { s.destroy(); res(true); }) : net.connect(opts, () => { s.destroy(); res(true); });
    s.on('error', () => res(false)); s.on('timeout', () => { s.destroy(); res(false); });
  });
}
// Certificate expiry even for self-signed portals (common on VPN gateways)
const certDays = url => new Promise(res => {
  let u; try { u = new URL(url); } catch { return res(null); }
  const s = tls.connect({ host: u.hostname, port: +u.port || 443, servername: net.isIP(u.hostname) ? undefined : u.hostname, rejectUnauthorized: false, timeout: 8000 }, () => {
    const c = s.getPeerCertificate(); s.destroy(); res(c?.valid_to ? Math.floor((new Date(c.valid_to) - Date.now()) / 864e5) : null);
  });
  s.on('error', () => res(null)); s.on('timeout', () => { s.destroy(); res(null); });
});

async function checkEdge(inv) {
  const devices = inv.flatMap(a => a.stack.filter(s => s.edge).map(s => ({ a, s, dev: `${a.id}:${s.edgeIndex}`, feeds: [...new Set([...s.feeds, ...RESEARCH])] })));
  if (!devices.length) return;
  // only the feeds some device needs; one failing feed does not stop the others, but three failures in a row are a P2
  const needed = [...new Set(devices.flatMap(d => d.feeds))].filter(f => FEEDS[f]), items = {};
  let failed = 0, lastErr = '';
  await L.pool(needed, 4, async f => {
    try {
      const r = await fetch(FEEDS[f], { headers: UA, signal: AbortSignal.timeout(30_000) });
      if (!r.ok) { await r.body?.cancel(); throw new Error(`HTTP ${r.status}`); }
      items[f] = L.parseFeed(await readCapped(r, 8_000_000));
      cover('feed', f, true, null, null, SOURCE[f] || f);
    } catch (e) { failed++; lastErr = `${f}: ${e.message}`; cover('feed', f, false, e.message, null, SOURCE[f] || f); }
  });
  if (needed.length && failed === needed.length) throw new Error(`no advisory feed reachable — ${lastErr}`);
  // old posts are history, not news: a device added today must not page for last year's research
  const fresh = it => !it.date || Date.now() - it.date < +ADVISORY_MAX_AGE_DAYS * 864e5;

  const isOnline = await online();
  await L.pool(devices, 6, async ({ a, s, dev, feeds }) => {
    // 1. advisories: new to this device, recent, and not a CVE this device was already alerted about (feeds overlap)
    const done = state.adv[dev] ||= { ids: [], cves: [] };
    for (const f of feeds) for (const it of items[f] || []) {
      if (done.ids.includes(it.id) || !L.advisoryMatches(it, s)) continue;
      done.ids.push(it.id);
      if (!fresh(it) || (it.cves.length && it.cves.every(c => done.cves.includes(c)))) continue;
      done.cves.push(...it.cves);
      const sev = L.advisorySeverity(it);
      raise(`adv:${dev}:${shortHash(it.id)}`, sev.prio, sev.recon ? T.advRecon(a, s, it) : T.adv(a, s, it, sev.exploited),
        `${T.advBody(a, s, it, SOURCE[f] || f)}${sev.exploited ? ` ${T.huntHint}` : ''}`, a.id, null, { dev, ...(sev.exploited && { exploited: true }) });
    }
    done.ids = done.ids.slice(-1000); done.cves = done.cves.slice(-2000);

    // 2. management interface reachable from the Internet (skipped while Vigía itself is offline).
    //    Exposed AND exploited right now is the worst case for a small business: one P1, not two separate alerts.
    if (s.management && isOnline) {
      const k = `edge:mgmt:${dev}`;
      const exploited = Object.values(state.alerts).some(x => x.dev === dev && !x.key.startsWith('edge:') && (x.exploited || x.key.startsWith('kev:')));
      if (await reachable(s.management)) raise(k, exploited ? 'P1' : 'P2', exploited ? T.mgmtExposedExploited(a, s) : T.mgmtExposed(a, s), T.mgmtExposedBody(s), a.id, null, { dev });
      else resolve(k, T.mgmtClosed);
    }
    // 3. portal certificate
    if (s.portal?.startsWith('https://')) {
      const days = await certDays(s.portal), p = days === null ? null : L.tlsPriority(days), k = `edge:tls:${dev}`;
      if (p) raise(k, p, T.edgeTls(a, s, days), s.portal, a.id); else if (days !== null) resolve(k, T.tlsRenewed);
    }
    // 4. a declared firmware version nobody has confirmed for weeks is probably wrong: matching would run on stale data
    const seen = state.edgeSeen[dev];
    if (!seen || seen.version !== s.version) state.edgeSeen[dev] = { version: s.version, since: Date.now() };
    const confirmed = Date.parse(s.checked || '') || state.edgeSeen[dev].since, ageDays = Math.floor((Date.now() - confirmed) / 864e5);
    if (s.version && ageDays > +EDGE_VERSION_DAYS) raise(`edge:version:${dev}`, 'P3', T.edgeVersionOld(a, s, ageDays), T.edgeVersionOldBody(s), a.id, null, { dev });
    else resolve(`edge:version:${dev}`, '', { quiet: true });
  });
}

// ---------- EPSS (every 2 h): escalate open vulnerability alerts that are likely to be exploited soon ----------
async function checkEpss() {
  const open = Object.values(state.alerts).filter(a => /^(osv|wp|kev|adv):/.test(a.key));
  const cvesOf = a => L.cvesIn(`${a.title} ${a.body}`);
  const want = [...new Set(open.flatMap(cvesOf))].filter(c => !state.epss[c] || Date.now() - state.epss[c].at > 864e5);
  for (let i = 0; i < want.length; i += 100) {
    const got = L.parseEpss(await getJSON(`${EPSS_URL}?cve=${want.slice(i, i + 100).join(',')}`));
    for (const c of want.slice(i, i + 100)) state.epss[c] = { ...(got[c] || { epss: 0, pct: 0 }), at: Date.now() };
  }
  for (const a of open) {
    const e = Math.max(0, ...cvesOf(a).map(c => state.epss[c]?.epss || 0));
    if (!e) continue;
    a.epss = e;
    const p = L.epssPriority(a.prio, e, { p1: +EPSS_P1, p2: +EPSS_P2 });
    if (p === a.prio) continue;
    alerts.escalate(a, p, T.epssUp(a.title, e)); // the risk changed: an earlier acknowledgement no longer covers it
  }
  for (const [c, v] of Object.entries(state.epss)) if (Date.now() - v.at > 7 * 864e5) delete state.epss[c];
}

// ---------- Pushed inventory: freshness (every 15 min) ----------
async function checkInventoryAge(inv) {
  let changed = false;
  for (const a of inv) if (a.inventoryMaxAgeHours && !pushed[a.id]) { pushed[a.id] = { since: Date.now() }; changed = true; }
  if (changed) savePushed();
  for (const a of inv) {
    const f = L.inventoryStale(a, pushed[a.id]);
    if (f) raise(`inv:stale:${a.id}`, 'P2', T.invStale(a), T.invStaleBody(f), a.id);
    else resolve(`inv:stale:${a.id}`, '', { quiet: true });
  }
}

// ---------- End of life (every 6 h) ----------
async function checkEOL(inv) {
  const cache = {}, found = new Set(), scanned = new Set();
  let complete = true, lookups = 0, failures = 0;
  for (const a of inv) for (const s of a.stack) {
    if (!s.eol || !s.version) continue;
    lookups++;
    scanned.add(a.id);
    if (!(s.eol in cache)) cache[s.eol] = await getJSON(`https://endoflife.date/api/${encodeURIComponent(s.eol)}.json`).catch(e => { log('eol', s.eol, e.message); return null; });
    const cycles = cache[s.eol];
    if (!Array.isArray(cycles)) { complete = false; failures++; continue; }
    const c = L.matchCycle(cycles, s.version), days = L.eolDays(c), p = L.eolPriority(days, a.criticality);
    if (!p) continue;
    const k = `eol:${a.id}:${s.eol}`;
    found.add(k);
    if (days < 0) raise(k, p, T.eolPast(a, s), T.eolPastBody(a, s, c), a.id);
    else raise(k, p, T.eolSoon(a, s, days), a.name, a.id);
  }
  if (lookups && failures === lookups) throw new Error('every endoflife.date lookup failed');
  if (complete) prune('eol', scanned, found, '');
}

const skips = (a, check) => (a.skip || []).includes(check);
const regOf = a => a.registrableDomain || L.registrableDomain(a.domain);

// ---------- Domain registration via RDAP (every 6 h) ----------
let rdapBoot = null, rdapBootAt = 0;
async function rdapFor(domain) {
  if (!rdapBoot || Date.now() - rdapBootAt > 864e5) { rdapBoot = await getJSON('https://data.iana.org/rdap/dns.json'); rdapBootAt = Date.now(); }
  const base = L.rdapBase(rdapBoot, domain);
  if (!base) return null; // TLD without public RDAP (e.g. .es)
  return L.parseRdap(await getJSON(`${base.replace(/\/?$/, '/')}domain/${encodeURIComponent(domain)}`, { headers: { ...UA, accept: 'application/rdap+json' } }));
}

async function checkDomains(inv) {
  const cache = {};
  let ok = 0, failed = 0, lastErr = '';
  for (const a of inv) {
    if (!a.domain || skips(a, 'domain')) continue;
    const d = regOf(a), base = state.domain[a.id] ||= {};
    let info;
    try { info = d in cache ? cache[d] : (cache[d] = await rdapFor(d)); ok++; cover('rdap', a.id, true, null, a.id, a.name || a.id); }
    catch (e) { failed++; lastErr = e.message; cover('rdap', a.id, false, e.message, a.id, a.name || a.id); continue; }

    const expires = info?.expires || a.domainExpires || null;
    if (!expires) raise(`domain:nordap:${a.id}`, 'P3', T.noRdap(a, d), T.noRdapBody(d), a.id);
    else resolve(`domain:nordap:${a.id}`, '', { quiet: true });
    const days = L.daysUntil(expires), p = L.domainExpiryPriority(days);
    if (p) raise(`domain:exp:${a.id}`, p, T.domainExpiring(a, d, days), T.domainExpiringBody(a, expires.slice(0, 10)), a.id);
    else resolve(`domain:exp:${a.id}`, T.domainRenewed);
    if (!info) continue;

    if (info.hold.length) raise(`domain:hold:${a.id}`, 'P1', T.domainHold(a, d), T.domainHoldBody(a, info.hold), a.id);
    else resolve(`domain:hold:${a.id}`, '');

    // Baselines: the first observation is trusted, later differences alert
    if (base.locked === undefined || info.locked) { base.locked = info.locked; resolve(`domain:lock:${a.id}`, '', { quiet: true }); }
    else if (base.locked && !info.locked) raise(`domain:lock:${a.id}`, 'P2', T.domainUnlocked(a, d), T.domainUnlockedBody(a), a.id, { path: ['domain', a.id, 'locked'], set: false });

    if (info.registrar) {
      if (!base.registrar || base.registrar.toLowerCase() === info.registrar.toLowerCase()) { base.registrar = info.registrar; resolve(`domain:registrar:${a.id}`, '', { quiet: true }); }
      else raise(`domain:registrar:${a.id}`, L.downPriority(a.criticality), T.domainRegistrar(a, d), T.domainRegistrarBody(a, base.registrar, info.registrar), a.id,
        { path: ['domain', a.id, 'registrar'], set: info.registrar });
    }
  }
  if (failed && !ok) throw new Error(lastErr);
}

// ---------- DNS against a baseline (every 5 min) ----------
const resolver = new Resolver({ timeout: 5000, tries: 2 });
resolver.setServers(DNS_SERVERS.split(',').map(s => s.trim()).filter(Boolean));

async function lookup(type, name) {
  try {
    const r = type === 'NS' ? await resolver.resolveNs(name)
      : type === 'MX' ? (await resolver.resolveMx(name)).map(x => x.exchange)
      : type === 'AAAA' ? await resolver.resolve6(name) : await resolver.resolve4(name);
    return L.normRecords(r);
  } catch (e) {
    if (e.code === 'ENODATA') return [];
    if (e.code === 'ENOTFOUND') return null; // NXDOMAIN
    throw e;
  }
}

async function checkDNS(inv) {
  let ok = 0, failed = 0, lastErr = '';
  await L.pool(inv, 10, async a => {
    if (!a.domain || skips(a, 'dns')) return;
    const d = regOf(a), base = state.dns[a.id] ||= {}, pend = base._pending ||= {};
    let assetFailed = null;
    // NS and MX of the registrable domain always; A/AAAA of the host only when asked (CDNs rotate IPs)
    for (const t of [...new Set(['NS', 'MX', ...(a.dnsWatch || []).map(x => String(x).toUpperCase())])]) {
      if (!['NS', 'MX', 'A', 'AAAA'].includes(t)) continue;
      const name = t === 'NS' || t === 'MX' ? d : a.domain;
      let cur;
      try { cur = await lookup(t, name); ok++; } catch (e) { failed++; lastErr = assetFailed = `${name} ${t}: ${e.code || e.message}`; continue; }
      if (t === 'NS') {
        if (cur === null) { pend.nx = (pend.nx || 0) + 1; if (pend.nx >= 2) raise(`dns:nx:${a.id}`, 'P1', T.dnsNx(a, d), T.dnsNxBody(a), a.id); continue; }
        pend.nx = 0;
        resolve(`dns:nx:${a.id}`, '');
      }
      if (cur === null) continue;
      compareBaseline(a, t, name, cur, prev => (t === 'NS' ? L.downPriority(a.criticality) : 'P2'));
    }

    // SPF and DMARC: audit what is missing (P3) and alert when protection against spoofing gets weaker (P2)
    if (skips(a, 'mail')) return cover('dns', a.id, !assetFailed, assetFailed, a.id, a.name || a.id);
    let spf, dmarc;
    try {
      spf = L.normRecords(L.spfRecords(await lookupTxt(d)));
      dmarc = L.normRecords(L.dmarcRecords(await lookupTxt(`_dmarc.${d}`)));
      ok++;
    } catch (e) { failed++; lastErr = `${d} TXT: ${e.code || e.message}`; return cover('dns', a.id, false, lastErr, a.id, a.name || a.id); }
    cover('dns', a.id, !assetFailed, assetFailed, a.id, a.name || a.id);
    const issues = [...L.spfIssues(spf), ...L.dmarcIssues(dmarc)];
    if (issues.length) raise(`mail:audit:${a.id}`, 'P3', T.mailAudit(a, d), T.mailAuditBody(a, issues.map(T.mailIssue)), a.id);
    else resolve(`mail:audit:${a.id}`, '', { quiet: true });
    compareBaseline(a, 'SPF', d, spf, prev => L.mailChangePriority('SPF', prev, spf));
    compareBaseline(a, 'DMARC', `_dmarc.${d}`, dmarc, prev => L.mailChangePriority('DMARC', prev, dmarc));
  });
  if (failed && !ok) throw new Error(lastErr);
}

// First value seen is the baseline; a different value must be seen twice in a row (a flaky resolver must not page anyone)
function compareBaseline(a, t, name, cur, prioFor) {
  const base = state.dns[a.id], pend = base._pending, key = `dns:${a.id}:${t}`;
  if (!base[t]) { base[t] = cur; return; }
  const diff = L.diffSets(base[t], cur);
  if (!diff.added.length && !diff.removed.length) { delete pend[t]; resolve(key, T.dnsBack(t)); return; }
  const sig = cur.join(',');
  pend[t] = pend[t]?.sig === sig ? { sig, n: pend[t].n + 1 } : { sig, n: 1 };
  if (pend[t].n < 2) return;
  raise(key, prioFor(base[t]), T.dnsChanged(a, name, t), T.dnsChangedBody(diff), a.id, { path: ['dns', a.id, t], set: cur });
}

async function lookupTxt(name) {
  try { return (await resolver.resolveTxt(name)).map(chunks => chunks.join('')); }
  catch (e) { if (e.code === 'ENODATA' || e.code === 'ENOTFOUND') return []; throw e; }
}

// ---------- Page content: redirects, defacement, new third-party scripts (every 15 min) ----------
async function checkContent(inv) {
  await L.pool(inv, 8, async a => {
    if ((!a.url && !a.domain) || skips(a, 'content') || state.status[a.id]?.ok === false) return; // a down site already alerts
    const url = a.url || `https://${a.domain}`;
    let r, html;
    try {
      r = await fetch(url, { redirect: 'follow', headers: UA, signal: AbortSignal.timeout(20_000) });
      if (!r.ok) { await r.body?.cancel(); return cover('content', a.id, false, `HTTP ${r.status}`, a.id, a.name || a.id); }
      html = await readCapped(r);
    } catch (e) { return cover('content', a.id, false, e.cause?.code || e.message, a.id, a.name || a.id); }
    cover('content', a.id, true, null, a.id, a.name || a.id);
    const site = a.domain || new URL(url).hostname, base = state.web[a.id] ||= {};
    const allowed = [...(a.allowedHosts || []), ...(base.allowed || [])];

    const off = [new URL(r.url).hostname, L.metaRefreshTarget(html, r.url)].find(h => h && L.isForeign(h, site, allowed));
    if (off) raise(`web:redirect:${a.id}`, L.downPriority(a.criticality), T.webRedirect(a, off), T.webRedirectBody(url, off), a.id, { path: ['web', a.id, 'allowed'], add: off });
    else resolve(`web:redirect:${a.id}`, '');

    const signs = L.defacementSigns(html, a.ignoreKeywords);
    if (signs.length) raise(`web:deface:${a.id}`, L.downPriority(a.criticality), T.webDeface(a), T.webDefaceBody(url, signs), a.id);
    else resolve(`web:deface:${a.id}`, T.webClean);

    // Foreign hosts that scripts load from, forms submit to and iframes embed; new ones alert
    const kinds = [
      ['scripts', 'script', L.scriptHosts, a.strictScripts ? 'P1' : 'P2', T.webScript, T.webScriptBody],
      ['forms', 'form', L.formHosts, L.downPriority(a.criticality), T.webForm, T.webFormBody],
      ['iframes', 'iframe', L.iframeHosts, 'P2', T.webIframe, T.webIframeBody],
    ];
    for (const [field, tag, extract, prio, title, body] of kinds) {
      const ext = extract(html, r.url).filter(h => L.isForeign(h, site, allowed));
      if (!base[field]) { base[field] = ext; continue; } // first sighting is the baseline
      for (const h of ext) if (!base[field].includes(h))
        raise(`web:${tag}:${a.id}:${h}`, prio, title(a, h), body(url, h), a.id, { path: ['web', a.id, field], add: h });
    }
  });
}

// ---------- Backups: signed check-ins from the backup jobs, judged against RPO (every 5 min and on each check-in) ----------
const jobsOf = inv => inv.flatMap(a => (a.backups || []).filter(j => j?.id).map(j => ({ a, j, key: `${a.id}/${j.id}` })));
const BACKUP_KINDS = ['failed', 'overdue', 'restore', 'shrunk'];

async function checkBackups(inv) {
  const now = Date.now();
  for (const { a, j, key } of jobsOf(inv)) {
    const rec = state.backups[key] ||= { since: now };
    const found = L.backupFindings(j, rec, now);
    for (const kind of BACKUP_KINDS) {
      const k = `backup:${kind}:${key}`, f = found.find(x => x.kind === kind);
      if (f) raise(k, kind === 'failed' || kind === 'overdue' ? j.priority || L.downPriority(a.criticality) : 'P2', T.backupTitle(kind, a, j), T.backupBody(f, a, j, rec), a.id);
      else resolve(k, T.backupOk(j), { quiet: kind === 'restore' || kind === 'shrunk' });
    }
  }
  // forget jobs removed from the inventory (paused assets keep theirs)
  const live = new Set(jobsOf(inventory({ includePaused: true })).map(x => x.key));
  for (const k of Object.keys(state.backups)) if (!live.has(k)) delete state.backups[k];
}

function readBody(req, max = 64 * 1024) {
  return new Promise((res, rej) => {
    const chunks = [];
    let size = 0;
    req.on('data', d => { size += d.length; if (size > max) { rej(new Error('body too large')); req.destroy(); } else chunks.push(d); });
    req.on('end', () => res(Buffer.concat(chunks).toString('utf8'))).on('error', rej);
  });
}

// POST /api/backup/<assetId>/<jobId>?status=start|success|fail|restore
// headers: x-vigia-timestamp (unix seconds), x-vigia-signature (HMAC, see lib.signCheckin)
// body (optional JSON): { bytes, objects, durationS, restoreTest: true | "YYYY-MM-DD", message }
// Shared by backup check-ins and inventory pushes: same secret, same signature scheme
// Accepts the per-asset key (`node server.mjs key <asset>`) and, unless CHECKIN_ALLOW_MASTER=false, the master secret
async function readSigned(req, u, max, assetId, scope) {
  const body = await readBody(req, max), sig = req.headers['x-vigia-signature'], ts = req.headers['x-vigia-timestamp'];
  const keys = CHECKIN_SECRET ? [L.deriveKey(CHECKIN_SECRET, assetId), ...(CHECKIN_ALLOW_MASTER === 'true' ? [CHECKIN_SECRET] : [])] : [];
  if (!keys.some(secret => L.verifyCheckin({ secret, ts, path: u.pathname + u.search, body, sig }))) return { ok: false, body, sig };
  const next = L.replayCheck(state.replay[scope], ts, sig);
  if (!next) return { ok: false, replay: true, body, sig };
  state.replay[scope] = next;
  return { ok: true, body, sig };
}

async function backupCheckin(req, u) {
  const [, , , assetId, jobId] = u.pathname.split('/').map(decodeURIComponent);
  const { ok, replay, body } = await readSigned(req, u, undefined, assetId, `backup:${assetId}/${jobId}`);
  if (replay) return [409, { error: 'replayed or out-of-order check-in' }];
  if (!ok) return [401, { error: 'bad or expired signature' }];
  const job = jobsOf(inventory({ includePaused: true })).find(x => x.a.id === assetId && x.j.id === jobId);
  if (!job) return [404, { error: `unknown backup job ${assetId}/${jobId}` }];
  const status = u.searchParams.get('status') || 'success';
  if (!['start', 'success', 'fail', 'restore'].includes(status)) return [400, { error: 'status must be start, success, fail or restore' }];
  let data = {};
  try { data = body ? JSON.parse(body) : {}; } catch { return [400, { error: 'body must be JSON' }]; }
  const rec = state.backups[job.key] ||= { since: Date.now() }, now = Date.now();
  delete rec.lastSig;
  if (status === 'start') rec.lastStart = now;
  if (status === 'fail') Object.assign(rec, { lastFail: now, lastMessage: String(data.message || '').slice(0, 300) });
  if (status === 'success') {
    rec.lastSuccess = now;
    if (Number.isFinite(data.bytes)) { rec.bytesHistory = [...(rec.bytesHistory || []), rec.lastBytes].filter(n => n != null).slice(-10); rec.lastBytes = data.bytes; }
    if (Number.isFinite(data.durationS)) rec.lastDurationS = data.durationS;
  }
  if (status === 'restore' || data.restoreTest) rec.lastRestoreTest = data.restoreTest && data.restoreTest !== true ? Date.parse(data.restoreTest) || now : now;
  await checkBackups(inventory());
  save();
  return [200, { ok: true, job: job.key, status }];
}

// POST /api/inventory/<assetId> — signed like check-ins; body { host, parts: [ {kind: wp|npm-lock|composer-lock|cyclonedx|spdx|os|runtime, …} ] }
// Replaces the asset's pushed stack. The declared stack in inventory.json is kept and merged.
async function inventoryPush(req, u) {
  const assetId = decodeURIComponent(u.pathname.split('/')[3] || '');
  const { ok, replay, body } = await readSigned(req, u, 16 * 1024 * 1024, assetId, `inv:${assetId}`);
  if (replay) return [409, { error: 'replayed or out-of-order push' }];
  if (!ok) return [401, { error: 'bad or expired signature' }];
  const asset = inventory({ includePaused: true }).find(a => a.id === assetId);
  if (!asset) return [404, { error: `unknown asset ${assetId}` }];
  let data;
  try { data = JSON.parse(body); } catch { return [400, { error: 'body must be JSON' }]; }
  const prev = pushed[assetId];
  const { stack, errors, total, truncated } = L.parsePush(data);
  if (!stack.length) return [400, { error: 'no components recognised', errors }];
  const first = !prev?.at;
  pushed[assetId] = { at: Date.now(), since: prev?.since, host: String(data.host || '').slice(0, 100), stack, errors, total };
  savePushed();
  // never cut silently: the components past the limit are not being checked
  if (truncated) raise(`inv:truncated:${assetId}`, 'P2', T.invTruncated(asset, total, L.MAX_PUSH), T.invTruncatedBody(asset), assetId);
  else resolve(`inv:truncated:${assetId}`, '', { quiet: true });
  // A first push can bring hundreds of packages: treat it as onboarding, so it is summarised instead of paging per finding
  if (first) for (const k of ['osv', 'eol', 'wp']) delete state.scanned[`${k}:${assetId}`];
  setTimeout(() => ['osv', 'wordpress', 'eol', 'inventory'].forEach(n => runners[n]?.()), 500);
  const count = t => stack.filter(t).length;
  return [200, { ok: true, asset: assetId, components: stack.length, total, truncated,
    wordpress: count(s => s.wp), packages: count(s => s.ecosystem), eol: count(s => s.eol), errors }];
}

// ---------- Inventory editing from the dashboard ----------
// Every write checks the revision the editor started from (a hand edit in between is never overwritten),
// keeps the previous file in data/inventory-history/ (last 20) and is atomic.
const INV_HISTORY = path.join(path.dirname(INV), 'inventory-history');
const LEGACY = ['cliente', 'criticidad', 'contacto'];
function readInventoryFile() {
  const text = fs.readFileSync(INV, 'utf8'), list = JSON.parse(text);
  if (!Array.isArray(list)) throw new Error('inventory.json must be a JSON array');
  return { list, rev: shortHash(text) };
}
function writeInventoryFile(list) {
  fs.mkdirSync(INV_HISTORY, { recursive: true });
  try { fs.copyFileSync(INV, path.join(INV_HISTORY, `inventory-${new Date().toISOString().replace(/[:.]/g, '-')}.json`)); } catch {}
  for (const f of fs.readdirSync(INV_HISTORY).sort().slice(0, -20)) fs.rmSync(path.join(INV_HISTORY, f), { force: true });
  const text = `${JSON.stringify(list, null, 2)}\n`;
  writeAtomic(INV, text);
  inventory(); // pick the change up now, not at the next cycle
  return shortHash(text);
}
// Drop empty optional fields and legacy Spanish names, so the file stays readable
const empty = v => v === '' || v == null || v === false || (Array.isArray(v) && !v.length);
function tidy(a, depth = 0) {
  const out = {};
  for (const [k, v] of Object.entries(a || {})) {
    if ((depth === 0 && LEGACY.includes(k)) || empty(v)) continue;
    // devices, backup jobs and software rows are tidied too; a row left completely empty is dropped
    out[k] = Array.isArray(v) && depth === 0 ? v.map(x => (x && typeof x === 'object' && !Array.isArray(x) ? tidy(x, 1) : x)).filter(x => !(x && typeof x === 'object' && !Object.keys(x).length)) : v;
    if (Array.isArray(out[k]) && !out[k].length) delete out[k];
  }
  return out;
}
const edgeTypes = Object.keys(L.EDGE);
async function editInventory(req, u) {
  let file;
  try { file = readInventoryFile(); } catch (e) { return [409, { error: 'inventoryBroken', detail: e.message }]; }
  if (req.method === 'GET') return [200, { rev: file.rev, assets: file.list, edgeTypes: Object.entries(L.EDGE).map(([type, c]) => ({ type, label: c.label })) }];
  let body = {};
  try { body = JSON.parse((await readBody(req, 256 * 1024)) || '{}'); } catch { return [400, { error: 'badJson' }]; }
  if (body.rev !== file.rev) return [409, { error: 'conflict', rev: file.rev }];
  const [, , , id, action] = u.pathname.split('/').map(decodeURIComponent);
  const ids = file.list.map(a => a.id), i = ids.indexOf(id);
  if (req.method === 'POST' && !id) {
    const asset = tidy(body.asset || {}), errors = validateAsset(asset, { ids, creating: true, edgeTypes });
    if (errors.length) return [422, { error: 'invalid', errors }];
    return [201, { ok: true, rev: writeInventoryFile([...file.list, asset]), id: asset.id }];
  }
  if (i < 0) return [404, { error: 'unknownAsset' }];
  if (req.method === 'POST' && action === 'pause') {
    const list = [...file.list];
    list[i] = tidy({ ...list[i], paused: !!body.paused });
    return [200, { ok: true, rev: writeInventoryFile(list) }];
  }
  if (req.method === 'PUT') {
    const asset = tidy(body.asset || {});
    if (asset.id !== id) return [422, { error: 'invalid', errors: [{ field: 'id', code: 'immutable' }] }]; // alerts and history are keyed on it
    const errors = validateAsset(asset, { ids, edgeTypes });
    if (errors.length) return [422, { error: 'invalid', errors }];
    const list = [...file.list]; list[i] = asset;
    return [200, { ok: true, rev: writeInventoryFile(list) }];
  }
  if (req.method === 'DELETE') return [200, { ok: true, rev: writeInventoryFile(file.list.filter(a => a.id !== id)) }];
  return [405, { error: 'method' }];
}

// ---------- Maintenance windows ----------
async function editMaintenance(req, u) {
  const now = Date.now();
  state.maintenance = (state.maintenance || []).filter(w => Date.parse(w.to) > now - 864e5); // keep yesterday's for the record
  if (req.method === 'GET') return [200, { windows: state.maintenance }];
  const id = decodeURIComponent(u.pathname.split('/')[3] || '');
  if (req.method === 'DELETE') {
    const before = state.maintenance.length;
    state.maintenance = state.maintenance.filter(w => w.id !== id);
    if (state.maintenance.length === before) return [404, { error: 'unknownWindow' }];
    save(); runners.health?.(); // alerts kept during the window go out now
    return [200, { ok: true }];
  }
  let w = {};
  try { w = JSON.parse((await readBody(req, 16 * 1024)) || '{}'); } catch { return [400, { error: 'badJson' }]; }
  const all = inventory({ includePaused: true });
  const errors = validateWindow(w, { ids: all.map(a => a.id), clients: clientsOf(all), now });
  if (errors.length) return [422, { error: 'invalid', errors }];
  const win = { id: crypto.randomBytes(5).toString('hex'), from: new Date(Date.parse(w.from)).toISOString(), to: new Date(Date.parse(w.to)).toISOString(),
    ...(w.all ? { all: true } : w.client ? { client: w.client } : { assets: w.assets }), ...(w.reason && { reason: String(w.reason) }), createdAt: new Date(now).toISOString() };
  state.maintenance.push(win);
  save();
  return [201, { ok: true, window: win }];
}

// ---------- Local AI (optional): explain an alert, or draft a message for the client ----------
// Nothing here decides or sends anything. One generation at a time (a laptop runs the model), results cached by alert text.
const aiCache = new Map();
let aiQueue = Promise.resolve();
function ollama(prompt) {
  const job = aiQueue.then(async () => {
    const r = await fetch(`${OLLAMA_URL.replace(/\/$/, '')}/api/generate`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, signal: AbortSignal.timeout(+OLLAMA_TIMEOUT_S * 1000),
      body: JSON.stringify({ model: OLLAMA_MODEL, prompt, stream: false, think: false, options: { temperature: 0.2, num_predict: 600 } }),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || j.error) throw new Error(j.error || `HTTP ${r.status}`);
    return j;
  });
  aiQueue = job.catch(() => {});
  return job;
}

// What Vigía knows about the asset, component, device or backup behind one alert
function alertContext(alert) {
  const all = inventory({ includePaused: true }), asset = all.find(a => a.id === alert.asset), parts = alert.key.split(':'), kind = parts[0];
  const ctx = { asset, now: Date.now() };
  if (!asset) return ctx;
  ctx.status = state.status[asset.id];
  ctx.domain = state.domain[asset.id];
  const { _pending, ...dns } = state.dns[asset.id] || {}; ctx.dns = dns;
  const pick = s => s && Object.fromEntries(Object.entries(s).filter(([k, v]) => !['edgeIndex', 'feeds', 'adv', 'kev', 'edge'].includes(k) && v != null));
  if (kind === 'osv') ctx.component = pick(asset.stack.find(x => x.ecosystem && x.name === parts.slice(3).join(':')));
  if (kind === 'wp') ctx.component = pick(asset.stack.find(x => x.wp && L.wpKey(x) === parts.slice(3).join(':')));
  if (kind === 'eol') ctx.component = pick(asset.stack.find(x => x.eol === parts[2]));
  if (kind === 'kev' && alert.term) ctx.component = pick(asset.stack.find(x => L.kevTerm(x) === alert.term));
  if (alert.dev) ctx.device = pick(asset.stack.find(x => x.edge && `${asset.id}:${x.edgeIndex}` === alert.dev));
  if (kind === 'backup') ctx.backup = state.backups[parts.slice(2).join(':')];
  ctx.maintenance = muted(asset.id);
  return ctx;
}

async function aiDraft(req, u) {
  if (!OLLAMA_MODEL) return [503, { error: 'aiDisabled' }];
  const mode = u.pathname.split('/')[3], key = u.searchParams.get('key'), lang = u.searchParams.get('lang') || VIGIA_LANG;
  if (!AI.MODES.includes(mode)) return [400, { error: 'unknownMode' }];
  const alert = state.alerts[key];
  if (!alert) return [404, { error: 'unknownAlert' }];
  const cacheKey = [mode, lang, key, shortHash(`${alert.prio}|${alert.title}|${alert.body}`)].join('|');
  if (aiCache.has(cacheKey) && u.searchParams.get('regen') !== '1') return [200, { ...aiCache.get(cacheKey), cached: true }];
  const t0 = Date.now();
  try {
    const j = await ollama(AI.promptFor(mode, AI.factsFor(alert, alertContext(alert)), lang));
    const text = AI.cleanOutput(j.response);
    if (!text) return [502, { error: 'emptyAnswer' }];
    const out = { text, model: OLLAMA_MODEL, ms: Date.now() - t0, ai: true };
    aiCache.set(cacheKey, out);
    if (aiCache.size > 100) aiCache.delete(aiCache.keys().next().value);
    return [200, out];
  } catch (e) {
    return e.name === 'TimeoutError' ? [504, { error: 'timeout', detail: `no answer in ${OLLAMA_TIMEOUT_S} s` }] : [502, { error: 'ollama', detail: e.message }];
  }
}

// ---------- Monthly report per client ----------
const clientsOf = inv => [...new Set(inv.map(a => a.client).filter(Boolean))].sort();
// "A&B" and "A B" would share a slug: a short hash keeps every client's file apart
const slug = x => `${String(x).toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'client'}-${shortHash(x).slice(0, 6)}`;

function reportData(client, month) {
  monthRange(month); // validates
  const assets = inventory({ includePaused: true }).filter(a => a.client === client);
  const ids = new Set(assets.map(a => a.id)), open = Object.values(state.alerts).filter(a => ids.has(a.asset));
  const openFor = prefix => open.filter(x => x.key.startsWith(prefix));
  return {
    client, month, brand: REPORT_BRAND, generatedAt: Date.now(), timeZone: DIGEST_TZ, open,
    history: state.history.filter(h => ids.has(h.asset)),
    assets: assets.map(a => ({
      id: a.id, name: a.name || a.id, url: a.url, domain: a.domain, criticality: a.criticality, avail: state.avail[a.id]?.[month] || null,
      pushedAt: pushed[a.id]?.at || null,
      edge: a.stack.filter(x => x.edge).map(x => ({ name: x.name, product: x.product, version: x.version,
        alerts: [`adv:${a.id}:${x.edgeIndex}:`, `edge:mgmt:${a.id}:${x.edgeIndex}`, `edge:tls:${a.id}:${x.edgeIndex}`].reduce((n, p) => n + openFor(p).length, 0) })),
    })),
    backups: jobsOf(assets).map(({ key }) => ({ key, ...(state.backups[key] || {}), problems: openFor('backup:').filter(x => x.key.endsWith(`:${key}`)).map(x => x.prio) })),
    maintenance: (state.maintenance || []).filter(w => w.all || w.client === client || (w.assets || []).some(id => ids.has(id))),
  };
}

const REPORTS = path.join(DATA, 'reports');
function writeReports(month) {
  fs.mkdirSync(REPORTS, { recursive: true });
  const clients = clientsOf(inventory({ includePaused: true }));
  for (const c of clients) writeAtomic(path.join(REPORTS, `${slug(c)}-${month}.html`), renderReport(reportData(c, month), VIGIA_LANG));
  return clients.length;
}

// `node server.mjs report "<client>" YYYY-MM > report.html` (or "all" to write every client into data/reports/)
if (process.argv[2] === 'report') {
  const [, , , client, month = previousMonth(monthOf())] = process.argv;
  if (!client) { console.error('usage: node server.mjs report "<client>"|all [YYYY-MM]'); process.exit(2); }
  if (client === 'all') console.error(`${writeReports(month)} reports written to ${REPORTS}`);
  else process.stdout.write(renderReport(reportData(client, month), VIGIA_LANG));
  process.exit(0);
}

// ---------- Scheduler ----------
const runners = {}; // name -> run(), so a push can trigger checks right away
const every = (name, ms, fn) => {
  let busy = false, again = false;
  const run = async () => {
    if (busy) { again = true; return; } // e.g. a push during a scan: scan again with the new inventory, do not drop it
    busy = true;
    try {
      await alerts.run(name, () => fn(inventory()));
      state.feeds[name] = Date.now(); state.feeds[name + 'Err'] = null;
    } catch (e) { log(name, 'error:', e.message); state.feeds[name + 'Err'] = e.message; }
    finally { busy = false; save(); }
    if (again) { again = false; setImmediate(run); }
  };
  runners[name] = run;
  run(); setInterval(run, ms);
};
// If Vigía's own connection is down, every site looks down: skip the round instead of paging 300 times.
// The uptime feed then goes stale and the heartbeat stops reaching its service, which is the right alarm.
async function online() {
  for (const url of CONNECTIVITY_URLS.split(',').map(x => x.trim()).filter(Boolean)) {
    try { const r = await fetch(url, { method: 'HEAD', signal: AbortSignal.timeout(5000) }); await r.body?.cancel(); return true; } catch {}
  }
  return false;
}
every('uptime', 60_000, async inv => {
  if (!(await online())) throw new Error('Vigía itself seems offline (connectivity probe failed): uptime round skipped');
  await L.pool(inv.filter(a => a.url || a.domain), 25, checkAsset);
});
every('kev', 15 * 60_000, inv => onboard(inv, 'kev', () => checkKEV(inv)));
setTimeout(() => every('osv', 30 * 60_000, inv => onboard(inv, 'osv', () => checkOSV(inv))), 15_000); // after KEV is loaded
setTimeout(() => every('eol', 6 * 3600_000, inv => onboard(inv, 'eol', () => checkEOL(inv))), 30_000);
setTimeout(() => every('dns', 5 * 60_000, inv => onboard(inv, 'dns', () => checkDNS(inv))), 5_000);
setTimeout(() => every('content', 15 * 60_000, inv => onboard(inv, 'web', () => checkContent(inv))), 20_000); // after the first uptime pass
setTimeout(() => every('domain', 6 * 3600_000, inv => onboard(inv, 'domain', () => checkDomains(inv))), 40_000);
every('backups', 5 * 60_000, checkBackups);
if (OLLAMA_MODEL) every('ai', 10 * 60_000, async () => {
  try {
    const tags = await getJSON(`${OLLAMA_URL.replace(/\/$/, '')}/api/tags`, { signal: AbortSignal.timeout(5000) });
    const has = (tags.models || []).some(m => m.name === OLLAMA_MODEL || m.name === `${OLLAMA_MODEL}:latest`);
    state.aiStatus = has ? { ok: true } : { ok: false, err: `model ${OLLAMA_MODEL} not installed (ollama pull ${OLLAMA_MODEL})` };
  } catch (e) { state.aiStatus = { ok: false, err: `Ollama not reachable at ${OLLAMA_URL}: ${e.message}` }; }
});
setTimeout(() => every('wordpress', 30 * 60_000, inv => onboard(inv, 'wp', () => checkWordPress(inv))), 25_000); // after KEV is loaded
every('inventory', 15 * 60_000, checkInventoryAge);
setTimeout(() => every('edge', 15 * 60_000, inv => onboard(inv, 'adv', () => checkEdge(inv))), 35_000); // after KEV is loaded
setTimeout(() => every('epss', 2 * 3600_000, checkEpss), 90_000); // after the first OSV / Wordfence / KEV results

// Watch the watcher: a feed that misses ~3 cycles is a blind spot
const STALE = { uptime: 5 * 60_000, kev: 60 * 60_000, osv: 2 * 3600_000, eol: 24 * 3600_000, dns: 20 * 60_000, content: 60 * 60_000, domain: 24 * 3600_000, wordpress: 2 * 3600_000, edge: 60 * 60_000, epss: 6 * 3600_000 };
every('health', 60_000, async () => {
  for (const [f, max] of Object.entries(STALE)) {
    // a feed that never succeeded since start counts from the start (a firewall blocking KEV from day one)
    const t = state.feeds[f] || START;
    if (Date.now() - t > max) raise(`feed:${f}`, 'P2', T.feedStale(f), T.feedStaleBody(Math.round((Date.now() - t) / 60_000), state.feeds[f + 'Err']), null);
    else if (state.feeds[f]) resolve(`feed:${f}`, T.feedOk(f));
  }
  const now = Date.now();

  // P1s ring again every 10 minutes, P2s that never reached a channel are retried, forgotten onboarding findings are announced
  alerts.sweep(now);
  if (saveErr) raise('vigia:disk', 'P1', T.diskError, T.diskErrorBody(saveErr), null); else resolve('vigia:disk', '');

  // Inventory problems are alerts, and while there are any nothing is deleted as an orphan
  inventory();
  if (inv$.broken) raise('inventory:invalid', 'P2', T.invInvalid, T.invInvalidBody(inv$.broken), null); else resolve('inventory:invalid', '');
  if (inv$.errors.length) raise('inventory:errors', 'P2', T.invErrors(inv$.errors.length), T.invErrorsBody(inv$.errors), null); else resolve('inventory:errors', '', { quiet: true });
  if (!inv$.broken && !inv$.errors.length) {
    const ids = new Set(inventory({ includePaused: true }).map(a => a.id));
    for (const a of Object.values(state.alerts)) if (a.asset && !ids.has(a.asset)) delete state.alerts[a.key];
    for (const m of [state.status, state.web, state.dns, state.domain, state.avail, state.kev.checked || {}]) for (const id of Object.keys(m)) if (!ids.has(id)) delete m[id];
    // per-device and per-asset records: devices removed from an asset go too
    const devs = new Set(inventory({ includePaused: true }).flatMap(a => a.stack.filter(x => x.edge).map(x => `${a.id}:${x.edgeIndex}`)));
    for (const m of [state.adv, state.edgeSeen]) for (const d of Object.keys(m)) if (!devs.has(d)) delete m[d];
    for (const al of Object.values(state.alerts)) if (al.dev && !devs.has(al.dev)) delete state.alerts[al.key];
    for (const k of Object.keys(state.coverage)) { const id = k.slice(k.indexOf(':') + 1); if (!k.startsWith('feed:') && !ids.has(id)) delete state.coverage[k]; }
    for (const k of Object.keys(state.replay)) { const id = k.slice(k.indexOf(':') + 1).split('/')[0]; if (!ids.has(id)) delete state.replay[k]; }
    for (const k of Object.keys(state.scanned)) if (!ids.has(k.slice(k.indexOf(':') + 1))) delete state.scanned[k];
    let gone = false;
    for (const id of Object.keys(pushed)) if (!ids.has(id)) { delete pushed[id]; gone = true; }
    if (gone) savePushed();
  }
  for (const [id, d] of Object.entries(state.osv)) if (now - (d.at || 0) > 30 * 864e5) delete state.osv[id];
  state.history = state.history.filter(h => !h.resolvedAt || now - h.resolvedAt < 400 * 864e5).slice(-20_000);
  const keepFrom = previousMonth(previousMonth(monthOf(now - 330 * 864e5)));
  for (const months of Object.values(state.avail)) for (const m of Object.keys(months)) if (m < keepFrom) delete months[m];

  // New month: write every client's report for the month that just ended (not on a fresh install: there is no data)
  const thisMonth = monthOf(now);
  if (state.feeds.reportMonth !== thisMonth) {
    if (!state.feeds.reportMonth) state.feeds.reportMonth = thisMonth;
    else {
      // marked done only once every file is written: a full disk is retried next minute, not skipped for a month
      try {
        const last = previousMonth(thisMonth), n = writeReports(last);
        state.feeds.reportMonth = thisMonth; state.feeds.reportErr = null;
        if (n) send('P2', T.reportsReady(n, last), T.reportsReadyBody(PUBLIC_URL && `${PUBLIC_URL.replace(/\/$/, '')}/#/informes`));
      } catch (e) { if (state.feeds.reportErr !== e.message) log('monthly reports:', e.message); state.feeds.reportErr = e.message; }
    }
  }
  // Broken chain: retry every 10 min with a message that also tells you alerts may have been lost
  if (state.chain?.ok === false && now - state.chain.at > 10 * 60_000) await notify('P2', T.chainRestored, T.chainRestoredBody);

  // Weekly canary: proves end to end that a human receives and acknowledges alerts
  let problem = !channelCount() ? 'no alert channel configured' : state.chain?.ok === false ? `all alert channels failed — ${state.chain.err}` : null;
  const days = +CANARY_DAYS, ackH = +CANARY_ACK_HOURS, c = state.canary;
  if (days > 0 && channelCount()) {
    const open = c.key && state.alerts[c.key];
    if (open && (open.ack || state.alerts['canary:missed']?.ack)) { delete state.alerts[c.key]; resolve('canary:missed', '', { quiet: true }); }
    else if (open && now - c.sentAt > ackH * 3600_000) { raise('canary:missed', 'P1', T.canaryMissed, T.canaryMissedBody(ackH), null); problem ||= 'weekly test alert not acknowledged'; }
    if (!state.alerts[c.key] && (!c.sentAt || now - c.sentAt > days * 864e5)) {
      Object.assign(c, { key: `canary:${new Date(now).toISOString().slice(0, 10)}`, sentAt: now });
      raise(c.key, 'P2', T.canary, T.canaryBody(ackH), null);
    }
  }

  // Heartbeat to an external service (healthchecks.io, Better Stack…): if Vigía dies, that service alerts you.
  // While the alert chain is broken it gets /fail instead, so it alerts you through its own channels.
  if (problem) await failHeartbeat(problem);
  else if (HEARTBEAT_URL) await fetch(HEARTBEAT_URL, { signal: AbortSignal.timeout(10_000) }).catch(e => log('heartbeat error:', e.message));
});

// Daily digest: new P3s + open, unacknowledged P2s
every('digest', 5 * 60_000, async () => {
  const { day, hour } = L.localClock(DIGEST_TZ);
  if (hour < +DIGEST_HOUR || state.feeds.digestDay === day) return;
  // a fresh install does not open with a digest, but what it finds from its first minute is in the next one
  if (!state.feeds.digestDay) { state.feeds.digestDay = day; state.feeds.digestFrom ??= START; return; }
  const now = Date.now(), since = state.feeds.digestFrom ?? now - 864e5;
  const { p2, p3 } = L.digestPick(Object.values(state.alerts), since);
  if (!p3.length && !p2.length) { Object.assign(state.feeds, { digestDay: day, digestFrom: now }); return; }
  const top = [...p2, ...p3].slice(0, 8).map(a => `• ${a.prio} ${a.title}`).join('\n');
  const r = await notify('P2', T.digest(p2.length, p3.length), top + (p2.length + p3.length > 8 ? `\n${T.more}` : ''));
  if (r.sent) Object.assign(state.feeds, { digestDay: day, digestFrom: now }); // otherwise retried at the next tick
});

// ---------- Dashboard + API ----------
const authHeader = DASH_PASS ? Buffer.from('Basic ' + Buffer.from('vigia:' + DASH_PASS).toString('base64')) : null;
const authOk = h => { const b = Buffer.from(String(h || '')); return b.length === authHeader.length && crypto.timingSafeEqual(b, authHeader); };
// Without a password, only these Host names may load the dashboard (blocks DNS-rebinding pages from reading it)
const dashHosts = new Set(['localhost', '127.0.0.1', '[::1]', HOST, PUBLIC_URL && new URL(PUBLIC_URL).hostname, ...DASH_HOSTS.split(',')].filter(Boolean).map(h => h.trim().toLowerCase()));
const PUBLIC = path.join(DIR, 'public');
const STATIC_TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.webmanifest': 'application/manifest+json' };
const STATIC = new Set(fs.existsSync(PUBLIC) ? fs.readdirSync(PUBLIC).filter(f => STATIC_TYPES[path.extname(f)]) : []);
const SECURITY_HEADERS = { 'x-frame-options': 'DENY', 'referrer-policy': 'no-referrer', 'x-content-type-options': 'nosniff',
  'content-security-policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'" };
// data responses must never be stored by a browser or proxy
const NO_STORE = { 'cache-control': 'no-store' };

// Repeated wrong passwords from one address: 10 failures in 10 minutes block it for 10 minutes
const authFails = new Map();
const authBlocked = ip => { const f = authFails.get(ip); return f && f.n >= 10 && Date.now() - f.at < 600_000; };
function authFailed(ip) {
  const f = authFails.get(ip);
  authFails.set(ip, f && Date.now() - f.at < 600_000 ? { n: f.n + 1, at: f.at } : { n: 1, at: Date.now() });
  if (authFails.size > 10_000) authFails.clear();
}

// Listening beyond this machine without a password exposes every client's inventory: refuse unless explicitly allowed
const LOCAL = ['127.0.0.1', 'localhost', '::1'].includes(HOST);
if (!LOCAL && !DASH_PASS && ALLOW_NO_PASSWORD !== 'true') {
  console.error(`Refusing to listen on ${HOST} without DASH_PASS. Set DASH_PASS (recommended), or ALLOW_NO_PASSWORD=true if a proxy in front already authenticates.`);
  process.exit(1);
}
const escHtml = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  const json = (o, c = 200) => { res.writeHead(c, { 'content-type': 'application/json', ...SECURITY_HEADERS, ...NO_STORE }); res.end(JSON.stringify(o)); };
  const html = (s, c = 200) => { res.writeHead(c, { 'content-type': 'text/html; charset=utf-8', ...SECURITY_HEADERS, ...NO_STORE }); res.end(s); };
  const ip = req.socket.remoteAddress || '';
  const denyAuth = () => { authFailed(ip); res.writeHead(401, { 'www-authenticate': 'Basic realm="Vigia"', ...NO_STORE }); return res.end('unauthorized'); };
  if (authHeader && authBlocked(ip)) { res.writeHead(429, { 'retry-after': '600', ...NO_STORE }); return res.end('too many failed logins'); }

  // the installable app shell (no client data in it)
  const file = u.pathname === '/' ? 'index.html' : u.pathname.slice(1);
  if (req.method === 'GET' && STATIC.has(file)) {
    if (file === 'index.html' && authHeader && !authOk(req.headers.authorization)) return denyAuth();
    res.writeHead(200, { 'content-type': STATIC_TYPES[path.extname(file)], 'cache-control': 'no-cache', ...SECURITY_HEADERS,
      ...(file === 'sw.js' && { 'service-worker-allowed': '/' }) });
    return res.end(fs.readFileSync(path.join(PUBLIC, file)));
  }

  // unauthenticated, so it says nothing about clients (feed errors contain their domains)
  if (u.pathname === '/healthz') return json({ ok: true, uptimeAt: state.feeds.uptime || null });

  // Signed acknowledge link from a notification: bound to one alert instance and an expiry.
  // GET shows a confirm button (link previews cannot acknowledge), POST acknowledges.
  const key = u.searchParams.get('key'), f = u.searchParams.get('f'), e = u.searchParams.get('e');
  const signed = !!key && /^\d+$/.test(f || '') && /^\d+$/.test(e || '') && +e > Date.now()
    && L.verifyAck(L.ackPayload(key, f, e), u.searchParams.get('sig'), ACK_SECRET) && String(alerts.firstOf(key)) === f;
  if (u.pathname === '/api/ack' && u.searchParams.has('sig')) {
    if (!signed) return html(`<!doctype html><meta name="viewport" content="width=device-width"><body style="font:16px system-ui;padding:24px"><p>${escHtml(T.ackLinkInvalid)}</p>`, 410);
    if (req.method === 'POST') { ackAlert(key); return req.headers.accept?.includes('text/html') ? html(`<p>${escHtml(T.acked)}</p>`) : json({ ok: true }); }
    const a = state.alerts[key], g = String(key).startsWith('group:') ? state.groups[key.slice(6)] : null;
    const items = g ? g.keys.map(k => state.alerts[k]).filter(Boolean) : a ? [a] : [];
    return html(`<!doctype html><meta name="viewport" content="width=device-width"><body style="font:16px system-ui;padding:24px">
      ${items.slice(0, 20).map(x => `<p><b>${escHtml(`${x.prio} ${x.title}`)}</b><br>${escHtml(g ? '' : x.body)}</p>`).join('')}
      <form method="post"><button style="font-size:18px;padding:12px 20px">${escHtml(g ? T.ackAll(items.length) : T.ack)}</button></form>`);
  }

  if (u.pathname.startsWith('/api/inventory/') && req.method === 'POST') {
    try { const [code, out] = await inventoryPush(req, u); return json(out, code); }
    catch (e) { return json({ error: e.message }, 400); }
  }
  if (u.pathname.startsWith('/api/backup/') && req.method === 'POST') {
    try { const [code, out] = await backupCheckin(req, u); return json(out, code); }
    catch (e) { return json({ error: e.message }, 400); }
  }

  if (authHeader && !authOk(req.headers.authorization)) return denyAuth();
  if (!authHeader && !dashHosts.has(String(req.headers.host || '').replace(/:\d+$/, '').toLowerCase()))
    return json({ error: 'host not allowed: add it to DASH_HOSTS, or set DASH_PASS' }, 421);
  // Dashboard actions need a header a cross-site form or image cannot send (CSRF on "Accept change")
  if (req.method !== 'GET' && req.method !== 'HEAD' && req.headers['x-vigia-ui'] !== '1') return json({ error: 'missing x-vigia-ui header' }, 403);

  if (u.pathname === '/api/state') return json({
    version: VERSION, lang: VIGIA_LANG, month: monthOf(),
    inventory: inventory({ includePaused: true }).map(a => ({ ...a, stack: a.stack.filter(x => !x.edge).slice(0, 6), stackCount: a.stack.length,
      edge: a.stack.filter(x => x.edge).map(({ name, type, product, version, portal, management, edgeIndex }) => ({ name, type, product, version, portal, management, edgeIndex })),
      avail: state.avail[a.id]?.[monthOf()] || null })),
    config: { ai: OLLAMA_MODEL ? { model: OLLAMA_MODEL, ...(state.aiStatus || { ok: null }) } : null, checkin: !!CHECKIN_SECRET, checkinMasterAllowed: CHECKIN_ALLOW_MASTER === 'true', saveError: saveErr, wordfence: !!WORDFENCE_API_KEY, dashPass: !!DASH_PASS,
      canaryDays: +CANARY_DAYS, epss: [+EPSS_P1, +EPSS_P2], digestHour: +DIGEST_HOUR, timeZone: DIGEST_TZ, brand: REPORT_BRAND, inventoryError: inv$.broken },
    status: state.status, alerts: Object.values(state.alerts), feeds: state.feeds,
    maintenance: (state.maintenance || []).filter(w => Date.parse(w.to) > Date.now()),
    channels: state.channels, chain: state.chain, wordfence: { configured: !!WORDFENCE_API_KEY, feedAt: wf.at || null },
    pushed: Object.fromEntries(Object.entries(pushed).map(([k, v]) => [k, { at: v.at || null, host: v.host, components: v.stack?.length || 0, errors: v.errors || [] }])), backups: state.backups,
    notify: { ntfy: !!NTFY_TOPIC, telegram: !!TELEGRAM_BOT_TOKEN, webhook: !!WEBHOOK_URL, heartbeat: !!HEARTBEAT_URL, phoneAck: !!(PUBLIC_URL && ACK_SECRET) },
  });
  if (u.pathname === '/api/ack' && req.method === 'POST') { ackAlert(key); return json({ ok: true }); }
  if (u.pathname === '/api/test' && req.method === 'POST') {
    const r = await notify('P1', T.testTitle, T.testBody, 'test');
    if (!r.total) return json({ ok: false, error: 'no alert channel configured' }, 400);
    return r.sent ? json({ ok: true, sent: r.sent, failed: r.failed }) : json({ ok: false, error: `no channel delivered it: ${(r.errors || []).join('; ')}` }, 502);
  }
  if (u.pathname === '/api/inventory' || u.pathname.startsWith('/api/assets')) {
    if (u.pathname === '/api/inventory' && req.method !== 'GET') return json({ error: 'method' }, 405);
    const [code, out] = await editInventory(req, u); return json(out, code);
  }
  if (u.pathname === '/api/maintenance' || u.pathname.startsWith('/api/maintenance/')) { const [code, out] = await editMaintenance(req, u); return json(out, code); }
  if (u.pathname.startsWith('/api/ai/') && req.method === 'POST') { const [code, out] = await aiDraft(req, u); return json(out, code); }
  if (u.pathname === '/api/reports') return json({ clients: clientsOf(inventory({ includePaused: true })), months: [monthOf(), previousMonth(monthOf())] });
  if (u.pathname === '/report') {
    const client = u.searchParams.get('client'), month = u.searchParams.get('month') || monthOf();
    if (!clientsOf(inventory({ includePaused: true })).includes(client)) return json({ error: 'unknown client' }, 404);
    try { return html(renderReport(reportData(client, month), u.searchParams.get('lang') || VIGIA_LANG)); }
    catch (e) { return json({ error: e.message }, 400); }
  }
  json({ error: 'not found' }, 404);
}).listen(PORT, HOST, () => {
  const ch = [NTFY_TOPIC && 'ntfy', TELEGRAM_BOT_TOKEN && 'telegram', WEBHOOK_URL && 'webhook'].filter(Boolean).join('+') || 'NONE (console only)';
  log(`Vigía on http://${HOST}:${PORT} — alerts: ${ch} — heartbeat: ${HEARTBEAT_URL ? 'yes' : 'NO'} — phone ack: ${PUBLIC_URL && ACK_SECRET ? 'yes' : 'no'}`);
  if (!LOCAL && !DASH_PASS) log('WARNING: listening without DASH_PASS (ALLOW_NO_PASSWORD=true)');
});

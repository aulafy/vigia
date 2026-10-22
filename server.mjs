// Vigía — 24/7 watch over your clients' sites: uptime, TLS, exploited vulnerabilities (CISA KEV),
// vulnerable dependencies (OSV) and end-of-life software (endoflife.date). Zero dependencies.
import http from 'node:http';
import fs from 'node:fs';
import tls from 'node:tls';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Resolver } from 'node:dns/promises';
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
  DNS_SERVERS = '1.1.1.1,8.8.8.8', HEARTBEAT_FAIL_URL, CHECKIN_SECRET, CANARY_DAYS = '7', CANARY_ACK_HOURS = '24',
  WORDFENCE_API_KEY, WORDFENCE_HOURS = '6', WORDFENCE_URL = 'https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production',
} = process.env;
const INV = process.env.VIGIA_INV || path.join(DATA, 'inventory.json');
const STATE_F = process.env.VIGIA_STATE || path.join(DATA, 'state.json');
const T = messages(VIGIA_LANG);
const REPEAT_P1_MS = 10 * 60_000;
const UA = { 'user-agent': 'vigia/0.6 (+https://github.com/aulafy/vigia)' };
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);

if (!fs.existsSync(INV)) fs.copyFileSync(path.join(DIR, 'inventory.example.json'), INV);

// domain / dns / web hold the baselines that change alerts compare against
let state = { alerts: {}, status: {}, kev: { seen: [], seeded: false }, osv: {}, feeds: {}, scanned: {}, domain: {}, dns: {}, web: {},
  channels: {}, chain: null, canary: {}, backups: {} };
try { state = { ...state, ...JSON.parse(fs.readFileSync(STATE_F, 'utf8')) }; } catch {}
// Atomic write: a crash mid-write cannot corrupt the state file
const save = () => { fs.writeFileSync(STATE_F + '.tmp', JSON.stringify(state, null, 1)); fs.renameSync(STATE_F + '.tmp', STATE_F); };

// Inventories pushed by collectors live in their own file: they can be large and only change on a push
const PUSHED_F = process.env.VIGIA_PUSHED || path.join(DATA, 'pushed.json');
let pushed = {};
try { pushed = JSON.parse(fs.readFileSync(PUSHED_F, 'utf8')); } catch {}
const savePushed = () => { fs.writeFileSync(PUSHED_F + '.tmp', JSON.stringify(pushed)); fs.renameSync(PUSHED_F + '.tmp', PUSHED_F); };

// Re-read on every cycle, so editing the inventory needs no restart. The pushed stack is merged into the declared one.
let lastInvErr = '';
function inventory({ includePaused = false } = {}) {
  let res;
  try { res = L.loadInventory(JSON.parse(fs.readFileSync(INV, 'utf8'))); }
  catch (e) { res = { assets: [], errors: [`${INV}: ${e.message}`] }; }
  const err = res.errors.join('; ');
  if (err && err !== lastInvErr) log('inventory:', err);
  lastInvErr = err;
  for (const a of res.assets) if (pushed[a.id]?.stack) a.stack = L.dedupeStack([...a.stack, ...pushed[a.id].stack]);
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
  if (prio === 'P3') return;
  const ack = key && key !== 'test' ? ackUrl(key) : null;
  log(`[${prio}] ${title} — ${body}`);
  const list = channels(prio, title, body, ack);
  if (!list.length) return;
  const results = await Promise.allSettled(list.map(([, send]) => send()));
  const failed = [];
  results.forEach((r, i) => {
    const name = list[i][0], ch = state.channels[name] ||= {};
    if (r.status === 'fulfilled') Object.assign(ch, { ok: true, lastOk: Date.now(), err: null });
    else { Object.assign(ch, { ok: false, lastFail: Date.now(), err: r.reason?.message }); failed.push(name); log('notify error:', r.reason?.message); }
  });
  if (failed.length === list.length) {
    state.chain = { ok: false, at: Date.now(), err: failed.map(n => state.channels[n].err).join('; ') };
    return failHeartbeat(`all alert channels failed — ${state.chain.err}`);
  }
  state.chain = { ok: true, at: Date.now() };
  // channel alerts go out through the channels that still work (raise deduplicates, so no loop)
  for (const [name] of list) {
    if (failed.includes(name)) raise(`channel:${name}`, 'P2', T.channelDown(name), T.channelDownBody(state.channels[name].err), null);
    else if (state.alerts[`channel:${name}`]) resolve(`channel:${name}`, T.channelOk(name));
  }
}

// ---------- Alert lifecycle ----------
// Assets in their first scan of a given kind: findings are stored silently and summarised in one message.
const onboarding = {}; // kind -> Set(assetId)
const inOnboarding = (key, asset) => Object.entries(onboarding).some(([k, s]) => key.startsWith(k + ':') && s.has(asset));

// raise: create an alert (deduplicated by key); an unacknowledged P1 is re-sent every 10 minutes.
// `accept` turns it into a change alert: acknowledging it makes the new value the baseline.
function raise(key, prio, title, body, asset, accept) {
  const now = Date.now(), a = state.alerts[key];
  if (accept) body = `${body} ${T.acceptHint}`;
  if (!a) {
    state.alerts[key] = { key, prio, title, body, asset, first: now, sentAt: now, ack: false, ...(accept && { accept }) };
    if (inOnboarding(key, asset)) state.alerts[key].ack = prio !== 'P1'; // P1s still ring
    else notify(prio, title, body, key);
  } else {
    Object.assign(a, { title, body }, accept && { accept });
    if (a.prio === 'P1' && !a.ack && now - a.sentAt > REPEAT_P1_MS) { a.sentAt = now; notify(prio, T.repeat(title), body, key); }
  }
}

function ackAlert(key) {
  const a = state.alerts[key];
  if (!a) return;
  if (a.accept) { L.applyAccept(state, a.accept); delete state.alerts[key]; }
  else a.ack = true;
  save();
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
    if (!c.P1 && !c.P2) return; // P3-only findings wait for the daily digest
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
    st.tlsAt = Date.now(); st.tlsDays = (await tlsDays(a.domain)) ?? (await tlsDays(a.domain)); // one retry: a blip is not an alert
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
    const r = await getJSON('https://api.osv.dev/v1/querybatch', {
      method: 'POST', headers: { ...UA, 'content-type': 'application/json' },
      body: JSON.stringify({ queries: chunk.map(({ s }) => ({ package: { name: s.name, ecosystem: s.ecosystem }, version: s.version })) }),
    });
    for (let k = 0; k < chunk.length; k++) for (const v of r.results[k]?.vulns || []) {
      const { s, users } = chunk[k], d = await osvDetails(v.id), inKev = d.cves.some(c => kevSet.has(c));
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

// ---------- Pushed inventory: freshness (every 15 min) ----------
async function checkInventoryAge(inv) {
  for (const a of inv) {
    if (a.inventoryMaxAgeHours && !pushed[a.id]) { pushed[a.id] = { since: Date.now() }; savePushed(); }
    const f = L.inventoryStale(a, pushed[a.id]);
    if (f) raise(`inv:stale:${a.id}`, 'P2', T.invStale(a), T.invStaleBody(f), a.id);
    else resolve(`inv:stale:${a.id}`, '', { quiet: true });
  }
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
    try { info = d in cache ? cache[d] : (cache[d] = await rdapFor(d)); ok++; }
    catch (e) { failed++; lastErr = e.message; continue; }

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
  state.feeds.domainPartialErr = failed ? lastErr : null;
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
  for (const a of inv) {
    if (!a.domain || skips(a, 'dns')) continue;
    const d = regOf(a), base = state.dns[a.id] ||= {}, pend = base._pending ||= {};
    // NS and MX of the registrable domain always; A/AAAA of the host only when asked (CDNs rotate IPs)
    for (const t of [...new Set(['NS', 'MX', ...(a.dnsWatch || []).map(x => String(x).toUpperCase())])]) {
      if (!['NS', 'MX', 'A', 'AAAA'].includes(t)) continue;
      const name = t === 'NS' || t === 'MX' ? d : a.domain;
      let cur;
      try { cur = await lookup(t, name); ok++; } catch (e) { failed++; lastErr = `${name} ${t}: ${e.code || e.message}`; continue; }
      if (t === 'NS') {
        if (cur === null) { pend.nx = (pend.nx || 0) + 1; if (pend.nx >= 2) raise(`dns:nx:${a.id}`, 'P1', T.dnsNx(a, d), T.dnsNxBody(a), a.id); continue; }
        pend.nx = 0;
        resolve(`dns:nx:${a.id}`, '');
      }
      if (cur === null) continue;
      compareBaseline(a, t, name, cur, prev => (t === 'NS' ? L.downPriority(a.criticality) : 'P2'));
    }

    // SPF and DMARC: audit what is missing (P3) and alert when protection against spoofing gets weaker (P2)
    if (skips(a, 'mail')) continue;
    let spf, dmarc;
    try {
      spf = L.normRecords(L.spfRecords(await lookupTxt(d)));
      dmarc = L.normRecords(L.dmarcRecords(await lookupTxt(`_dmarc.${d}`)));
      ok++;
    } catch (e) { failed++; lastErr = `${d} TXT: ${e.code || e.message}`; continue; }
    const issues = [...L.spfIssues(spf), ...L.dmarcIssues(dmarc)];
    if (issues.length) raise(`mail:audit:${a.id}`, 'P3', T.mailAudit(a, d), T.mailAuditBody(a, issues.map(T.mailIssue)), a.id);
    else resolve(`mail:audit:${a.id}`, '', { quiet: true });
    compareBaseline(a, 'SPF', d, spf, prev => L.mailChangePriority('SPF', prev, spf));
    compareBaseline(a, 'DMARC', `_dmarc.${d}`, dmarc, prev => L.mailChangePriority('DMARC', prev, dmarc));
  }
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
  for (const a of inv) {
    if (skips(a, 'content') || state.status[a.id]?.ok === false) continue; // a down site already alerts
    const url = a.url || `https://${a.domain}`;
    let r, html;
    try {
      r = await fetch(url, { redirect: 'follow', headers: UA, signal: AbortSignal.timeout(20_000) });
      if (!r.ok) { await r.body?.cancel(); continue; }
      html = (await r.text()).slice(0, 3_000_000);
    } catch { continue; }
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
  }
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
    let b = '';
    req.on('data', d => { b += d; if (b.length > max) { rej(new Error('body too large')); req.destroy(); } });
    req.on('end', () => res(b)).on('error', rej);
  });
}

// POST /api/backup/<assetId>/<jobId>?status=start|success|fail|restore
// headers: x-vigia-timestamp (unix seconds), x-vigia-signature (HMAC, see lib.signCheckin)
// body (optional JSON): { bytes, objects, durationS, restoreTest: true | "YYYY-MM-DD", message }
// Shared by backup check-ins and inventory pushes: same secret, same signature scheme
async function readSigned(req, u, max) {
  const body = await readBody(req, max), sig = req.headers['x-vigia-signature'];
  const ok = L.verifyCheckin({ secret: CHECKIN_SECRET, ts: req.headers['x-vigia-timestamp'], path: u.pathname + u.search, body, sig });
  return { ok, body, sig };
}

async function backupCheckin(req, u) {
  const [, , , assetId, jobId] = u.pathname.split('/').map(decodeURIComponent);
  const { ok, body, sig } = await readSigned(req, u);
  if (!ok) return [401, { error: 'bad or expired signature' }];
  const job = jobsOf(inventory({ includePaused: true })).find(x => x.a.id === assetId && x.j.id === jobId);
  if (!job) return [404, { error: `unknown backup job ${assetId}/${jobId}` }];
  const status = u.searchParams.get('status') || 'success';
  if (!['start', 'success', 'fail', 'restore'].includes(status)) return [400, { error: 'status must be start, success, fail or restore' }];
  let data = {};
  try { data = body ? JSON.parse(body) : {}; } catch { return [400, { error: 'body must be JSON' }]; }
  const rec = state.backups[job.key] ||= { since: Date.now() }, now = Date.now();
  if (rec.lastSig === sig) return [409, { error: 'replayed check-in' }];
  rec.lastSig = sig;
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
  const { ok, body, sig } = await readSigned(req, u, 16 * 1024 * 1024);
  if (!ok) return [401, { error: 'bad or expired signature' }];
  const asset = inventory({ includePaused: true }).find(a => a.id === assetId);
  if (!asset) return [404, { error: `unknown asset ${assetId}` }];
  let data;
  try { data = JSON.parse(body); } catch { return [400, { error: 'body must be JSON' }]; }
  const prev = pushed[assetId];
  if (prev?.lastSig === sig) return [409, { error: 'replayed push' }];
  const { stack, errors } = L.parsePush(data);
  if (!stack.length) return [400, { error: 'no components recognised', errors }];
  const first = !prev?.at;
  pushed[assetId] = { at: Date.now(), since: prev?.since, host: String(data.host || '').slice(0, 100), stack, lastSig: sig, errors };
  savePushed();
  // A first push can bring hundreds of packages: treat it as onboarding, so it is summarised instead of paging per finding
  if (first) for (const k of ['osv', 'eol', 'wp']) delete state.scanned[`${k}:${assetId}`];
  setTimeout(() => ['osv', 'wordpress', 'eol', 'inventory'].forEach(n => runners[n]?.()), 500);
  const count = t => stack.filter(t).length;
  return [200, { ok: true, asset: assetId, components: stack.length,
    wordpress: count(s => s.wp), packages: count(s => s.ecosystem), eol: count(s => s.eol), errors }];
}

// ---------- Scheduler ----------
const runners = {}; // name -> run(), so a push can trigger checks right away
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
  runners[name] = run;
  run(); setInterval(run, ms);
};
every('uptime', 60_000, inv => Promise.all(inv.map(checkAsset)));
every('kev', 15 * 60_000, checkKEV);
setTimeout(() => every('osv', 30 * 60_000, inv => onboard(inv, 'osv', () => checkOSV(inv))), 15_000); // after KEV is loaded
setTimeout(() => every('eol', 6 * 3600_000, inv => onboard(inv, 'eol', () => checkEOL(inv))), 30_000);
setTimeout(() => every('dns', 5 * 60_000, inv => onboard(inv, 'dns', () => checkDNS(inv))), 5_000);
setTimeout(() => every('content', 15 * 60_000, inv => onboard(inv, 'web', () => checkContent(inv))), 20_000); // after the first uptime pass
setTimeout(() => every('domain', 6 * 3600_000, inv => onboard(inv, 'domain', () => checkDomains(inv))), 40_000);
every('backups', 5 * 60_000, checkBackups);
setTimeout(() => every('wordpress', 30 * 60_000, inv => onboard(inv, 'wp', () => checkWordPress(inv))), 25_000); // after KEV is loaded
every('inventory', 15 * 60_000, checkInventoryAge);

// Watch the watcher: a feed that misses ~3 cycles is a blind spot
const STALE = { kev: 60 * 60_000, osv: 2 * 3600_000, eol: 24 * 3600_000, dns: 20 * 60_000, content: 60 * 60_000, domain: 24 * 3600_000, wordpress: 2 * 3600_000 };
every('health', 60_000, async () => {
  for (const [f, max] of Object.entries(STALE)) {
    const t = state.feeds[f];
    if (t && Date.now() - t > max) raise(`feed:${f}`, 'P2', T.feedStale(f), T.feedStaleBody(Math.round((Date.now() - t) / 60_000), state.feeds[f + 'Err']), null);
    else if (t) resolve(`feed:${f}`, T.feedOk(f));
  }
  // Drop alerts of assets removed from the inventory
  const ids = new Set(inventory({ includePaused: true }).map(a => a.id));
  for (const a of Object.values(state.alerts)) if (a.asset && !ids.has(a.asset)) delete state.alerts[a.key];
  const now = Date.now();
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
  const firstRun = !state.feeds.digestDay;
  state.feeds.digestDay = day;
  if (firstRun) return; // a fresh install does not open with a digest
  const since = Date.now() - 864e5, all = Object.values(state.alerts).filter(a => !a.key.startsWith('canary:'));
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
    if (req.method === 'POST') { ackAlert(key); return req.headers.accept?.includes('text/html') ? html(`<p>${escHtml(T.acked)}</p>`) : json({ ok: true }); }
    const a = state.alerts[key];
    return html(`<!doctype html><meta name="viewport" content="width=device-width"><body style="font:16px system-ui;padding:24px">
      <p><b>${escHtml(a ? `${a.prio} ${a.title}` : key)}</b></p><p>${escHtml(a?.body || '')}</p>
      <form method="post"><button style="font-size:18px;padding:12px 20px">${escHtml(T.ack)}</button></form>`);
  }

  if (u.pathname.startsWith('/api/inventory/') && req.method === 'POST') {
    try { const [code, out] = await inventoryPush(req, u); return json(out, code); }
    catch (e) { return json({ error: e.message }, 400); }
  }
  if (u.pathname.startsWith('/api/backup/') && req.method === 'POST') {
    try { const [code, out] = await backupCheckin(req, u); return json(out, code); }
    catch (e) { return json({ error: e.message }, 400); }
  }

  if (authHeader && req.headers.authorization !== authHeader) { res.writeHead(401, { 'www-authenticate': 'Basic realm="Vigia"' }); return res.end('unauthorized'); }

  if (u.pathname === '/api/state') return json({
    lang: VIGIA_LANG, inventory: inventory({ includePaused: true }), status: state.status, alerts: Object.values(state.alerts), feeds: state.feeds,
    channels: state.channels, chain: state.chain, wordfence: { configured: !!WORDFENCE_API_KEY, feedAt: wf.at || null },
    pushed: Object.fromEntries(Object.entries(pushed).map(([k, v]) => [k, { at: v.at || null, host: v.host, components: v.stack?.length || 0, errors: v.errors || [] }])), backups: Object.fromEntries(Object.entries(state.backups).map(([k, v]) => [k, { ...v, lastSig: undefined }])),
    notify: { ntfy: !!NTFY_TOPIC, telegram: !!TELEGRAM_BOT_TOKEN, webhook: !!WEBHOOK_URL, heartbeat: !!HEARTBEAT_URL, phoneAck: !!(PUBLIC_URL && ACK_SECRET) },
  });
  if (u.pathname === '/api/ack' && req.method === 'POST') { ackAlert(key); return json({ ok: true }); }
  if (u.pathname === '/api/test' && req.method === 'POST') { await notify('P1', T.testTitle, T.testBody, 'test'); return json({ ok: true }); }
  if (u.pathname === '/') return html(fs.readFileSync(path.join(DIR, 'index.html')));
  json({ error: 'not found' }, 404);
}).listen(PORT, HOST, () => {
  const ch = [NTFY_TOPIC && 'ntfy', TELEGRAM_BOT_TOKEN && 'telegram', WEBHOOK_URL && 'webhook'].filter(Boolean).join('+') || 'NONE (console only)';
  log(`Vigía on http://${HOST}:${PORT} — alerts: ${ch} — heartbeat: ${HEARTBEAT_URL ? 'yes' : 'NO'} — phone ack: ${PUBLIC_URL && ACK_SECRET ? 'yes' : 'no'}`);
  if (!['127.0.0.1', 'localhost', '::1'].includes(HOST) && !DASH_PASS) log('WARNING: dashboard exposed without DASH_PASS');
});

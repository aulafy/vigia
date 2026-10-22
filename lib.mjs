// Pure logic: no I/O, so it can be unit tested (see test/lib.test.mjs).
import crypto from 'node:crypto';

const LEVELS = { alta: 'high', media: 'medium', baja: 'low' };

// Accepts the English field names and the legacy Spanish ones (cliente, criticidad, contacto).
export function normalizeAsset(raw) {
  const a = { ...raw };
  a.client ??= raw.cliente;
  a.contact ??= raw.contacto;
  a.criticality = LEVELS[a.criticality ?? raw.criticidad] || a.criticality || raw.criticidad || 'medium';
  a.stack = Array.isArray(a.stack) ? a.stack : [];
  return a;
}

export function loadInventory(list) {
  const errors = [], ids = new Set(), assets = [];
  if (!Array.isArray(list)) return { assets, errors: ['inventory must be a JSON array'] };
  list.forEach((raw, i) => {
    const a = normalizeAsset(raw || {});
    if (!a.id) return errors.push(`#${i}: missing "id"`);
    if (ids.has(a.id)) return errors.push(`${a.id}: duplicate id`);
    if (!a.url && !a.domain) return errors.push(`${a.id}: needs "url" or "domain"`);
    if (!['high', 'medium', 'low'].includes(a.criticality)) errors.push(`${a.id}: criticality must be high, medium or low`);
    ids.add(a.id);
    assets.push(a);
  });
  return { assets, errors };
}

const reEscape = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Whole-word match of the stack item against a KEV entry, so "php" does not match "phpMyAdmin".
// `kev` overrides the search terms: "kev": ["apache http server"].
export function kevMatches(vuln, item) {
  const hay = `${vuln.vendorProject} ${vuln.product}`.toLowerCase();
  const terms = item.kev ? [].concat(item.kev) : item.product ? [item.product] : [];
  return terms.some(t => new RegExp(`(^|[^a-z0-9])${reEscape(String(t).toLowerCase())}($|[^a-z0-9])`).test(hay));
}

export const downPriority = criticality => (criticality === 'high' ? 'P1' : 'P2');
export const kevPriority = criticality => (criticality === 'high' ? 'P1' : 'P2');
export const tlsPriority = days => (days < 3 ? 'P1' : days < 14 ? 'P2' : null);

export function osvPriority({ sev, inKev, criticality }) {
  if (inKev || (sev === 'CRITICAL' && criticality === 'high')) return 'P1';
  return sev === 'CRITICAL' || sev === 'HIGH' ? 'P2' : 'P3';
}

// endoflife.date release cycles: "8.1.27" belongs to cycle "8.1"; the most specific cycle wins.
export function matchCycle(cycles, version) {
  const v = String(version);
  return cycles
    .filter(c => v === String(c.cycle) || v.startsWith(`${c.cycle}.`))
    .sort((x, y) => String(y.cycle).length - String(x.cycle).length)[0] || null;
}

export function eolDays(cycle, now = Date.now()) {
  if (!cycle || cycle.eol === false || cycle.eol == null) return null;
  if (cycle.eol === true) return -1;
  return Math.floor((new Date(cycle.eol) - now) / 864e5);
}

export function eolPriority(days, criticality) {
  if (days === null) return null;
  if (days < 0) return criticality === 'high' ? 'P2' : 'P3';
  return days < 90 ? 'P3' : null;
}

// Signed acknowledge links, so an alert can be acknowledged from the phone without the dashboard password.
export const signAck = (key, secret) => crypto.createHmac('sha256', secret).update(key).digest('hex').slice(0, 32);

export function verifyAck(key, sig, secret) {
  if (!secret || !key || typeof sig !== 'string') return false;
  const a = Buffer.from(signAck(key, secret)), b = Buffer.from(sig);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ---------- Domain (RDAP) ----------
// Second-level suffixes where the registrable domain has three labels. Override per asset with `registrableDomain`.
const MULTI_SLD = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'com.es', 'org.es', 'nom.es', 'gob.es', 'edu.es',
  'com.ar', 'com.mx', 'org.mx', 'com.br', 'com.au', 'net.au', 'org.au', 'co.jp', 'co.nz', 'com.co', 'com.pe', 'com.tr',
  'co.za', 'com.cn', 'co.in', 'com.pt']);

export function registrableDomain(host) {
  const h = String(host).toLowerCase().replace(/\.$/, '');
  if (/^[\d.]+$/.test(h) || h.includes(':')) return h; // IP address
  const p = h.split('.');
  if (p.length <= 2) return h;
  return p.slice(MULTI_SLD.has(p.slice(-2).join('.')) ? -3 : -2).join('.');
}

// IANA bootstrap file (https://data.iana.org/rdap/dns.json) → RDAP base URL for the domain's TLD, or null (e.g. .es)
export function rdapBase(bootstrap, domain) {
  const tld = domain.split('.').pop();
  for (const [tlds, urls] of bootstrap?.services || []) if (tlds.includes(tld)) return urls.find(u => u.startsWith('https://')) || urls[0];
  return null;
}

export function parseRdap(j) {
  const status = (j.status || []).map(s => String(s).toLowerCase());
  const reg = (j.entities || []).find(e => (e.roles || []).includes('registrar'));
  const fn = reg?.vcardArray?.[1]?.find(x => x[0] === 'fn')?.[3];
  return {
    expires: (j.events || []).find(e => e.eventAction === 'expiration')?.eventDate || null,
    status,
    registrar: fn || reg?.publicIds?.find(p => /iana/i.test(p.type))?.identifier || reg?.handle || null,
    locked: status.some(s => s.includes('transfer prohibited')),
    hold: status.filter(s => /hold|redemption|pending delete/.test(s)), // the domain stops resolving or is being deleted
  };
}

export const daysUntil = (date, now = Date.now()) => (date ? Math.floor((new Date(date) - now) / 864e5) : null);
export const domainExpiryPriority = days => (days === null || Number.isNaN(days) ? null : days < 7 ? 'P1' : days < 30 ? 'P2' : null);

// ---------- DNS ----------
// Empty values are dropped: a "null MX" (RFC 7505, exchange ".") means the domain receives no mail
export const normRecords = list => [...new Set(list.map(x => String(x).toLowerCase().replace(/\.$/, '')).filter(Boolean))].sort();

export function diffSets(before, after) {
  const b = new Set(before), a = new Set(after);
  return { added: after.filter(x => !b.has(x)), removed: before.filter(x => !a.has(x)) };
}

// ---------- Page content ----------
// A host is foreign when it belongs to another registrable domain and is not explicitly allowed (subdomains of allowed hosts count).
export function isForeign(host, siteHost, allowed = []) {
  const h = String(host).toLowerCase();
  if (registrableDomain(h) === registrableDomain(siteHost)) return false;
  return !allowed.some(x => h === x || h.endsWith('.' + x));
}

// Hosts referenced by <tag attr="…"> (script src, form action, iframe src). Relative URLs resolve to the page host.
export function tagHosts(html, pageUrl, tag, attr) {
  const hosts = new Set(), re = new RegExp(`<${tag}\\b[^>]*?\\b${attr}\\s*=\\s*["']?([^"'\\s>]+)`, 'gi');
  for (const m of html.matchAll(re)) {
    try {
      const u = new URL(m[1].replace(/&amp;/g, '&'), pageUrl);
      if (u.protocol === 'http:' || u.protocol === 'https:') hosts.add(u.hostname.toLowerCase());
    } catch {}
  }
  return [...hosts].filter(Boolean).sort();
}
export const scriptHosts = (html, pageUrl) => tagHosts(html, pageUrl, 'script', 'src');
export const formHosts = (html, pageUrl) => tagHosts(html, pageUrl, 'form', 'action');
export const iframeHosts = (html, pageUrl) => tagHosts(html, pageUrl, 'iframe', 'src');

// ---------- Mail policy (SPF / DMARC) ----------
export const spfRecords = txt => txt.filter(t => /^v=spf1(\s|$)/i.test(t));
export const dmarcRecords = txt => txt.filter(t => /^v=dmarc1(\s*;|$)/i.test(t));

export function spfIssues(records) {
  const spf = spfRecords(records);
  if (!spf.length) return ['spf-missing'];
  if (spf.length > 1) return ['spf-multiple']; // receivers treat this as a permanent error
  return /(^|\s)\+?all(\s|$)/i.test(spf[0]) ? ['spf-plusall'] : []; // "all" without - ~ ? lets anyone send
}

export function parseDmarc(records) {
  const d = dmarcRecords(records);
  if (d.length !== 1) return { count: d.length, p: null };
  const tags = Object.fromEntries(d[0].split(';').map(x => x.split('=').map(s => s.trim().toLowerCase())).filter(x => x[0] && x[1] !== undefined));
  return { count: 1, p: tags.p || null };
}

const DMARC_LEVEL = { none: 0, quarantine: 1, reject: 2 };
export function dmarcLevel(records) {
  const d = parseDmarc(records);
  return d.count === 1 ? DMARC_LEVEL[d.p] ?? -1 : -1;
}

export function dmarcIssues(records) {
  const d = parseDmarc(records);
  if (d.count === 0) return ['dmarc-missing'];
  if (d.count > 1) return ['dmarc-multiple'];
  return d.p === 'none' ? ['dmarc-none'] : [];
}

// A change that weakens protection against spoofing is P2; anything else (including improvements) is P3
export function mailChangePriority(type, before, after) {
  if (type === 'DMARC') return dmarcLevel(after) < dmarcLevel(before) ? 'P2' : 'P3';
  return spfIssues(after).length && !spfIssues(before).length ? 'P2' : 'P3';
}

// ---------- Alert delivery ----------
export async function retry(fn, delays = [2000, 8000]) {
  let err;
  for (let i = 0; i <= delays.length; i++) {
    try { return await fn(i); }
    catch (e) { err = e; if (i < delays.length) await new Promise(r => setTimeout(r, delays[i])); }
  }
  throw err;
}

// HTTP 200 is not proof of delivery: Telegram can answer {ok:false}, and ntfy returns the message id
export function deliveryOk(channel, status, body) {
  if (status < 200 || status >= 300) return false;
  if (channel === 'telegram') return body?.ok === true;
  if (channel === 'ntfy') return typeof body?.id === 'string';
  return true;
}

// healthchecks.io and Better Stack both accept "<ping url>/fail"
export const heartbeatFailUrl = (url, override) => override || (url ? `${url.replace(/\/+$/, '')}/fail` : null);

// ---------- Backup check-ins ----------
// Signature = HMAC-SHA256(secret, "<unix ts>.<path and query>.<body>"), hex. Valid for 5 minutes.
export const signCheckin = (secret, ts, path, body) => crypto.createHmac('sha256', secret).update(`${ts}.${path}.${body}`).digest('hex');

export function verifyCheckin({ secret, ts, path, body, sig, now = Date.now(), windowMs = 300_000 }) {
  if (!secret || !/^\d+$/.test(String(ts)) || typeof sig !== 'string') return false;
  if (Math.abs(now - Number(ts) * 1000) > windowMs) return false;
  const a = Buffer.from(signCheckin(secret, ts, path, body)), b = Buffer.from(sig.replace(/^sha256=/, '').toLowerCase());
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

const median = xs => { const s = [...xs].sort((a, b) => a - b), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };

// job: { rpoHours = 24, graceMinutes = 60, restoreTestDays?, minRatio = 0.5 }
// rec: { since, lastSuccess, lastFail, lastBytes, bytesHistory (previous runs), lastRestoreTest }
export function backupFindings(job, rec = {}, now = Date.now()) {
  const out = [], H = 3600_000;
  const ref = rec.lastSuccess || rec.since || now;
  if (rec.lastFail && rec.lastFail > (rec.lastSuccess || 0)) out.push({ kind: 'failed' });
  else if (now - ref > (job.rpoHours ?? 24) * H + (job.graceMinutes ?? 60) * 60_000)
    out.push({ kind: 'overdue', hours: Math.floor((now - ref) / H), never: !rec.lastSuccess });
  if (job.restoreTestDays) {
    const rt = rec.lastRestoreTest || rec.since || now;
    if (now - rt > job.restoreTestDays * 864e5) out.push({ kind: 'restore', days: Math.floor((now - rt) / 864e5), never: !rec.lastRestoreTest });
  }
  const hist = rec.bytesHistory || [];
  if (rec.lastBytes != null && hist.length >= 3) {
    const m = median(hist);
    if (m > 0 && rec.lastBytes < m * (job.minRatio ?? 0.5)) out.push({ kind: 'shrunk', bytes: rec.lastBytes, median: m });
  }
  return out;
}

export function metaRefreshTarget(html, pageUrl) {
  for (const [tag] of html.matchAll(/<meta\b[^>]*>/gi)) {
    if (!/http-equiv\s*=\s*["']?refresh/i.test(tag)) continue;
    const m = tag.match(/content\s*=\s*["'][^"']*?url\s*=\s*['"]?([^"'>\s;]+)/i);
    if (m) try { return new URL(m[1], pageUrl).hostname.toLowerCase(); } catch {}
  }
  return null;
}

// Typical signs of a defaced or SEO-spam-injected site. Comments are included on purpose: spam often hides there.
const DEFACE = [/\bhacked\s+by\b/i, /\bdefaced\s+by\b/i, /\bh[a4]ck[e3]d\s+by\b/i, /\b(buy|cheap)\s+(viagra|cialis|levitra)\b/i,
  /\bslot\s+gacor\b/i, /\bjudi\s+(online|slot|bola)\b/i, /\bsitus\s+slot\b/i];

export function defacementSigns(html, ignore = []) {
  const ign = ignore.map(i => String(i).toLowerCase());
  return [...new Set(DEFACE.map(re => html.match(re)?.[0]).filter(m => m && !ign.some(i => m.toLowerCase().includes(i))))];
}

// "Acknowledge" on a change alert accepts the new value as the baseline
export function applyAccept(root, { path, set, add }) {
  let o = root;
  for (const k of path.slice(0, -1)) o = o[k] ??= {};
  const last = path.at(-1);
  if (add !== undefined) o[last] = [...new Set([...(o[last] || []), add])].sort();
  else o[last] = set;
}

export function localClock(timeZone, date = new Date()) {
  const p = Object.fromEntries(new Intl.DateTimeFormat('en-CA', {
    timeZone, hourCycle: 'h23', hour: 'numeric', year: 'numeric', month: '2-digit', day: '2-digit',
  }).formatToParts(date).map(x => [x.type, x.value]));
  return { day: `${p.year}-${p.month}-${p.day}`, hour: +p.hour };
}

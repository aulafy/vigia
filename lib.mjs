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

export function scriptHosts(html, pageUrl) {
  const hosts = new Set();
  for (const m of html.matchAll(/<script\b[^>]*?\bsrc\s*=\s*["']?([^"'\s>]+)/gi)) {
    try { hosts.add(new URL(m[1].replace(/&amp;/g, '&'), pageUrl).hostname.toLowerCase()); } catch {}
  }
  return [...hosts].filter(Boolean).sort();
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

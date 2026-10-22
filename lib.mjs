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

export function localClock(timeZone, date = new Date()) {
  const p = Object.fromEntries(new Intl.DateTimeFormat('en-CA', {
    timeZone, hourCycle: 'h23', hour: 'numeric', year: 'numeric', month: '2-digit', day: '2-digit',
  }).formatToParts(date).map(x => [x.type, x.value]));
  return { day: `${p.year}-${p.month}-${p.day}`, hour: +p.hour };
}

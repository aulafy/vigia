// Pure logic: no I/O, so it can be unit tested (see test/lib.test.mjs).
import crypto from 'node:crypto';
import { suggestId, ID_RE } from './public/validate.js';

const LEVELS = { alta: 'high', media: 'medium', baja: 'low' };

// ---------- Edge devices (firewalls, VPN gateways, remote access) ----------
// The front door of most small-business breaches. `kev`: phrases matched against CISA KEV; `adv`: phrases matched
// against vendor advisories; `feeds`: which advisory feeds can mention it; `eol`: endoflife.date id.
export const EDGE = {
  fortigate: { label: 'FortiGate (FortiOS)', kev: ['fortios', 'fortiproxy'], adv: ['fortios', 'fortigate', 'fortiproxy', 'ssl-vpn', 'ssl vpn'], feeds: ['fortinet', 'incibe'], eol: 'fortios' },
  paloalto: { label: 'Palo Alto (PAN-OS / GlobalProtect)', kev: ['pan-os', 'globalprotect'], adv: ['pan-os', 'globalprotect gateway', 'globalprotect portal'], feeds: ['paloalto', 'incibe'], eol: 'panos' },
  'cisco-asa': { label: 'Cisco ASA / Firepower', kev: ['adaptive security appliance', 'firepower threat defense'], adv: ['adaptive security appliance', 'firepower threat defense', 'secure firewall asa'], feeds: ['cisco', 'incibe'] },
  'cisco-iosxe': { label: 'Cisco IOS XE', kev: ['ios xe'], adv: ['ios xe'], feeds: ['cisco', 'incibe'], eol: 'cisco-ios-xe' },
  ivanti: { label: 'Ivanti Connect Secure', kev: ['connect secure', 'policy secure'], adv: ['connect secure', 'policy secure'], feeds: ['incibe'] },
  netscaler: { label: 'Citrix NetScaler ADC / Gateway', kev: ['netscaler', 'citrix adc', 'citrix gateway'], adv: ['netscaler', 'citrix adc', 'citrix gateway'], feeds: ['incibe'] },
  sonicwall: { label: 'SonicWall (SonicOS / SMA)', kev: ['sonicos', 'sma100', 'secure mobile access'], adv: ['sonicwall', 'sonicos'], feeds: ['incibe'] },
  sophos: { label: 'Sophos Firewall', kev: ['sophos firewall', 'xg firewall'], adv: ['sophos firewall'], feeds: ['incibe'] },
  checkpoint: { label: 'Check Point Quantum', kev: ['quantum security gateway', 'check point security gateway'], adv: ['check point'], feeds: ['incibe'] },
  watchguard: { label: 'WatchGuard Firebox', kev: ['fireware'], adv: ['watchguard', 'fireware'], feeds: ['incibe'] },
  zyxel: { label: 'Zyxel firewall / VPN', kev: ['zyxel'], adv: ['zyxel'], feeds: ['incibe'] },
  mikrotik: { label: 'MikroTik RouterOS', kev: ['routeros'], adv: ['mikrotik', 'routeros'], feeds: ['incibe'], eol: 'routeros' },
  beyondtrust: { label: 'BeyondTrust Remote Support', kev: ['remote support', 'privileged remote access'], adv: ['beyondtrust'], feeds: ['incibe'] },
  screenconnect: { label: 'ConnectWise ScreenConnect', kev: ['screenconnect'], adv: ['screenconnect'], feeds: ['incibe'] },
  opnsense: { label: 'OPNsense', kev: ['opnsense'], adv: ['opnsense'], feeds: ['incibe'], eol: 'opnsense' },
};

// A declared device becomes a stack item, so KEV and end-of-life checks cover it like any other software.
// Unknown types work too when they bring their own `kev` / `adv` phrases.
export function edgeItem(d, i) {
  const c = EDGE[String(d.type || '').toLowerCase()] || {};
  return {
    edge: true, edgeIndex: i, type: d.type, name: d.name || c.label || d.type, product: c.label || d.type, version: d.version ? String(d.version) : undefined,
    kev: d.kev || c.kev || [d.type], adv: d.adv || c.adv || [d.type], feeds: d.feeds || c.feeds || ['incibe'], ...(c.eol && d.version && { eol: c.eol }),
    portal: d.portal, management: d.management, ...(d.checked && { checked: d.checked }),
  };
}

// Accepts the English field names and the legacy Spanish ones (cliente, criticidad, contacto).
export function normalizeAsset(raw) {
  const a = { ...raw };
  a.client ??= raw.cliente;
  a.contact ??= raw.contacto;
  a.criticality = LEVELS[a.criticality ?? raw.criticidad] || a.criticality || raw.criticidad || 'medium';
  a.stack = Array.isArray(a.stack) ? a.stack : [];
  a.edge = Array.isArray(a.edge) ? a.edge : [];
  if (a.edge.length) a.stack = [...a.stack, ...a.edge.map(edgeItem)];
  return a;
}

export function loadInventory(list) {
  const errors = [], ids = new Set(), assets = [];
  if (!Array.isArray(list)) return { assets, errors: ['inventory must be a JSON array'] };
  list.forEach((raw, i) => {
    const a = normalizeAsset(raw || {});
    if (!a.id) return errors.push(`#${i}: missing "id"`);
    if (ids.has(a.id)) return errors.push(`${a.id}: duplicate id`);
    if (!a.url && !a.domain && !a.edge.length && !a.machine) return errors.push(`${a.id}: needs "url", "domain", "edge" devices or "machine"`);
    a.edge.forEach((d, j) => { if (!d?.type) errors.push(`${a.id}: edge[${j}] needs a "type"`); });
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
// Windows carries several candidate cycles ("11-24h2-e-lts", "11-24h2-e", "11-24h2"): the first that exists wins
export const matchCycles = (cycles, versions) => versions.map(v => cycles.find(c => String(c.cycle) === String(v))).find(Boolean) || null;

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

// An acknowledge link is bound to the alert instance (its creation time) and expires
export const ackPayload = (key, first, exp) => `${key}|${first}|${exp}`;

// Signed calls must move forward in time: a captured older call cannot be replayed after a newer one (A, B, A).
// Calls in the same second are told apart by their signature. Returns the updated record, or null to reject.
export function replayCheck(rec = {}, ts, sig) {
  const t = Number(ts);
  if (rec.ts != null && t < rec.ts) return null;
  if (t === rec.ts && (rec.sigs || []).includes(sig)) return null;
  return { ts: t, sigs: t === rec.ts ? [...rec.sigs, sig].slice(-20) : [sig] };
}

// Daily digest: open unacknowledged P2s, and P3s created since the last digest that went out
export function digestPick(alerts, since) {
  const all = alerts.filter(a => !String(a.key).startsWith('canary:'));
  return { p2: all.filter(a => a.prio === 'P2' && !a.ack), p3: all.filter(a => a.prio === 'P3' && a.first > since) };
}

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

// ---------- Versions ----------
const PRE_RANK = { dev: 0, alpha: 1, a: 1, beta: 2, b: 2, pre: 3, preview: 3, rc: 4 };
const vparts = v => String(v).trim().replace(/^v/i, '').split(/[.\-_+~]/).filter(Boolean).flatMap(p => p.match(/\d+|[a-z]+/gi) || []);
const isNum = s => /^\d+$/.test(s);

// Like PHP's version_compare for the cases that matter: 1.0 = 1.0.0, 1.0-beta < 1.0 < 1.0.1, rc > beta
export function compareVersions(a, b) {
  const x = vparts(a), y = vparts(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    let p = x[i], q = y[i];
    if (p === undefined && isNum(q)) p = '0';
    if (q === undefined && isNum(p)) q = '0';
    if (p === undefined) return q.toLowerCase() in PRE_RANK ? 1 : -1;
    if (q === undefined) return p.toLowerCase() in PRE_RANK ? -1 : 1;
    if (isNum(p) && isNum(q)) { const d = Number(p) - Number(q); if (d) return Math.sign(d); continue; }
    if (isNum(p) !== isNum(q)) return isNum(p) ? 1 : -1;
    const rp = PRE_RANK[p.toLowerCase()], rq = PRE_RANK[q.toLowerCase()];
    const d = rp !== undefined && rq !== undefined ? rp - rq : p.toLowerCase().localeCompare(q.toLowerCase());
    if (d) return Math.sign(d);
  }
  return 0;
}

// Wordfence range: [from, fromInclusive, to, toInclusive]; "*" means unbounded
export function inRange(version, [from, fromInc, to, toInc]) {
  if (from && from !== '*') { const c = compareVersions(version, from); if (c < 0 || (c === 0 && !fromInc)) return false; }
  if (to && to !== '*') { const c = compareVersions(version, to); if (c > 0 || (c === 0 && !toInc)) return false; }
  return true;
}

// ---------- WordPress (Wordfence Intelligence v3) ----------
// Slim index of the feed: "plugin:<slug>" → vulnerabilities, so only what matching needs is kept in memory and on disk
export function indexWordfence(feed) {
  const idx = {};
  for (const v of Object.values(feed || {})) {
    if (v.informational) continue;
    for (const s of v.software || []) {
      (idx[`${s.type}:${s.slug}`] ||= []).push({
        id: v.id, title: v.title, score: v.cvss?.score ?? null, rating: v.cvss?.rating || '', cve: v.cve || null,
        ranges: Object.values(s.affected_versions || {}).map(r => [r.from_version, r.from_inclusive, r.to_version, r.to_inclusive]),
        patched: !!s.patched, fix: s.patched_versions || [],
      });
    }
  }
  return idx;
}

export const wpKey = item => `${item.wp}:${item.slug || (item.wp === 'core' ? 'wordpress' : '')}`;
export const wpMatches = (idx, item) => (idx[wpKey(item)] || []).filter(v => v.ranges.some(r => inRange(item.version, r)));

export function wpPriority({ score, title, inKev, criticality }) {
  if (inKev || (score >= 9 && (criticality === 'high' || /\bunauthenticated\b/i.test(title)))) return 'P1';
  return score >= 7 ? 'P2' : 'P3';
}

// ---------- Pushed inventory: parse what collectors send ----------
const OSV_ECO = { npm: 'npm', composer: 'Packagist', pypi: 'PyPI', golang: 'Go', maven: 'Maven', gem: 'RubyGems', cargo: 'crates.io', nuget: 'NuGet', hex: 'Hex', pub: 'Pub' };

// Package URL (https://github.com/package-url/purl-spec) → OSV query item
export function purlToItem(purl) {
  const m = /^pkg:([^/]+)\/([^?#]+)(?:\?([^#]*))?/.exec(String(purl || ''));
  if (!m) return null;
  const type = m[1].toLowerCase(), at = m[2].lastIndexOf('@');
  if (at <= 0) return null;
  const path = m[2].slice(0, at).split('/').map(decodeURIComponent), version = decodeURIComponent(m[2].slice(at + 1));
  const q = Object.fromEntries(new URLSearchParams(m[3] || ''));
  if (type === 'deb') {
    const d = /^(debian|ubuntu)-([\d.]+)/i.exec(q.distro || '');
    return d ? { ecosystem: d[1].toLowerCase() === 'debian' ? `Debian:${d[2].split('.')[0]}` : `Ubuntu:${d[2]}`, name: path.at(-1), version } : null;
  }
  if (type === 'apk') {
    const d = /(\d+\.\d+)/.exec(q.distro || '');
    return d ? { ecosystem: `Alpine:v${d[1]}`, name: path.at(-1), version } : null;
  }
  if (!OSV_ECO[type]) return null;
  const name = type === 'maven' ? path.join(':') : type === 'pypi' ? path.at(-1) : path.join('/');
  return { ecosystem: OSV_ECO[type], name, version: type === 'composer' ? version.replace(/^v/, '') : version };
}

export function npmLockItems(lock) {
  const out = [];
  if (lock?.packages) {
    for (const [p, v] of Object.entries(lock.packages)) {
      if (!p || v.dev || v.link || !v.version) continue; // "" is the project itself; dev dependencies are not deployed
      out.push({ ecosystem: 'npm', name: v.name || p.slice(p.lastIndexOf('node_modules/') + 13), version: v.version });
    }
  } else if (lock?.dependencies) {
    const walk = deps => { for (const [name, v] of Object.entries(deps)) {
      if (!v.dev && v.version && /^\d/.test(v.version)) out.push({ ecosystem: 'npm', name, version: v.version });
      if (v.dependencies) walk(v.dependencies);
    } };
    walk(lock.dependencies);
  }
  return out;
}

export const composerLockItems = lock => (lock?.packages || [])
  .filter(p => p.name && p.version && !/^dev-/.test(p.version))
  .map(p => ({ ecosystem: 'Packagist', name: p.name, version: String(p.version).replace(/^v/, '') }));

export function cyclonedxItems(bom) {
  const out = [], walk = list => { for (const c of list || []) { const i = purlToItem(c.purl); if (i) out.push(i); walk(c.components); } };
  walk(bom?.components);
  return out;
}

export const spdxItems = doc => (doc?.packages || []).flatMap(p => (p.externalRefs || [])
  .filter(r => r.referenceType === 'purl').map(r => purlToItem(r.referenceLocator)).filter(Boolean));

// OS and runtimes → endoflife.date ids (and KEV phrases where the product name alone is ambiguous)
const OS_EOL = { ubuntu: 'ubuntu', debian: 'debian', rhel: 'rhel', rocky: 'rocky-linux', almalinux: 'almalinux', centos: 'centos', alpine: 'alpine', fedora: 'fedora', opensuse: 'opensuse', sles: 'sles', amzn: 'amazon-linux' };
const RUNTIME = { php: {}, nodejs: {}, node: { eol: 'nodejs', product: 'nodejs' }, python: {}, nginx: {}, apache: { eol: 'apache-http-server', kev: ['apache http server'] },
  mysql: {}, mariadb: {}, postgresql: {}, redis: {}, openssl: {}, wordpress: {} };

export function parsePush(body) {
  const stack = [], errors = [], machine = {};
  for (const [i, part] of (Array.isArray(body?.parts) ? body.parts : []).entries()) {
    try {
      switch (part?.kind) {
        case 'wp':
          if (part.core) stack.push({ wp: 'core', slug: 'wordpress', product: 'wordpress', eol: 'wordpress', version: String(part.core).trim() });
          for (const [type, list] of [['plugin', part.plugins], ['theme', part.themes]])
            for (const p of list || []) if (p?.name && p.version) stack.push({ wp: type, slug: p.name, version: String(p.version), ...(p.status && { status: p.status }) });
          break;
        case 'npm-lock': stack.push(...npmLockItems(part.lock)); break;
        case 'composer-lock': stack.push(...composerLockItems(part.lock)); break;
        case 'cyclonedx': stack.push(...cyclonedxItems(part.bom)); break;
        case 'spdx': stack.push(...spdxItems(part.doc)); break;
        case 'os': {
          const id = String(part.id || '').toLowerCase();
          if (id === 'windows') {
            const w = windowsOs(part);
            machine.platform = 'windows'; machine.os = w.label;
            if (w.item) stack.push(w.item);
          } else if (id === 'macos') {
            machine.platform = 'macos'; machine.os = `macOS ${part.version || ''}`.trim();
            // `behind`: compared with the latest release of its cycle (macOS updates are not automatic everywhere)
            if (part.version) stack.push({ product: 'macos', eol: 'macos', version: String(part.version), behind: true });
          } else {
            if (part.name || part.version) { machine.platform ||= 'linux'; machine.os = String(part.name || `${id} ${part.version || ''}`).trim().slice(0, 80); }
            if (OS_EOL[id] && part.version) stack.push({ product: id, eol: OS_EOL[id], version: String(part.version) });
          }
          break;
        }
        case 'software': {
          const items = (Array.isArray(part.items) ? part.items : []).filter(x => x?.name).slice(0, MAX_SOFTWARE)
            .map(x => ({ name: clip(x.name, 120), version: x.version ? clip(x.version, 40) : undefined, publisher: x.publisher ? clip(x.publisher, 80) : undefined }));
          machine.software = items;
          stack.push(...items.map(softwareItem).filter(Boolean));
          break;
        }
        case 'listening': machine.listening = normListening(part.ports); break;
        case 'av': machine.av = (Array.isArray(part.products) ? part.products : []).slice(0, 10).map(p => ({
          name: clip(p?.name || '?', 80), enabled: typeof p?.enabled === 'boolean' ? p.enabled : null, realTime: typeof p?.realTime === 'boolean' ? p.realTime : null,
          upToDate: typeof p?.upToDate === 'boolean' ? p.upToDate : null, signaturesAt: Date.parse(p?.signaturesAt) || null, version: p?.version ? clip(p.version, 40) : null })); break;
        case 'patches': machine.patches = { lastInstalled: Date.parse(part.lastInstalled) || null, id: part.id ? clip(part.id, 20) : null }; break;
        case 'runtime': {
          const n = String(part.name || '').toLowerCase(), r = RUNTIME[n];
          if (r && part.version) stack.push({ product: r.product || n, eol: r.eol || n, version: String(part.version).replace(/^v/, ''), ...(r.kev && { kev: r.kev }) });
          break;
        }
        default: errors.push(`part ${i}: unknown kind "${part?.kind}"`);
      }
    } catch (e) { errors.push(`part ${i} (${part?.kind}): ${e.message}`); }
  }
  const all = dedupeStack(stack);
  return { stack: all.slice(0, MAX_PUSH), errors, total: all.length, truncated: all.length > MAX_PUSH, machine: Object.keys(machine).length ? machine : null };
}
export const MAX_PUSH = 20_000;
const MAX_SOFTWARE = 3000;

// ---------- Computers and servers: what the agent reports about the machine itself ----------
// endoflife.date ids its Windows cycles "11-24h2-w" (Home/Pro), "11-24h2-e" (Enterprise/Education), "10-22h2", "2022" (Server)
export function windowsOs({ productName = '', displayVersion = '', build = 0, edition = '', installationType = '' } = {}) {
  const server = /server/i.test(`${installationType} ${productName}`);
  if (server) {
    const m = /Server (\d{4})(?: (R2))?/i.exec(productName), cycle = m ? `${m[1]}${m[2] ? '-r2' : ''}` : null;
    return { label: clip(productName || 'Windows Server', 80), item: cycle && { product: 'windows server', eol: 'windows-server', version: cycle.replace('-r2', ' R2'), cycles: [cycle] } };
  }
  const major = +build >= 22000 ? 11 : 10, dv = String(displayVersion || '').toLowerCase(); // ProductName still says "Windows 10" on 11
  const ed = /enterprise|education|iot/i.test(edition) ? 'e' : 'w', lts = /ltsc|ltsb/i.test(`${edition} ${productName}`);
  const label = `Windows ${major}${dv ? ` ${dv.toUpperCase()}` : ''}${edition ? ` (${edition})` : ''}`;
  if (!dv) return { label, item: null };
  const cycles = [...(lts ? [`${major}-${dv}-${/iot/i.test(edition) ? 'iot' : 'e'}-lts`] : []), `${major}-${dv}-${ed}`, `${major}-${dv}`];
  return { label, item: { product: 'windows', eol: 'windows', version: `${major} ${dv.toUpperCase()}`, cycles } };
}

// Installed programs worth watching: the ones attackers go after, mapped to their CISA KEV names.
// `kevPrio: 'P3'` for software that updates itself (browsers, Office, Zoom): a KEV entry is news, not an emergency.
const SOFTWARE = [
  [/^google chrome$/i, 'Google Chrome', ['chromium', 'google chrome'], 'P3'],
  [/^microsoft edge$/i, 'Microsoft Edge', ['microsoft edge'], 'P3'],
  [/^(mozilla )?firefox\b/i, 'Mozilla Firefox', ['firefox'], 'P3'],
  [/^microsoft (office|365)\b/i, 'Microsoft Office', ['microsoft office'], 'P3'],
  [/^zoom(\.us| workplace)?\b/i, 'Zoom', ['zoom'], 'P3'],
  [/^7-zip\b/i, '7-Zip', ['7-zip']],
  [/^winrar\b/i, 'WinRAR', ['winrar']],
  [/^adobe acrobat\b/i, 'Adobe Acrobat / Reader', ['acrobat']],
  [/^foxit (pdf )?(reader|editor)/i, 'Foxit PDF', ['foxit']],
  [/^java( \d+)?( update \d+)?$|^java\(tm\)|^oracle java/i, 'Oracle Java', ['java se', 'java runtime environment']],
  [/^notepad\+\+/i, 'Notepad++', ['notepad++']],
  [/^anydesk\b/i, 'AnyDesk', ['anydesk']],
  [/^teamviewer\b/i, 'TeamViewer', ['teamviewer']],
  [/screenconnect/i, 'ConnectWise ScreenConnect', ['screenconnect']],
  [/simplehelp/i, 'SimpleHelp', ['simplehelp']],
  [/^splashtop/i, 'Splashtop', ['splashtop']],
  [/^filezilla\b/i, 'FileZilla', ['filezilla']],
  [/^winscp\b/i, 'WinSCP', ['winscp']],
  [/^putty\b/i, 'PuTTY', ['putty']],
  [/^vlc( media player)?\b/i, 'VLC', ['vlc']],
  [/^veeam backup/i, 'Veeam Backup & Replication', ['veeam']],
  [/^papercut/i, 'PaperCut', ['papercut']],
  [/manageengine/i, 'ManageEngine', ['manageengine']],
  [/moveit/i, 'MOVEit', ['moveit']],
  [/goanywhere/i, 'GoAnywhere MFT', ['goanywhere']],
  [/crushftp/i, 'CrushFTP', ['crushftp']],
  [/wing ftp/i, 'Wing FTP Server', ['wing ftp']],
  [/centrestack|triofox/i, 'Gladinet CentreStack', ['centrestack', 'triofox']],
  [/^forticlient/i, 'FortiClient', ['forticlient']],
  [/^globalprotect/i, 'GlobalProtect', ['globalprotect']],
  [/^cisco (anyconnect|secure client)/i, 'Cisco Secure Client', ['anyconnect', 'secure client']],
  [/^openvpn\b/i, 'OpenVPN', ['openvpn']],
  [/^microsoft exchange server/i, 'Microsoft Exchange Server', ['exchange server']],
  [/^microsoft sql server \d{4}( \(64-bit\))?$/i, 'Microsoft SQL Server', ['sql server']],
  [/^citrix workspace/i, 'Citrix Workspace', ['workspace app']],
  [/^vmware (workstation|player)/i, 'VMware Workstation', ['vmware workstation']],
  [/^vmware tools$/i, 'VMware Tools', ['vmware tools']],
];
export function softwareItem(sw) {
  const hit = SOFTWARE.find(([re]) => re.test(String(sw?.name || '').trim()));
  if (!hit) return null;
  const [, product, kev, kevPrio] = hit;
  return { product, kev, sw: true, ...(sw.version && { version: String(sw.version) }), ...(kevPrio && { kevPrio }) };
}
export const softwareCatalogue = () => SOFTWARE.map(([, product]) => product);

// Listening sockets: deduplicated, and marked "network" when bound beyond loopback
const LOOPBACK = /^(127\.|::1$|::ffff:127\.|localhost$|\[::1\]$)/i;
export function normListening(list) {
  const seen = new Map();
  for (const p of Array.isArray(list) ? list : []) {
    const port = +p?.port, proto = String(p?.proto || 'tcp').toLowerCase().replace(/[46]$/, '');
    if (!Number.isInteger(port) || port < 1 || port > 65535 || !['tcp', 'udp'].includes(proto)) continue;
    const addr = String(p.addr ?? '*').replace(/%.*$/, '').slice(0, 64), net = !LOOPBACK.test(addr);
    const k = `${proto}/${port}`, prev = seen.get(k);
    // the same port on 127.0.0.1 and 0.0.0.0 counts as the network one
    if (!prev || (net && !prev.network)) seen.set(k, { proto, port, addr, network: net, ...(p.process && { process: clip(p.process, 60) }) });
  }
  return [...seen.values()].sort((a, b) => a.port - b.port).slice(0, 500);
}
export const networkPorts = listening => (listening || []).filter(p => p.network).map(p => `${p.proto}/${p.port}`);

// Services that should not answer on the network of a small business. Windows always listens on 135/139/445: not news there.
export const RISKY_PORTS = { 21: 'FTP', 23: 'Telnet', 445: 'SMB', 1433: 'SQL Server', 2375: 'Docker API', 3306: 'MySQL', 3389: 'RDP',
  5432: 'PostgreSQL', 5900: 'VNC', 5901: 'VNC', 6379: 'Redis', 9200: 'Elasticsearch', 11211: 'memcached', 27017: 'MongoDB' };
const NO_AUTH = new Set([2375]); // anyone who reaches it is root on the host

/**
 * machineFindings(machine, now) → [{ kind, prio, ... }]
 * av: Windows without an active antivirus (P2) · avold: signatures older than 7 days (P3)
 * patch: Windows without updates for 45 days (P3) or 90 (P2) · risky: risky services listening on the network (P3; Docker API P2)
 */
export function machineFindings(m, now = Date.now()) {
  const out = [], days = t => Math.floor((now - t) / 864e5);
  const av = m?.av;
  if (m?.platform === 'windows' && Array.isArray(av)) {
    const active = av.filter(p => p.enabled !== false && p.realTime !== false);
    if (!active.length) out.push({ kind: 'av', prio: 'P2', products: av.map(p => p.name) });
  }
  const old = (av || []).filter(p => p.enabled !== false && (p.upToDate === false || (p.signaturesAt && days(p.signaturesAt) > 7)));
  if (old.length) out.push({ kind: 'avold', prio: 'P3', products: old.map(p => p.name), days: old.map(p => p.signaturesAt).filter(Boolean).map(days).sort((a, b) => b - a)[0] ?? null });
  const last = m?.patches?.lastInstalled;
  if (m?.platform === 'windows' && last && days(last) > 45) out.push({ kind: 'patch', prio: days(last) > 90 ? 'P2' : 'P3', days: days(last), id: m.patches.id });
  const risky = (m?.listening || []).filter(p => p.network && p.proto === 'tcp' && RISKY_PORTS[p.port] && !(m.platform === 'windows' && p.port === 445));
  if (risky.length) out.push({ kind: 'risky', prio: risky.some(p => NO_AUTH.has(p.port)) ? 'P2' : 'P3',
    services: risky.map(p => `${RISKY_PORTS[p.port]} (${p.proto}/${p.port}${p.process ? `, ${p.process}` : ''})`) });
  return out;
}

// ---------- Enrolment: one line on a computer adds it to a client ----------
// The token names the client and expires; it is signed with CHECKIN_SECRET, so nothing has to be stored
export function signEnroll(secret, client, expSec) {
  const sig = crypto.createHmac('sha256', secret).update(`vigia-enroll|${client}|${expSec}`).digest('hex').slice(0, 32);
  return `${Buffer.from(client, 'utf8').toString('base64url')}.${expSec}.${sig}`;
}
export function verifyEnroll(secret, token, now = Date.now()) {
  const [c, exp, sig] = String(token || '').split('.');
  if (!secret || !c || !/^\d{1,12}$/.test(exp || '') || !/^[0-9a-f]{32}$/.test(sig || '') || +exp * 1000 < now) return null;
  const client = Buffer.from(c, 'base64url').toString('utf8');
  const want = Buffer.from(signEnroll(secret, client, +exp).split('.')[2]);
  return want.length === sig.length && crypto.timingSafeEqual(want, Buffer.from(sig)) ? client : null;
}
// Re-running the line on the same computer reuses its asset; a different computer with the same name gets "-2"
export function enrollTarget(list, { client, host, machineId }) {
  const same = list.find(a => a.machineId && a.machineId === machineId && (a.client ?? a.cliente) === client);
  if (same) return { id: same.id, existing: true };
  const ids = new Set(list.map(a => a.id));
  let base = suggestId(client, host).slice(0, 58).replace(/-+$/, '');
  if (!ID_RE.test(base)) base = `pc-${machineId.slice(0, 8)}`;
  let id = base;
  for (let n = 2; ids.has(id); n++) id = `${base}-${n}`;
  return { id, existing: false };
}

const stackKey = s => (s.wp ? `wp:${wpKey(s)}@${s.version}` : s.ecosystem ? `${s.ecosystem}:${s.name}@${s.version}` : `${s.product}@${s.version}`);
export function dedupeStack(list) {
  const seen = new Map();
  for (const s of list) if (!seen.has(stackKey(s))) seen.set(stackKey(s), s);
  return [...seen.values()];
}

// An asset expects pushes once it has pushed (default 48 h) or when inventoryMaxAgeHours is set
export function inventoryStale(asset, rec, now = Date.now()) {
  const maxH = asset.inventoryMaxAgeHours ?? (rec?.at ? 48 : null);
  if (!maxH) return null;
  const ref = rec?.at || rec?.since || now, hours = Math.floor((now - ref) / 3600_000);
  return now - ref > maxH * 3600_000 ? { hours, never: !rec?.at, maxH } : null;
}

// ---------- Vendor advisories (RSS) ----------
const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };
const codePoint = n => (Number.isInteger(n) && n >= 0 && n <= 0x10ffff && !(n >= 0xd800 && n <= 0xdfff) ? String.fromCodePoint(n) : '\ufffd');
const decode = s => s.replace(/&(#x[\da-f]+|#\d+|\w+);/gi, (m, e) => e[0] === '#'
  ? codePoint(e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : +e.slice(1)) : ENTITIES[e.toLowerCase()] ?? m);
export const htmlText = s => decode(decode(String(s || '')).replace(/<!\[CDATA\[|\]\]>/g, '').replace(/<[^>]*>/g, ' ')).replace(/\s+/g, ' ').trim();

// Minimal RSS/Atom reader: enough for vendor PSIRT feeds, no XML library
export function parseFeed(xml) {
  const items = [];
  for (const [, block] of String(xml).matchAll(/<(?:item|entry)\b[^>]*>([\s\S]*?)<\/(?:item|entry)>/gi)) {
    const tag = t => block.match(new RegExp(`<${t}\\b[^>]*>([\\s\\S]*?)</${t}>`, 'i'))?.[1] ?? '';
    const link = htmlText(tag('link')) || block.match(/<link\b[^>]*href="([^"]+)"/i)?.[1] || '';
    const title = htmlText(tag('title')), text = htmlText(tag('description') || tag('summary') || tag('content'));
    const date = Date.parse(htmlText(tag('pubDate') || tag('updated') || tag('published')));
    items.push({ id: htmlText(tag('guid') || tag('id')) || link || title, title, link: link.trim(), text: text.slice(0, 4000), date: Number.isNaN(date) ? null : date, cves: cvesIn(`${title} ${text}`) });
  }
  return items;
}

export const cvesIn = text => [...new Set(String(text).toUpperCase().match(/CVE-\d{4}-\d{4,}/g) || [])];

const phraseRe = p => new RegExp(`(^|[^a-z0-9])${reEscape(String(p).toLowerCase())}($|[^a-z0-9])`);
// Does this advisory concern this device? Product phrases only: "Fortinet" alone would match every PHP or OpenSSL bulletin
export const advisoryMatches = (item, device) => { const hay = `${item.title} ${item.text}`.toLowerCase(); return (device.adv || []).some(p => phraseRe(p).test(hay)); };

// "Not known to be exploited in the wild" must never read as exploitation: negated phrases are removed first
const NEGATED = [
  // a negation, then "exploit…" later in the same sentence ("not aware of any malicious exploitation of this issue")
  /\b(?:not|no|never|without|unaware)\b[^.;]{0,50}?\bexploit\w*(?:[^.;]{0,40}?\bin the wild)?/gi,
  /\b(?:no|sin|ninguna?)\b[^.;]{0,50}?\bexplota\w*(?:[^.;]{0,20}?\bactiva(?:mente)?)?/gi,
];
const EXPLOITED = [
  /\b(actively exploited|exploited in the wild|in the wild|under active exploitation|known exploited|exploited in attacks|being exploited|explotad[ao]s? activamente|explotaci[oó]n activa)\b/i,
  /\b(0-?day|zero-?day)s?\b.{0,50}\b(exploit(ed|ation)|attacks?|campaign)\b/i,
  /\b(exploit(ed|ation)|attacks?)\b.{0,50}\b(0-?day|zero-?day)s?\b/i,
];
const PREAUTH = /\b(pre-?auth(entication)?|unauthenticated|sin autenticaci[oó]n)\b.{0,40}\b(rce|remote code execution|code execution|command injection|memory (overflow|corruption)|ejecuci[oó]n remota)\b/i;
const RECON = /\b(scanning|reconnaissance|recon|probing|brute[- ]?forc\w*|credential[- ]based|spike|surge|escaneos?)\b/i;

// Exploited in the wild beats everything; then reconnaissance against the product (GreyNoise-style early warning); then severity
export function advisorySeverity(item) {
  let t = `${item.title} ${item.text}`;
  for (const re of NEGATED) t = t.replace(re, ' ');
  if (EXPLOITED.some(re => re.test(t))) return { prio: 'P1', exploited: true };
  if (PREAUTH.test(t)) return { prio: 'P2', exploited: false };
  if (RECON.test(item.title)) return { prio: 'P2', exploited: false, recon: true };
  // on an edge device, "high" from the vendor is already worth a push: these are the boxes attackers scan for
  if (/\bseverity:?\s*(critical|high)\b|\b(critical|cr[ií]tic[ao]s?)\b|cvss(v3|v4)?( base)? score:? *([7-9]|10)(\.\d)?\b/i.test(t)) return { prio: 'P2', exploited: false };
  return { prio: 'P3', exploited: false };
}

// ---------- EPSS (FIRST): probability of exploitation in the next 30 days ----------
export const parseEpss = j => Object.fromEntries((j?.data || []).map(d => [d.cve, { epss: +d.epss, pct: +d.percentile }]));

// Raise the priority of an alert whose CVEs are likely to be exploited soon (never lowers it)
export function epssPriority(prio, epss, { p1 = 0.5, p2 = 0.1 } = {}) {
  if (epss >= p1 && prio !== 'P1') return 'P1';
  if (epss >= p2 && prio === 'P3') return 'P2';
  return prio;
}

// ---------- Plumbing ----------
// Run fn over items with at most n in flight; results keep the input order
export async function pool(items, n, fn) {
  const out = new Array(items.length);
  let next = 0;
  const worker = async () => { while (next < items.length) { const i = next++; out[i] = await fn(items[i], i); } };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(n, items.length)) }, worker));
  return out;
}

// One .env line → [name, value]; quotes are stripped and unquoted " # comments" dropped
export function parseEnvLine(line) {
  const m = String(line).match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
  if (!m) return null;
  const v = m[2];
  return [m[1], /^(["']).*\1$/.test(v) ? v.slice(1, -1) : v.replace(/\s+#.*$/, '')];
}

// Per-asset check-in key derived from the master secret: a compromised server can only report for its own asset
export const deriveKey = (master, assetId) => crypto.createHmac('sha256', master).update(`vigia-asset:${assetId}`).digest('hex');

export const clip = (s, n) => { const t = String(s ?? ''); return t.length > n ? `${t.slice(0, n - 1)}…` : t; };

// The KEV search terms of a stack item, as one stable string (to remember which ones were already checked)
export const kevTerm = item => (item.kev ? [].concat(item.kev).join('|') : item.product || '').toLowerCase();

export function localClock(timeZone, date = new Date()) {
  const p = Object.fromEntries(new Intl.DateTimeFormat('en-CA', {
    timeZone, hourCycle: 'h23', hour: 'numeric', year: 'numeric', month: '2-digit', day: '2-digit',
  }).formatToParts(date).map(x => [x.type, x.value]));
  return { day: `${p.year}-${p.month}-${p.day}`, hour: +p.hour };
}

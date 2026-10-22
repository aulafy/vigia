// Pure logic: no I/O, so it can be unit tested (see test/lib.test.mjs).
import crypto from 'node:crypto';

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
    portal: d.portal, management: d.management,
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
    if (!a.url && !a.domain && !a.edge.length) return errors.push(`${a.id}: needs "url", "domain" or "edge" devices`);
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
  const stack = [], errors = [];
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
          if (OS_EOL[id] && part.version) stack.push({ product: id, eol: OS_EOL[id], version: String(part.version) });
          break;
        }
        case 'runtime': {
          const n = String(part.name || '').toLowerCase(), r = RUNTIME[n];
          if (r && part.version) stack.push({ product: r.product || n, eol: r.eol || n, version: String(part.version).replace(/^v/, ''), ...(r.kev && { kev: r.kev }) });
          break;
        }
        default: errors.push(`part ${i}: unknown kind "${part?.kind}"`);
      }
    } catch (e) { errors.push(`part ${i} (${part?.kind}): ${e.message}`); }
  }
  return { stack: dedupeStack(stack).slice(0, 20_000), errors };
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
const decode = s => s.replace(/&(#x[\da-f]+|#\d+|\w+);/gi, (m, e) => e[0] === '#'
  ? String.fromCodePoint(e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : +e.slice(1)) : ENTITIES[e.toLowerCase()] ?? m);
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

// Exploited in the wild beats everything; then the vendor's own severity
export function advisorySeverity(item) {
  const t = `${item.title} ${item.text}`;
  if (/\b(actively exploited|exploited in the wild|in the wild|under active exploitation|known exploited|explotad[ao]s? activamente|explotaci[oó]n activa)\b/i.test(t)) return { prio: 'P1', exploited: true };
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

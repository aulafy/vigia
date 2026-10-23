// Asset validation shared by the server (which enforces it) and the dashboard editor (which shows it while typing).
// No imports: it runs in Node and in the browser. Errors are codes, so each side words them in its own language.

export const ID_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const HOST_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i;
const CHECKS = ['domain', 'dns', 'mail', 'content'];
const LEVELS = ['high', 'medium', 'low'];

const isUrl = (v, protocols = ['http:', 'https:']) => { try { return protocols.includes(new URL(v).protocol); } catch { return false; } };
const isDate = v => /^\d{4}-\d{2}-\d{2}$/.test(v) && !Number.isNaN(Date.parse(v));
const num = (v, min, max, int = false) => typeof v === 'number' && Number.isFinite(v) && v >= min && v <= max && (!int || Number.isInteger(v));

// Suggested id from client and name: "ACME Ltd" + "Online shop" → "acme-ltd-online-shop"
export const suggestId = (client, name) => `${client || ''} ${name || ''}`.toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '')
  .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 64) || 'asset';

/**
 * validateAsset(asset, { ids: existing ids, creating: bool, edgeTypes: known edge types })
 * → [{ field, code, ... }]  (empty when valid). `field` is a path such as "edge.1.management".
 */
export function validateAsset(a, { ids = [], creating = false, edgeTypes = [] } = {}) {
  const e = [], add = (field, code, extra) => e.push({ field, code, ...extra });
  if (!a || typeof a !== 'object' || Array.isArray(a)) return [{ field: '', code: 'notObject' }];

  if (!a.id) add('id', 'required');
  else if (!ID_RE.test(a.id)) add('id', 'idFormat');
  else if (creating && ids.includes(a.id)) add('id', 'duplicate');
  if (!String(a.client || '').trim()) add('client', 'required');
  if (a.client && String(a.client).length > 100) add('client', 'tooLong', { max: 100 });
  if (a.name && String(a.name).length > 100) add('name', 'tooLong', { max: 100 });

  const edge = Array.isArray(a.edge) ? a.edge : [];
  if (!a.url && !a.domain && !edge.length && !a.machine) add('url', 'needTarget');
  if (a.machine != null && (typeof a.machine !== 'string' || a.machine.length > 100)) add('machine', 'tooLong', { max: 100 });
  if (a.url && !isUrl(a.url)) add('url', 'url');
  if (a.domain && !HOST_RE.test(a.domain)) add('domain', 'host');
  if (a.criticality && !LEVELS.includes(a.criticality)) add('criticality', 'oneOf', { values: LEVELS });
  if (a.expect != null && typeof a.expect !== 'string') add('expect', 'text');
  if (a.failThreshold != null && !num(a.failThreshold, 1, 10, true)) add('failThreshold', 'range', { min: 1, max: 10 });
  if (a.timeoutMs != null && !num(a.timeoutMs, 1000, 60000, true)) add('timeoutMs', 'range', { min: 1000, max: 60000 });
  if (a.inventoryMaxAgeHours != null && !num(a.inventoryMaxAgeHours, 1, 24 * 90)) add('inventoryMaxAgeHours', 'range', { min: 1, max: 2160 });
  if (a.domainExpires != null && a.domainExpires !== '' && !isDate(a.domainExpires)) add('domainExpires', 'date');
  if (a.skip != null && (!Array.isArray(a.skip) || a.skip.some(s => !CHECKS.includes(s)))) add('skip', 'oneOf', { values: CHECKS });
  if (a.dnsWatch != null && (!Array.isArray(a.dnsWatch) || a.dnsWatch.some(s => !['A', 'AAAA'].includes(s)))) add('dnsWatch', 'oneOf', { values: ['A', 'AAAA'] });
  for (const [i, h] of (Array.isArray(a.allowedHosts) ? a.allowedHosts : []).entries()) if (!HOST_RE.test(h)) add(`allowedHosts.${i}`, 'host');

  edge.forEach((d, i) => {
    if (!d?.type) add(`edge.${i}.type`, 'required');
    else if (!edgeTypes.includes(d.type) && !(Array.isArray(d.kev) && d.kev.length)) add(`edge.${i}.type`, 'edgeCustom');
    if (d?.management && !isUrl(d.management)) add(`edge.${i}.management`, 'url');
    if (d?.portal && !isUrl(d.portal, ['https:'])) add(`edge.${i}.portal`, 'httpsUrl');
    if (d?.checked && !isDate(d.checked)) add(`edge.${i}.checked`, 'date');
  });

  const jobs = Array.isArray(a.backups) ? a.backups : [];
  const seen = new Set();
  jobs.forEach((j, i) => {
    if (!j?.id) add(`backups.${i}.id`, 'required');
    else if (!ID_RE.test(j.id)) add(`backups.${i}.id`, 'idFormat');
    else if (seen.has(j.id)) add(`backups.${i}.id`, 'duplicate');
    seen.add(j?.id);
    if (j?.rpoHours != null && !num(j.rpoHours, 0.25, 24 * 31)) add(`backups.${i}.rpoHours`, 'range', { min: 0.25, max: 744 });
    if (j?.graceMinutes != null && !num(j.graceMinutes, 0, 24 * 60)) add(`backups.${i}.graceMinutes`, 'range', { min: 0, max: 1440 });
    if (j?.restoreTestDays != null && !num(j.restoreTestDays, 1, 366)) add(`backups.${i}.restoreTestDays`, 'range', { min: 1, max: 366 });
  });

  (Array.isArray(a.stack) ? a.stack : []).forEach((s, i) => {
    const kind = s?.wp ? 'wp' : s?.ecosystem ? 'pkg' : s?.eol ? 'eol' : s?.product ? 'product' : null;
    if (!kind) return add(`stack.${i}`, 'stackKind');
    if (kind === 'wp' && !['core', 'plugin', 'theme'].includes(s.wp)) add(`stack.${i}.wp`, 'oneOf', { values: ['core', 'plugin', 'theme'] });
    if (kind === 'wp' && s.wp !== 'core' && !s.slug) add(`stack.${i}.slug`, 'required');
    if (kind === 'pkg' && !s.name) add(`stack.${i}.name`, 'required');
    if (kind !== 'product' && !s.version) add(`stack.${i}.version`, 'required');
  });
  return e;
}

// Maintenance window: who it covers (asset ids, a client, or everything) and when
export function validateWindow(w, { ids = [], clients = [], now = Date.now() } = {}) {
  const e = [], add = (field, code, extra) => e.push({ field, code, ...extra });
  if (!w || typeof w !== 'object') return [{ field: '', code: 'notObject' }];
  const from = Date.parse(w.from), to = Date.parse(w.to);
  if (Number.isNaN(from)) add('from', 'date');
  if (Number.isNaN(to)) add('to', 'date');
  if (!Number.isNaN(from) && !Number.isNaN(to)) {
    if (to <= from) add('to', 'afterFrom');
    if (to - from > 7 * 864e5) add('to', 'maxDays', { max: 7 });
    if (to <= now) add('to', 'past');
  }
  const scopes = [w.all ? 1 : 0, w.client ? 1 : 0, Array.isArray(w.assets) && w.assets.length ? 1 : 0].reduce((x, y) => x + y, 0);
  if (scopes !== 1) add('scope', 'oneScope');
  if (w.client && !clients.includes(w.client)) add('client', 'unknown');
  for (const id of Array.isArray(w.assets) ? w.assets : []) if (!ids.includes(id)) add('assets', 'unknown', { id });
  if (w.reason && String(w.reason).length > 200) add('reason', 'tooLong', { max: 200 });
  return e;
}

// Is this asset inside an active window right now?
export const inWindow = (windows, asset, now = Date.now()) => (windows || []).some(w =>
  Date.parse(w.from) <= now && now < Date.parse(w.to) && (w.all || (w.client && w.client === asset?.client) || (w.assets || []).includes(asset?.id)));

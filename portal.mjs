// Client portal: one read-only page per client, opened with a signed link. Pure functions (data in, HTML out), no scripts.
import crypto from 'node:crypto';

const P = {
  en: {
    title: 'Service status', by: 'Monitored by', updated: 'Updated', allGood: 'Everything is working', allGoodSub: 'No open issues. Monitoring continues 24/7.',
    issues: n => `${n} open issue${n === 1 ? '' : 's'}`, issuesSub: 'Your IT team has been notified and is on it.',
    open: 'Open issues', since: 'since', handled: 'IT is on it', sites: 'Websites and services', up: 'working', down: 'down', paused: 'paused',
    avail: 'availability this month', cert: 'certificate', days: 'd', computers: 'Computers and servers', av: 'antivirus', noAv: 'no active antivirus',
    lastPatch: 'last update', inventory: 'last report', never: 'never', devices: 'Firewalls, VPN and remote access', backups: 'Backups', lastOk: 'last good backup',
    ok: 'OK', problem: 'needs attention', reports: 'Monthly reports', thisMonth: 'This month', lastMonth: 'Last month', none: 'Nothing here yet.',
    prio: { P1: 'Urgent', P2: 'Important', P3: 'Notice' },
    foot: brand => `Read-only view. ${brand ? `Questions? Contact ${brand}.` : 'Questions? Contact your IT team.'} Monitored 24/7 with Vigía.`,
  },
  es: {
    title: 'Estado de los servicios', by: 'Vigilado por', updated: 'Actualizado', allGood: 'Todo funciona', allGoodSub: 'No hay incidencias abiertas. La vigilancia sigue 24/7.',
    issues: n => `${n} incidencia${n === 1 ? '' : 's'} abierta${n === 1 ? '' : 's'}`, issuesSub: 'Tu equipo de IT ya está avisado y se está ocupando.',
    open: 'Incidencias abiertas', since: 'desde', handled: 'IT se está ocupando', sites: 'Webs y servicios', up: 'funciona', down: 'caída', paused: 'en pausa',
    avail: 'disponibilidad este mes', cert: 'certificado', days: 'd', computers: 'Ordenadores y servidores', av: 'antivirus', noAv: 'sin antivirus activo',
    lastPatch: 'última actualización', inventory: 'último informe', never: 'nunca', devices: 'Firewalls, VPN y acceso remoto', backups: 'Copias de seguridad', lastOk: 'última copia correcta',
    ok: 'OK', problem: 'requiere atención', reports: 'Informes mensuales', thisMonth: 'Este mes', lastMonth: 'Mes pasado', none: 'Aún no hay nada aquí.',
    prio: { P1: 'Urgente', P2: 'Importante', P3: 'Aviso' },
    foot: brand => `Vista de solo lectura. ${brand ? `¿Dudas? Contacta con ${brand}.` : '¿Dudas? Contacta con tu equipo de IT.'} Vigilancia 24/7 con Vigía.`,
  },
};
export const portalStrings = lang => (String(lang).startsWith('es') ? P.es : P.en);

// ---------- Links ----------
// The link names the client and a version: creating a new link (or revoking it) bumps the version, so old links stop working.
// No expiry: clients bookmark it. The key is derived from Vigía's own secret, so nothing else has to be stored.
const sigOf = (key, client, v) => crypto.createHmac('sha256', key).update(`vigia-portal|${client}|${v}`).digest('hex').slice(0, 32);
export const portalKey = secret => (secret ? crypto.createHmac('sha256', secret).update('vigia-portal-key').digest() : null);
export const signPortal = (key, client, v) => `${Buffer.from(client, 'utf8').toString('base64url')}.${v}.${sigOf(key, client, v)}`;
// → { client, v } when the signature is right (the caller still checks the version is the current one)
export function verifyPortal(key, token) {
  const m = /^([A-Za-z0-9_-]{1,200})\.(\d{1,9})\.([0-9a-f]{32})$/.exec(String(token || ''));
  if (!key || !m) return null;
  const client = Buffer.from(m[1], 'base64url').toString('utf8'), want = Buffer.from(sigOf(key, client, +m[2]));
  return crypto.timingSafeEqual(want, Buffer.from(m[3])) ? { client, v: +m[2] } : null;
}

// What a client sees of an alert: its own words, without the technician's "acknowledge to accept" hints
export const CLIENT_HIDDEN = ['cover:', 'enroll:', 'inv:', 'canary', 'channel:', 'feed:', 'vigia:', 'inventory:'];
export const clientVisible = a => !!a.asset && !CLIENT_HIDDEN.some(p => a.key.startsWith(p));
// "ACME: Shop is DOWN" → "Shop is DOWN" on ACME's own page and e-mails
export const forClient = (title, client) => (client && String(title).startsWith(`${client}: `) ? String(title).slice(client.length + 2) : String(title));

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const RANK = { P1: 0, P2: 1, P3: 2 };

/**
 * renderPortal(d, lang): d = { client, brand, generatedAt, timeZone, sites, computers, devices, backups, alerts, reports: [{ label, href }] }
 */
export function renderPortal(d, lang = 'en') {
  const S = portalStrings(lang), loc = lang.startsWith('es') ? 'es-ES' : 'en-GB';
  const date = t => (t ? new Date(t).toLocaleDateString(loc, { timeZone: d.timeZone || 'UTC', day: 'numeric', month: 'short' }) : S.never);
  const time = t => new Date(t).toLocaleString(loc, { timeZone: d.timeZone || 'UTC', dateStyle: 'medium', timeStyle: 'short' });
  const open = [...d.alerts].sort((a, b) => RANK[a.prio] - RANK[b.prio] || a.first - b.first);
  const worst = open[0]?.prio;
  const row = (state, title, meta, side = '') => `<div class="row"><span class="dot ${state}"></span><div class="main"><b>${title}</b>${meta ? `<div class="mut">${meta}</div>` : ''}</div>${side}</div>`;
  const block = (title, rows) => (rows.length ? `<h2>${esc(title)}</h2><div class="list">${rows.join('')}</div>` : '');
  const pill = (cls, text) => `<span class="pill ${cls}">${esc(text)}</span>`;

  return `<!doctype html><html lang="${esc(lang)}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><meta http-equiv="refresh" content="300">
<title>${esc(S.title)} — ${esc(d.client)}</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--tx:#14161a;--mut:#5f6675;--bd:#e3e5ea;--p1:#b3261e;--p2:#9a4f0f;--p3:#4f5666;--ok:#1e7a46;--okbg:#e7f4ec;--badbg:#fbeaea;--warnbg:#fdf1e4}
@media (prefers-color-scheme:dark){:root{--bg:#121417;--card:#1b1e23;--tx:#e8eaed;--mut:#9aa1ad;--bd:#2c3038;--p1:#ef6b62;--p2:#e39a4f;--p3:#a3aab6;--ok:#5cc58a;--okbg:#17301f;--badbg:#3a1d1b;--warnbg:#3a2a17}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:15px/1.5 system-ui,-apple-system,sans-serif}
main{max-width:760px;margin:0 auto;padding:28px 16px 40px}h1{font-size:22px;margin:0}h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);margin:28px 0 8px}
.mut{color:var(--mut);font-size:13px}.top{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:flex-end}
.hero{margin-top:18px;border-radius:12px;padding:16px 18px;border:1px solid var(--bd)}.hero b{font-size:18px}.hero.ok{background:var(--okbg)}.hero.P1{background:var(--badbg)}.hero.P2,.hero.P3{background:var(--warnbg)}
.list{background:var(--card);border:1px solid var(--bd);border-radius:12px;overflow:hidden}.row{display:flex;gap:12px;align-items:flex-start;padding:12px 14px;border-top:1px solid var(--bd)}.row:first-child{border-top:0}
.main{flex:1;min-width:0;overflow-wrap:anywhere}.dot{width:10px;height:10px;border-radius:50%;margin-top:6px;flex:none;background:var(--ok)}.dot.bad{background:var(--p1)}.dot.warn{background:var(--p2)}.dot.off{background:var(--mut)}
.pill{font-size:12px;font-weight:600;border-radius:999px;padding:2px 9px;white-space:nowrap;border:1px solid var(--bd)}.pill.P1{color:var(--p1)}.pill.P2{color:var(--p2)}.pill.P3{color:var(--p3)}.pill.ok{color:var(--ok)}
.body{font-size:14px;margin-top:4px}a{color:inherit}.reports a{display:inline-block;margin:0 8px 8px 0;padding:8px 12px;border:1px solid var(--bd);border-radius:8px;background:var(--card);text-decoration:none}
footer{margin-top:32px}
</style></head><body><main>
<div class="top"><div><h1>${esc(d.client)}</h1><div class="mut">${esc(S.title)}${d.brand ? ` · ${esc(S.by)} ${esc(d.brand)}` : ''}</div></div><div class="mut">${esc(S.updated)} ${esc(time(d.generatedAt))}</div></div>
<div class="hero ${worst || 'ok'}">${worst ? `<b>${esc(S.issues(open.length))}</b><div>${esc(S.issuesSub)}</div>` : `<b>${esc(S.allGood)}</b><div>${esc(S.allGoodSub)}</div>`}</div>

${block(S.open, open.map(a => row(a.prio === 'P1' ? 'bad' : a.prio === 'P2' ? 'warn' : 'off', esc(a.title), `${esc(S.since)} ${esc(date(a.first))}${a.ack ? ` · ${esc(S.handled)}` : ''}${a.body ? `<div class="body">${esc(a.body)}</div>` : ''}`, pill(a.prio, S.prio[a.prio]))))}
${block(S.sites, d.sites.map(s => row(s.paused ? 'off' : s.down ? 'bad' : '', esc(s.name), [esc(s.host), s.avail != null ? `${esc(s.avail)} ${esc(S.avail)}` : '', s.tlsDays != null ? `${esc(S.cert)} ${s.tlsDays} ${S.days}` : ''].filter(Boolean).join(' · '),
  pill(s.paused ? '' : s.down ? 'P1' : 'ok', s.paused ? S.paused : s.down ? S.down : S.up))))}
${block(S.computers, d.computers.map(c => row(c.alerts ? 'warn' : '', esc(c.name), [esc(c.os || ''), c.av === null ? esc(S.noAv) : c.av ? `${esc(S.av)}: ${esc(c.av)}` : '',
  c.lastPatch ? `${esc(S.lastPatch)}: ${esc(date(c.lastPatch))}` : '', `${esc(S.inventory)}: ${esc(date(c.pushedAt))}`].filter(Boolean).join(' · '),
  pill(c.alerts ? 'P2' : 'ok', c.alerts ? S.problem : S.ok))))}
${block(S.devices, d.devices.map(x => row(x.alerts ? 'warn' : '', esc(x.name), [esc(x.product), esc(x.version || '')].filter(Boolean).join(' · '), pill(x.alerts ? 'P2' : 'ok', x.alerts ? S.problem : S.ok))))}
${block(S.backups, d.backups.map(b => row(b.problems ? 'bad' : '', esc(b.job), `${esc(S.lastOk)}: ${esc(date(b.lastSuccess))}`, pill(b.problems ? 'P1' : 'ok', b.problems ? S.problem : S.ok))))}
${d.reports?.length ? `<h2>${esc(S.reports)}</h2><div class="reports">${d.reports.map(r => `<a href="${esc(r.href)}">${esc(r.label)}</a>`).join('')}</div>` : ''}
<footer class="mut">${esc(S.foot(d.brand))}</footer>
</main></body></html>`;
}

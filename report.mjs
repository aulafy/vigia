// Monthly report per client: pure functions (data in, HTML out), so it can be tested and rendered anywhere.
const R = {
  en: {
    title: 'Security and availability report', period: 'Period', generated: 'Generated', for: 'Prepared for', by: 'Prepared by',
    summary: 'Summary', availability: 'Availability', incidents: 'Incidents this month', open: 'Open issues now', mtta: 'Median time to acknowledge',
    mttr: 'Median time to resolve', sites: 'Sites and services', site: 'Site', crit: 'Criticality', checks: 'Checks', avail: 'Availability',
    lastInv: 'Inventory reported', never: 'never', na: '—', none: 'None.', openTitle: 'Open issues', prio: 'Priority', issue: 'Issue', since: 'Since',
    history: 'What happened this month', opened: 'Opened', closed: 'Closed', status: 'Status', resolved: 'resolved', acked: 'acknowledged',
    stillOpen: 'open', accepted: 'change accepted', backups: 'Backups', job: 'Job', lastOk: 'Last good backup', restore: 'Last restore test',
    edge: 'Firewalls, VPN and remote access', device: 'Device', version: 'Version', alerts: 'Open alerts', recs: 'Recommended actions',
    noRecs: 'No pending actions. Keep the current routine.', maint: 'Planned maintenance', maintNote: 'Probes during planned maintenance are not counted in availability.', everything: 'all services', cat: {
      availability: 'Availability and certificates', vulns: 'Vulnerabilities and outdated software', domain: 'Domain and email',
      backup: 'Backups', web: 'Website integrity', edge: 'Firewalls and VPN', other: 'Monitoring',
    }, foot: 'Monitored 24/7 with Vigía (github.com/aulafy/vigia). P1 = act now, P2 = act within hours, P3 = plan it.',
  },
  es: {
    title: 'Informe de seguridad y disponibilidad', period: 'Periodo', generated: 'Generado', for: 'Para', by: 'Elaborado por',
    summary: 'Resumen', availability: 'Disponibilidad', incidents: 'Incidencias del mes', open: 'Pendientes ahora', mtta: 'Tiempo medio hasta atenderla',
    mttr: 'Tiempo medio hasta resolverla', sites: 'Webs y servicios', site: 'Servicio', crit: 'Criticidad', checks: 'Comprobaciones', avail: 'Disponibilidad',
    lastInv: 'Inventario recibido', never: 'nunca', na: '—', none: 'Ninguno.', openTitle: 'Pendientes', prio: 'Prioridad', issue: 'Asunto', since: 'Desde',
    history: 'Qué ha pasado este mes', opened: 'Abierta', closed: 'Cerrada', status: 'Estado', resolved: 'resuelta', acked: 'atendida',
    stillOpen: 'abierta', accepted: 'cambio aceptado', backups: 'Copias de seguridad', job: 'Tarea', lastOk: 'Última copia correcta', restore: 'Última prueba de restauración',
    edge: 'Firewalls, VPN y acceso remoto', device: 'Equipo', version: 'Versión', alerts: 'Alertas abiertas', recs: 'Acciones recomendadas',
    noRecs: 'No hay acciones pendientes. Mantener la rutina actual.', maint: 'Mantenimiento programado', maintNote: 'Las comprobaciones durante el mantenimiento programado no cuentan en la disponibilidad.', everything: 'todos los servicios', cat: {
      availability: 'Disponibilidad y certificados', vulns: 'Vulnerabilidades y software obsoleto', domain: 'Dominio y correo',
      backup: 'Copias de seguridad', web: 'Integridad de la web', edge: 'Firewalls y VPN', other: 'Monitorización',
    }, foot: 'Vigilancia 24/7 con Vigía (github.com/aulafy/vigia). P1 = actuar ya, P2 = actuar en horas, P3 = planificar.',
  },
};
export const reportStrings = lang => (String(lang).startsWith('es') ? R.es : R.en);

export function category(key) {
  const k = key.split(':')[0];
  if (k === 'down' || k === 'tls') return 'availability';
  if (['osv', 'wp', 'kev', 'eol', 'inv'].includes(k)) return 'vulns';
  if (['domain', 'dns', 'mail'].includes(k)) return 'domain';
  if (k === 'backup') return 'backup';
  if (k === 'web') return 'web';
  if (k === 'adv' || k === 'edge') return 'edge';
  return 'other';
}

const median = xs => { if (!xs.length) return null; const s = [...xs].sort((a, b) => a - b), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };

// Offset of a time zone at an instant (ms), from Intl only
function tzOffset(ms, timeZone) {
  const p = Object.fromEntries(new Intl.DateTimeFormat('en-US', { timeZone, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' })
    .formatToParts(new Date(ms)).map(x => [x.type, x.value]));
  return Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour, +p.minute, +p.second) - ms;
}
// The instant local midnight of the 1st happens in that zone (twice-corrected for DST changes)
export function zonedMonthStart(y, m, timeZone = 'UTC') {
  const guess = Date.UTC(y, m - 1, 1);
  const first = guess - tzOffset(guess, timeZone);
  return guess - tzOffset(first, timeZone);
}

// "2026-10" → [start, end) in ms, as months are lived in `timeZone` (Madrid's October starts at 22:00 UTC on 30 September)
export function monthRange(month, timeZone = 'UTC') {
  const [y, m] = String(month).split('-').map(Number);
  if (!y || !m || m < 1 || m > 12) throw new Error(`invalid month "${month}", expected YYYY-MM`);
  return [zonedMonthStart(y, m, timeZone), zonedMonthStart(m === 12 ? y + 1 : y, m === 12 ? 1 : m + 1, timeZone)];
}
export const previousMonth = month => { const [y, m] = month.split('-').map(Number); return m === 1 ? `${y - 1}-12` : `${y}-${String(m - 1).padStart(2, '0')}`; };

export function reportStats({ month, assets = [], history = [], open = [], timeZone = 'UTC' }) {
  const [from, to] = monthRange(month, timeZone);
  const inMonth = history.filter(h => h.first >= from && h.first < to && h.prio !== 'P3');
  let checks = 0, ok = 0;
  for (const a of assets) if (a.avail) { checks += a.avail[0]; ok += a.avail[1]; }
  const count = list => ({ P1: list.filter(x => x.prio === 'P1').length, P2: list.filter(x => x.prio === 'P2').length, P3: list.filter(x => x.prio === 'P3').length });
  return {
    availability: checks ? ok / checks : null,
    incidents: count(inMonth), openNow: count(open),
    mtta: median(inMonth.filter(h => h.ackAt).map(h => h.ackAt - h.first)),
    mttr: median(inMonth.filter(h => h.resolvedAt && h.resolvedAt < to).map(h => h.resolvedAt - h.first)),
    byCategory: Object.entries(open.reduce((m, a) => { const c = category(a.key); m[c] = (m[c] || 0) + 1; return m; }, {})),
  };
}

export const fmtDuration = ms => {
  if (ms == null) return null;
  const m = Math.round(ms / 60_000);
  return m < 60 ? `${m} min` : m < 2880 ? `${(m / 60).toFixed(1)} h` : `${Math.round(m / 1440)} d`;
};

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const pct = x => (x == null ? null : `${(Math.floor(x * 10000) / 100).toFixed(2)} %`); // floor: never round 99.996 up to 100

export function renderReport(d, lang = 'en') {
  const S = reportStrings(lang), st = reportStats(d);
  const date = t => (t ? new Date(t).toLocaleDateString(lang.startsWith('es') ? 'es-ES' : 'en-GB', { timeZone: d.timeZone || 'UTC' }) : S.never);
  const dt = t => (t ? new Date(t).toLocaleString(lang.startsWith('es') ? 'es-ES' : 'en-GB', { timeZone: d.timeZone || 'UTC', dateStyle: 'short', timeStyle: 'short' }) : S.na);
  const tag = p => `<span class="tag ${esc(p)}">${esc(p)}</span>`;
  const table = (head, rows) => rows.length ? `<table><thead><tr>${head.map(h => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.map(r => `<tr>${r.map(c => `<td>${c}</td>`).join('')}</tr>`).join('')}</tbody></table>` : `<p class="mut">${S.none}</p>`;
  const prioRank = { P1: 0, P2: 1, P3: 2 };
  const open = [...d.open].sort((a, b) => prioRank[a.prio] - prioRank[b.prio] || a.first - b.first);
  const [from, to] = monthRange(d.month, d.timeZone || 'UTC');
  const hist = d.history.filter(h => h.first >= from && h.first < to && h.prio !== 'P3').sort((a, b) => a.first - b.first);
  const recs = open.filter(a => a.prio !== 'P3').slice(0, 8);
  const kpi = (label, value, sub = '') => `<div class="kpi"><div class="v">${esc(value ?? S.na)}</div><div class="l">${esc(label)}</div>${sub ? `<div class="s">${sub}</div>` : ''}</div>`;
  const counts = c => `${tag('P1')} ${c.P1} &nbsp; ${tag('P2')} ${c.P2}${c.P3 != null ? ` &nbsp; ${tag('P3')} ${c.P3}` : ''}`;
  const edges = d.assets.flatMap(a => (a.edge || []).map(e => ({ ...e, site: a.name })));

  return `<!doctype html><html lang="${esc(lang)}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(S.title)} — ${esc(d.client)} — ${esc(d.month)}</title>
<style>
:root{--tx:#14161a;--mut:#5f6675;--bd:#e3e5ea;--p1:#c62828;--p2:#b25e09;--p3:#5f6675;--ok:#1e7a46}
*{box-sizing:border-box}body{margin:0 auto;max-width:900px;padding:32px 24px;font:14px/1.5 system-ui,sans-serif;color:var(--tx);background:#fff}
h1{font-size:22px;margin:0}h2{font-size:15px;margin:28px 0 8px;padding-bottom:4px;border-bottom:2px solid var(--tx)}
.head{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:8px}.mut{color:var(--mut)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}.kpi{border:1px solid var(--bd);border-radius:8px;padding:10px 12px}
.kpi .v{font-size:20px;font-weight:700}.kpi .l{color:var(--mut);font-size:12px}.kpi .s{font-size:12px;margin-top:4px}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--bd);vertical-align:top}th{font-size:12px;color:var(--mut)}
.tag{display:inline-block;font-weight:700;font-size:11px;color:#fff;border-radius:4px;padding:1px 6px}.P1{background:var(--p1)}.P2{background:var(--p2)}.P3{background:var(--p3)}
.good{color:var(--ok);font-weight:600}ol{padding-left:20px}li{margin:4px 0}footer{margin-top:32px;font-size:12px;color:var(--mut)}
@media print{body{padding:0}h2{break-after:avoid}table,.kpi{break-inside:avoid}}
</style></head><body>
<div class="head"><div><h1>${esc(S.title)}</h1><div class="mut">${esc(S.for)}: <b>${esc(d.client)}</b>${d.brand ? ` · ${esc(S.by)}: ${esc(d.brand)}` : ''}</div></div>
<div class="mut">${esc(S.period)}: <b>${esc(d.month)}</b><br>${esc(S.generated)}: ${esc(dt(d.generatedAt))}</div></div>

<h2>${esc(S.summary)}</h2>
<div class="kpis">
${kpi(S.availability, pct(st.availability))}
${kpi(S.incidents, st.incidents.P1 + st.incidents.P2, counts({ P1: st.incidents.P1, P2: st.incidents.P2 }))}
${kpi(S.open, st.openNow.P1 + st.openNow.P2 + st.openNow.P3, counts(st.openNow))}
${kpi(S.mtta, fmtDuration(st.mtta))}
${kpi(S.mttr, fmtDuration(st.mttr))}
</div>
${st.byCategory.length ? `<p class="mut">${st.byCategory.map(([c, n]) => `${esc(S.cat[c])}: ${n}`).join(' · ')}</p>` : ''}

<h2>${esc(S.recs)}</h2>
${recs.length ? `<ol>${recs.map(a => `<li>${tag(a.prio)} ${esc(a.title)}</li>`).join('')}</ol>` : `<p class="good">${esc(S.noRecs)}</p>`}

<h2>${esc(S.sites)}</h2>
${table([S.site, S.crit, S.checks, S.avail, S.lastInv], d.assets.filter(a => a.url || a.domain || a.avail).map(a => [
  `<b>${esc(a.name)}</b><br><span class="mut">${esc(a.url || a.domain || '')}</span>`, esc(a.criticality), a.avail ? a.avail[0] : S.na,
  a.avail ? esc(pct(a.avail[1] / a.avail[0])) : S.na, esc(a.pushedAt ? date(a.pushedAt) : S.na)]))}

${edges.length ? `<h2>${esc(S.edge)}</h2>${table([S.device, S.version, S.site, S.alerts], edges.map(e => [`<b>${esc(e.name)}</b><br><span class="mut">${esc(e.product)}</span>`, esc(e.version || S.na), esc(e.site), e.alerts ? `<b>${e.alerts}</b>` : '<span class="good">0</span>']))}` : ''}

${d.backups.length ? `<h2>${esc(S.backups)}</h2>${table([S.job, S.lastOk, S.restore, S.status], d.backups.map(b => [esc(b.key), esc(date(b.lastSuccess)), esc(b.lastRestoreTest ? date(b.lastRestoreTest) : S.never), b.problems.length ? b.problems.map(tag).join(' ') : '<span class="good">OK</span>']))}` : ''}

${(() => {
  const m = (d.maintenance || []).filter(w => Date.parse(w.from) < to && Date.parse(w.to) > from);
  if (!m.length) return '';
  const who = w => (w.all ? S.everything : w.client ? w.client : d.assets.filter(a => (w.assets || []).includes(a.id)).map(a => a.name).join(', '));
  return `<h2>${esc(S.maint)}</h2><p class="mut">${esc(S.maintNote)}</p>${table([S.opened, S.closed, S.site, S.issue], m.map(w => [esc(dt(Date.parse(w.from))), esc(dt(Date.parse(w.to))), esc(who(w)), esc(w.reason || '')]))}`;
})()}

<h2>${esc(S.openTitle)}</h2>
${table([S.prio, S.issue, S.since], open.map(a => [tag(a.prio), esc(a.title), esc(date(a.first))]))}

<h2>${esc(S.history)}</h2>
${table([S.prio, S.issue, S.opened, S.closed, S.status], hist.map(h => [tag(h.prio), esc(h.title), esc(dt(h.first)), esc(dt(h.resolvedAt)),
  esc(h.accepted ? S.accepted : h.resolvedAt ? S.resolved : h.ackAt ? S.acked : S.stillOpen)]))}

<footer>${esc(S.foot)}</footer>
</body></html>`;
}

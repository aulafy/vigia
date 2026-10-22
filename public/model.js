// Pure view model of the dashboard: turns /api/state into what each screen shows. No DOM, so it runs (and is tested) in Node too.

export const STR = {
  en: {
    nav: { hoy: 'Today', alertas: 'Alerts', clientes: 'Clients', equipos: 'Devices', copias: 'Backups', informes: 'Reports', ajustes: 'Settings', mas: 'More' },
    sub: { hoy: 'What needs you now', alertas: 'Everything Vigía found', clientes: 'Each company you look after', equipos: 'Firewalls, VPN and remote access', copias: 'Backup jobs reporting in', informes: 'Monthly report per client', ajustes: 'Channels, feeds and appearance' },
    level: { ok: 'All clear', warn: 'Needs attention', crit: 'Act now' },
    levelSub: { ok: 'No unacknowledged P1 or P2 alerts.', warn: 'Unacknowledged P2 alerts, or a site or channel is down.', crit: 'There are unacknowledged P1 alerts.' },
    sitesUp: 'Sites up', p1: 'P1 open', p2: 'P2 open', lastCheck: 'Last check', urgent: 'Urgent', nothingUrgent: 'Nothing urgent. Vigía keeps watching.',
    health: 'Vigía health', channels: 'Alert channels', feeds: 'Data feeds', ok: 'OK', failing: 'failing', notSet: 'not set', never: 'never', ago: 'ago',
    unack: 'Unacknowledged', all: 'All', search: 'Search alerts, clients…', none: 'Nothing here.', ack: 'Acknowledge', accept: 'Accept change', acked: 'acknowledged',
    since: 'since', system: 'Vigía', sites: 'sites', devices: 'devices', jobs: 'backup jobs', open: 'open', availability: 'availability this month',
    down: 'down', up: 'up', paused: 'paused', exposed: 'admin exposed', version: 'version', noDevices: 'No devices declared. Add an "edge" list to an asset (see docs/edge.md).',
    noBackups: 'No backup jobs. Add "backups" to an asset and call vigia-checkin.sh from the job (see docs/backups.md).', lastOk: 'last good', restore: 'restore test',
    size: 'size', report: 'Report', thisMonth: 'this month', lastMonth: 'last month', print: 'Open, then print or save as PDF.', test: 'Send test alert', testSent: 'Test alert sent',
    theme: 'Appearance', auto: 'Automatic', light: 'Light', dark: 'Dark', lang: 'Language', offline: 'Cannot reach Vigía. Showing the last data received.', updated: 'Updated',
    config: 'Configuration', heartbeat: 'Heartbeat', phoneAck: 'Acknowledge from phone', checkin: 'Check-ins and pushes', wordfence: 'Wordfence (WordPress)', password: 'Dashboard password',
    yes: 'yes', no: 'no', canary: 'Weekly test alert', every: 'every', days: 'days', off: 'off', docs: 'Documentation', install: 'Install as an app from your browser menu (Add to Home Screen).',
    back: 'Back', websites: 'Websites', justNow: 'just now', skip: 'Skip to content', authExpired: 'Your session expired. Reload the page to sign in again.', serverError: 'Vigía answered with an error', offlineBoot: 'Cannot reach Vigía. Check that it is running and that you are connected.', showMore: 'Show more', showLess: 'Show less', coverage: 'Coverage', alertsFor: 'Open alerts', contact: 'Contact', inventory: 'Inventory reported', chainDown: 'ALERT CHANNELS FAILING: alerts may not be reaching you.',
    invError: 'inventory.json cannot be read: Vigía is using the last valid copy.', clientsEmpty: 'No clients yet. Edit data/inventory.json.',
  },
  es: {
    nav: { hoy: 'Hoy', alertas: 'Alertas', clientes: 'Clientes', equipos: 'Equipos', copias: 'Copias', informes: 'Informes', ajustes: 'Ajustes', mas: 'Más' },
    sub: { hoy: 'Lo que te necesita ahora', alertas: 'Todo lo que ha encontrado Vigía', clientes: 'Cada empresa que llevas', equipos: 'Firewalls, VPN y acceso remoto', copias: 'Tareas de copia que informan', informes: 'Informe mensual por cliente', ajustes: 'Canales, fuentes y apariencia' },
    level: { ok: 'Todo en orden', warn: 'Requiere atención', crit: 'Actúa ya' },
    levelSub: { ok: 'No hay alertas P1 ni P2 sin confirmar.', warn: 'Hay P2 sin confirmar, o una web o un canal caído.', crit: 'Hay alertas P1 sin confirmar.' },
    sitesUp: 'Webs activas', p1: 'P1 abiertas', p2: 'P2 abiertas', lastCheck: 'Última comprobación', urgent: 'Urgente', nothingUrgent: 'Nada urgente. Vigía sigue vigilando.',
    health: 'Salud de Vigía', channels: 'Canales de aviso', feeds: 'Fuentes de datos', ok: 'OK', failing: 'falla', notSet: 'sin configurar', never: 'nunca', ago: 'hace',
    unack: 'Sin confirmar', all: 'Todas', search: 'Buscar alertas, clientes…', none: 'No hay nada aquí.', ack: 'Confirmar', accept: 'Aceptar cambio', acked: 'confirmada',
    since: 'desde', system: 'Vigía', sites: 'webs', devices: 'equipos', jobs: 'copias', open: 'abiertas', availability: 'disponibilidad este mes',
    down: 'caída', up: 'activa', paused: 'en pausa', exposed: 'admin expuesta', version: 'versión', noDevices: 'No hay equipos declarados. Añade una lista "edge" a un activo (ver docs/edge.md).',
    noBackups: 'No hay copias. Añade "backups" a un activo y llama a vigia-checkin.sh desde la tarea (ver docs/backups.md).', lastOk: 'última correcta', restore: 'prueba de restauración',
    size: 'tamaño', report: 'Informe', thisMonth: 'este mes', lastMonth: 'mes pasado', print: 'Ábrelo y luego imprime o guarda como PDF.', test: 'Enviar aviso de prueba', testSent: 'Aviso de prueba enviado',
    theme: 'Apariencia', auto: 'Automática', light: 'Clara', dark: 'Oscura', lang: 'Idioma', offline: 'No se puede contactar con Vigía. Se muestran los últimos datos recibidos.', updated: 'Actualizado',
    config: 'Configuración', heartbeat: 'Heartbeat', phoneAck: 'Confirmar desde el móvil', checkin: 'Check-ins e inventario', wordfence: 'Wordfence (WordPress)', password: 'Contraseña del panel',
    yes: 'sí', no: 'no', canary: 'Aviso de prueba semanal', every: 'cada', days: 'días', off: 'desactivado', docs: 'Documentación', install: 'Instálalo como app desde el menú del navegador (Añadir a pantalla de inicio).',
    back: 'Volver', websites: 'Webs', justNow: 'ahora mismo', skip: 'Saltar al contenido', authExpired: 'La sesión ha caducado. Recarga la página para volver a entrar.', serverError: 'Vigía ha respondido con un error', offlineBoot: 'No se puede contactar con Vigía. Comprueba que está en marcha y que tienes conexión.', showMore: 'Ver más', showLess: 'Ver menos', coverage: 'Cobertura', alertsFor: 'Alertas abiertas', contact: 'Contacto', inventory: 'Inventario recibido', chainDown: 'FALLAN LOS CANALES DE AVISO: puede que no te lleguen las alertas.',
    invError: 'No se puede leer inventory.json: Vigía usa la última copia válida.', clientsEmpty: 'Aún no hay clientes. Edita data/inventory.json.',
  },
};
export const strings = lang => (String(lang || '').startsWith('es') ? STR.es : STR.en);

export const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export const PRIO = { P1: 0, P2: 1, P3: 2 };

// same grouping as the monthly report (report.mjs), kept here so the browser does not load server code
export function category(key) {
  const k = String(key).split(':')[0];
  if (k === 'down' || k === 'tls') return 'availability';
  if (['osv', 'wp', 'kev', 'eol', 'inv'].includes(k)) return 'vulns';
  if (['domain', 'dns', 'mail'].includes(k)) return 'domain';
  if (k === 'backup') return 'backup';
  if (k === 'web') return 'web';
  if (k === 'adv' || k === 'edge') return 'edge';
  return 'other';
}

export function ago(t, lang, now = Date.now()) {
  if (!t) return strings(lang).never;
  const s = Math.max(0, (now - t) / 1000);
  if (s < 60) return strings(lang).justNow;
  const v = s < 5400 ? `${Math.max(1, Math.round(s / 60))} min` : s < 172800 ? `${Math.round(s / 3600)} h` : `${Math.round(s / 86400)} d`;
  return String(lang).startsWith('es') ? `hace ${v}` : `${v} ago`;
}
export const fmtBytes = n => (n == null ? '—' : n >= 1e9 ? `${(n / 1e9).toFixed(1)} GB` : n >= 1e6 ? `${(n / 1e6).toFixed(1)} MB` : n >= 1e3 ? `${Math.round(n / 1e3)} kB` : `${n} B`);
export const fmtPct = (ok, total) => (total ? `${(Math.floor((ok / total) * 10000) / 100).toFixed(2)} %` : '—');

export const assetIndex = S => Object.fromEntries((S.inventory || []).map(a => [a.id, a]));
export const sortAlerts = list => [...list].sort((a, b) => Number(a.ack) - Number(b.ack) || PRIO[a.prio] - PRIO[b.prio] || b.first - a.first);

export function summarize(S) {
  const sites = (S.inventory || []).filter(a => (a.url || a.domain) && !a.paused);
  const down = sites.filter(a => S.status?.[a.id]?.ok === false).length;
  const live = (S.alerts || []).filter(a => !a.ack);
  const p1 = live.filter(a => a.prio === 'P1').length, p2 = live.filter(a => a.prio === 'P2').length;
  const chainDown = S.chain?.ok === false;
  return {
    level: p1 || chainDown ? 'crit' : p2 || down ? 'warn' : 'ok',
    sites: sites.length, down, up: sites.length - down, p1, p2, chainDown,
    urgent: sortAlerts(live.filter(a => a.prio !== 'P3')).slice(0, 6),
    lastCheck: S.feeds?.uptime || null,
  };
}

// filter: { view: 'open' | 'all', prio: 'P1'|'P2'|'P3'|'', client: name|'', q: text }
export function filterAlerts(S, { view = 'open', prio = '', client = '', q = '' } = {}) {
  const idx = assetIndex(S), needle = q.trim().toLowerCase();
  return sortAlerts((S.alerts || []).filter(a => {
    if (view === 'open' && a.ack) return false;
    if (prio && a.prio !== prio) return false;
    const c = idx[a.asset]?.client || '';
    if (client && c !== client) return false;
    return !needle || `${a.title} ${a.body} ${c}`.toLowerCase().includes(needle);
  }));
}

export function clientsView(S) {
  const idx = assetIndex(S), by = new Map();
  for (const a of S.inventory || []) {
    const c = a.client || '—';
    if (!by.has(c)) by.set(c, { name: c, assets: [], devices: 0, down: 0, checks: 0, ok: 0, P1: 0, P2: 0, P3: 0 });
    const v = by.get(c);
    v.assets.push(a); v.devices += (a.edge || []).length;
    if (S.status?.[a.id]?.ok === false && !a.paused) v.down++;
    if (a.avail) { v.checks += a.avail[0]; v.ok += a.avail[1]; }
  }
  for (const al of S.alerts || []) { const c = idx[al.asset]?.client; if (c && by.has(c) && !al.ack) by.get(c)[al.prio]++; }
  return [...by.values()].sort((a, b) => b.P1 - a.P1 || b.P2 - a.P2 || a.name.localeCompare(b.name));
}

export function devicesView(S) {
  const alerts = S.alerts || [];
  return (S.inventory || []).flatMap(a => (a.edge || []).map(d => {
    const dev = `${a.id}:${d.edgeIndex}`;
    const mine = alerts.filter(x => x.key.startsWith(`adv:${dev}:`) || x.key === `edge:mgmt:${dev}` || x.key === `edge:tls:${dev}`
      || (x.key.startsWith('kev:') && x.asset === a.id && d.product && String(x.body).includes(d.product)));
    return { ...d, client: a.client, asset: a.name || a.id, alerts: sortAlerts(mine), exposed: mine.some(x => x.key === `edge:mgmt:${dev}`),
      worst: mine.length ? sortAlerts(mine.filter(x => !x.ack))[0]?.prio || null : null };
  })).sort((x, y) => (PRIO[x.worst] ?? 9) - (PRIO[y.worst] ?? 9) || String(x.client).localeCompare(String(y.client)));
}

export function backupsView(S) {
  const idx = assetIndex(S), alerts = S.alerts || [];
  return Object.entries(S.backups || {}).map(([key, b]) => {
    const problems = sortAlerts(alerts.filter(x => x.key.startsWith('backup:') && x.key.endsWith(`:${key}`)));
    const asset = idx[key.split('/')[0]];
    return { key, job: key.split('/').slice(1).join('/'), client: asset?.client || '—', asset: asset?.name || key.split('/')[0], ...b, problems, worst: problems[0]?.prio || null };
  }).sort((x, y) => (PRIO[x.worst] ?? 9) - (PRIO[y.worst] ?? 9) || x.key.localeCompare(y.key));
}

const FEEDS = ['uptime', 'dns', 'content', 'kev', 'osv', 'wordpress', 'eol', 'domain', 'edge', 'epss'];
export const feedsView = S => FEEDS.map(f => ({ name: f, at: S.feeds?.[f] || null, err: S.feeds?.[`${f}Err`] || null }));

export const channelsView = S => Object.entries(S.notify || {}).filter(([k]) => ['ntfy', 'telegram', 'webhook'].includes(k))
  .map(([name, configured]) => ({ name, configured, ok: configured ? S.channels?.[name]?.ok !== false : null, err: S.channels?.[name]?.err || null }));

export const navBadge = S => (S.alerts || []).filter(a => !a.ack && a.prio !== 'P3').length;

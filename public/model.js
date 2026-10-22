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
    invError: 'inventory.json cannot be read: Vigía is using the last valid copy.', clientsEmpty: 'No clients yet. Add the first asset.',
    ed: {
      newAsset: 'New asset', editAsset: 'Edit asset', add: 'Add asset', edit: 'Edit', save: 'Save', cancel: 'Cancel', del: 'Delete', pause: 'Pause', resume: 'Resume',
      confirmDel: 'Delete this asset? Its alerts and history stop being kept. This cannot be undone from the dashboard (a copy of inventory.json is kept in data/inventory-history/).',
      saved: 'Saved', deleted: 'Deleted', paused: 'Paused', resumed: 'Resumed', conflict: 'inventory.json changed meanwhile (edited by hand?). Your changes are kept: review them and save again.',
      broken: 'inventory.json cannot be read, so it cannot be edited here. Fix the file first.', fixErrors: 'Fix the highlighted fields',
      basics: 'Basics', checks: 'Checks', software: 'Software', devices: 'Firewalls, VPN and remote access', backups: 'Backup jobs', addRow: 'Add', remove: 'Remove',
      f: { client: 'Client', name: 'Name', id: 'ID', domain: 'Domain', url: 'URL to check', expect: 'Text that must appear', criticality: 'Criticality', contact: 'Contact',
        skip: 'Turn off', failThreshold: 'Failures before alerting', timeoutMs: 'Timeout (ms)', domainExpires: 'Domain expiry (.es and others)', dnsWatch: 'Also watch',
        allowedHosts: 'Allowed foreign domains', strictScripts: 'New third-party script is P1 (checkout pages)', ignoreKeywords: 'Ignore these defacement phrases',
        inventoryMaxAgeHours: 'Expect inventory every (hours)', paused: 'Paused', type: 'Type', version: 'Version', management: 'Management URL', portal: 'VPN / login portal',
        checked: 'Version confirmed on', kev: 'KEV phrases', kind: 'Kind', product: 'Product', ecosystem: 'Ecosystem', pkg: 'Package', wp: 'WordPress', slug: 'Slug', eol: 'endoflife.date id',
        rpoHours: 'RPO (hours)', graceMinutes: 'Grace (minutes)', restoreTestDays: 'Restore test every (days)', jobId: 'Job ID' },
      kinds: { product: 'Product (KEV)', pkg: 'Package (OSV)', wp: 'WordPress', eol: 'End of life' },
      lv: { high: 'High: P1 at night', medium: 'Medium', low: 'Low' },
      hint: { id: 'Lowercase letters, digits, dot, dash. Cannot change later: alerts and history use it.', domain: 'Enables domain, DNS and e-mail checks.', url: 'Leave empty to check https://domain.',
        list: 'Comma-separated', custom: 'Custom: give KEV phrases', management: 'Vigía only checks whether this address answers from the Internet.' },
      err: { required: 'Required', idFormat: 'Use lowercase letters, digits, dot or dash (max 64)', duplicate: 'Already used', needTarget: 'Give a URL, a domain or at least one device',
        url: 'Must be an http(s) URL', httpsUrl: 'Must be an https URL', host: 'Not a valid host name', oneOf: 'Must be one of: {values}', text: 'Must be text',
        range: 'Between {min} and {max}', date: 'Use YYYY-MM-DD', edgeCustom: 'Unknown type: give KEV phrases', stackKind: 'Choose what kind of software this is',
        tooLong: 'At most {max} characters', immutable: 'The ID cannot change', afterFrom: 'Must be after the start', maxDays: 'At most {max} days', past: 'Already over',
        oneScope: 'Choose one: everything, a client or assets', unknown: 'Unknown', notObject: 'Invalid' },
    },
    ai: { explain: 'Explain', client: 'Draft for the client', generating: 'Writing with {model} on this machine… (usually 10–40 s)', label: 'AI draft · {model} · check it before using it. Vigía sends nothing.',
      copy: 'Copy', copied: 'Copied', regen: 'Regenerate', close: 'Close', error: 'Could not write it: {err}', title: 'Local AI (Ollama)', on: 'On', off: 'Off',
      offHint: 'Set OLLAMA_MODEL in .env (for example qwen3.5:9b) to enable "Explain" and client drafts. Everything runs on this machine.', unavailable: 'Not available', modeExplain: 'Explanation', modeClient: 'Message for the client' },
    mt: { title: 'Maintenance', schedule: 'Schedule maintenance', active: 'In maintenance now', upcoming: 'Scheduled', none: 'No maintenance scheduled.',
      scope: 'What', everything: 'Everything (Vigía itself too)', thisClient: 'This whole client', asset: 'One asset', duration: 'For', from: 'From', to: 'To', reason: 'Reason (optional)',
      start: 'Start', end: 'End now', ended: 'Maintenance ended', scheduled: 'Maintenance scheduled', custom: 'Custom',
      explain: 'Alerts for these assets are kept but not sent, planned downtime does not count against availability, and anything still wrong when the window ends is sent then.',
      until: 'until', h: 'h', tomorrow8: 'Until 08:00 tomorrow' },
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
    invError: 'No se puede leer inventory.json: Vigía usa la última copia válida.', clientsEmpty: 'Aún no hay clientes. Añade el primer activo.',
    ed: {
      newAsset: 'Nuevo activo', editAsset: 'Editar activo', add: 'Añadir activo', edit: 'Editar', save: 'Guardar', cancel: 'Cancelar', del: 'Eliminar', pause: 'Pausar', resume: 'Reanudar',
      confirmDel: '¿Eliminar este activo? Dejarán de guardarse sus alertas e historial. No se puede deshacer desde el panel (queda una copia de inventory.json en data/inventory-history/).',
      saved: 'Guardado', deleted: 'Eliminado', paused: 'En pausa', resumed: 'Reanudado', conflict: 'inventory.json ha cambiado mientras tanto (¿editado a mano?). Tus cambios se conservan: revísalos y vuelve a guardar.',
      broken: 'No se puede leer inventory.json, así que no se puede editar aquí. Corrige el fichero primero.', fixErrors: 'Corrige los campos marcados',
      basics: 'Datos básicos', checks: 'Comprobaciones', software: 'Software', devices: 'Firewalls, VPN y acceso remoto', backups: 'Copias de seguridad', addRow: 'Añadir', remove: 'Quitar',
      f: { client: 'Cliente', name: 'Nombre', id: 'ID', domain: 'Dominio', url: 'URL a comprobar', expect: 'Texto que debe aparecer', criticality: 'Criticidad', contact: 'Contacto',
        skip: 'Desactivar', failThreshold: 'Fallos antes de avisar', timeoutMs: 'Tiempo máximo (ms)', domainExpires: 'Caducidad del dominio (.es y otros)', dnsWatch: 'Vigilar también',
        allowedHosts: 'Dominios ajenos permitidos', strictScripts: 'Script nuevo de terceros es P1 (páginas de pago)', ignoreKeywords: 'Ignorar estas frases de defacement',
        inventoryMaxAgeHours: 'Esperar inventario cada (horas)', paused: 'En pausa', type: 'Tipo', version: 'Versión', management: 'URL de administración', portal: 'Portal VPN / acceso',
        checked: 'Versión confirmada el', kev: 'Frases KEV', kind: 'Tipo', product: 'Producto', ecosystem: 'Ecosistema', pkg: 'Paquete', wp: 'WordPress', slug: 'Slug', eol: 'id en endoflife.date',
        rpoHours: 'RPO (horas)', graceMinutes: 'Margen (minutos)', restoreTestDays: 'Prueba de restauración cada (días)', jobId: 'ID de la tarea' },
      kinds: { product: 'Producto (KEV)', pkg: 'Paquete (OSV)', wp: 'WordPress', eol: 'Fin de soporte' },
      lv: { high: 'Alta: P1 de noche', medium: 'Media', low: 'Baja' },
      hint: { id: 'Minúsculas, números, punto o guion. No se puede cambiar después: las alertas y el historial lo usan.', domain: 'Activa las comprobaciones de dominio, DNS y correo.', url: 'Vacío = se comprueba https://dominio.',
        list: 'Separados por comas', custom: 'Personalizado: indica frases KEV', management: 'Vigía solo comprueba si esta dirección responde desde Internet.' },
      err: { required: 'Obligatorio', idFormat: 'Usa minúsculas, números, punto o guion (máx. 64)', duplicate: 'Ya existe', needTarget: 'Indica una URL, un dominio o al menos un equipo',
        url: 'Debe ser una URL http(s)', httpsUrl: 'Debe ser una URL https', host: 'Nombre de dominio no válido', oneOf: 'Debe ser uno de: {values}', text: 'Debe ser texto',
        range: 'Entre {min} y {max}', date: 'Usa AAAA-MM-DD', edgeCustom: 'Tipo desconocido: indica frases KEV', stackKind: 'Elige qué tipo de software es',
        tooLong: 'Como máximo {max} caracteres', immutable: 'El ID no se puede cambiar', afterFrom: 'Debe ser posterior al inicio', maxDays: 'Como máximo {max} días', past: 'Ya ha terminado',
        oneScope: 'Elige uno: todo, un cliente o activos', unknown: 'Desconocido', notObject: 'No válido' },
    },
    ai: { explain: 'Explícamelo', client: 'Borrador para el cliente', generating: 'Escribiendo con {model} en este equipo… (suele tardar 10–40 s)', label: 'Borrador IA · {model} · revísalo antes de usarlo. Vigía no envía nada.',
      copy: 'Copiar', copied: 'Copiado', regen: 'Regenerar', close: 'Cerrar', error: 'No se pudo escribir: {err}', title: 'IA local (Ollama)', on: 'Activada', off: 'Desactivada',
      offHint: 'Pon OLLAMA_MODEL en .env (por ejemplo qwen3.5:9b) para activar «Explícamelo» y los borradores. Todo se ejecuta en este equipo.', unavailable: 'No disponible', modeExplain: 'Explicación', modeClient: 'Mensaje para el cliente' },
    mt: { title: 'Mantenimiento', schedule: 'Programar mantenimiento', active: 'En mantenimiento ahora', upcoming: 'Programado', none: 'No hay mantenimientos programados.',
      scope: 'Qué', everything: 'Todo (también el propio Vigía)', thisClient: 'Todo este cliente', asset: 'Un activo', duration: 'Durante', from: 'Desde', to: 'Hasta', reason: 'Motivo (opcional)',
      start: 'Empezar', end: 'Terminar ya', ended: 'Mantenimiento terminado', scheduled: 'Mantenimiento programado', custom: 'Personalizado',
      explain: 'Las alertas de estos activos se guardan pero no se envían, la caída planificada no cuenta en la disponibilidad, y lo que siga mal al terminar se envía entonces.',
      until: 'hasta', h: 'h', tomorrow8: 'Hasta mañana a las 08:00' },
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

// Validation error → text in the dashboard's language ({min}, {max}, {values} filled in)
export const errText = (e, t) => String(t.ed.err[e.code] || e.code).replace(/\{(\w+)\}/g, (_, k) => (Array.isArray(e[k]) ? e[k].join(', ') : e[k] ?? ''));

// Maintenance windows from the state: active first, then upcoming; who each one covers in words
export function maintenanceView(S, now = Date.now()) {
  const idx = assetIndex(S);
  return (S.maintenance || []).map(w => ({ ...w, active: Date.parse(w.from) <= now && now < Date.parse(w.to),
    covers: w.all ? '*' : w.client ? w.client : (w.assets || []).map(id => idx[id]?.name || id).join(', ') }))
    .sort((a, b) => Number(b.active) - Number(a.active) || Date.parse(a.from) - Date.parse(b.from));
}
export const assetInMaintenance = (S, a, now = Date.now()) => (S.maintenance || []).some(w =>
  Date.parse(w.from) <= now && now < Date.parse(w.to) && (w.all || w.client === a.client || (w.assets || []).includes(a.id)));

// Editor rows: what kind of software a stack entry is (the form keeps it while fields are still empty)
export const stackKind = s => s._kind || (s.wp ? 'wp' : s.ecosystem ? 'pkg' : s.eol ? 'eol' : 'product');
// What gets saved: no UI-only fields (those starting with "_"), no empty values, numbers as numbers
export function cleanDraft(a) {
  const clean = v => (Array.isArray(v) ? v.map(clean) : v && typeof v === 'object'
    ? Object.fromEntries(Object.entries(v).filter(([k, x]) => !k.startsWith('_') && x !== '' && x != null && x !== false && !(Array.isArray(x) && !x.length)).map(([k, x]) => [k, clean(x)])) : v);
  return clean(a);
}

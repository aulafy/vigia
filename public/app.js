// Vigía dashboard: hash router + seven screens, rendered from /api/state every 10 s. No framework, no build step.
import { icon } from './icons.js';
import * as M from './model.js';

const esc = M.esc;
const root = document.getElementById('root');
const ui = { S: null, offline: false, filter: { view: 'open', prio: '', client: '', q: '' }, open: new Set() };

// per-viewer preferences only (theme, language); everything that matters lives on the server
const pref = (k, v) => { try { if (v === undefined) return localStorage.getItem(k); if (v === null) localStorage.removeItem(k); else localStorage.setItem(k, v); } catch { return null; } return null; };
const lang = () => pref('vigia-lang') || ui.S?.lang || navigator.language || 'en';
const T = () => M.strings(lang());
const ago = t => M.ago(t, lang());

const NAV = [['hoy', 'hoy'], ['alertas', 'alert'], ['clientes', 'clientes'], ['equipos', 'equipos'], ['copias', 'copias'], ['informes', 'informes'], ['ajustes', 'ajustes']];
const MORE = ['copias', 'informes', 'ajustes'];

function route() {
  const [page, ...rest] = location.hash.replace(/^#\/?/, '').split('/');
  return { page: NAV.some(n => n[0] === page) || page === 'mas' ? page : 'hoy', arg: rest.length ? decodeURIComponent(rest.join('/')) : null };
}

async function api(method, path) {
  const r = await fetch(path, { method, headers: { 'x-vigia-ui': '1' }, cache: 'no-store' });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || `HTTP ${r.status}`);
  return r.json();
}

// A redraw under the user's finger would swallow the tap: right after a touch or click, wait for it to finish
let lastPointer = 0;
document.addEventListener('pointerdown', () => { lastPointer = Date.now(); }, true);
async function refresh() {
  try { ui.S = await api('GET', '/api/state'); ui.offline = false; } catch { ui.offline = true; }
  const wait = 1500 - (Date.now() - lastPointer);
  if (wait > 0) setTimeout(render, wait); else render();
}

function toast(msg) {
  const el = document.createElement('div');
  el.className = 'toast'; el.textContent = msg;
  document.getElementById('toasts').append(el);
  setTimeout(() => el.remove(), 3200);
}

// ---------- building blocks ----------
const head = (title, sub, extra = '') => `<div class="head"><div><h1>${esc(title)}</h1>${sub ? `<p>${esc(sub)}</p>` : ''}</div>${extra}</div>`;
const section = (title, inner, ic = '') => `<div class="section"><h2>${ic ? icon(ic, 'sm') : ''}${esc(title)}</h2>${inner}</div>`;
const list = (rows, emptyText) => `<div class="list">${rows.length ? rows.join('') : `<div class="empty">${esc(emptyText)}</div>`}</div>`;
const kpi = (value, label) => `<div class="kpi"><b>${esc(value)}</b><span>${esc(label)}</span></div>`;
const tags = c => ['P1', 'P2', 'P3'].filter(p => c[p]).map(p => `<span class="tag ${p}">${c[p]} ${p}</span>`).join(' ');

function alertRow(a, idx, { client = true } = {}) {
  const t = T(), c = idx[a.asset]?.client;
  const meta = [client ? esc(c || t.system) : '', esc(ago(a.first)), a.epss ? `EPSS ${Math.round(a.epss * 100)} %` : ''].filter(Boolean).join(' · ');
  const action = a.ack ? `<span class="mut small">${esc(t.acked)}</span>`
    : `<button class="btn small ${a.prio === 'P1' ? 'primary' : ''}" data-act="ack" data-key="${esc(a.key)}">${icon('check', 'sm')}${esc(a.accept ? t.accept : t.ack)}</button>`;
  return `<div class="row alert ${a.ack ? 'acked' : ''}"><span class="tag ${a.prio}">${a.prio}</span><div class="main"><div class="title">${esc(a.title)}</div><div class="meta">${meta}</div><div class="body clamp ${ui.open.has(a.key) ? 'open' : ''}" data-act="expand" data-key="${esc(a.key)}" title="${esc(ui.open.has(a.key) ? '' : '…')}">${esc(a.body)}</div></div><div class="side-r">${action}</div></div>`;
}

function siteRow(a, S) {
  const t = T(), st = S.status?.[a.id] || {}, bad = st.ok === false;
  const meta = [esc(a.url || a.domain), st.code ? `HTTP ${st.code}` : '', st.ms != null ? `${st.ms} ms` : '', st.tlsDays != null ? `TLS ${st.tlsDays} d` : ''].filter(Boolean).join(' · ');
  const avail = a.avail ? M.fmtPct(a.avail[1], a.avail[0]) : '—';
  return `<div class="row"><span class="state ${a.paused ? 'off' : bad ? 'bad' : ''}"></span><div class="main"><div class="title">${esc(a.name || a.id)}${a.paused ? ` <span class="pill">${esc(t.paused)}</span>` : ''}</div><div class="meta">${meta}</div></div><div class="side-r"><span class="pill ${bad ? 'bad' : 'ok'}">${esc(bad ? t.down : t.up)}</span><span class="mut small">${esc(avail)}</span></div></div>`;
}

function deviceRow(d) {
  const t = T(), open = d.alerts.filter(a => !a.ack);
  const count = { P1: open.filter(a => a.prio === 'P1').length, P2: open.filter(a => a.prio === 'P2').length, P3: open.filter(a => a.prio === 'P3').length };
  const top = open.slice(0, 2).map(a => `<div class="body"><span class="tag ${a.prio}">${a.prio}</span> ${esc(a.title)}</div>`).join('');
  return `<div class="row"><span class="state ${d.worst === 'P1' ? 'bad' : d.worst ? 'warn' : ''}"></span><div class="main"><div class="title">${esc(d.name)}</div>
    <div class="meta">${esc(d.product)}${d.version ? ` · ${esc(t.version)} ${esc(d.version)}` : ''} · ${esc(d.client)}</div>${top}</div>
    <div class="side-r">${d.exposed ? `<span class="pill bad">${icon('lock', 'sm')}${esc(t.exposed)}</span>` : ''}${tags(count) || `<span class="pill ok">${icon('check', 'sm')}OK</span>`}</div></div>`;
}

function backupRow(b) {
  const t = T();
  const meta = `${esc(t.lastOk)}: ${esc(b.lastSuccess ? ago(b.lastSuccess) : t.never)} · ${esc(t.restore)}: ${esc(b.lastRestoreTest ? ago(b.lastRestoreTest) : t.never)} · ${esc(t.size)} ${esc(M.fmtBytes(b.lastBytes))}`;
  return `<div class="row"><span class="state ${b.worst === 'P1' ? 'bad' : b.worst ? 'warn' : ''}"></span><div class="main"><div class="title">${esc(b.client)} · ${esc(b.asset)} / ${esc(b.job)}</div><div class="meta">${meta}</div>
    ${b.problems.filter(a => !a.ack).slice(0, 1).map(a => `<div class="body">${esc(a.title)}</div>`).join('')}</div><div class="side-r">${b.worst ? `<span class="tag ${b.worst}">${b.worst}</span>` : `<span class="pill ok">OK</span>`}</div></div>`;
}

const reportLinks = (client, S) => [S.month, prevMonth(S.month)].map((m, i) =>
  `<a class="btn small" href="/report?client=${encodeURIComponent(client)}&month=${m}&lang=${lang().startsWith('es') ? 'es' : 'en'}" target="_blank" rel="noopener">${icon('informes', 'sm')}${esc(m)} · ${esc(i ? T().lastMonth : T().thisMonth)}</a>`).join(' ');
const prevMonth = m => { const [y, n] = m.split('-').map(Number); return n === 1 ? `${y - 1}-12` : `${y}-${String(n - 1).padStart(2, '0')}`; };

// ---------- screens ----------
const PAGES = {
  hoy(S) {
    const t = T(), s = M.summarize(S), idx = M.assetIndex(S);
    const hero = `<div class="hero ${s.level}"><div class="mark">${icon(s.level === 'ok' ? 'shield' : 'alert')}</div><div><h2>${esc(t.level[s.level])}</h2><p>${esc(t.levelSub[s.level])}</p></div></div>`;
    const kpis = `<div class="kpis">${kpi(`${s.up}/${s.sites}`, t.sitesUp)}${kpi(s.p1, t.p1)}${kpi(s.p2, t.p2)}${kpi(ago(s.lastCheck), t.lastCheck)}</div>`;
    const ch = M.channelsView(S).filter(c => c.configured).map(c => `<span class="pill ${c.ok ? 'ok' : 'bad'}" title="${esc(c.err || '')}">${icon(c.ok ? 'check' : 'x', 'sm')}${esc(c.name)}</span>`).join(' ') || `<span class="pill bad">${esc(t.notSet)}</span>`;
    const feeds = M.feedsView(S).filter(f => f.at || f.err).map(f => `<span class="pill ${f.err ? 'warn' : ''}" title="${esc(f.err || '')}">${esc(f.name)} · ${esc(ago(f.at))}</span>`).join(' ');
    return head(t.nav.hoy, t.sub.hoy) + hero + kpis
      + section(t.urgent, list(s.urgent.map(a => alertRow(a, idx)), t.nothingUrgent), 'bell')
      + section(t.health, `<div class="card"><div class="small mut">${esc(t.channels)}</div><div style="margin:6px 0 12px">${ch}</div><div class="small mut">${esc(t.feeds)}</div><div style="margin-top:6px;display:flex;gap:6px;flex-wrap:wrap">${feeds}</div></div>`, 'shield');
  },

  alertas(S) {
    const t = T(), f = ui.filter, idx = M.assetIndex(S), clients = [...new Set((S.inventory || []).map(a => a.client).filter(Boolean))].sort();
    const seg = (k, opts) => `<div class="seg">${opts.map(([v, label]) => `<button data-act="filter" data-k="${k}" data-v="${v}" aria-pressed="${f[k] === v}">${esc(label)}</button>`).join('')}</div>`;
    const tools = `<div class="toolbar">${seg('view', [['open', t.unack], ['all', t.all]])}${seg('prio', [['', t.all], ['P1', 'P1'], ['P2', 'P2'], ['P3', 'P3']])}
      <select data-act="client" aria-label="${esc(t.nav.clientes)}"><option value="">${esc(t.nav.clientes)}: ${esc(t.all)}</option>${clients.map(c => `<option ${f.client === c ? 'selected' : ''}>${esc(c)}</option>`).join('')}</select>
      <label class="search">${icon('search', 'sm')}<input id="q" type="search" value="${esc(f.q)}" placeholder="${esc(t.search)}" autocomplete="off"></label></div>`;
    return head(t.nav.alertas, t.sub.alertas) + tools + list(M.filterAlerts(S, f).map(a => alertRow(a, idx)), t.none);
  },

  clientes(S, arg) {
    const t = T(), view = M.clientsView(S);
    if (arg) return clientDetail(S, view.find(c => c.name === arg));
    return head(t.nav.clientes, t.sub.clientes) + list(view.map(c => {
      const meta = [`${c.assets.filter(a => a.url || a.domain).length} ${t.sites}`, c.devices ? `${c.devices} ${t.devices}` : '', c.checks ? `${M.fmtPct(c.ok, c.checks)} ${t.availability}` : ''].filter(Boolean).join(' · ');
      return `<a class="row link" href="#/clientes/${encodeURIComponent(c.name)}" style="color:inherit;text-decoration:none"><span class="state ${c.P1 || c.down ? 'bad' : c.P2 ? 'warn' : ''}"></span><div class="main"><div class="title">${esc(c.name)}</div><div class="meta">${esc(meta)}</div></div><div class="side-r">${tags(c) || `<span class="pill ok">OK</span>`}</div>${icon('chevron', 'sm')}</a>`;
    }), t.clientsEmpty);
  },

  equipos(S) {
    const t = T();
    return head(t.nav.equipos, t.sub.equipos) + list(M.devicesView(S).map(deviceRow), t.noDevices);
  },

  copias(S) {
    const t = T();
    return head(t.nav.copias, t.sub.copias) + list(M.backupsView(S).map(backupRow), t.noBackups);
  },

  informes(S) {
    const t = T(), clients = M.clientsView(S);
    return head(t.nav.informes, t.sub.informes) + `<p class="mut">${esc(t.print)}</p>`
      + list(clients.map(c => `<div class="row"><div class="main"><div class="title">${esc(c.name)}</div></div><div class="side-r" style="flex-direction:row;flex-wrap:wrap;justify-content:flex-end">${reportLinks(c.name, S)}</div></div>`), t.clientsEmpty);
  },

  ajustes(S) {
    const t = T(), c = S.config || {}, theme = pref('vigia-theme') || 'auto', lng = pref('vigia-lang') || 'auto';
    const seg = (act, cur, opts) => `<div class="seg">${opts.map(([v, label, ic]) => `<button data-act="${act}" data-v="${v}" aria-pressed="${cur === v}">${ic ? icon(ic, 'sm') : ''} ${esc(label)}</button>`).join('')}</div>`;
    const yn = (v, okWord = t.yes) => `<span class="pill ${v ? 'ok' : ''}">${esc(v ? okWord : t.no)}</span>`;
    const channels = M.channelsView(S).map(ch => `<div class="row"><span class="state ${!ch.configured ? 'off' : ch.ok ? '' : 'bad'}"></span><div class="main"><div class="title">${esc(ch.name)}</div><div class="meta">${esc(!ch.configured ? t.notSet : ch.ok ? t.ok : `${t.failing}: ${ch.err || ''}`)}</div></div></div>`);
    const feeds = M.feedsView(S).map(f => `<div class="row"><span class="state ${f.err ? 'warn' : f.at ? '' : 'off'}"></span><div class="main"><div class="title">${esc(f.name)}</div><div class="meta">${esc(f.at ? ago(f.at) : t.never)}${f.err ? ` · ${esc(f.err)}` : ''}</div></div></div>`);
    return head(t.nav.ajustes, t.sub.ajustes, `<button class="btn primary" data-act="test">${icon('bell', 'sm')}${esc(t.test)}</button>`)
      + `<div class="grid2">
        <div class="card"><div class="small mut" style="margin-bottom:8px">${esc(t.theme)}</div>${seg('theme', theme, [['auto', t.auto], ['light', t.light, 'sun'], ['dark', t.dark, 'moon']])}
          <div class="small mut" style="margin:16px 0 8px">${esc(t.lang)}</div>${seg('lang', lng, [['auto', t.auto], ['es', 'Español'], ['en', 'English']])}
          <p class="small mut" style="margin-bottom:0">${esc(t.install)}</p></div>
        <div class="card"><dl class="kv">
          <dt>${esc(t.heartbeat)}</dt><dd>${yn(S.notify?.heartbeat)}</dd><dt>${esc(t.phoneAck)}</dt><dd>${yn(S.notify?.phoneAck)}</dd>
          <dt>${esc(t.checkin)}</dt><dd>${yn(c.checkin)}</dd><dt>${esc(t.wordfence)}</dt><dd>${yn(c.wordfence)}</dd>
          <dt>${esc(t.password)}</dt><dd>${yn(c.dashPass)}</dd><dt>${esc(t.canary)}</dt><dd>${esc(c.canaryDays ? `${t.every} ${c.canaryDays} ${t.days}` : t.off)}</dd>
          <dt>EPSS</dt><dd>P1 ≥ ${Math.round((c.epss?.[0] ?? 0.5) * 100)} % · P2 ≥ ${Math.round((c.epss?.[1] ?? 0.1) * 100)} %</dd>
          <dt>Vigía</dt><dd>v${esc(S.version)} · <a href="https://github.com/aulafy/vigia#readme" target="_blank" rel="noopener">${esc(t.docs)} ${icon('ext', 'sm')}</a></dd></dl></div>
      </div>`
      + section(t.channels, list(channels, t.notSet), 'bell') + section(t.feeds, list(feeds, t.none), 'refresh');
  },

  mas() {
    const t = T();
    return head(t.nav.mas, '') + list(MORE.map(p => `<a class="row link" href="#/${p}" style="color:inherit;text-decoration:none">${icon(NAV.find(n => n[0] === p)[1])}<div class="main"><div class="title">${esc(t.nav[p])}</div><div class="meta">${esc(t.sub[p])}</div></div>${icon('chevron', 'sm')}</a>`), '');
  },
};

function clientDetail(S, c) {
  const t = T();
  if (!c) return head(t.nav.clientes, '') + `<a class="btn" href="#/clientes">${icon('back', 'sm')}${esc(t.back)}</a>`;
  const idx = M.assetIndex(S), ids = new Set(c.assets.map(a => a.id));
  const open = M.sortAlerts((S.alerts || []).filter(a => ids.has(a.asset)));
  const devices = M.devicesView(S).filter(d => d.client === c.name), backups = M.backupsView(S).filter(b => b.client === c.name);
  const sites = c.assets.filter(a => a.url || a.domain), contact = c.assets.map(a => a.contact).find(Boolean);
  return head(c.name, contact ? `${t.contact}: ${contact}` : '', `<a class="btn" href="#/clientes">${icon('back', 'sm')}${esc(t.back)}</a>`)
    + `<div class="kpis">${kpi(c.checks ? M.fmtPct(c.ok, c.checks) : '—', t.availability)}${kpi(c.P1, t.p1)}${kpi(c.P2, t.p2)}${kpi(devices.length, t.nav.equipos)}</div>`
    + section(t.alertsFor, list(open.filter(a => !a.ack).map(a => alertRow(a, idx, { client: false })), t.nothingUrgent), 'alert')
    + (sites.length ? section(t.websites, list(sites.map(a => siteRow(a, S)), t.none), 'globe') : '')
    + (devices.length ? section(t.nav.equipos, list(devices.map(deviceRow), t.none), 'equipos') : '')
    + (backups.length ? section(t.nav.copias, list(backups.map(backupRow), t.none), 'copias') : '')
    + section(t.report, `<div style="display:flex;gap:8px;flex-wrap:wrap">${reportLinks(c.name, S)}</div>`, 'informes');
}

// ---------- shell ----------
function render() {
  const t = T();
  if (!ui.S) {
    if (ui.offline) root.innerHTML = `<div class="app"><aside class="side"></aside><main><div class="banner bad">${icon('alert')}${esc(t.offline)}</div></main></div>`;
    return;
  }
  const S = ui.S, { page, arg } = route(), badge = M.navBadge(S), s = M.summarize(S);
  document.documentElement.lang = lang().startsWith('es') ? 'es' : 'en';
  document.title = `${badge ? `(${badge}) ` : ''}Vigía`;
  const current = p => (p === page || (p === 'mas' && MORE.includes(page)) ? 'aria-current="page"' : '');
  const nav = NAV.map(([p, ic]) => `<a href="#/${p}" ${current(p)}>${icon(ic)}<span>${esc(t.nav[p])}</span>${p === 'alertas' && badge ? `<span class="badge">${badge}</span>` : ''}</a>`).join('');
  const tabs = ['hoy', 'alertas', 'clientes', 'equipos', 'mas'].map(p => `<a href="#/${p}" ${current(p)}>${icon(p === 'mas' ? 'more' : NAV.find(n => n[0] === p)[1])}<span>${esc(t.nav[p])}</span>${p === 'alertas' && badge ? `<span class="badge">${badge}</span>` : ''}</a>`).join('');
  const banners = (ui.offline ? `<div class="banner warn">${icon('alert')}${esc(t.offline)}</div>` : '')
    + (s.chainDown ? `<div class="banner bad">${icon('bell')}${esc(t.chainDown)}</div>` : '')
    + (S.config?.inventoryError ? `<div class="banner bad">${icon('alert')}${esc(t.invError)}</div>` : '');

  // keep the search box usable across the 10-second refresh
  const q = document.activeElement?.id === 'q' ? [document.activeElement.selectionStart, document.activeElement.selectionEnd] : null;
  root.innerHTML = `<div class="app"><aside class="side"><div class="brand"><img src="icon.svg" alt="">Vigía</div><nav class="nav" aria-label="Vigía">${nav}</nav>
    <div class="side-foot"><div><span class="dot ${s.level === 'ok' ? '' : 'bad'}"></span>${esc(t.level[s.level])}</div><div>${esc(t.updated)} ${esc(ago(Date.now()))}</div><div>v${esc(S.version)}</div></div></aside>
    <main id="main">${banners}${(PAGES[page] || PAGES.hoy)(S, arg)}</main><nav class="tabbar" aria-label="Vigía">${tabs}</nav></div>`;
  if (q) { const el = document.getElementById('q'); el.focus(); el.setSelectionRange(...q); }
}

// ---------- events ----------
root.addEventListener('click', async e => {
  const b = e.target.closest('[data-act]');
  if (!b || b.tagName === 'SELECT') return;
  const act = b.dataset.act, t = T();
  if (act === 'ack') { b.disabled = true; try { await api('POST', `/api/ack?key=${encodeURIComponent(b.dataset.key)}`); toast(`${t.acked} ✓`); } catch (err) { toast(err.message); } return refresh(); }
  if (act === 'test') { try { await api('POST', '/api/test'); toast(t.testSent); } catch (err) { toast(err.message); } return; }
  if (act === 'expand') { const k = b.dataset.key; if (ui.open.has(k)) ui.open.delete(k); else ui.open.add(k); b.classList.toggle('open'); return; }
  if (act === 'filter') { ui.filter[b.dataset.k] = b.dataset.v; return render(); }
  if (act === 'theme') { const v = b.dataset.v; pref('vigia-theme', v === 'auto' ? null : v); if (v === 'auto') delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = v; return render(); }
  if (act === 'lang') { pref('vigia-lang', b.dataset.v === 'auto' ? null : b.dataset.v); return render(); }
});
root.addEventListener('change', e => { if (e.target.dataset.act === 'client') { ui.filter.client = e.target.value; render(); } });
root.addEventListener('input', e => { if (e.target.id === 'q') { ui.filter.q = e.target.value; render(); } });
window.addEventListener('hashchange', () => { render(); window.scrollTo(0, 0); });

if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
refresh();
setInterval(refresh, 10_000);

// Asset editor and maintenance windows for the dashboard. Validation is the same module the server enforces.
import { validateAsset, suggestId } from './validate.js';
import * as M from './model.js';
import { icon } from './icons.js';

const esc = M.esc;
const ECOSYSTEMS = ['npm', 'Packagist', 'PyPI', 'Go', 'Maven', 'RubyGems', 'crates.io', 'NuGet', 'Debian:12', 'Ubuntu:22.04', 'Ubuntu:24.04', 'Alpine:v3.19'];

async function call(method, path, body) {
  const r = await fetch(path, { method, cache: 'no-store', headers: { 'x-vigia-ui': '1', ...(body && { 'content-type': 'application/json' }) }, body: body && JSON.stringify(body) });
  return { status: r.status, data: await r.json().catch(() => ({})) };
}

// ---------- draft helpers ----------
const getPath = (o, p) => p.split('.').reduce((x, k) => x?.[k], o);
function setPath(o, p, v) {
  const ks = p.split('.'), last = ks.pop();
  const target = ks.reduce((x, k, i) => (x[k] ??= /^\d+$/.test(ks[i + 1] ?? last) ? [] : {}), o);
  if (v === undefined) delete target[last]; else target[last] = v;
}
const blank = client => ({ client: client || '', name: '', id: '', criticality: 'medium', stack: [], edge: [], backups: [] });

// ---------- editor state ----------
export const ed = { for: null, loading: false, broken: null, rev: null, assets: [], edgeTypes: [], draft: null, creating: false, tried: false, server: [], idTouched: false, saving: false };

export async function openEditor(hash, id, client, rerender) {
  if (ed.for === hash) return; // already loaded or loading for this page
  Object.assign(ed, { for: hash, loading: true, broken: null, tried: false, server: [], idTouched: false, saving: false });
  const { status, data } = await call('GET', '/api/inventory');
  ed.loading = false;
  if (status === 409) { ed.broken = data.detail || 'inventory.json'; return rerender(); }
  Object.assign(ed, { rev: data.rev, assets: data.assets || [], edgeTypes: data.edgeTypes || [] });
  const current = id && ed.assets.find(a => a.id === id);
  ed.creating = !current;
  const d = structuredClone(current || blank(client));
  // Spanish legacy names are shown (and saved) as their English equivalents
  d.client ??= d.cliente; d.contact ??= d.contacto; d.criticality ??= { alta: 'high', media: 'medium', baja: 'low' }[d.criticidad] || 'medium';
  for (const k of ['stack', 'edge', 'backups']) d[k] = Array.isArray(d[k]) ? d[k] : [];
  d.stack = d.stack.map(s => ({ ...s, _kind: M.stackKind(s) })); // the row keeps its kind while its fields are still empty
  ed.draft = d;
  rerender();
}

const errorsNow = () => {
  if (!ed.draft) return [];
  const local = validateAsset(M.cleanDraft(ed.draft), { ids: ed.assets.map(a => a.id), creating: ed.creating, edgeTypes: ed.edgeTypes.map(e => e.type) });
  return [...local, ...ed.server.filter(s => !local.some(l => l.field === s.field))];
};

// ---------- rendering ----------
export function editorPage(t, back) {
  const E = t.ed;
  if (ed.broken) return `<div class="head"><div><h1>${esc(E.editAsset)}</h1></div></div><div class="banner bad">${icon('alert')}${esc(E.broken)}</div><p class="mut small">${esc(ed.broken)}</p><a class="btn" href="${back}">${icon('back', 'sm')}${esc(t.back)}</a>`;
  if (!ed.draft) return `<div class="head"><div><h1>${esc(E.editAsset)}</h1></div></div><i class="sk" style="height:240px;display:block"></i>`;
  const d = ed.draft, errs = ed.tried ? errorsNow() : [], errOf = p => errs.filter(e => e.field === p).map(e => M.errText(e, t)).join(' · ');
  const id = p => `f-${p.replace(/\./g, '-')}`;
  const field = (label, p, { type = 'text', hint, options, list, placeholder, readonly, as = 'text', wide } = {}) => {
    const v = getPath(d, p), err = errOf(p);
    let control;
    if (options) control = `<select id="${id(p)}" data-f="${p}" data-as="${as}" ${err ? 'aria-invalid="true"' : ''}>${options.map(([k, l]) => `<option value="${esc(k)}" ${String(v ?? '') === String(k) ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select>`;
    else if (type === 'checkbox') control = `<input id="${id(p)}" type="checkbox" data-f="${p}" data-as="bool" ${v ? 'checked' : ''}>`;
    else control = `<input id="${id(p)}" type="${type}" data-f="${p}" data-as="${as}" value="${esc(as === 'csv' && Array.isArray(v) ? v.join(', ') : v ?? '')}" ${placeholder ? `placeholder="${esc(placeholder)}"` : ''} ${list ? `list="${list}"` : ''} ${readonly ? 'readonly' : ''} ${err ? 'aria-invalid="true"' : ''} autocomplete="off">`;
    return `<label class="fld ${type === 'checkbox' ? 'check' : ''} ${wide ? 'wide' : ''}" for="${id(p)}"><span>${esc(label)}</span>${control}${hint ? `<small class="hint">${esc(hint)}</small>` : ''}${err ? `<small class="err" role="alert">${esc(err)}</small>` : ''}</label>`;
  };
  const multi = (label, p, values) => `<fieldset class="fld"><legend>${esc(label)}</legend><div class="chips">${values.map(([v, l]) => `<label class="tick"><input type="checkbox" data-multi="${p}" value="${v}" ${(getPath(d, p) || []).includes(v) ? 'checked' : ''}> ${esc(l)}</label>`).join('')}</div>${errOf(p) ? `<small class="err">${esc(errOf(p))}</small>` : ''}</fieldset>`;
  const rows = (key, title, render, addLabel) => `<div class="section"><h2>${esc(title)}</h2>${d[key].map((row, i) => `<div class="rowbox">${render(row, i)}<button type="button" class="btn small ghost" data-act="row-del" data-k="${key}" data-v="${i}">${icon('x', 'sm')}${esc(E.remove)}</button></div>`).join('')}
    <button type="button" class="btn small" data-act="row-add" data-k="${key}">${icon('plus', 'sm')}${esc(addLabel || E.addRow)}</button></div>`;
  const F = E.f, clients = [...new Set(ed.assets.map(a => a.client || a.cliente).filter(Boolean))].sort();
  const edgeOpts = [...ed.edgeTypes.map(e => [e.type, e.label]), ['custom', E.hint.custom]];

  const stackRow = (s, i) => {
    const k = M.stackKind(s), p = `stack.${i}`;
    const kindSel = field(F.kind, `${p}._kind`, { options: Object.entries(E.kinds), as: 'text' });
    const by = {
      product: [field(F.product, `${p}.product`), field(F.version, `${p}.version`), field(F.kev, `${p}.kev`, { as: 'csv', hint: E.hint.list })],
      pkg: [field(F.ecosystem, `${p}.ecosystem`, { list: 'ecos' }), field(F.pkg, `${p}.name`), field(F.version, `${p}.version`)],
      wp: [field(F.wp, `${p}.wp`, { options: [['core', 'core'], ['plugin', 'plugin'], ['theme', 'theme']] }), field(F.slug, `${p}.slug`), field(F.version, `${p}.version`)],
      eol: [field(F.product, `${p}.product`), field(F.eol, `${p}.eol`), field(F.version, `${p}.version`)],
    }[k];
    return `<div class="grid4">${kindSel}${by.join('')}</div>${errOf(p) ? `<small class="err">${esc(errOf(p))}</small>` : ''}`;
  };
  const edgeRow = (x, i) => {
    const p = `edge.${i}`, custom = x.type && !ed.edgeTypes.some(e => e.type === x.type);
    return `<div class="grid3">${field(F.type, `${p}.type`, { options: [['', '—'], ...edgeOpts], as: 'text' }).replace(custom ? 'value="custom"' : '\u0000', 'value="custom" selected')}
      ${field(F.name, `${p}.name`)}${field(F.version, `${p}.version`)}
      ${field(F.management, `${p}.management`, { type: 'url', placeholder: 'https://203.0.113.10:4443', hint: E.hint.management })}
      ${field(F.portal, `${p}.portal`, { type: 'url', placeholder: 'https://vpn.example.com' })}${field(F.checked, `${p}.checked`, { type: 'date' })}
      ${custom || x.type === 'custom' ? field(F.kev, `${p}.kev`, { as: 'csv', hint: E.hint.list }) : ''}</div>`;
  };
  const backupRow = (j, i) => `<div class="grid4">${field(F.jobId, `backups.${i}.id`, { placeholder: 'db' })}${field(F.rpoHours, `backups.${i}.rpoHours`, { type: 'number', as: 'num', placeholder: '24' })}
    ${field(F.graceMinutes, `backups.${i}.graceMinutes`, { type: 'number', as: 'num', placeholder: '60' })}${field(F.restoreTestDays, `backups.${i}.restoreTestDays`, { type: 'number', as: 'num', placeholder: '30' })}</div>`;

  return `<form class="editor" data-editor novalidate>
    <div class="head"><div><h1>${esc(ed.creating ? E.newAsset : `${E.editAsset}: ${d.name || d.id}`)}</h1></div>
      <div class="actions"><a class="btn" href="${back}">${esc(E.cancel)}</a><button class="btn primary" data-act="save" ${ed.saving ? 'disabled' : ''}>${icon('check', 'sm')}${esc(E.save)}</button></div></div>
    ${ed.tried && errs.length ? `<div class="banner warn" role="alert">${icon('alert')}${esc(E.fixErrors)}</div>` : ''}
    <datalist id="clients">${clients.map(c => `<option value="${esc(c)}">`).join('')}</datalist><datalist id="ecos">${ECOSYSTEMS.map(e => `<option value="${e}">`).join('')}</datalist>
    <div class="section"><h2>${esc(E.basics)}</h2><div class="grid2">
      ${field(F.client, 'client', { list: 'clients' })}${field(F.name, 'name')}
      ${field(F.id, 'id', { readonly: !ed.creating, hint: E.hint.id })}${field(F.criticality, 'criticality', { options: Object.entries(E.lv) })}
      ${field(F.domain, 'domain', { placeholder: 'shop.example.com', hint: E.hint.domain })}${field(F.url, 'url', { type: 'url', placeholder: 'https://shop.example.com/checkout', hint: E.hint.url })}
      ${field(F.expect, 'expect')}${field(F.contact, 'contact')}</div></div>
    <details class="section" ${ed.tried && errs.some(e => /^(skip|failThreshold|timeoutMs|domainExpires|dnsWatch|allowedHosts|inventoryMaxAgeHours)/.test(e.field)) ? 'open' : ''}><summary><h2>${esc(E.checks)}</h2></summary><div class="grid2">
      ${multi(F.skip, 'skip', [['domain', 'RDAP'], ['dns', 'DNS'], ['mail', 'SPF/DMARC'], ['content', t.websites]])}${multi(F.dnsWatch, 'dnsWatch', [['A', 'A'], ['AAAA', 'AAAA']])}
      ${field(F.failThreshold, 'failThreshold', { type: 'number', as: 'num', placeholder: '2' })}${field(F.timeoutMs, 'timeoutMs', { type: 'number', as: 'num', placeholder: '10000' })}
      ${field(F.domainExpires, 'domainExpires', { type: 'date' })}${field(F.inventoryMaxAgeHours, 'inventoryMaxAgeHours', { type: 'number', as: 'num' })}
      ${field(F.allowedHosts, 'allowedHosts', { as: 'csv', hint: E.hint.list, placeholder: 'stripe.com, googletagmanager.com' })}${field(F.ignoreKeywords, 'ignoreKeywords', { as: 'csv', hint: E.hint.list })}
      ${field(F.strictScripts, 'strictScripts', { type: 'checkbox' })}${field(F.paused, 'paused', { type: 'checkbox' })}</div></details>
    ${rows('stack', E.software, stackRow)}
    ${rows('edge', E.devices, edgeRow)}
    ${rows('backups', E.backups, backupRow)}
    ${ed.creating ? '' : `<div class="section danger"><button type="button" class="btn small ghost" data-act="asset-del">${icon('x', 'sm')}${esc(E.del)}</button></div>`}
  </form>`;
}

// ---------- events (wired from app.js) ----------
export function onInput(el) {
  if (!ed.draft) return false;
  if (el.dataset.multi) {
    const p = el.dataset.multi, cur = new Set(getPath(ed.draft, p) || []);
    if (el.checked) cur.add(el.value); else cur.delete(el.value);
    setPath(ed.draft, p, [...cur]);
    return true;
  }
  const p = el.dataset.f;
  if (!p) return false;
  const as = el.dataset.as;
  let v = as === 'bool' ? el.checked : el.value;
  if (as === 'num') v = el.value === '' ? undefined : Number(el.value);
  if (as === 'csv') v = el.value.split(',').map(x => x.trim()).filter(Boolean);
  if (p.endsWith('._kind')) { setPath(ed.draft, p.slice(0, -6), { _kind: v }); return true; } // a new kind starts a clean row
  if (/^edge\.\d+\.type$/.test(p) && v === 'custom') v = 'custom';
  setPath(ed.draft, p, v);
  if (p === 'id') ed.idTouched = true;
  if (ed.creating && !ed.idTouched && (p === 'client' || p === 'name')) ed.draft.id = suggestId(ed.draft.client, ed.draft.name);
  ed.server = ed.server.filter(e => e.field !== p);
  return true;
}

export async function onAction(act, b, { t, toast, go, refresh }) {
  const E = t.ed;
  if (act === 'row-add') { ed.draft[b.dataset.k].push(b.dataset.k === 'stack' ? { _kind: 'pkg' } : {}); return true; }
  if (act === 'row-del') { ed.draft[b.dataset.k].splice(+b.dataset.v, 1); return true; }
  if (act === 'save') {
    ed.tried = true;
    if (errorsNow().length) return true;
    ed.saving = true;
    const asset = M.cleanDraft(ed.draft);
    const r = ed.creating ? await call('POST', '/api/assets', { rev: ed.rev, asset }) : await call('PUT', `/api/assets/${encodeURIComponent(asset.id)}`, { rev: ed.rev, asset });
    ed.saving = false;
    if (r.status === 201 || r.status === 200) { toast(E.saved); ed.for = null; await refresh(); go(`#/clientes/${encodeURIComponent(asset.client)}`); return false; }
    if (r.status === 422) { ed.server = r.data.errors || []; return true; }
    if (r.status === 409) { toast(r.data.error === 'inventoryBroken' ? E.broken : E.conflict); const keep = ed.draft; ed.for = null; await openEditor(location.hash, ed.creating ? null : keep.id, keep.client, () => {}); if (r.data.error !== 'inventoryBroken') ed.draft = keep; return true; }
    toast(r.data.error || `HTTP ${r.status}`); return true;
  }
  if (act === 'asset-del') {
    if (!confirm(E.confirmDel)) return false;
    const r = await call('DELETE', `/api/assets/${encodeURIComponent(ed.draft.id)}`, { rev: ed.rev });
    if (r.status === 200) { toast(E.deleted); ed.for = null; await refresh(); go(`#/clientes/${encodeURIComponent(ed.draft.client)}`); return false; }
    toast(r.status === 409 ? E.conflict : r.data.error || `HTTP ${r.status}`); return false;
  }
  if (act === 'pause') {
    const inv = await call('GET', '/api/inventory');
    const r = await call('POST', `/api/assets/${encodeURIComponent(b.dataset.key)}/pause`, { rev: inv.data.rev, paused: b.dataset.v === '1' });
    toast(r.status === 200 ? (b.dataset.v === '1' ? E.paused : E.resumed) : r.data.error || `HTTP ${r.status}`);
    await refresh(); return false;
  }
  return false;
}

// ---------- maintenance ----------
export const mt = { scope: 'client', asset: '', dur: '2', from: '', to: '', reason: '' };
const localInput = ms => { const d = new Date(ms - new Date(ms).getTimezoneOffset() * 60_000); return d.toISOString().slice(0, 16); };

export function maintenanceBlock(S, t, { client = null } = {}) {
  const T = t.mt, all = M.maintenanceView(S).filter(w => !client || w.all || w.client === client || (S.inventory || []).some(a => a.client === client && (w.assets || []).includes(a.id)));
  const fmt = iso => new Date(iso).toLocaleString(String(t.nav.hoy) === 'Hoy' ? 'es-ES' : 'en-GB', { dateStyle: 'short', timeStyle: 'short' });
  const list = all.length ? `<div class="list">${all.map(w => `<div class="row"><span class="state ${w.active ? 'warn' : 'off'}"></span><div class="main"><div class="title">${esc(w.covers === '*' ? T.everything : w.covers)}</div>
    <div class="meta">${esc(w.active ? T.active : T.upcoming)} · ${esc(fmt(w.from))} → ${esc(fmt(w.to))}${w.reason ? ` · ${esc(w.reason)}` : ''}</div></div>
    <div class="side-r"><button class="btn small" data-act="mt-end" data-key="${esc(w.id)}">${esc(T.end)}</button></div></div>`).join('')}</div>` : `<p class="mut small">${esc(T.none)}</p>`;
  const assets = (S.inventory || []).filter(a => !client || a.client === client);
  const scopeOpts = [...(client ? [['client', T.thisClient]] : [['all', T.everything], ['client', t.nav.clientes]]), ['asset', T.asset]];
  if (!scopeOpts.some(([v]) => v === mt.scope)) mt.scope = scopeOpts[0][0];
  const sel = (name, opts, cur) => `<select data-m="${name}">${opts.map(([v, l]) => `<option value="${esc(v)}" ${String(cur) === String(v) ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select>`;
  const clients = [...new Set((S.inventory || []).map(a => a.client).filter(Boolean))].sort();
  const form = `<div class="card mtform"><div class="grid4">
    <label class="fld"><span>${esc(T.scope)}</span>${sel('scope', scopeOpts, mt.scope)}</label>
    ${mt.scope === 'asset' ? `<label class="fld"><span>${esc(T.asset)}</span>${sel('asset', assets.map(a => [a.id, `${client ? '' : `${a.client} · `}${a.name || a.id}`]), mt.asset || assets[0]?.id)}</label>` : ''}
    ${mt.scope === 'client' && !client ? `<label class="fld"><span>${esc(t.nav.clientes)}</span>${sel('client', clients.map(c => [c, c]), mt.client || clients[0])}</label>` : ''}
    <label class="fld"><span>${esc(T.duration)}</span>${sel('dur', [['1', `1 ${T.h}`], ['2', `2 ${T.h}`], ['4', `4 ${T.h}`], ['8', `8 ${T.h}`], ['t8', T.tomorrow8], ['custom', T.custom]], mt.dur)}</label>
    ${mt.dur === 'custom' ? `<label class="fld"><span>${esc(T.from)}</span><input type="datetime-local" data-m="from" value="${esc(mt.from || localInput(Date.now()))}"></label><label class="fld"><span>${esc(T.to)}</span><input type="datetime-local" data-m="to" value="${esc(mt.to || localInput(Date.now() + 2 * 3600_000))}"></label>` : ''}
    <label class="fld wide"><span>${esc(T.reason)}</span><input data-m="reason" value="${esc(mt.reason)}" maxlength="200"></label></div>
    <p class="mut small">${esc(T.explain)}</p><button class="btn primary" data-act="mt-start" data-client="${esc(client || '')}">${icon('clock', 'sm')}${esc(T.start)}</button></div>`;
  return `<div class="section"><h2>${icon('clock', 'sm')}${esc(T.title)}</h2>${list}<details ${all.length ? '' : 'open'}><summary class="btn small">${icon('plus', 'sm')}${esc(T.schedule)}</summary>${form}</details></div>`;
}

export function onMaintenanceInput(el) { if (!el.dataset.m) return false; mt[el.dataset.m] = el.value; return true; }

export async function onMaintenanceAction(act, b, S, { t, toast, refresh }) {
  if (act === 'mt-end') {
    const r = await call('DELETE', `/api/maintenance/${encodeURIComponent(b.dataset.key)}`);
    toast(r.status === 200 ? t.mt.ended : r.data.error || `HTTP ${r.status}`); await refresh(); return;
  }
  if (act !== 'mt-start') return;
  const now = Date.now(), client = b.dataset.client || mt.client || [...new Set((S.inventory || []).map(a => a.client))].sort()[0];
  let from = now, to;
  if (mt.dur === 'custom') { from = Date.parse(mt.from || localInput(now)); to = Date.parse(mt.to || localInput(now + 2 * 3600_000)); }
  else if (mt.dur === 't8') { const d = new Date(now); d.setDate(d.getDate() + 1); d.setHours(8, 0, 0, 0); to = d.getTime(); }
  else to = now + Number(mt.dur) * 3600_000;
  const assets = (S.inventory || []).filter(a => !b.dataset.client || a.client === b.dataset.client);
  const body = { from: new Date(from).toISOString(), to: new Date(to).toISOString(), reason: mt.reason || undefined,
    ...(mt.scope === 'all' ? { all: true } : mt.scope === 'client' ? { client } : { assets: [mt.asset || assets[0]?.id] }) };
  const r = await call('POST', '/api/maintenance', body);
  if (r.status === 201) { toast(t.mt.scheduled); mt.reason = ''; await refresh(); return; }
  toast(r.status === 422 ? (r.data.errors || []).map(e => M.errText(e, t)).join(' · ') : r.data.error || `HTTP ${r.status}`);
}

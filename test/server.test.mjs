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
const hooks = [];

const freePort = () => new Promise(r => { const s = http.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });

function start(env, { waitFor = 'Vigía on' } = {}) {
  const p = spawn(process.execPath, [path.join(ROOT, 'server.mjs')], { env: { PATH: process.env.PATH, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
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
  aux = http.createServer((q, r) => { let b = ''; q.on('data', d => { b += d; }).on('end', () => { if (q.url === '/hook') hooks.push(JSON.parse(b)); r.end('ok'); }); }).listen(auxPort, '127.0.0.1');
  fs.writeFileSync(path.join(dir, 'inventory.json'), JSON.stringify([{ id: 'shop', client: 'ACME', name: 'Shop', url: `http://127.0.0.1:${auxPort}/`, criticality: 'high', backups: [{ id: 'db' }] }]));
  ({ p: srv } = await start({
    PORT: String(port), DASH_PASS: PASS, CHECKIN_SECRET: MASTER, ACK_SECRET: ACK, PUBLIC_URL: `http://127.0.0.1:${port}`, CANARY_DAYS: '0',
    WEBHOOK_URL: `http://127.0.0.1:${auxPort}/hook`, CONNECTIVITY_URLS: `http://127.0.0.1:${auxPort}/ok`,
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

test('ten wrong passwords block the address for a while', async () => {
  const bad = { authorization: `Basic ${Buffer.from('vigia:nope').toString('base64')}` };
  for (let i = 0; i < 10; i++) await fetch(url('/api/state'), { headers: bad });
  assert.equal((await fetch(url('/api/state'), { headers: bad })).status, 429);
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createAlerts, REPEAT_P1_MS, RETRY_MS } from '../alerts.mjs';
import { messages } from '../i18n.mjs';
import { applyAccept } from '../lib.mjs';

function rig({ deliverOk = true } = {}) {
  const sent = [], clock = { t: Date.parse('2026-10-23T10:00:00Z') };
  const state = {};
  const ok = { value: deliverOk };
  const notify = async (prio, title, body, key) => { sent.push({ prio, title, body, key }); return ok.value ? { sent: 1, total: 1 } : { sent: 0, total: 1 }; };
  const A = createAlerts({ state, T: messages('en'), notify, applyAccept, now: () => clock.t });
  const tick = ms => { clock.t += ms; };
  const settle = () => new Promise(r => setImmediate(r));
  return { A, state, sent, clock, tick, settle, ok };
}

test('a worse priority re-pages and resets the acknowledgement (Codex: priority frozen)', async () => {
  const { A, state, sent, settle } = rig();
  A.raise('tls:x', 'P2', 'cert expires in 10 d', '', 'x');
  await settle();
  A.ack('tls:x');
  A.raise('tls:x', 'P2', 'cert expires in 9 d', '', 'x'); // same priority: quiet update
  A.raise('tls:x', 'P1', 'cert expires in 2 d', '', 'x');  // worse: page again
  await settle();
  const a = state.alerts['tls:x'];
  assert.deepEqual([a.prio, a.ack, a.title], ['P1', false, 'cert expires in 2 d']);
  assert.deepEqual(sent.map(s => s.prio), ['P2', 'P1']);
  assert.match(sent[1].title, /worse/i);
  assert.equal(state.history.at(-1).prio, 'P1');
  A.raise('tls:x', 'P2', 'better?', '', 'x'); // never lowered automatically
  assert.equal(state.alerts['tls:x'].prio, 'P1');
});

test('a burst becomes one summary whose group key acknowledges every alert in it', async () => {
  const { A, state, sent } = rig();
  await A.run('uptime', async () => { for (let i = 0; i < 6; i++) A.raise(`down:s${i}`, 'P1', `site ${i} DOWN`, '', `s${i}`); });
  assert.equal(sent.length, 1);
  assert.match(sent[0].key, /^group:/);
  assert.ok(Object.values(state.alerts).every(a => a.deliveredAt));
  assert.ok(A.ack(sent[0].key));
  assert.ok(Object.values(state.alerts).every(a => a.ack));
  assert.equal(Object.keys(state.groups).length, 0);
});

test('three or fewer messages go out one by one', async () => {
  const { A, sent } = rig();
  await A.run('uptime', async () => { A.raise('down:a', 'P1', 'a', '', 'a'); A.raise('down:b', 'P2', 'b', '', 'b'); A.raise('mail:audit:c', 'P3', 'c', '', 'c'); });
  assert.deepEqual(sent.map(s => s.key), ['down:a', 'down:b']); // P3 never pushed
});

test('onboarding summarises; a scan that fails half-way keeps its findings for the next summary (Codex: silenced forever)', async () => {
  const { A, state, sent } = rig();
  const inv = [{ id: 'a', client: 'C', name: 'Shop' }];
  await assert.rejects(A.run('osv', () => A.onboard(inv, 'osv', async () => {
    A.raise('osv:X:a:lodash', 'P2', 'GHSA-x', '', 'a');
    throw new Error('network');
  })));
  assert.equal(sent.length, 0);
  assert.ok(state.alerts['osv:X:a:lodash'].onb, 'still waiting for a summary');
  assert.equal(state.scanned['osv:a'], undefined);
  await A.run('osv', () => A.onboard(inv, 'osv', async () => { A.raise('osv:Y:a:lodash', 'P2', 'GHSA-y', '', 'a'); }));
  assert.equal(sent.length, 1);
  assert.match(sent[0].title, /2 findings/);
  assert.ok(!state.alerts['osv:X:a:lodash'].onb && state.alerts['osv:X:a:lodash'].deliveredAt);
  assert.ok(state.scanned['osv:a']);
  A.ack(sent[0].key);
  assert.ok(state.alerts['osv:Y:a:lodash'].ack);
});

test('P3-only onboarding sends nothing but counts as delivered', async () => {
  const { A, state, sent } = rig();
  await A.run('dns', () => A.onboard([{ id: 'a' }], 'mail', async () => A.raise('mail:audit:a', 'P3', 'spoofable', '', 'a')));
  assert.equal(sent.length, 0);
  assert.ok(state.alerts['mail:audit:a'].deliveredAt);
});

test('undelivered P2s are retried and P1s repeat until acknowledged (Codex: lost on restart / outage)', async () => {
  const { A, state, sent, tick, settle, ok } = rig({ deliverOk: false });
  A.raise('backup:failed:x', 'P2', 'backup failed', '', 'x');
  A.raise('down:y', 'P1', 'site DOWN', '', 'y');
  await settle();
  assert.equal(state.alerts['backup:failed:x'].deliveredAt, null);
  ok.value = true;
  tick(RETRY_MS + 1);
  await A.run('health', async () => A.sweep());
  assert.ok(state.alerts['backup:failed:x'].deliveredAt);
  assert.ok(sent.some(s => s.title.startsWith('(repeat)')));
  const before = sent.length;
  tick(RETRY_MS + 1);
  await A.run('health', async () => A.sweep());
  assert.equal(sent.filter(s => s.key === 'backup:failed:x').length, 2, 'a delivered P2 is not sent again');
  A.ack('down:y');
  tick(REPEAT_P1_MS + 1);
  await A.run('health', async () => A.sweep());
  assert.equal(sent.length, before + 1, 'only the P1 repeat of the previous sweep; nothing after the ack');
});

test('a P1 found during onboarding does not wait for the summary forever', async () => {
  const { A, state, sent, tick } = rig({ deliverOk: false });
  await A.run('kev', () => A.onboard([{ id: 'a' }], 'kev', async () => A.raise('kev:CVE-1:a', 'P1', 'KEV', '', 'a')));
  assert.ok(state.alerts['kev:CVE-1:a'].onb);
  tick(REPEAT_P1_MS + 1);
  await A.run('health', async () => A.sweep());
  assert.ok(sent.some(s => s.key === 'kev:CVE-1:a' && s.title.startsWith('(repeat)')));
});

test('onboarding findings nobody summarised are announced by the sweep', async () => {
  const { A, state, sent, tick } = rig();
  state.alerts['osv:Z:a:x'] = { key: 'osv:Z:a:x', prio: 'P2', title: 'orphan', body: '', asset: 'a', first: 0, sentAt: 0, ack: false, deliveredAt: null, onb: Date.now() - 2 * 3600_000 };
  tick(0);
  await A.run('health', async () => A.sweep());
  assert.equal(sent.length, 1);
  assert.match(sent[0].key, /^group:/);
});

test('accept-change alerts apply the new baseline on acknowledge', () => {
  const { A, state } = rig();
  state.dns = { a: { NS: ['old'] } };
  A.raise('dns:a:NS', 'P1', 'NS changed', '', 'a', { path: ['dns', 'a', 'NS'], set: ['new'] });
  A.ack('dns:a:NS');
  assert.deepEqual(state.dns.a.NS, ['new']);
  assert.equal(state.alerts['dns:a:NS'], undefined);
  assert.equal(state.history.at(-1).accepted, true);
});

test('resolve sends RECOVERED only for P1/P2 and when not quiet', async () => {
  const { A, sent, settle } = rig();
  A.raise('down:a', 'P1', 'DOWN', '', 'a'); A.raise('mail:audit:a', 'P3', 'x', '', 'a'); A.raise('edge:mgmt:a:0', 'P2', 'exposed', '', 'a');
  await settle(); sent.length = 0;
  A.resolve('down:a', 'back'); A.resolve('mail:audit:a', ''); A.resolve('edge:mgmt:a:0', '', { quiet: true });
  await settle();
  assert.deepEqual(sent.map(s => s.title), ['RECOVERED DOWN']);
});

test('firstOf binds acknowledge links to one alert instance or group', async () => {
  const { A, state, sent } = rig();
  const a = A.raise('down:a', 'P1', 'x', '', 'a');
  assert.equal(A.firstOf('down:a'), a.first);
  await A.run('u', async () => { for (let i = 0; i < 5; i++) A.raise(`down:b${i}`, 'P1', 'x', '', `b${i}`); });
  assert.equal(A.firstOf(sent.at(-1).key), state.groups[sent.at(-1).key.slice(6)].at);
  assert.equal(A.firstOf('down:none'), null);
});

test('maintenance: alerts are kept but not sent; still-open ones go out when the window ends', async () => {
  const sent = [], clock = { t: Date.parse('2026-10-23T10:00:00Z') }, state = {};
  let muted = true;
  const A = createAlerts({ state, T: messages('en'), notify: async (...m) => { sent.push(m); return { sent: 1 }; }, applyAccept, now: () => clock.t, isMuted: id => muted && id === 'shop' });
  await A.run('uptime', async () => { A.raise('down:shop', 'P1', 'Shop DOWN', '', 'shop'); A.raise('tls:shop', 'P2', 'cert', '', 'shop'); A.raise('down:other', 'P1', 'Other DOWN', '', 'other'); });
  assert.deepEqual(sent.map(m => m[3]), ['down:other'], 'only the asset outside maintenance pages');
  assert.ok(state.alerts['down:shop'].muted);
  A.resolve('tls:shop', 'renewed'); // fixed during the window: nothing to announce
  clock.t += 20 * 60_000;
  await A.run('health', async () => A.sweep());
  assert.ok(!sent.some(m => m[3] === 'down:shop'), 'no P1 repeat during maintenance');
  muted = false;
  await A.run('health', async () => A.sweep());
  const after = sent.filter(m => m[3] === 'down:shop');
  assert.equal(after.length, 1);
  assert.match(after[0][1], /after maintenance/);
  assert.ok(!sent.some(m => /RECOVERED cert/.test(m[1])));
  assert.equal(state.alerts['down:shop'].muted, undefined);
});

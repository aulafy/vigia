import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderReport, reportStats, category, monthRange, previousMonth, fmtDuration, reportStrings } from '../report.mjs';

const H = 3600_000, oct = Date.UTC(2026, 9, 1);
const data = {
  client: 'ACME <Ltd>', month: '2026-10', brand: 'IT Pro', generatedAt: oct + 25 * 24 * H, timeZone: 'Europe/Madrid',
  assets: [{ id: 'a', name: 'Shop', url: 'https://shop', criticality: 'high', avail: [1000, 998], pushedAt: oct + 10 * 24 * H,
    edge: [{ name: 'Office FW', product: 'FortiGate (FortiOS)', version: '7.2.5', alerts: 1 }] }],
  history: [
    { key: 'down:a', prio: 'P1', title: 'Shop is DOWN', asset: 'a', first: oct + 2 * H, ackAt: oct + 2 * H + 10 * 60_000, resolvedAt: oct + 3 * H },
    { key: 'osv:X:a:lodash', prio: 'P2', title: 'GHSA-x in lodash', asset: 'a', first: oct + 5 * H, ackAt: oct + 6 * H },
    { key: 'dns:a:NS', prio: 'P1', title: 'NS changed', asset: 'a', first: oct + 7 * H, ackAt: oct + 7 * H, resolvedAt: oct + 7 * H, accepted: true },
    { key: 'mail:audit:a', prio: 'P3', title: 'spoofable', asset: 'a', first: oct + 8 * H },
    { key: 'down:a', prio: 'P1', title: 'September outage', asset: 'a', first: oct - 5 * H, resolvedAt: oct - 4 * H },
  ],
  open: [
    { key: 'osv:X:a:lodash', prio: 'P2', title: 'GHSA-x in lodash <script>', first: oct + 5 * H },
    { key: 'adv:a:0:abc', prio: 'P1', title: 'FortiOS SSL-VPN exploited', first: oct + 20 * H },
    { key: 'mail:audit:a', prio: 'P3', title: 'spoofable', first: oct + 8 * H },
  ],
  backups: [{ key: 'a/db', lastSuccess: oct + 24 * H, lastRestoreTest: null, problems: ['P2'] }],
};

test('monthRange and previousMonth', () => {
  assert.deepEqual(monthRange('2026-10'), [Date.UTC(2026, 9, 1), Date.UTC(2026, 10, 1)]);
  assert.equal(previousMonth('2026-01'), '2025-12');
  assert.equal(previousMonth('2026-10'), '2026-09');
  assert.throws(() => monthRange('2026-13'), /invalid month/);
});

test('reportStats', () => {
  const s = reportStats(data);
  assert.equal(s.availability, 0.998);
  assert.deepEqual(s.incidents, { P1: 2, P2: 1, P3: 0 }); // P3 and last month's outage excluded
  assert.deepEqual(s.openNow, { P1: 1, P2: 1, P3: 1 });
  assert.equal(s.mtta, 10 * 60_000); // median of 10 min, 1 h, 0
  assert.equal(s.mttr, 30 * 60_000); // median of 1 h and 0
  assert.deepEqual(Object.fromEntries(s.byCategory), { vulns: 1, edge: 1, domain: 1 });
});

test('category and fmtDuration', () => {
  assert.equal(category('down:a'), 'availability');
  assert.equal(category('wp:x:a:plugin:y'), 'vulns');
  assert.equal(category('edge:mgmt:a:0'), 'edge');
  assert.equal(category('backup:failed:a/db'), 'backup');
  assert.equal(category('canary:x'), 'other');
  assert.equal(fmtDuration(45 * 60_000), '45 min');
  assert.equal(fmtDuration(3 * H), '3.0 h');
  assert.equal(fmtDuration(4 * 24 * H), '4 d');
  assert.equal(fmtDuration(null), null);
});

test('renderReport escapes, includes every section, and both languages have the same strings', () => {
  for (const lang of ['en', 'es']) {
    const html = renderReport(data, lang);
    assert.match(html, /^<!doctype html>/);
    assert.ok(!html.includes('<script>') && html.includes('&lt;script&gt;'), 'titles are escaped');
    assert.ok(html.includes('ACME &lt;Ltd&gt;'));
    assert.ok(html.includes('99.80 %'));
    assert.ok(html.includes('Office FW') && html.includes('a/db') && html.includes('FortiOS SSL-VPN exploited'));
    assert.ok(!html.includes('September outage'));
  }
  assert.ok(renderReport(data, 'es').includes('Informe de seguridad'));
  const keys = o => Object.keys(o).sort();
  assert.deepEqual(keys(reportStrings('en')), keys(reportStrings('es')));
  assert.deepEqual(keys(reportStrings('en').cat), keys(reportStrings('es').cat));
});

test('renderReport with an empty month says so instead of failing', () => {
  const html = renderReport({ client: 'X', month: '2026-10', assets: [], history: [], open: [], backups: [] }, 'en');
  assert.match(html, /No pending actions/);
});

test('months are counted in the configured time zone, DST included (Codex: UTC boundaries)', async () => {
  const { monthRange: mr } = await import('../report.mjs');
  assert.deepEqual(mr('2026-10', 'Europe/Madrid').map(t => new Date(t).toISOString()), ['2026-09-30T22:00:00.000Z', '2026-10-31T23:00:00.000Z']);
  assert.deepEqual(mr('2026-03', 'Europe/Madrid').map(t => new Date(t).toISOString()), ['2026-02-28T23:00:00.000Z', '2026-03-31T22:00:00.000Z']);
  assert.deepEqual(mr('2026-10').map(t => new Date(t).toISOString()), ['2026-10-01T00:00:00.000Z', '2026-11-01T00:00:00.000Z']);
  // an incident at 00:30 local on 1 October belongs to October in Madrid, to September in UTC
  const at = Date.parse('2026-09-30T22:30:00Z');
  const s = reportStats({ month: '2026-10', timeZone: 'Europe/Madrid', history: [{ key: 'down:a', prio: 'P1', first: at, asset: 'a' }] });
  assert.equal(s.incidents.P1, 1);
  assert.equal(reportStats({ month: '2026-10', history: [{ key: 'down:a', prio: 'P1', first: at, asset: 'a' }] }).incidents.P1, 0);
});

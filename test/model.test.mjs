import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import * as M from '../public/model.js';
import { category as reportCategory } from '../report.mjs';
import { ICONS } from '../public/icons.js';

const now = Date.parse('2026-10-23T10:00:00Z');
const S = {
  lang: 'es', month: '2026-10',
  inventory: [
    { id: 'shop', client: 'ACME', name: 'Shop', url: 'https://shop', avail: [100, 99], edge: [] },
    { id: 'blog', client: 'ACME', name: 'Blog', url: 'https://blog', paused: true, edge: [] },
    { id: 'net', client: 'ACME', name: 'Network', edge: [{ name: 'FW', type: 'fortigate', product: 'FortiGate (FortiOS)', version: '7.2.5', edgeIndex: 0 }] },
    { id: 'dent', client: 'Dental', name: 'Citas', url: 'https://citas', avail: [10, 0], edge: [] },
  ],
  status: { shop: { ok: true }, blog: { ok: false }, dent: { ok: false } },
  alerts: [
    { key: 'down:dent', prio: 'P2', title: 'Citas DOWN', body: '', asset: 'dent', first: now - 60_000, ack: false },
    { key: 'kev:CVE-1:net', prio: 'P1', title: 'CVE-1 KEV', body: 'uses FortiGate (FortiOS) 7.2.5', asset: 'net', first: now - 120_000, ack: false },
    { key: 'edge:mgmt:net:0', prio: 'P2', title: 'admin exposed', body: '', asset: 'net', first: now - 30_000, ack: true },
    { key: 'mail:audit:shop', prio: 'P3', title: 'spoofable', body: 'no DMARC', asset: 'shop', first: now, ack: false },
    { key: 'backup:failed:shop/db', prio: 'P1', title: 'db FAILED', body: '', asset: 'shop', first: now - 10_000, ack: false },
    { key: 'feed:kev', prio: 'P2', title: 'KEV feed stale', body: '', asset: null, first: now - 5_000, ack: false },
  ],
  backups: { 'shop/db': { lastSuccess: now - 864e5, lastBytes: 2e9 }, 'dent/nas': { lastSuccess: now } },
  feeds: { uptime: now - 20_000, kev: now - 60_000, kevErr: 'timeout' },
  notify: { ntfy: true, telegram: false, webhook: true, heartbeat: true }, channels: { ntfy: { ok: false, err: 'HTTP 500' }, webhook: { ok: true } },
};

test('UI strings: both languages have the same keys', () => {
  const keys = o => Object.entries(o).flatMap(([k, v]) => (v && typeof v === 'object' ? keys(v).map(x => `${k}.${x}`) : [k])).sort();
  assert.deepEqual(keys(M.STR.en), keys(M.STR.es));
  assert.equal(M.strings('es-ES').nav.hoy, 'Hoy');
  assert.equal(M.strings('fr').nav.hoy, 'Today');
});

test('category matches the monthly report', () => {
  for (const k of ['down:x', 'tls:x', 'osv:a:b:c', 'wp:x', 'kev:x', 'eol:x', 'inv:stale:x', 'domain:exp:x', 'dns:x:NS', 'mail:audit:x', 'backup:failed:a/b', 'web:script:x:h', 'adv:x:0:h', 'edge:mgmt:x:0', 'canary:x', 'feed:kev'])
    assert.equal(M.category(k), reportCategory(k), k);
});

test('summarize', () => {
  const s = M.summarize(S);
  assert.equal(s.level, 'crit'); // unacknowledged P1s
  assert.deepEqual([s.sites, s.up, s.down, s.p1, s.p2], [2, 1, 1, 2, 2]); // the paused blog is not counted
  assert.deepEqual(s.urgent.map(a => a.key), ['backup:failed:shop/db', 'kev:CVE-1:net', 'feed:kev', 'down:dent']); // P1 newest first, no P3, no acked
  assert.equal(M.summarize({ inventory: [], alerts: [] }).level, 'ok');
  assert.equal(M.summarize({ inventory: [], alerts: [], chain: { ok: false } }).level, 'crit');
});

test('filterAlerts by view, priority, client and text', () => {
  const keys = f => M.filterAlerts(S, f).map(a => a.key);
  assert.equal(keys({}).length, 5); // acked one hidden
  assert.equal(keys({ view: 'all' }).length, 6);
  assert.deepEqual(keys({ prio: 'P3' }), ['mail:audit:shop']);
  assert.deepEqual(keys({ client: 'Dental' }), ['down:dent']);
  assert.deepEqual(keys({ q: 'dmarc' }), ['mail:audit:shop']); // body text
  assert.deepEqual(keys({ q: 'acme', prio: 'P1' }), ['backup:failed:shop/db', 'kev:CVE-1:net']); // client name
  assert.deepEqual(M.sortAlerts(S.alerts).at(-1).key, 'edge:mgmt:net:0'); // acknowledged last
});

test('clientsView', () => {
  const [acme, dental] = M.clientsView(S);
  assert.equal(acme.name, 'ACME'); assert.deepEqual([acme.P1, acme.P2, acme.P3, acme.devices, acme.down], [2, 0, 1, 1, 0]);
  assert.deepEqual([acme.checks, acme.ok], [100, 99]);
  assert.deepEqual([dental.P2, dental.down], [1, 1]);
});

test('devicesView links alerts to the device', () => {
  const [fw] = M.devicesView(S);
  assert.equal(fw.client, 'ACME');
  assert.deepEqual(fw.alerts.map(a => a.key), ['kev:CVE-1:net', 'edge:mgmt:net:0']);
  assert.equal(fw.exposed, true);
  assert.equal(fw.worst, 'P1');
});

test('backupsView', () => {
  const [bad, ok] = M.backupsView(S);
  assert.deepEqual([bad.key, bad.client, bad.job, bad.worst], ['shop/db', 'ACME', 'db', 'P1']);
  assert.deepEqual([ok.key, ok.worst], ['dent/nas', null]);
});

test('feeds, channels, badge and formatting', () => {
  const kev = M.feedsView(S).find(f => f.name === 'kev');
  assert.deepEqual(kev, { name: 'kev', at: now - 60_000, err: 'timeout' });
  assert.deepEqual(M.channelsView(S).map(c => [c.name, c.configured, c.ok]), [['ntfy', true, false], ['telegram', false, null], ['webhook', true, true]]);
  assert.equal(M.navBadge(S), 4);
  assert.equal(M.ago(now - 30_000, 'es', now), 'hace 30 s');
  assert.equal(M.ago(now - 3 * 3600_000, 'en', now), '3 h ago');
  assert.equal(M.ago(null, 'en', now), 'never');
  assert.equal(M.fmtBytes(2.4e9), '2.4 GB');
  assert.equal(M.fmtPct(999, 1000), '99.90 %');
  assert.equal(M.fmtPct(0, 0), '—');
  assert.equal(M.esc('<a href="x">'), '&lt;a href=&quot;x&quot;&gt;');
});

test('app shell: manifest, icons and service worker list real files', () => {
  const pub = new URL('../public/', import.meta.url);
  const manifest = JSON.parse(fs.readFileSync(new URL('manifest.webmanifest', pub)));
  for (const i of manifest.icons) assert.ok(fs.existsSync(new URL(i.src, pub)), i.src);
  assert.ok(manifest.icons.some(i => i.sizes === '512x512' && i.purpose === 'maskable'));
  const sw = fs.readFileSync(new URL('sw.js', pub), 'utf8');
  for (const f of JSON.parse(sw.match(/const SHELL = (\[[^\]]*\])/)[1].replace(/'/g, '"'))) assert.ok(f === '/' || fs.existsSync(new URL(f.slice(1), pub)), f);
  const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url)));
  assert.match(sw, new RegExp(`vigia-shell-${pkg.version.replace(/\./g, '\\.')}`), 'bump the service-worker cache name with the version');
  const app = fs.readFileSync(new URL('app.js', pub), 'utf8');
  for (const [, name] of app.matchAll(/icon\('([a-z]+)'/g)) assert.ok(ICONS.includes(name), `icon ${name}`);
});

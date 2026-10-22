import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as L from '../lib.mjs';
import { messages } from '../i18n.mjs';

test('normalizeAsset maps legacy Spanish fields', () => {
  const a = L.normalizeAsset({ id: 'x', cliente: 'C', criticidad: 'alta', contacto: 'Z' });
  assert.equal(a.client, 'C');
  assert.equal(a.criticality, 'high');
  assert.equal(a.contact, 'Z');
  assert.deepEqual(a.stack, []);
  assert.equal(L.normalizeAsset({ id: 'y' }).criticality, 'medium');
});

test('loadInventory reports bad entries and keeps good ones', () => {
  const { assets, errors } = L.loadInventory([
    { id: 'a', domain: 'a.com' }, { id: 'a', domain: 'b.com' }, { domain: 'c.com' }, { id: 'd' }, { id: 'e', url: 'https://e', criticality: 'urgent' },
  ]);
  assert.deepEqual(assets.map(a => a.id), ['a', 'e']);
  assert.equal(errors.length, 4);
  assert.match(L.loadInventory({}).errors[0], /array/);
});

test('kevMatches uses whole words and kev overrides', () => {
  const v = (vendorProject, product) => ({ vendorProject, product });
  assert.ok(L.kevMatches(v('WordPress', 'WordPress'), { product: 'wordpress' }));
  assert.ok(!L.kevMatches(v('phpMyAdmin', 'phpMyAdmin'), { product: 'php' }));
  assert.ok(L.kevMatches(v('PHP', 'PHP'), { product: 'php' }));
  assert.ok(L.kevMatches(v('Apache', 'HTTP Server'), { product: 'apache', kev: ['apache http server'] }));
  assert.ok(!L.kevMatches(v('Apache', 'OFBiz'), { product: 'apache', kev: ['apache http server'] }));
  assert.ok(L.kevMatches(v('Fortinet', 'FortiOS'), { product: 'fortios' }));
  assert.ok(!L.kevMatches(v('Fortinet', 'FortiOS'), { name: 'lodash' }));
});

test('priorities', () => {
  assert.equal(L.osvPriority({ sev: 'LOW', inKev: true, criticality: 'low' }), 'P1');
  assert.equal(L.osvPriority({ sev: 'CRITICAL', inKev: false, criticality: 'high' }), 'P1');
  assert.equal(L.osvPriority({ sev: 'CRITICAL', inKev: false, criticality: 'low' }), 'P2');
  assert.equal(L.osvPriority({ sev: 'HIGH', inKev: false, criticality: 'high' }), 'P2');
  assert.equal(L.osvPriority({ sev: '', inKev: false, criticality: 'high' }), 'P3');
  assert.equal(L.downPriority('high'), 'P1');
  assert.equal(L.downPriority('low'), 'P2');
  assert.equal(L.tlsPriority(1), 'P1');
  assert.equal(L.tlsPriority(10), 'P2');
  assert.equal(L.tlsPriority(30), null);
});

test('matchCycle picks the most specific cycle', () => {
  const cycles = [{ cycle: '8' }, { cycle: '8.1' }, { cycle: '8.10' }];
  assert.equal(L.matchCycle(cycles, '8.1.27').cycle, '8.1');
  assert.equal(L.matchCycle(cycles, '8.10.2').cycle, '8.10');
  assert.equal(L.matchCycle(cycles, '8.2.0').cycle, '8');
  assert.equal(L.matchCycle(cycles, '7.4'), null);
});

test('eolDays and eolPriority', () => {
  const now = Date.parse('2026-06-01');
  assert.equal(L.eolDays({ eol: false }, now), null);
  assert.equal(L.eolDays({ eol: true }, now), -1);
  assert.equal(L.eolDays({ eol: '2026-06-11' }, now), 10);
  assert.equal(L.eolPriority(-5, 'high'), 'P2');
  assert.equal(L.eolPriority(-5, 'low'), 'P3');
  assert.equal(L.eolPriority(30, 'high'), 'P3');
  assert.equal(L.eolPriority(200, 'high'), null);
  assert.equal(L.eolPriority(null, 'high'), null);
});

test('ack signatures', () => {
  const sig = L.signAck('down:x', 's3cret');
  assert.equal(sig.length, 32);
  assert.ok(L.verifyAck('down:x', sig, 's3cret'));
  assert.ok(!L.verifyAck('down:y', sig, 's3cret'));
  assert.ok(!L.verifyAck('down:x', sig, 'other'));
  assert.ok(!L.verifyAck('down:x', sig, undefined));
  assert.ok(!L.verifyAck('down:x', null, 's3cret'));
});

test('localClock respects the time zone', () => {
  const d = new Date('2026-01-01T23:30:00Z');
  assert.deepEqual(L.localClock('Europe/Madrid', d), { day: '2026-01-02', hour: 0 });
  assert.deepEqual(L.localClock('UTC', d), { day: '2026-01-01', hour: 23 });
});

test('both languages define the same messages', () => {
  assert.deepEqual(Object.keys(messages('en')).sort(), Object.keys(messages('es')).sort());
  assert.equal(messages('es-ES').ack, 'Confirmar');
  assert.equal(messages('fr').ack, 'Acknowledge');
});

test('registrableDomain', () => {
  assert.equal(L.registrableDomain('www.shop.example.com'), 'example.com');
  assert.equal(L.registrableDomain('Example.COM.'), 'example.com');
  assert.equal(L.registrableDomain('tienda.empresa.com.es'), 'empresa.com.es');
  assert.equal(L.registrableDomain('www.bbc.co.uk'), 'bbc.co.uk');
  assert.equal(L.registrableDomain('mi-web.es'), 'mi-web.es');
  assert.equal(L.registrableDomain('127.0.0.1'), '127.0.0.1');
});

test('rdapBase and parseRdap', () => {
  const boot = { services: [[['com', 'net'], ['http://x/', 'https://rdap.verisign.com/com/v1/']], [['org'], ['https://rdap.org/']]] };
  assert.equal(L.rdapBase(boot, 'example.com'), 'https://rdap.verisign.com/com/v1/');
  assert.equal(L.rdapBase(boot, 'example.es'), null);
  const r = L.parseRdap({
    status: ['client transfer prohibited', 'active'],
    events: [{ eventAction: 'registration', eventDate: '1995-08-14' }, { eventAction: 'expiration', eventDate: '2027-08-13T04:00:00Z' }],
    entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'RESERVED-IANA']]] }],
  });
  assert.equal(r.expires, '2027-08-13T04:00:00Z');
  assert.equal(r.registrar, 'RESERVED-IANA');
  assert.equal(r.locked, true);
  assert.deepEqual(r.hold, []);
  const h = L.parseRdap({ status: ['client hold', 'redemption period'], entities: [{ roles: ['registrar'], handle: 'R1' }] });
  assert.deepEqual(h.hold, ['client hold', 'redemption period']);
  assert.equal(h.registrar, 'R1');
  assert.equal(h.locked, false);
});

test('domain expiry priority', () => {
  const now = Date.parse('2026-06-01');
  assert.equal(L.daysUntil('2026-06-04', now), 3);
  assert.equal(L.daysUntil(null, now), null);
  assert.equal(L.domainExpiryPriority(-1), 'P1');
  assert.equal(L.domainExpiryPriority(3), 'P1');
  assert.equal(L.domainExpiryPriority(20), 'P2');
  assert.equal(L.domainExpiryPriority(60), null);
  assert.equal(L.domainExpiryPriority(null), null);
  assert.equal(L.domainExpiryPriority(L.daysUntil('garbage', now)), null);
});

test('DNS normalisation and diff', () => {
  assert.deepEqual(L.normRecords(['B.iana-servers.net.', 'a.iana-servers.net', 'a.iana-servers.net.']), ['a.iana-servers.net', 'b.iana-servers.net']);
  assert.deepEqual(L.normRecords(['']), []); // null MX
  assert.deepEqual(L.diffSets(['a', 'b'], ['b', 'c']), { added: ['c'], removed: ['a'] });
  assert.deepEqual(L.diffSets(['a'], ['a']), { added: [], removed: [] });
});

test('isForeign', () => {
  assert.ok(!L.isForeign('cdn.example.com', 'www.example.com'));
  assert.ok(L.isForeign('evil.io', 'example.com'));
  assert.ok(!L.isForeign('www.googletagmanager.com', 'example.com', ['googletagmanager.com']));
  assert.ok(L.isForeign('googletagmanager.com.evil.io', 'example.com', ['googletagmanager.com']));
});

test('scriptHosts and metaRefreshTarget', () => {
  const html = `<script src="/js/app.js"></script><script async src='https://www.googletagmanager.com/gtag/js?id=1&amp;l=x'></script>
    <SCRIPT type="module" SRC=//cdn.evil.io/x.js></SCRIPT><script>inline()</script>`;
  assert.deepEqual(L.scriptHosts(html, 'https://shop.example.com/'), ['cdn.evil.io', 'shop.example.com', 'www.googletagmanager.com']);
  assert.equal(L.metaRefreshTarget('<meta content="0; url=https://spam.io/x" http-equiv="refresh">', 'https://a.com'), 'spam.io');
  assert.equal(L.metaRefreshTarget(`<meta http-equiv='Refresh' content='5;URL=/home'>`, 'https://a.com/'), 'a.com');
  assert.equal(L.metaRefreshTarget('<meta name="viewport" content="width=device-width">', 'https://a.com'), null);
});

test('defacementSigns', () => {
  assert.deepEqual(L.defacementSigns('<h1>Hacked By Team X</h1>'), ['Hacked By']);
  assert.deepEqual(L.defacementSigns('<!-- slot gacor hari ini --> <p>ok</p>'), ['slot gacor']);
  assert.deepEqual(L.defacementSigns('<p>We sell blinds. Book a call.</p>'), []);
  assert.deepEqual(L.defacementSigns('<p>Hacked by curiosity: our blog</p>', ['hacked by']), []);
});

test('applyAccept sets and adds baseline values', () => {
  const s = { dns: { x: { NS: ['a'] } }, web: {} };
  L.applyAccept(s, { path: ['dns', 'x', 'NS'], set: ['b'] });
  assert.deepEqual(s.dns.x.NS, ['b']);
  L.applyAccept(s, { path: ['web', 'y', 'scripts'], add: 'z.io' });
  L.applyAccept(s, { path: ['web', 'y', 'scripts'], add: 'a.io' });
  L.applyAccept(s, { path: ['web', 'y', 'scripts'], add: 'z.io' });
  assert.deepEqual(s.web.y.scripts, ['a.io', 'z.io']);
});

test('formHosts and iframeHosts', () => {
  const html = `<form action="/login"></form><form method=post action="https://collect.evil.io/p"></form><form></form>
    <iframe src="https://www.youtube.com/embed/x"></iframe><iframe src="javascript:void(0)"></iframe>`;
  assert.deepEqual(L.formHosts(html, 'https://shop.example.com/'), ['collect.evil.io', 'shop.example.com']);
  assert.deepEqual(L.iframeHosts(html, 'https://shop.example.com/'), ['www.youtube.com']);
});

test('SPF issues', () => {
  assert.deepEqual(L.spfIssues(['google-site-verification=x']), ['spf-missing']);
  assert.deepEqual(L.spfIssues(['v=spf1 include:_spf.google.com ~all']), []);
  assert.deepEqual(L.spfIssues(['v=spf1 -all']), []);
  assert.deepEqual(L.spfIssues(['v=spf1 a mx +all']), ['spf-plusall']);
  assert.deepEqual(L.spfIssues(['v=spf1 a mx all']), ['spf-plusall']);
  assert.deepEqual(L.spfIssues(['v=spf1 a -all', 'v=spf1 mx -all']), ['spf-multiple']);
  assert.deepEqual(L.spfRecords(['v=spf1 -all', 'v=spf10 x', 'other']), ['v=spf1 -all']);
});

test('DMARC parsing, issues and levels', () => {
  assert.deepEqual(L.parseDmarc(['v=DMARC1; p=reject; rua=mailto:d@example.com']), { count: 1, p: 'reject' });
  assert.deepEqual(L.dmarcIssues([]), ['dmarc-missing']);
  assert.deepEqual(L.dmarcIssues(['v=DMARC1; p=none']), ['dmarc-none']);
  assert.deepEqual(L.dmarcIssues(['v=DMARC1; p=quarantine']), []);
  assert.deepEqual(L.dmarcIssues(['v=DMARC1; p=reject', 'v=DMARC1; p=none']), ['dmarc-multiple']);
  assert.equal(L.dmarcLevel(['v=DMARC1; p=reject']), 2);
  assert.equal(L.dmarcLevel([]), -1);
});

test('mail change priority: weaker is P2, the rest P3', () => {
  assert.equal(L.mailChangePriority('DMARC', ['v=dmarc1; p=reject'], ['v=dmarc1; p=none']), 'P2');
  assert.equal(L.mailChangePriority('DMARC', ['v=dmarc1; p=reject'], []), 'P2');
  assert.equal(L.mailChangePriority('DMARC', ['v=dmarc1; p=none'], ['v=dmarc1; p=reject']), 'P3');
  assert.equal(L.mailChangePriority('SPF', ['v=spf1 -all'], []), 'P2');
  assert.equal(L.mailChangePriority('SPF', ['v=spf1 -all'], ['v=spf1 +all']), 'P2');
  assert.equal(L.mailChangePriority('SPF', ['v=spf1 -all'], ['v=spf1 include:x -all']), 'P3');
  assert.equal(L.mailChangePriority('SPF', [], ['v=spf1 -all']), 'P3');
});

test('deliveryOk checks real delivery per channel', () => {
  assert.ok(L.deliveryOk('ntfy', 200, { id: 'abc', event: 'message' }));
  assert.ok(!L.deliveryOk('ntfy', 200, null));
  assert.ok(L.deliveryOk('telegram', 200, { ok: true }));
  assert.ok(!L.deliveryOk('telegram', 200, { ok: false }));
  assert.ok(!L.deliveryOk('telegram', 403, { ok: false }));
  assert.ok(L.deliveryOk('webhook', 204, null));
  assert.ok(!L.deliveryOk('webhook', 500, null));
});

test('retry retries, then gives up with the last error', async () => {
  let n = 0;
  assert.equal(await L.retry(async () => { if (++n < 3) throw new Error('x'); return 'ok'; }, [0, 0]), 'ok');
  assert.equal(n, 3);
  n = 0;
  await assert.rejects(L.retry(async () => { n++; throw new Error(`fail ${n}`); }, [0, 0]), /fail 3/);
});

test('heartbeatFailUrl', () => {
  assert.equal(L.heartbeatFailUrl('https://hc-ping.com/uuid'), 'https://hc-ping.com/uuid/fail');
  assert.equal(L.heartbeatFailUrl('https://hc-ping.com/uuid/'), 'https://hc-ping.com/uuid/fail');
  assert.equal(L.heartbeatFailUrl('https://x', 'https://y/fail'), 'https://y/fail');
  assert.equal(L.heartbeatFailUrl(undefined), null);
});

test('check-in signatures: valid, tampered, expired', () => {
  const now = Date.parse('2026-10-22T10:00:00Z'), ts = Math.floor(now / 1000), path = '/api/backup/acme/db?status=success', body = '{"bytes":10}';
  const sig = L.signCheckin('k', ts, path, body);
  assert.ok(L.verifyCheckin({ secret: 'k', ts, path, body, sig, now }));
  assert.ok(L.verifyCheckin({ secret: 'k', ts: String(ts), path, body, sig: 'sha256=' + sig, now }));
  assert.ok(!L.verifyCheckin({ secret: 'k', ts, path: '/api/backup/acme/other?status=success', body, sig, now }));
  assert.ok(!L.verifyCheckin({ secret: 'k', ts, path, body: '{"bytes":99}', sig, now }));
  assert.ok(!L.verifyCheckin({ secret: 'k', ts, path, body, sig, now: now + 10 * 60_000 }));
  assert.ok(!L.verifyCheckin({ secret: undefined, ts, path, body, sig, now }));
  assert.ok(!L.verifyCheckin({ secret: 'k', ts: 'abc', path, body, sig, now }));
});

test('backupFindings', () => {
  const H = 3600_000, now = Date.parse('2026-10-22T10:00:00Z'), job = { rpoHours: 24, graceMinutes: 60, restoreTestDays: 30 };
  assert.deepEqual(L.backupFindings(job, { since: now - H, lastRestoreTest: now }, now), []);
  assert.deepEqual(L.backupFindings(job, { since: now - 26 * H, lastRestoreTest: now }, now).map(f => [f.kind, f.never]), [['overdue', true]]);
  assert.deepEqual(L.backupFindings(job, { since: now - 99 * H, lastSuccess: now - 2 * H, lastRestoreTest: now }, now), []);
  assert.deepEqual(L.backupFindings(job, { lastSuccess: now - 30 * H, lastRestoreTest: now }, now).map(f => f.kind), ['overdue']);
  assert.deepEqual(L.backupFindings(job, { lastSuccess: now - 30 * H, lastFail: now - H, lastRestoreTest: now }, now).map(f => f.kind), ['failed']);
  assert.deepEqual(L.backupFindings(job, { lastSuccess: now, lastFail: now - H, lastRestoreTest: now }, now), []);
  assert.deepEqual(L.backupFindings(job, { since: now - 40 * 864e5, lastSuccess: now }, now).map(f => [f.kind, f.never]), [['restore', true]]);
  const shrunk = L.backupFindings(job, { lastSuccess: now, lastRestoreTest: now, lastBytes: 100, bytesHistory: [1000, 1100, 900] }, now);
  assert.deepEqual(shrunk.map(f => [f.kind, f.median]), [['shrunk', 1000]]);
  assert.deepEqual(L.backupFindings(job, { lastSuccess: now, lastRestoreTest: now, lastBytes: 100, bytesHistory: [1000, 1100] }, now), []);
  assert.deepEqual(L.backupFindings({}, { since: now - 23 * H }, now), []);
});

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

test('compareVersions', () => {
  const c = L.compareVersions;
  assert.equal(c('1.0', '1.0.0'), 0);
  assert.equal(c('v2.4', '2.4.0'), 0);
  assert.equal(c('5.8.10', '5.8.9'), 1);
  assert.equal(c('1.0-beta', '1.0'), -1);
  assert.equal(c('1.0', '1.0-rc1'), 1);
  assert.equal(c('1.0-rc1', '1.0-beta2'), 1);
  assert.equal(c('1.0.1', '1.0-beta'), 1);
  assert.equal(c('2.0.0', '10.0'), -1);
});

test('inRange with inclusive and open bounds', () => {
  assert.ok(L.inRange('5.8.2', ['*', true, '5.8.3', false]));
  assert.ok(!L.inRange('5.8.3', ['*', true, '5.8.3', false]));
  assert.ok(L.inRange('5.8.3', ['*', true, '5.8.3', true]));
  assert.ok(!L.inRange('2.0', ['2.0', false, '*', true]));
  assert.ok(L.inRange('2.1', ['2.0', true, '2.5', true]));
  assert.ok(!L.inRange('1.9', ['2.0', true, '2.5', true]));
});

const WF_FEED = {
  'aaa': { id: 'aaa', title: 'Contact Form 7 <= 5.3.1 - Unauthenticated Arbitrary File Upload', informational: false, cve: 'CVE-2020-35489',
    cvss: { score: 10, rating: 'Critical', vector: 'x' },
    software: [{ type: 'plugin', slug: 'contact-form-7', name: 'Contact Form 7', patched: true, patched_versions: ['5.3.2'],
      affected_versions: { '* - 5.3.1': { from_version: '*', from_inclusive: true, to_version: '5.3.1', to_inclusive: true } } }] },
  'bbb': { id: 'bbb', title: 'Info only', informational: true, software: [{ type: 'plugin', slug: 'contact-form-7', affected_versions: {}, patched: false, patched_versions: [] }] },
  'ccc': { id: 'ccc', title: 'WordPress Core < 6.4.3 - Authenticated PHP Object Injection', cvss: { score: 7.2, rating: 'High' }, cve: null,
    software: [{ type: 'core', slug: 'wordpress', patched: true, patched_versions: ['6.4.3'],
      affected_versions: { '6.4 - 6.4.2': { from_version: '6.4', from_inclusive: true, to_version: '6.4.2', to_inclusive: true } } }] },
};

test('indexWordfence and wpMatches', () => {
  const idx = L.indexWordfence(WF_FEED);
  assert.deepEqual(Object.keys(idx).sort(), ['core:wordpress', 'plugin:contact-form-7']);
  assert.equal(idx['plugin:contact-form-7'].length, 1); // informational skipped
  assert.deepEqual(L.wpMatches(idx, { wp: 'plugin', slug: 'contact-form-7', version: '5.3.1' }).map(v => v.id), ['aaa']);
  assert.deepEqual(L.wpMatches(idx, { wp: 'plugin', slug: 'contact-form-7', version: '5.3.2' }), []);
  assert.deepEqual(L.wpMatches(idx, { wp: 'core', version: '6.4.1' }).map(v => v.id), ['ccc']);
  assert.deepEqual(L.wpMatches(idx, { wp: 'core', version: '6.3.9' }), []);
  assert.deepEqual(L.wpMatches(idx, { wp: 'theme', slug: 'nope', version: '1' }), []);
});

test('wpPriority', () => {
  assert.equal(L.wpPriority({ score: 10, title: 'X - Unauthenticated RCE', inKev: false, criticality: 'low' }), 'P1');
  assert.equal(L.wpPriority({ score: 9.1, title: 'X - Authenticated (Admin+) RCE', inKev: false, criticality: 'medium' }), 'P2');
  assert.equal(L.wpPriority({ score: 9.1, title: 'X - Authenticated', inKev: false, criticality: 'high' }), 'P1');
  assert.equal(L.wpPriority({ score: 4.3, title: 'X', inKev: true, criticality: 'low' }), 'P1');
  assert.equal(L.wpPriority({ score: 6.1, title: 'X - Unauthenticated Stored XSS', inKev: false, criticality: 'high' }), 'P3');
  assert.equal(L.wpPriority({ score: null, title: 'X', inKev: false, criticality: 'high' }), 'P3');
});

test('purlToItem', () => {
  assert.deepEqual(L.purlToItem('pkg:npm/%40babel/core@7.22.0'), { ecosystem: 'npm', name: '@babel/core', version: '7.22.0' });
  assert.deepEqual(L.purlToItem('pkg:composer/guzzlehttp/guzzle@v7.4.0'), { ecosystem: 'Packagist', name: 'guzzlehttp/guzzle', version: '7.4.0' });
  assert.deepEqual(L.purlToItem('pkg:pypi/django@4.2.1'), { ecosystem: 'PyPI', name: 'django', version: '4.2.1' });
  assert.deepEqual(L.purlToItem('pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1'), { ecosystem: 'Maven', name: 'org.apache.logging.log4j:log4j-core', version: '2.14.1' });
  assert.deepEqual(L.purlToItem('pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12.4'), { ecosystem: 'Debian:12', name: 'openssl', version: '3.0.11-1~deb12u2' });
  assert.deepEqual(L.purlToItem('pkg:deb/ubuntu/openssl@3.0.2?distro=ubuntu-22.04'), { ecosystem: 'Ubuntu:22.04', name: 'openssl', version: '3.0.2' });
  assert.deepEqual(L.purlToItem('pkg:apk/alpine/musl@1.2.4-r2?distro=3.19.1'), { ecosystem: 'Alpine:v3.19', name: 'musl', version: '1.2.4-r2' });
  assert.equal(L.purlToItem('pkg:deb/debian/openssl@3.0'), null); // no distro: ecosystem unknown
  assert.equal(L.purlToItem('pkg:generic/foo@1'), null);
  assert.equal(L.purlToItem('not a purl'), null);
});

test('lockfile parsers skip dev dependencies', () => {
  const v3 = { packages: { '': { name: 'app' }, 'node_modules/lodash': { version: '4.17.15' }, 'node_modules/jest': { version: '29.0.0', dev: true },
    'node_modules/a/node_modules/@scope/b': { version: '1.0.0' }, 'node_modules/local': { link: true } } };
  assert.deepEqual(L.npmLockItems(v3).map(x => `${x.name}@${x.version}`), ['lodash@4.17.15', '@scope/b@1.0.0']);
  const v1 = { dependencies: { lodash: { version: '4.17.15', dependencies: { x: { version: '1.0.0' } } }, jest: { version: '29.0.0', dev: true }, g: { version: 'git+https://x' } } };
  assert.deepEqual(L.npmLockItems(v1).map(x => `${x.name}@${x.version}`), ['lodash@4.17.15', 'x@1.0.0']);
  const comp = { packages: [{ name: 'guzzlehttp/guzzle', version: 'v7.4.0' }, { name: 'x/y', version: 'dev-main' }], 'packages-dev': [{ name: 'phpunit/phpunit', version: '10.0.0' }] };
  assert.deepEqual(L.composerLockItems(comp), [{ ecosystem: 'Packagist', name: 'guzzlehttp/guzzle', version: '7.4.0' }]);
});

test('SBOM parsers', () => {
  const bom = { components: [{ purl: 'pkg:npm/lodash@4.17.15', components: [{ purl: 'pkg:pypi/django@4.2.1' }] }, { name: 'no purl' }] };
  assert.deepEqual(L.cyclonedxItems(bom).map(x => x.name), ['lodash', 'django']);
  const spdx = { packages: [{ externalRefs: [{ referenceType: 'purl', referenceLocator: 'pkg:npm/lodash@4.17.15' }, { referenceType: 'cpe23Type', referenceLocator: 'cpe:x' }] }] };
  assert.deepEqual(L.spdxItems(spdx), [{ ecosystem: 'npm', name: 'lodash', version: '4.17.15' }]);
});

test('parsePush builds a deduplicated stack and reports bad parts', () => {
  const { stack, errors } = L.parsePush({ parts: [
    { kind: 'wp', core: '6.4.1', plugins: [{ name: 'contact-form-7', status: 'inactive', version: '5.3.1' }], themes: [{ name: 'astra', version: '4.0' }] },
    { kind: 'os', id: 'ubuntu', version: '22.04' }, { kind: 'os', id: 'templeos', version: '1' },
    { kind: 'runtime', name: 'php', version: '8.1.27' }, { kind: 'runtime', name: 'node', version: 'v20.11.0' }, { kind: 'runtime', name: 'apache', version: '2.4.58' },
    { kind: 'npm-lock', lock: { packages: { 'node_modules/lodash': { version: '4.17.15' } } } },
    { kind: 'cyclonedx', bom: { components: [{ purl: 'pkg:npm/lodash@4.17.15' }] } },
    { kind: 'bogus' },
  ] });
  assert.deepEqual(errors, ['part 8: unknown kind "bogus"']);
  const keys = stack.map(s => s.wp ? `${s.wp}:${s.slug}@${s.version}` : s.ecosystem ? `${s.ecosystem}:${s.name}@${s.version}` : `${s.product}/${s.eol}@${s.version}`);
  assert.deepEqual(keys, ['core:wordpress@6.4.1', 'plugin:contact-form-7@5.3.1', 'theme:astra@4.0', 'ubuntu/ubuntu@22.04',
    'php/php@8.1.27', 'nodejs/nodejs@20.11.0', 'apache/apache-http-server@2.4.58', 'npm:lodash@4.17.15']);
  assert.equal(stack[1].status, 'inactive');
  assert.deepEqual(stack[6].kev, ['apache http server']);
  assert.deepEqual(L.parsePush({}).stack, []);
});

test('inventoryStale', () => {
  const H = 3600_000, now = Date.parse('2026-10-22T10:00:00Z');
  assert.equal(L.inventoryStale({}, undefined, now), null); // never pushed, no expectation
  assert.equal(L.inventoryStale({}, { at: now - 47 * H }, now), null);
  assert.deepEqual(L.inventoryStale({}, { at: now - 50 * H }, now), { hours: 50, never: false, maxH: 48 });
  assert.deepEqual(L.inventoryStale({ inventoryMaxAgeHours: 24 }, { since: now - 30 * H }, now), { hours: 30, never: true, maxH: 24 });
  assert.equal(L.inventoryStale({ inventoryMaxAgeHours: 24 }, { since: now - 2 * H }, now), null);
});

test('pool keeps order and limits concurrency', async () => {
  let live = 0, peak = 0;
  const out = await L.pool([5, 1, 4, 2, 3], 2, async x => { live++; peak = Math.max(peak, live); await new Promise(r => setTimeout(r, x)); live--; return x * 10; });
  assert.deepEqual(out, [50, 10, 40, 20, 30]);
  assert.equal(peak, 2);
  assert.deepEqual(await L.pool([], 5, async x => x), []);
});

test('parseEnvLine strips quotes and comments', () => {
  assert.deepEqual(L.parseEnvLine('NTFY_TOPIC="abc def"'), ['NTFY_TOPIC', 'abc def']);
  assert.deepEqual(L.parseEnvLine("export X='1'"), ['X', '1']);
  assert.deepEqual(L.parseEnvLine('PORT=4848   # dashboard'), ['PORT', '4848']);
  assert.deepEqual(L.parseEnvLine('URL=https://x.io/#frag'), ['URL', 'https://x.io/#frag']);
  assert.equal(L.parseEnvLine('# comment'), null);
  assert.equal(L.parseEnvLine(''), null);
});

test('deriveKey is per asset and deterministic', () => {
  assert.equal(L.deriveKey('m', 'a'), L.deriveKey('m', 'a'));
  assert.notEqual(L.deriveKey('m', 'a'), L.deriveKey('m', 'b'));
  assert.notEqual(L.deriveKey('m', 'a'), L.deriveKey('n', 'a'));
  assert.match(L.deriveKey('m', 'a'), /^[0-9a-f]{64}$/);
});

test('clip and kevTerm', () => {
  assert.equal(L.clip('abcdef', 4), 'abc…');
  assert.equal(L.clip('abc', 4), 'abc');
  assert.equal(L.clip(undefined, 4), '');
  assert.equal(L.kevTerm({ product: 'WordPress' }), 'wordpress');
  assert.equal(L.kevTerm({ product: 'apache', kev: ['Apache HTTP Server', 'httpd'] }), 'apache http server|httpd');
  assert.equal(L.kevTerm({ ecosystem: 'npm', name: 'x' }), '');
});

test('edge devices become stack items', () => {
  const a = L.normalizeAsset({ id: 'net', client: 'C', edge: [{ type: 'fortigate', version: '7.2.5', management: 'https://203.0.113.10:4443', name: 'Madrid office' }, { type: 'custom-box', kev: ['acme vpn'] }] });
  const [f, c] = a.stack;
  assert.equal(f.edge, true); assert.equal(f.eol, 'fortios'); assert.deepEqual(f.kev, ['fortios', 'fortiproxy']); assert.equal(f.name, 'Madrid office');
  assert.deepEqual(c.kev, ['acme vpn']); assert.deepEqual(c.feeds, ['incibe']);
  assert.ok(L.kevMatches({ vendorProject: 'Fortinet', product: 'FortiOS' }, f));
  const { assets, errors } = L.loadInventory([{ id: 'only-edge', edge: [{ type: 'paloalto' }] }, { id: 'bad', edge: [{}] }]);
  assert.deepEqual(assets.map(x => x.id), ['only-edge', 'bad']);
  assert.deepEqual(errors, ['bad: edge[0] needs a "type"']);
});

const RSS = `<rss><channel>
<item><title>CVE-2026-0322 PAN-OS: Authenticated Remote Code Execution (RCE) in the Management Interface (Severity: HIGH)</title><pubDate>2026-10-15T18:30:00.000Z</pubDate><link>https://security.paloaltonetworks.com/CVE-2026-0322</link><guid>https://security.paloaltonetworks.com/CVE-2026-0322</guid></item>
<item><title>Impact of PHP vulnerabilities on Palo Alto Networks products</title><description><![CDATA[<p>CVE-2026-109618 affects Prisma Cloud</p>]]></description><link>https://x/php</link></item>
<item><title>Heap overflow in FortiOS SSL-VPN</title><description>&lt;p&gt;&lt;strong&gt;CVSSv3 Score:&lt;/strong&gt; 9.8&lt;/p&gt; This vulnerability is being exploited in the wild.</description><link>https://fortiguard.fortinet.com/psirt/FG-IR-1</link></item>
</channel></rss>`;

test('parseFeed, advisoryMatches and advisorySeverity', () => {
  const items = L.parseFeed(RSS);
  assert.equal(items.length, 3);
  assert.deepEqual(items[0].cves, ['CVE-2026-0322']);
  assert.equal(items[0].date, Date.parse('2026-10-15T18:30:00.000Z'));
  assert.match(items[2].text, /CVSSv3 Score: 9\.8/);
  const pa = L.edgeItem({ type: 'paloalto' }, 0), fg = L.edgeItem({ type: 'fortigate' }, 1);
  assert.deepEqual(items.map(i => L.advisoryMatches(i, pa)), [true, false, false]); // the PHP bulletin is not about PAN-OS
  assert.deepEqual(items.map(i => L.advisoryMatches(i, fg)), [false, false, true]);
  assert.deepEqual(L.advisorySeverity(items[0]), { prio: 'P2', exploited: false });
  assert.deepEqual(L.advisorySeverity(items[2]), { prio: 'P1', exploited: true });
  assert.deepEqual(L.advisorySeverity({ title: 'GUI denial of service (Severity: LOW)', text: '' }), { prio: 'P3', exploited: false });
  assert.deepEqual(L.advisorySeverity({ title: 'Vulnerabilidad crítica en SonicOS', text: 'explotada activamente' }), { prio: 'P1', exploited: true });
  assert.equal(L.htmlText('&lt;b&gt;A&amp;amp;B&lt;/b&gt; &#233;'), 'A&B é');
});

test('EPSS parsing and escalation', () => {
  const e = L.parseEpss({ data: [{ cve: 'CVE-1', epss: '0.97', percentile: '0.999' }] });
  assert.deepEqual(e, { 'CVE-1': { epss: 0.97, pct: 0.999 } });
  assert.equal(L.epssPriority('P2', 0.6), 'P1');
  assert.equal(L.epssPriority('P3', 0.2), 'P2');
  assert.equal(L.epssPriority('P3', 0.05), 'P3');
  assert.equal(L.epssPriority('P1', 0.01), 'P1'); // never lowers
  assert.equal(L.epssPriority('P2', 0.2, { p1: 0.15, p2: 0.05 }), 'P1');
  assert.deepEqual(L.cvesIn('fix CVE-2026-0322 and cve-2024-3400, again CVE-2026-0322'), ['CVE-2026-0322', 'CVE-2024-3400']);
});

test('advisorySeverity: negations never read as exploitation; research wording does', () => {
  const p = (title, text = '') => L.advisorySeverity({ title, text });
  assert.equal(p('X (Severity: HIGH)', 'Fortinet is not aware of any active exploitation in the wild.').prio, 'P2');
  assert.equal(p('X (Severity: HIGH)', 'Palo Alto Networks is not aware of any malicious exploitation of this issue.').prio, 'P2');
  assert.equal(p('X', 'This issue is not known to be exploited in the wild.').prio, 'P3');
  assert.equal(p('X', 'There is no evidence of active exploitation.').prio, 'P3');
  assert.equal(p('Aviso crítico', 'No se tiene constancia de que esté siendo explotada activamente.').prio, 'P2');
  assert.equal(p('X', 'Not known to be exploited. However, CISA reports it was exploited in the wild.').prio, 'P1');
  assert.deepEqual(p('Swarming Against Citrix 0-Day Exploitation'), { prio: 'P1', exploited: true });
  assert.equal(p('Citrix NetScaler DTLS Preauth Memory Overflow').prio, 'P2');
  assert.deepEqual(p('A New SonicWall Scanning Spike Echoes the Pattern That Preceded CVE-2026-1'), { prio: 'P2', exploited: false, recon: true });
});

test('htmlText survives entities outside Unicode', () => {
  assert.equal(L.htmlText('a &#x110000; b &#55296; c &#233;'), 'a � b � c é');
  assert.doesNotThrow(() => L.parseFeed('<item><title>&#99999999;</title></item>'));
});

test('parsePush reports truncation instead of cutting silently', () => {
  const lock = { packages: Object.fromEntries(Array.from({ length: L.MAX_PUSH + 5 }, (_, i) => [`node_modules/p${i}`, { version: '1.0.0' }])) };
  const r = L.parsePush({ parts: [{ kind: 'npm-lock', lock }] });
  assert.deepEqual([r.stack.length, r.total, r.truncated], [L.MAX_PUSH, L.MAX_PUSH + 5, true]);
  assert.equal(L.parsePush({ parts: [{ kind: 'os', id: 'ubuntu', version: '22.04' }] }).truncated, false);
});

test('replayCheck: A, B, A is rejected; same-second calls with different signatures pass', () => {
  let rec = L.replayCheck(undefined, '100', 'A');
  assert.deepEqual(rec, { ts: 100, sigs: ['A'] });
  rec = L.replayCheck(rec, '101', 'B');
  assert.equal(L.replayCheck(rec, '100', 'A'), null, 'older call after a newer one');
  assert.equal(L.replayCheck(rec, '101', 'B'), null, 'exact replay');
  rec = L.replayCheck(rec, '101', 'C');
  assert.deepEqual(rec.sigs, ['B', 'C']);
});

test('ack payload binds key, instance and expiry', () => {
  const sig = L.signAck(L.ackPayload('down:a', 111, 999), 's');
  assert.ok(L.verifyAck(L.ackPayload('down:a', 111, 999), sig, 's'));
  assert.ok(!L.verifyAck(L.ackPayload('down:a', 112, 999), sig, 's'), 'another instance of the same alert');
  assert.ok(!L.verifyAck(L.ackPayload('down:a', 111, 1999), sig, 's'), 'extended expiry');
});

test('digestPick uses the cursor, not the last 24 h', () => {
  const al = [{ key: 'a', prio: 'P3', first: 50 }, { key: 'b', prio: 'P3', first: 150 }, { key: 'c', prio: 'P2', first: 10, ack: false }, { key: 'd', prio: 'P2', first: 10, ack: true }, { key: 'canary:x', prio: 'P2', first: 200 }];
  const { p2, p3 } = L.digestPick(al, 100);
  assert.deepEqual([p2.map(x => x.key), p3.map(x => x.key)], [['c'], ['b']]);
});

test('edge devices keep the "checked" date', () => {
  assert.equal(L.edgeItem({ type: 'fortigate', version: '7.2.5', checked: '2026-10-01' }, 0).checked, '2026-10-01');
});

test('Windows: endoflife.date cycles from the registry, Server by year', () => {
  assert.deepEqual(L.windowsOs({ productName: 'Windows 10 Pro', displayVersion: '24H2', build: 26100, edition: 'Professional' }).item.cycles, ['11-24h2-w', '11-24h2']);
  assert.deepEqual(L.windowsOs({ productName: 'Windows 10 Enterprise', displayVersion: '22H2', build: 19045, edition: 'Enterprise' }).item.cycles, ['10-22h2-e', '10-22h2']);
  assert.equal(L.windowsOs({ productName: 'Windows 10 Enterprise LTSC 2021', displayVersion: '21H2', build: 19044, edition: 'EnterpriseS' }).item.cycles[0], '10-21h2-e-lts');
  const srv = L.windowsOs({ productName: 'Windows Server 2012 R2 Standard', build: 9600, installationType: 'Server' });
  assert.deepEqual([srv.item.eol, srv.item.cycles[0]], ['windows-server', '2012-r2']);
  assert.equal(L.windowsOs({ productName: 'Windows 10 Pro', build: 10240 }).item, null, 'no version, no guess');
  const cycles = [{ cycle: '11-24h2-w', eol: '2026-10-13' }, { cycle: '10-22h2', eol: '2025-10-14' }];
  assert.equal(L.matchCycles(cycles, ['10-22h2-w', '10-22h2']).cycle, '10-22h2');
  assert.equal(L.matchCycles(cycles, ['11-25h2-w']), null);
});

test('installed software: only what attackers go after becomes a KEV watch', () => {
  assert.deepEqual(L.softwareItem({ name: 'Google Chrome', version: '131.0.1' }), { product: 'Google Chrome', kev: ['chromium', 'google chrome'], sw: true, version: '131.0.1', kevPrio: 'P3' });
  assert.equal(L.softwareItem({ name: '7-Zip 24.08 (x64)', version: '24.08' }).product, '7-Zip');
  assert.equal(L.softwareItem({ name: 'Veeam Backup & Replication', version: '12.1' }).kevPrio, undefined, 'servers software pages normally');
  assert.equal(L.softwareItem({ name: 'Microsoft SQL Server 2019 Setup (English)' }), null);
  assert.equal(L.softwareItem({ name: 'Paint.NET' }), null);
  assert.ok(L.kevMatches({ vendorProject: 'RARLAB', product: 'WinRAR' }, L.softwareItem({ name: 'WinRAR 7.01 (64-bit)' })));
  assert.ok(L.kevMatches({ vendorProject: 'Google', product: 'Chromium V8' }, L.softwareItem({ name: 'Google Chrome' })));
});

test('listening ports: loopback apart, one entry per port, risky services found', () => {
  const l = L.normListening([{ proto: 'tcp', addr: '127.0.0.1', port: 3306 }, { proto: 'tcp6', addr: '::', port: 3306, process: 'mysqld' },
    { proto: 'tcp', addr: '127.0.0.1', port: 631 }, { proto: 'tcp', addr: 'fe80::1%en0', port: 22 }, { port: 'x' }, { port: 70000 }]);
  assert.deepEqual(l.map(p => [p.port, p.network]), [[22, true], [631, false], [3306, true]]);
  assert.deepEqual(L.networkPorts(l), ['tcp/22', 'tcp/3306']);
  const f = L.machineFindings({ platform: 'linux', listening: l });
  assert.deepEqual(f.map(x => [x.kind, x.prio]), [['risky', 'P3']]);
  assert.match(f[0].services[0], /^MySQL \(tcp\/3306, mysqld\)$/);
  // Windows always listens on SMB: not news there; an open Docker API is
  assert.deepEqual(L.machineFindings({ platform: 'windows', av: [{ name: 'Microsoft Defender', enabled: true }], listening: L.normListening([{ addr: '0.0.0.0', port: 445 }]) }), []);
  assert.equal(L.machineFindings({ platform: 'linux', listening: L.normListening([{ addr: '0.0.0.0', port: 2375 }]) })[0].prio, 'P2');
});

test('antivirus and updates: Windows without protection pages, old signatures and patches are noted', () => {
  const now = Date.parse('2026-10-23T10:00:00Z'), day = 864e5, kinds = m => L.machineFindings(m, now).map(x => `${x.kind}:${x.prio}`);
  assert.deepEqual(kinds({ platform: 'windows', av: [] }), ['av:P2']);
  assert.deepEqual(kinds({ platform: 'windows', av: [{ name: 'Microsoft Defender', enabled: true, realTime: false }] }), ['av:P2']);
  // Defender passive behind an active third-party product is fine
  assert.deepEqual(kinds({ platform: 'windows', av: [{ name: 'Microsoft Defender', enabled: false }, { name: 'ESET', enabled: true, realTime: true, upToDate: true }] }), []);
  assert.deepEqual(kinds({ platform: 'windows', av: [{ name: 'Microsoft Defender', enabled: true, signaturesAt: now - 12 * day }] }), ['avold:P3']);
  assert.deepEqual(kinds({ platform: 'linux', av: [] }), [], 'a Linux server without antivirus is normal');
  assert.deepEqual(kinds({ platform: 'windows', av: [{ name: 'D', enabled: true }], patches: { lastInstalled: now - 50 * day } }), ['patch:P3']);
  assert.deepEqual(kinds({ platform: 'windows', av: [{ name: 'D', enabled: true }], patches: { lastInstalled: now - 100 * day } }), ['patch:P2']);
});

test('push with machine parts: OS, antivirus, software and ports parsed, nothing else needed', () => {
  const r = L.parsePush({ parts: [
    { kind: 'os', id: 'windows', productName: 'Windows 10 Pro', displayVersion: '23H2', build: 22631, edition: 'Professional' },
    { kind: 'av', products: [{ name: 'Microsoft Defender', enabled: true, realTime: true, upToDate: true, signaturesAt: '2026-10-22T08:00:00Z' }] },
    { kind: 'software', items: [{ name: 'Google Chrome', version: '131.0' }, { name: 'Paint.NET', version: '5.0' }, { version: 'no name' }] },
    { kind: 'listening', ports: [{ proto: 'tcp', addr: '0.0.0.0', port: 3389, process: 'svchost' }] },
    { kind: 'patches', lastInstalled: '2026-10-15T00:00:00Z', id: 'KB5066793' },
  ] });
  assert.deepEqual(r.errors, []);
  assert.equal(r.machine.platform, 'windows');
  assert.equal(r.machine.os, 'Windows 11 23H2 (Professional)');
  assert.equal(r.machine.software.length, 2);
  assert.equal(r.machine.av[0].signaturesAt, Date.parse('2026-10-22T08:00:00Z'));
  assert.deepEqual(r.stack.map(s => s.product), ['windows', 'Google Chrome']);
  const mac = L.parsePush({ parts: [{ kind: 'os', id: 'macos', version: '15.6.1' }] });
  assert.deepEqual([mac.machine.platform, mac.stack[0].behind], ['macos', true]);
});

test('enrolment tokens: client inside, expiring, tamper-proof; same computer, same asset', () => {
  const now = Date.now(), exp = Math.floor(now / 1000) + 3600, tok = L.signEnroll('s', 'Peluquería Ana', exp);
  assert.equal(L.verifyEnroll('s', tok, now), 'Peluquería Ana');
  assert.equal(L.verifyEnroll('other', tok, now), null);
  assert.equal(L.verifyEnroll('s', tok, (exp + 1) * 1000), null, 'expired');
  const [c, e, sig] = tok.split('.');
  assert.equal(L.verifyEnroll('s', `${Buffer.from('Otro').toString('base64url')}.${e}.${sig}`, now), null, 'client swapped');
  assert.equal(L.verifyEnroll('s', `${c}.${exp + 999}.${sig}`, now), null, 'expiry extended');
  assert.equal(L.verifyEnroll('s', '', now), null);
  const list = [{ id: 'peluqueria-ana-recepcion', client: 'Peluquería Ana', machineId: 'aa'.repeat(32) }];
  assert.deepEqual(L.enrollTarget(list, { client: 'Peluquería Ana', host: 'RECEPCION', machineId: 'aa'.repeat(32) }), { id: 'peluqueria-ana-recepcion', existing: true });
  assert.deepEqual(L.enrollTarget(list, { client: 'Peluquería Ana', host: 'RECEPCION', machineId: 'bb'.repeat(32) }), { id: 'peluqueria-ana-recepcion-2', existing: false });
  assert.deepEqual(L.loadInventory([{ id: 'pc', client: 'A', machine: 'PC' }]).errors, []);
});

test('portal links: signed per client and version, tamper-proof; what a client may see', async () => {
  const P = await import('../portal.mjs');
  const key = P.portalKey('s'), tok = P.signPortal(key, 'Clínica Sol', 3);
  assert.deepEqual(P.verifyPortal(key, tok), { client: 'Clínica Sol', v: 3 });
  assert.equal(P.verifyPortal(P.portalKey('other'), tok), null);
  const [c, , sig] = tok.split('.');
  assert.equal(P.verifyPortal(key, `${c}.4.${sig}`), null, 'version bumped by hand');
  assert.equal(P.verifyPortal(key, `${Buffer.from('ACME').toString('base64url')}.3.${sig}`), null, 'other client');
  assert.equal(P.verifyPortal(key, '../../etc'), null);
  assert.equal(P.verifyPortal(null, tok), null);
  assert.ok(P.clientVisible({ key: 'down:shop', asset: 'shop' }));
  for (const key of ['cover:osv:shop', 'enroll:x:2026-10-23', 'inv:stale:shop', 'canary:2026-10-23', 'channel:email']) assert.ok(!P.clientVisible({ key, asset: 'shop' }), key);
  assert.ok(!P.clientVisible({ key: 'feed:kev', asset: null }));
});

test('portal page: escaped, read-only, no scripts, status in plain words', async () => {
  const { renderPortal } = await import('../portal.mjs');
  const d = { client: 'ACME <script>', brand: 'IT & Co', generatedAt: Date.parse('2026-10-23T10:00:00Z'), timeZone: 'Europe/Madrid',
    alerts: [{ prio: 'P1', title: 'Shop is <b>DOWN</b>', body: 'HTTP 503', first: Date.now(), ack: true }],
    sites: [{ name: 'Shop', host: 'shop.example', down: true, avail: '99.50 %', tlsDays: 40 }],
    computers: [{ name: 'RECEPCION', os: 'Windows 11', av: null, pushedAt: Date.now(), alerts: 1 }], devices: [], backups: [],
    reports: [{ label: 'este mes · 2026-10', href: '/portal/t/report?month=2026-10' }] };
  const html = renderPortal(d, 'es');
  assert.ok(!/<script/i.test(html), 'no scripts, escaped');
  assert.match(html, /ACME &lt;script&gt;/);
  assert.match(html, /1 incidencia abierta/);
  assert.match(html, /IT se está ocupando/);
  assert.match(html, /sin antivirus activo/);
  assert.match(html, /noindex/);
  assert.match(renderPortal({ ...d, alerts: [] }, 'en'), /Everything is working/);
});

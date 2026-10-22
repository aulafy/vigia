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

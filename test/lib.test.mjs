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

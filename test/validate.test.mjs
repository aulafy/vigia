import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateAsset, validateWindow, inWindow, suggestId, ID_RE } from '../public/validate.js';

const codes = errs => errs.map(e => `${e.field}:${e.code}`);
const EDGE = ['fortigate', 'paloalto'];

test('a minimal valid asset, and what each missing piece reports', () => {
  assert.deepEqual(validateAsset({ id: 'acme-shop', client: 'ACME', domain: 'shop.acme.example' }), []);
  assert.deepEqual(codes(validateAsset({})), ['id:required', 'client:required', 'url:needTarget']);
  assert.deepEqual(codes(validateAsset({ id: 'Bad ID!', client: 'C', url: 'ftp://x' })), ['id:idFormat', 'url:url']);
  assert.deepEqual(codes(validateAsset({ id: 'a', client: 'C', domain: 'not a host' })), ['domain:host']);
  assert.deepEqual(codes(validateAsset({ id: 'a', client: 'C', domain: 'x.com' }, { ids: ['a'], creating: true })), ['id:duplicate']);
  assert.deepEqual(validateAsset({ id: 'a', client: 'C', domain: 'x.com' }, { ids: ['a'] }), [], 'editing keeps its own id');
  assert.deepEqual(codes(validateAsset([])), [':notObject']);
});

test('ranges, enums and dates', () => {
  const base = { id: 'a', client: 'C', domain: 'x.com' };
  assert.deepEqual(codes(validateAsset({ ...base, criticality: 'urgent', failThreshold: 0, timeoutMs: 500, domainExpires: '2027-13-40', skip: ['dns', 'nope'], dnsWatch: ['MX'], allowedHosts: ['ok.com', 'bad host'] })),
    ['criticality:oneOf', 'failThreshold:range', 'timeoutMs:range', 'domainExpires:date', 'skip:oneOf', 'dnsWatch:oneOf', 'allowedHosts.1:host']);
  assert.deepEqual(validateAsset({ ...base, criticality: 'high', failThreshold: 3, timeoutMs: 20000, domainExpires: '2027-03-01', skip: ['content'], dnsWatch: ['A'], allowedHosts: ['stripe.com'] }), []);
});

test('edge devices, backup jobs and software rows', () => {
  const base = { id: 'a', client: 'C' };
  assert.deepEqual(validateAsset({ ...base, edge: [{ type: 'fortigate', management: 'https://1.2.3.4:4443', portal: 'https://vpn.x.com', checked: '2026-10-01' }] }, { edgeTypes: EDGE }), [], 'device-only asset');
  assert.deepEqual(codes(validateAsset({ ...base, edge: [{}, { type: 'acme-box' }, { type: 'fortigate', management: 'nope', portal: 'http://vpn.x.com' }] }, { edgeTypes: EDGE })),
    ['edge.0.type:required', 'edge.1.type:edgeCustom', 'edge.2.management:url', 'edge.2.portal:httpsUrl']);
  assert.deepEqual(validateAsset({ ...base, edge: [{ type: 'acme-box', kev: ['acme vpn'] }] }, { edgeTypes: EDGE }), [], 'custom type with KEV phrases');
  assert.deepEqual(codes(validateAsset({ ...base, domain: 'x.com', backups: [{ id: 'db', rpoHours: 24 }, { id: 'db' }, { rpoHours: 0 }, { id: 'n', restoreTestDays: 0 }] })),
    ['backups.1.id:duplicate', 'backups.2.id:required', 'backups.2.rpoHours:range', 'backups.3.restoreTestDays:range']);
  assert.deepEqual(codes(validateAsset({ ...base, domain: 'x.com', stack: [{ wp: 'plugin', version: '1' }, { ecosystem: 'npm', version: '1' }, { eol: 'php' }, {}, { product: 'nginx' }] })),
    ['stack.0.slug:required', 'stack.1.name:required', 'stack.2.version:required', 'stack.3:stackKind']);
});

test('suggestId and ID_RE', () => {
  assert.equal(suggestId('Clínica Dental Sol', 'Citas online'), 'clinica-dental-sol-citas-online');
  assert.equal(suggestId('', ''), 'asset');
  assert.ok(ID_RE.test(suggestId('ACME & Co.', 'Web #1')));
});

test('maintenance windows: validation and who is covered', () => {
  const now = Date.parse('2026-10-23T10:00:00Z'), iso = h => new Date(now + h * 3600_000).toISOString();
  const ctx = { ids: ['a', 'b'], clients: ['ACME'], now };
  assert.deepEqual(validateWindow({ from: iso(0), to: iso(2), client: 'ACME' }, ctx), []);
  assert.deepEqual(codes(validateWindow({ from: iso(2), to: iso(1), client: 'ACME', all: true }, ctx)), ['to:afterFrom', 'to:past', 'scope:oneScope'].filter(c => c !== 'to:past'));
  assert.deepEqual(codes(validateWindow({ from: iso(0), to: iso(24 * 8), assets: ['a', 'z'] }, ctx)), ['to:maxDays', 'assets:unknown']);
  assert.deepEqual(codes(validateWindow({ from: iso(-3), to: iso(-1), client: 'Nobody' }, ctx)), ['to:past', 'client:unknown']);
  const ws = [{ from: iso(-1), to: iso(1), client: 'ACME' }, { from: iso(5), to: iso(6), assets: ['b'] }];
  assert.ok(inWindow(ws, { id: 'a', client: 'ACME' }, now));
  assert.ok(!inWindow(ws, { id: 'b', client: 'Other' }, now), 'b only from +5 h');
  assert.ok(inWindow(ws, { id: 'b', client: 'Other' }, now + 5.5 * 3600_000));
  assert.ok(inWindow([{ from: iso(-1), to: iso(1), all: true }], { id: 'x' }, now));
});

test('client names that would reach Object.prototype are refused', () => {
  for (const client of ['__proto__', 'constructor', 'prototype']) assert.ok(validateAsset({ id: 'x', client, url: 'https://x.es' }).some(e => e.code === 'reserved'), client);
});

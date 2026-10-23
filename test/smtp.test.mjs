import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { buildMessage, encodeHeader, parseAddress, plainAuthAllowed, smtpSend, validEmail } from '../smtp.mjs';
import { smtpMock, bodyOf } from './smtp-mock.mjs';

test('headers: ASCII as is, anything else as UTF-8 encoded words, no header injection', () => {
  assert.equal(encodeHeader('P1 shop is DOWN'), 'P1 shop is DOWN');
  const enc = encodeHeader('P1 Peluquería Ñandú: la web está caída');
  assert.match(enc, /^=\?UTF-8\?B\?/);
  const decoded = enc.split('\r\n ').map(w => Buffer.from(w.slice(10, -2), 'base64').toString()).join('');
  assert.equal(decoded, 'P1 Peluquería Ñandú: la web está caída');
  assert.ok(!encodeHeader('a\r\nBcc: x@evil').includes('\n'));
  assert.deepEqual(parseAddress('Vigía <alerts@example.com>'), { name: 'Vigía', email: 'alerts@example.com' });
  assert.deepEqual(parseAddress('alerts@example.com'), { name: '', email: 'alerts@example.com' });
  assert.ok(validEmail('it@acme.es') && !validEmail('it@acme') && !validEmail('a b@c.es'));
  assert.ok(plainAuthAllowed('127.0.0.1') && plainAuthAllowed('localhost') && !plainAuthAllowed('smtp.gmail.com'));
});

test('message: base64 body in short lines, priority headers, auto-generated', () => {
  const m = buildMessage({ from: 'Vigía <a@x.es>', to: ['b@y.es'], subject: 'P1 test', text: `línea 1\n.línea 2\n${'x'.repeat(300)}`, headers: { 'X-Priority': '1' } });
  const [head, body] = m.split('\r\n\r\n');
  assert.match(head, /^From: =\?UTF-8\?B\?.+\?= <a@x\.es>$/m);
  assert.match(head, /^X-Priority: 1$/m);
  assert.match(head, /^Auto-Submitted: auto-generated$/m);
  assert.match(head, /^Message-ID: <[0-9a-f-]+@x\.es>$/m);
  assert.ok(body.split('\r\n').every(l => l.length <= 76));
  assert.equal(Buffer.from(body.replace(/\s/g, ''), 'base64').toString(), `línea 1\r\n.línea 2\r\n${'x'.repeat(300)}`);
});

test('delivery: AUTH PLAIN and LOGIN, every recipient, server errors surface without the password', async () => {
  const mock = smtpMock({ user: 'u', pass: 's3cret' }), port = await mock.listen();
  const data = buildMessage({ from: 'a@x.es', to: ['b@y.es', 'c@y.es'], subject: 'hola', text: 'cuerpo' });
  await smtpSend({ host: '127.0.0.1', port, user: 'u', pass: 's3cret', from: 'a@x.es', to: ['b@y.es', 'c@y.es'], data });
  assert.equal(mock.mails.length, 1);
  assert.deepEqual(mock.mails[0].to, ['b@y.es', 'c@y.es']);
  assert.equal(bodyOf(mock.mails[0]), 'cuerpo');
  await assert.rejects(smtpSend({ host: '127.0.0.1', port, user: 'u', pass: 'wrong', from: 'a@x.es', to: ['b@y.es'], data }), e => /535/.test(e.message) && !/wrong/.test(e.message));
  mock.server.close();

  const login = smtpMock({ user: 'u', pass: 'p', offerAuth: 'LOGIN' }), lport = await login.listen();
  await smtpSend({ host: '127.0.0.1', port: lport, user: 'u', pass: 'p', from: 'a@x.es', to: ['b@y.es'], data });
  assert.equal(login.mails.length, 1);
  login.server.close();
});

test('STARTTLS: upgraded before the password is sent, certificate verified', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vigia-smtp-')), key = path.join(dir, 'k.pem'), cert = path.join(dir, 'c.pem');
  try { execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert, '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'ignore' }); }
  catch { t.skip('openssl not available'); return; }
  const tlsConf = { key: fs.readFileSync(key), cert: fs.readFileSync(cert) };
  const mock = smtpMock({ user: 'u', pass: 'p', starttls: tlsConf }), port = await mock.listen();
  const data = buildMessage({ from: 'a@x.es', to: ['b@y.es'], subject: 's', text: 't' });
  await smtpSend({ host: 'localhost', port, user: 'u', pass: 'p', from: 'a@x.es', to: ['b@y.es'], data, tlsOptions: { ca: tlsConf.cert } });
  assert.equal(mock.mails.length, 1);
  assert.equal(mock.mails[0].secure, true, 'the message went over TLS');
  await assert.rejects(smtpSend({ host: 'localhost', port, user: 'u', pass: 'p', from: 'a@x.es', to: ['b@y.es'], data }), /self[- ]signed|certificate/i);
  mock.server.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

test('addresses never reach an SMTP command unchecked', async () => {
  await assert.rejects(smtpSend({ host: '127.0.0.1', port: 1, from: 'a@x.es', to: ['b@y.es>\r\nRCPT TO:<evil@z.es'], data: '' }), /invalid address/);
  assert.throws(() => buildMessage({ from: 'a@x.es', to: ['b@y.es\r\nBcc: evil@z.es'], subject: 's', text: 't' }), /invalid recipient/);
});

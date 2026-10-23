// A small SMTP server for tests: records each message, optional STARTTLS and AUTH. Not for real use.
import net from 'node:net';
import tls from 'node:tls';

export function smtpMock({ user, pass, starttls = null, offerAuth = 'PLAIN LOGIN' } = {}) {
  const mails = [];
  const server = net.createServer(raw => {
    let sock = raw, buf = '', mail = null, inData = false, authed = !user, login = null, secure = false;
    const say = l => sock.write(`${l}\r\n`);
    const ehlo = () => { sock.write('250-mock.local\r\n'); if (starttls && !secure) sock.write('250-STARTTLS\r\n'); if (user) sock.write(`250-AUTH ${offerAuth}\r\n`); say('250 8BITMIME'); };
    const onLine = line => {
      if (inData) {
        if (line === '.') { inData = false; mails.push(mail); mail = null; return say('250 queued'); }
        mail.data += `${line.startsWith('..') ? line.slice(1) : line}\r\n`;
        return;
      }
      if (login) {
        const v = Buffer.from(line, 'base64').toString();
        if (login.step === 'user') { login = { step: 'pass', user: v }; return say('334 UGFzc3dvcmQ6'); }
        authed = login.user === user && v === pass; login = null;
        return say(authed ? '235 ok' : '535 bad credentials');
      }
      const [verb] = line.split(' '), V = verb.toUpperCase();
      if (V === 'EHLO' || V === 'HELO') return ehlo();
      if (V === 'STARTTLS' && starttls) {
        say('220 go ahead');
        sock.removeListener('data', onData);
        sock = new tls.TLSSocket(raw, { isServer: true, secureContext: tls.createSecureContext(starttls) });
        secure = true; buf = '';
        sock.on('data', onData);
        sock.on('error', () => {});
        return;
      }
      if (V === 'AUTH') {
        const [, mech, arg] = line.split(' ');
        if (mech.toUpperCase() === 'PLAIN') {
          const [, u, p] = Buffer.from(arg || '', 'base64').toString().split('\0');
          authed = u === user && p === pass;
          return say(authed ? '235 ok' : '535 bad credentials');
        }
        login = { step: 'user' };
        return say('334 VXNlcm5hbWU6');
      }
      if (V === 'MAIL') { if (!authed) return say('530 auth required'); mail = { from: line.slice(10).replace(/[<>]/g, ''), to: [], data: '', secure }; return say('250 ok'); }
      if (V === 'RCPT') { mail.to.push(line.slice(8).replace(/[<>]/g, '')); return say('250 ok'); }
      if (V === 'DATA') { inData = true; return say('354 end with .'); }
      if (V === 'QUIT') { say('221 bye'); return sock.end(); }
      say('502 not implemented');
    };
    const onData = d => {
      buf += d.toString('utf8');
      for (let i; (i = buf.indexOf('\r\n')) >= 0;) { const l = buf.slice(0, i); buf = buf.slice(i + 2); onLine(l); }
    };
    raw.on('error', () => {});
    sock.on('data', onData);
    say('220 mock.local ESMTP');
  });
  return { server, mails, listen: () => new Promise(r => server.listen(0, '127.0.0.1', () => r(server.address().port))) };
}

// Text of a base64 body
export const bodyOf = mail => Buffer.from(mail.data.split('\r\n\r\n').slice(1).join('').replace(/\s+/g, ''), 'base64').toString('utf8');
// Decoded Subject header
export const subjectOf = mail => (/^Subject: (.*(?:\r\n .*)*)/m.exec(mail.data)?.[1] || '').split('\r\n ')
  .map(w => (/^=\?UTF-8\?B\?(.*)\?=$/.exec(w) ? Buffer.from(RegExp.$1, 'base64').toString() : w)).join('');

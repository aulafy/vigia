// Minimal SMTP client for alert e-mails: implicit TLS (465) or STARTTLS (587), AUTH PLAIN / LOGIN. Zero dependencies.
import net from 'node:net';
import tls from 'node:tls';
import crypto from 'node:crypto';

const b64 = s => Buffer.from(s, 'utf8').toString('base64');
const LOCAL = new Set(['localhost', '127.0.0.1', '::1']);
// A password only goes in clear to a relay on this machine
export const plainAuthAllowed = host => LOCAL.has(String(host).toLowerCase());

// RFC 2047: non-ASCII header text as UTF-8 encoded words, split so no line gets too long
export function encodeHeader(s) {
  s = String(s ?? '').replace(/[\r\n]+/g, ' ');
  if (/^[\x20-\x7e]*$/.test(s)) return s;
  const words = [];
  let cur = '';
  for (const ch of s) { if (Buffer.byteLength(cur + ch) > 45) { words.push(cur); cur = ''; } cur += ch; }
  if (cur) words.push(cur);
  return words.map(w => `=?UTF-8?B?${b64(w)}?=`).join('\r\n ');
}

// "Vigía <alerts@example.com>" → { name: 'Vigía', email: 'alerts@example.com' }
export function parseAddress(s) {
  const m = /^\s*(.*?)\s*<([^<>\s]+@[^<>\s]+)>\s*$/.exec(String(s || ''));
  const email = (m ? m[2] : String(s || '').trim()).replace(/[\r\n<>]/g, '');
  return { name: m ? m[1].replace(/^"|"$/g, '') : '', email };
}
const formatAddress = ({ name, email }) => (name ? `${encodeHeader(name)} <${email}>` : email);
export const validEmail = s => /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(s);

// The whole message. The body is base64, so no line is too long and none starts with a dot.
export function buildMessage({ from, to, subject, text, date = new Date(), id = crypto.randomUUID(), headers = {} }) {
  const f = parseAddress(from), domain = f.email.split('@')[1] || 'vigia.local';
  if (to.some(x => !validEmail(x))) throw new Error('invalid recipient');
  const extra = Object.entries(headers).map(([k, v]) => `${k}: ${encodeHeader(v)}`);
  return [
    `From: ${formatAddress(f)}`, `To: ${to.join(', ')}`, `Subject: ${encodeHeader(subject)}`, `Date: ${date.toUTCString()}`,
    `Message-ID: <${id}@${domain}>`, 'MIME-Version: 1.0', 'Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: base64',
    'Auto-Submitted: auto-generated', ...extra, '',
    b64(String(text).replace(/\r?\n/g, '\r\n')).replace(/.{76}(?=.)/g, '$&\r\n'),
  ].join('\r\n');
}

/**
 * smtpSend({ host, port, secure, user, pass, from, to: [..], data, timeout, tlsOptions })
 * `secure` defaults to true on port 465 (implicit TLS); otherwise STARTTLS is used when offered,
 * and required before sending a password to anything but localhost.
 */
export async function smtpSend({ host, port = 587, secure, user, pass, from, to, data, timeout = 30_000, hostname = 'vigia', tlsOptions = {}, allowPlain = false }) {
  secure ??= +port === 465;
  // an address goes into an SMTP command: nothing that could end it
  for (const r of [parseAddress(from).email, ...to]) if (!validEmail(r)) throw new Error(`SMTP: invalid address ${JSON.stringify(r).slice(0, 80)}`);
  const servername = net.isIP(host) ? undefined : host;
  let sock, buf = '', waiting = null, failure = null, done = false;
  const replies = [], lines = [];
  const wake = () => {
    if (!waiting || (!replies.length && !failure)) return;
    const w = waiting; waiting = null;
    if (replies.length) w.res(replies.shift()); else w.rej(failure);
  };
  const onData = d => {
    buf += d.toString('utf8');
    for (let i; (i = buf.indexOf('\n')) >= 0;) {
      const line = buf.slice(0, i).replace(/\r$/, '');
      buf = buf.slice(i + 1);
      lines.push(line.slice(4));
      if (/^\d{3}(?: |$)/.test(line)) { replies.push({ code: +line.slice(0, 3), text: lines.join('\n') }); lines.length = 0; }
    }
    wake();
  };
  const attach = s => {
    s.on('data', onData);
    s.on('error', e => { failure ||= e; wake(); });
    s.on('close', () => { if (!done) { failure ||= new Error('SMTP connection closed'); wake(); } });
    s.setTimeout(timeout, () => s.destroy(new Error('SMTP timeout')));
    return s;
  };
  const reply = () => new Promise((res, rej) => { waiting = { res, rej }; wake(); });
  // `label` is what an error shows instead of the line sent (never a password)
  const cmd = async (line, ok, label = line) => {
    if (line != null) sock.write(`${line}\r\n`);
    const r = await reply();
    if (![].concat(ok).includes(r.code)) throw new Error(`SMTP ${label ? `${String(label).split(' ')[0]} ` : ''}${r.code} ${r.text.replace(/\s+/g, ' ').slice(0, 200)}`);
    return r;
  };
  const open = (opts, event) => new Promise((res, rej) => {
    const s = opts.socket ? tls.connect(opts) : secure ? tls.connect(opts) : net.connect(opts);
    s.once(event, () => { s.removeListener('error', rej); res(s); });
    s.once('error', rej);
    s.setTimeout(timeout, () => s.destroy(new Error('SMTP connect timeout')));
  });

  try {
    sock = attach(await open({ host, port, servername, ...tlsOptions }, secure ? 'secureConnect' : 'connect'));
    await cmd(null, 220, 'greeting');
    let ehlo = await cmd(`EHLO ${hostname}`, 250);
    if (!secure) {
      if (/^STARTTLS\b/im.test(ehlo.text)) {
        await cmd('STARTTLS', 220);
        sock.removeListener('data', onData);
        sock = attach(await open({ socket: sock, servername, ...tlsOptions }, 'secureConnect'));
        ehlo = await cmd(`EHLO ${hostname}`, 250);
      } else if (!plainAuthAllowed(host) && (user || !allowPlain)) {
        // alerts carry client names and acknowledge links: no plain text to a remote server unless explicitly allowed (and never a password)
        throw new Error(`SMTP ${host}:${port} offers no STARTTLS: refusing to send unencrypted (use port 465, or 587 with TLS${user ? '' : ', or SMTP_ALLOW_PLAIN=true'})`);
      }
    }
    if (user) {
      const mechs = (/^AUTH[ =](.*)$/im.exec(ehlo.text)?.[1] || '').toUpperCase().split(/\s+/);
      if (mechs.includes('PLAIN') || !mechs.includes('LOGIN')) await cmd(`AUTH PLAIN ${b64(`\0${user}\0${pass || ''}`)}`, 235, 'AUTH');
      else { await cmd('AUTH LOGIN', 334); await cmd(b64(user), 334, 'AUTH'); await cmd(b64(pass || ''), 235, 'AUTH'); }
    }
    await cmd(`MAIL FROM:<${parseAddress(from).email}>`, 250);
    for (const r of to) await cmd(`RCPT TO:<${r}>`, [250, 251]);
    await cmd('DATA', 354);
    await cmd(`${data.replace(/^\./gm, '..')}\r\n.`, 250, 'DATA');
    done = true;
    sock.write('QUIT\r\n');
  } finally {
    done = true;
    sock?.end();
    setTimeout(() => sock?.destroy(), 1000).unref();
  }
}

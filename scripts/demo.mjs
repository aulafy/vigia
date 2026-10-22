// `npm run demo`: Vigía with three demo clients, local sites (one down), declared firewalls and backups reporting in.
// Everything lives in a temporary folder; your data/ is not touched. Real public feeds (KEV, OSV, EPSS…) are used.
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vigia-demo-'));
const SITE_PORT = 4849, PORT = +(process.env.PORT || 4848), SECRET = 'demo-secret';
const site = p => `http://127.0.0.1:${SITE_PORT}/${p}`;
const inventory = [
  { id: 'acme-shop', client: 'ACME Retail', name: 'Online shop', url: site('shop'), criticality: 'high', contact: 'Laura Gil +34 600 111 222',
    stack: [{ ecosystem: 'npm', name: 'lodash', version: '4.17.15' }, { product: 'php', version: '8.1.27', eol: 'php' }],
    backups: [{ id: 'db', rpoHours: 24, restoreTestDays: 30 }, { id: 'files', rpoHours: 168 }] },
  { id: 'acme-blog', client: 'ACME Retail', name: 'Blog', url: site('blog'), criticality: 'low' },
  { id: 'acme-net', client: 'ACME Retail', name: 'Office network', criticality: 'high',
    edge: [{ type: 'fortigate', name: 'Madrid FortiGate', version: '7.2.5', management: `http://127.0.0.1:${SITE_PORT}/admin` }] },
  { id: 'dental', client: 'Clínica Dental Sol', name: 'Appointments', url: site('citas'), criticality: 'high',
    edge: [{ type: 'sonicwall', name: 'Front desk SonicWall', version: '7.0.1' }], backups: [{ id: 'nas', rpoHours: 24 }] },
  { id: 'gestoria', client: 'Gestoría Pérez', name: 'Client portal', url: site('down'), criticality: 'medium',
    edge: [{ type: 'paloalto', name: 'PA-440', version: '11.1.2' }] },
];
fs.writeFileSync(path.join(dir, 'inventory.json'), JSON.stringify(inventory, null, 2));

http.createServer((req, res) => {
  if (req.url === '/down') { res.writeHead(503); return res.end('maintenance'); }
  res.writeHead(200, { 'content-type': 'text/html' });
  res.end(`<html><body><h1>${req.url}</h1><script src="/app.js"></script></body></html>`);
}).listen(SITE_PORT, '127.0.0.1');

Object.assign(process.env, {
  VIGIA_INV: path.join(dir, 'inventory.json'), VIGIA_STATE: path.join(dir, 'state.json'), VIGIA_PUSHED: path.join(dir, 'pushed.json'),
  VIGIA_WORDFENCE: path.join(dir, 'wordfence.json'), CHECKIN_SECRET: SECRET, CANARY_DAYS: '0', PORT: String(PORT),
  CONNECTIVITY_URLS: site('ok'), REPORT_BRAND: 'Demo IT Services', VIGIA_LANG: process.env.VIGIA_LANG || 'es',
});
console.log(`Vigía demo: http://localhost:${PORT}  (data in ${dir})`);
await import('../server.mjs');

// backups report in, signed like real jobs would (one failed, one never reported)
const checkin = async (asset, job, status, body = '') => {
  const p = `/api/backup/${asset}/${job}?status=${status}`, ts = Math.floor(Date.now() / 1000);
  const key = crypto.createHmac('sha256', SECRET).update(`vigia-asset:${asset}`).digest('hex');
  const sig = crypto.createHmac('sha256', key).update(`${ts}.${p}.${body}`).digest('hex');
  await fetch(`http://127.0.0.1:${PORT}${p}`, { method: 'POST', headers: { 'x-vigia-timestamp': String(ts), 'x-vigia-signature': sig }, body });
};
setTimeout(async () => {
  await checkin('acme-shop', 'db', 'success', JSON.stringify({ bytes: 2_400_000_000, restoreTest: true }));
  await checkin('dental', 'nas', 'fail', JSON.stringify({ message: 'NAS unreachable: no space left on device' }));
}, 1500);

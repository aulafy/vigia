// `npm run demo`: Vigía with three demo clients, local sites (one down), declared firewalls, backups reporting in,
// and two computers added through the install line (a Windows PC with problems and a Mac).
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
// one client already has its portal link on (Clients → Clínica Dental Sol shows it)
fs.writeFileSync(path.join(dir, 'clients.json'), JSON.stringify({ 'Clínica Dental Sol': { emails: ['gerencia@clinica-sol.example'], minPrio: 'P2', portal: { v: 1, on: true } } }));

http.createServer((req, res) => {
  if (req.url === '/down') { res.writeHead(503); return res.end('maintenance'); }
  res.writeHead(200, { 'content-type': 'text/html' });
  res.end(`<html><body><h1>${req.url}</h1><script src="/app.js"></script></body></html>`);
}).listen(SITE_PORT, '127.0.0.1');

Object.assign(process.env, {
  VIGIA_ENV_FILE: path.join(dir, 'none.env'), // the demo never uses your real .env (alert channels, secrets)
  VIGIA_INV: path.join(dir, 'inventory.json'), VIGIA_STATE: path.join(dir, 'state.json'), VIGIA_PUSHED: path.join(dir, 'pushed.json'), VIGIA_CLIENTS: path.join(dir, 'clients.json'),
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
// computers: enrolled with a token, as the install line does, then a signed inventory
const { signEnroll } = await import('../lib.mjs');
async function computer(client, host, parts) {
  const token = signEnroll(SECRET, client, Math.floor(Date.now() / 1000) + 3600), machineId = crypto.createHash('sha256').update(host).digest('hex');
  const e = await (await fetch(`http://127.0.0.1:${PORT}/api/enroll`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token, host, machineId }) })).json();
  const body = JSON.stringify({ host, parts }), p = `/api/inventory/${e.asset}`, ts = Math.floor(Date.now() / 1000);
  const sig = crypto.createHmac('sha256', e.key).update(`${ts}.${p}.${body}`).digest('hex');
  await fetch(`http://127.0.0.1:${PORT}${p}`, { method: 'POST', headers: { 'x-vigia-timestamp': String(ts), 'x-vigia-signature': sig }, body });
}
const daysAgo = d => new Date(Date.now() - d * 864e5).toISOString();
setTimeout(async () => {
  await checkin('acme-shop', 'db', 'success', JSON.stringify({ bytes: 2_400_000_000, restoreTest: true }));
  await checkin('dental', 'nas', 'fail', JSON.stringify({ message: 'NAS unreachable: no space left on device' }));
  await computer('Clínica Dental Sol', 'RECEPCION', [
    { kind: 'os', id: 'windows', productName: 'Windows 10 Pro', displayVersion: '22H2', build: 19045, edition: 'Professional' },
    { kind: 'av', products: [{ name: 'Microsoft Defender', enabled: true, realTime: false, upToDate: false, signaturesAt: daysAgo(20) }] },
    { kind: 'software', items: [{ name: 'Google Chrome', version: '120.0.6099.130' }, { name: 'WinRAR 6.02 (64-bit)', version: '6.02' }, { name: 'AnyDesk', version: '7.1.0' }, { name: 'Gesden', version: '5.2' }] },
    { kind: 'listening', ports: [{ proto: 'tcp', addr: '0.0.0.0', port: 3389, process: 'svchost' }, { proto: 'tcp', addr: '0.0.0.0', port: 445, process: 'System' }, { proto: 'tcp', addr: '0.0.0.0', port: 7070, process: 'AnyDesk' }] },
    { kind: 'patches', lastInstalled: daysAgo(74), id: 'KB5039211' },
  ]);
  await computer('Clínica Dental Sol', 'Mac-Direccion', [
    { kind: 'os', id: 'macos', version: '15.1', name: 'macOS 15.1' },
    { kind: 'av', products: [{ name: 'XProtect', enabled: true }] },
    { kind: 'software', items: [{ name: 'Google Chrome', version: '141.0.7390.66' }, { name: 'zoom.us', version: '6.2.0' }] },
    { kind: 'listening', ports: [{ proto: 'tcp', addr: '127.0.0.1', port: 631, process: 'cupsd' }] },
  ]);
}, 1500);

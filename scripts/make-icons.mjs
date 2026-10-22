// Draws the app icons (public/icon-*.png, apple-touch-icon.png) with no dependencies: a tiny rasteriser + zlib PNG encoder.
// Run: node scripts/make-icons.mjs   (the PNGs are committed; this only needs re-running if the design changes)
import fs from 'node:fs';
import zlib from 'node:zlib';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const OUT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');

// Geometry in a 24-unit box, same shapes as public/icon.svg
const bez = (p0, p1, p2, p3, n = 24) => Array.from({ length: n + 1 }, (_, i) => {
  const t = i / n, u = 1 - t;
  return [u ** 3 * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t ** 3 * p3[0], u ** 3 * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t ** 3 * p3[1]];
});
const shield = [[12, 3.6], [5.2, 6.3], [5.2, 11.5], ...bez([5.2, 11.5], [5.2, 15.6], [8, 18.6], [12, 19.9]), ...bez([12, 19.9], [16, 18.6], [18.8, 15.6], [18.8, 11.5]), [18.8, 6.3]];
const check = [[8.9, 11.9], [11.1, 14.1], [15.3, 9.9]];

const inPoly = (x, y, pts) => { let c = false; for (let i = 0, j = pts.length - 1; i < pts.length; j = i++) { const [xi, yi] = pts[i], [xj, yj] = pts[j]; if ((yi > y) !== (yj > y) && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) c = !c; } return c; };
const segDist = (x, y, [ax, ay], [bx, by]) => { const dx = bx - ax, dy = by - ay, t = Math.max(0, Math.min(1, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy))); return Math.hypot(x - ax - t * dx, y - ay - t * dy); };
const roundRect = (x, y, r) => { const cx = Math.max(r, Math.min(24 - r, x)), cy = Math.max(r, Math.min(24 - r, y)); return Math.hypot(x - cx, y - cy) <= r; };
const mix = (a, b, t) => a.map((v, i) => v + (b[i] - v) * t);
const hex = h => [1, 3, 5].map(i => parseInt(h.slice(i, i + 2), 16));

// maskable: full-bleed background, artwork inside the 80 % safe zone
function render(size, { rounded = true } = {}) {
  const px = Buffer.alloc(size * size * 4), SS = 4;
  const top = hex('#2f3644'), bottom = hex('#1d2129'), sTop = hex('#5d8ad0'), sBot = hex('#3b6aaf'), white = [255, 255, 255];
  for (let py = 0; py < size; py++) for (let qx = 0; qx < size; qx++) {
    let acc = [0, 0, 0, 0];
    for (let sy = 0; sy < SS; sy++) for (let sx = 0; sx < SS; sx++) {
      const x = ((qx + (sx + 0.5) / SS) / size) * 24, y = ((py + (sy + 0.5) / SS) / size) * 24;
      if (rounded && !roundRect(x, y, 5.4)) continue;
      // artwork scaled to 78 % around the centre (maskable safe zone)
      const ax = 12 + (x - 12) / 0.78, ay = 12.3 + (y - 12) / 0.78;
      let c = mix(top, bottom, y / 24);
      if (inPoly(ax, ay, shield)) c = mix(sTop, sBot, (ay - 3.6) / 16.3);
      if (Math.min(segDist(ax, ay, check[0], check[1]), segDist(ax, ay, check[1], check[2])) < 1.05) c = white;
      acc = [acc[0] + c[0], acc[1] + c[1], acc[2] + c[2], acc[3] + 255];
    }
    const n = SS * SS, i = (py * size + qx) * 4, a = acc[3] / n;
    px[i] = a ? acc[0] / (acc[3] / 255) : 0; px[i + 1] = a ? acc[1] / (acc[3] / 255) : 0; px[i + 2] = a ? acc[2] / (acc[3] / 255) : 0; px[i + 3] = a;
  }
  return png(size, px);
}

function png(size, rgba) {
  const crcT = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
  const crc = b => { let c = 0xffffffff; for (const x of b) c = crcT[(c ^ x) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
  const chunk = (type, data) => { const t = Buffer.from(type), len = Buffer.alloc(4), c = Buffer.alloc(4); len.writeUInt32BE(data.length); c.writeUInt32BE(crc(Buffer.concat([t, data]))); return Buffer.concat([len, t, data, c]); };
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4); ihdr[8] = 8; ihdr[9] = 6;
  const raw = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y++) rgba.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw, { level: 9 })), chunk('IEND', Buffer.alloc(0))]);
}

fs.writeFileSync(path.join(OUT, 'icon-192.png'), render(192));
fs.writeFileSync(path.join(OUT, 'icon-512.png'), render(512));
fs.writeFileSync(path.join(OUT, 'icon-maskable-512.png'), render(512, { rounded: false }));
fs.writeFileSync(path.join(OUT, 'apple-touch-icon.png'), render(180, { rounded: false })); // iOS rounds it itself
console.log('icons written to', OUT);

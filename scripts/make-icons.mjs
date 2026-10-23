// Draws the transparent app icons (public/icon-*.png, apple-touch-icon.png) with no dependencies:
// a tiny supersampled rasteriser + zlib PNG encoder.
// Run: node scripts/make-icons.mjs
import fs from 'node:fs';
import zlib from 'node:zlib';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const OUT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const black = [0, 0, 0], white = [255, 255, 255];
const FIT = 0.64; // keeps every painted pixel inside the standard 80% circular safe zone

// Four projections of an A in a 64-unit box. The rear three are white lines with black edges;
// the front one reverses that relationship, making the mark readable on light and dark surfaces.
const shape = (dx = 0, dy = 0) => [
  [[8 + dx, 56 + dy], [30 + dx, 10 + dy]],
  [[30 + dx, 10 + dy], [52 + dx, 56 + dy]],
  [[17 + dx, 38 + dy], [43 + dx, 38 + dy]],
];
const strokes = [];
for (const [dx, dy] of [[9, -6], [6, -4], [3, -2]]) {
  strokes.push({ segments: shape(dx, dy), width: 6, color: black });
  strokes.push({ segments: shape(dx, dy), width: 2.25, color: white });
}
strokes.push({ segments: shape(), width: 10, color: white });
strokes.push({ segments: shape(), width: 6.5, color: black });

const segDist = (x, y, [ax, ay], [bx, by]) => {
  const dx = bx - ax, dy = by - ay;
  const t = Math.max(0, Math.min(1, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(x - ax - t * dx, y - ay - t * dy);
};

function render(size) {
  const px = Buffer.alloc(size * size * 4), SS = 4;
  for (let py = 0; py < size; py++) for (let qx = 0; qx < size; qx++) {
    const acc = [0, 0, 0, 0];
    for (let sy = 0; sy < SS; sy++) for (let sx = 0; sx < SS; sx++) {
      const x = ((qx + (sx + 0.5) / SS) / size) * 64;
      const y = ((py + (sy + 0.5) / SS) / size) * 64;
      const ax = 32 + (x - 32) / FIT, ay = 32 + (y - 32) / FIT;
      let color = null;
      for (const stroke of strokes) {
        if (stroke.segments.some(([a, b]) => segDist(ax, ay, a, b) <= stroke.width / 2)) color = stroke.color;
      }
      if (color) {
        acc[0] += color[0]; acc[1] += color[1]; acc[2] += color[2]; acc[3] += 255;
      }
    }
    const n = SS * SS, i = (py * size + qx) * 4, alpha = acc[3] / n;
    px[i] = alpha ? acc[0] / (acc[3] / 255) : 0;
    px[i + 1] = alpha ? acc[1] / (acc[3] / 255) : 0;
    px[i + 2] = alpha ? acc[2] / (acc[3] / 255) : 0;
    px[i + 3] = alpha;
  }
  // A maskable icon's guaranteed circular safe zone has a radius of 40% of the canvas.
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
    const alpha = px[(y * size + x) * 4 + 3];
    if (alpha && Math.hypot(x + 0.5 - size / 2, y + 0.5 - size / 2) > size * 0.4)
      throw new Error(`artwork leaves circular safe zone at ${x},${y}`);
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
fs.writeFileSync(path.join(OUT, 'icon-maskable-512.png'), render(512));
fs.writeFileSync(path.join(OUT, 'apple-touch-icon.png'), render(180));
console.log('transparent icons written to', OUT);

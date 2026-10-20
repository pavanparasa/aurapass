#!/usr/bin/env node
// Draws the AuraPass extension icons.
//
// The icons are generated rather than hand-drawn so they stay in sync with the
// palette and can be regenerated at any size. Everything is plain arithmetic on
// a supersampled grid, and the PNG is written with a tiny hand-rolled encoder
// (zlib's deflate plus the three PNG chunks), so no image library is needed.
//
//   node extensions/tools/make-icons.mjs

import { deflateSync } from "node:zlib";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, "..", "shared", "icons");
const SIZES = [16, 32, 48, 128];

// ------------------------------------------------------------------ PNG bits

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length, 0);
  const body = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([length, body, crc]);
}

/** Encode an RGBA buffer as a minimal 8-bit truecolour PNG. */
function encodePng(width, height, rgba) {
  const stride = width * 4;
  const raw = Buffer.alloc((stride + 1) * height);
  for (let y = 0; y < height; y++) {
    raw[y * (stride + 1)] = 0; // filter: none
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // colour type: RGBA
  ihdr[10] = 0; // deflate
  ihdr[11] = 0; // adaptive filtering
  ihdr[12] = 0; // no interlace
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

// ------------------------------------------------------------------ geometry

/** Signed distance to a rounded rectangle centred in [0,1]². */
function outsideRoundedRect(x, y, margin, radius) {
  const half = 0.5 - margin;
  const dx = Math.abs(x - 0.5) - (half - radius);
  const dy = Math.abs(y - 0.5) - (half - radius);
  const outside = Math.hypot(Math.max(dx, 0), Math.max(dy, 0));
  return outside + Math.min(Math.max(dx, dy), 0) - radius;
}

/** The white keyhole: a circle over a tapering stem. */
function insideKeyhole(x, y) {
  const circle = Math.hypot(x - 0.5, y - 0.40) - 0.155;
  if (circle <= 0) return true;
  if (y < 0.40 || y > 0.70) return false;
  // Half-width grows from the circle down to the flared foot.
  const t = (y - 0.40) / 0.30;
  const halfWidth = 0.048 + t * 0.070;
  return Math.abs(x - 0.5) <= halfWidth;
}

function mix(a, b, t) {
  return [
    a[0] + (b[0] - a[0]) * t,
    a[1] + (b[1] - a[1]) * t,
    a[2] + (b[2] - a[2]) * t,
  ];
}

const INDIGO = [79, 70, 229];
const VIOLET = [124, 58, 237];
const WHITE = [255, 255, 255];

/** Render one icon at `size` pixels square. */
function render(size) {
  const rgba = Buffer.alloc(size * size * 4);
  const samples = 4;
  const step = 1 / (size * samples);
  const half = step / 2;

  for (let py = 0; py < size; py++) {
    for (let px = 0; px < size; px++) {
      let insideCoverage = 0;
      let keyCoverage = 0;
      for (let sy = 0; sy < samples; sy++) {
        for (let sx = 0; sx < samples; sx++) {
          const x = (px * samples + sx) * step + half;
          const y = (py * samples + sy) * step + half;
          if (outsideRoundedRect(x, y, 0.03, 0.22) <= 0) insideCoverage += 1;
          if (insideKeyhole(x, y)) keyCoverage += 1;
        }
      }
      const total = samples * samples;
      const alpha = insideCoverage / total;
      if (alpha === 0) continue;
      const key = Math.min(1, keyCoverage / total);
      const x = (px + 0.5) / size;
      const y = (py + 0.5) / size;
      const base = mix(INDIGO, VIOLET, Math.min(1, Math.max(0, (x + y) / 2)));
      const colour = mix(base, WHITE, key);
      const offset = (py * size + px) * 4;
      rgba[offset] = Math.round(colour[0]);
      rgba[offset + 1] = Math.round(colour[1]);
      rgba[offset + 2] = Math.round(colour[2]);
      rgba[offset + 3] = Math.round(alpha * 255);
    }
  }
  return encodePng(size, size, rgba);
}

mkdirSync(OUT, { recursive: true });
for (const size of SIZES) {
  const file = join(OUT, `icon${size}.png`);
  writeFileSync(file, render(size));
  console.log(`wrote ${file}`);
}

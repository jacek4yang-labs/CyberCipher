// Generates the CyberCipher base icon (512x512 PNG) from a 16x16 pixel map.
// Run: node scripts/make-icon.mjs <output.png>
import { deflateSync } from "node:zlib";
import { writeFileSync } from "node:fs";

const SCALE = 32; // 16 * 32 = 512
const MAP = [
  "................",
  "....######......",
  "..##......##....",
  ".#..........#...",
  ".#..........#...",
  "#............#..",
  "#............#..",
  "#............#..",
  "#............#..",
  "#............#..",
  ".#..........#...",
  ".#....######....",
  "..##..#....##...",
  "....######......",
  "................",
  "................",
];

// Palette: dark navy background, cyan "C", soft border ring.
const PALETTE = {
  ".": [16, 20, 27, 255],
  "#": [79, 156, 249, 255],
};

const W = 16 * SCALE;
const raw = Buffer.alloc(W * (W * 4 + 1));
for (let y = 0; y < W; y++) {
  const rowStart = y * (W * 4 + 1);
  raw[rowStart] = 0; // filter none
  const mapY = Math.floor(y / SCALE);
  for (let x = 0; x < W; x++) {
    const mapX = Math.floor(x / SCALE);
    const [r, g, b, a] = PALETTE[MAP[mapY][mapX]];
    const o = rowStart + 1 + x * 4;
    raw[o] = r;
    raw[o + 1] = g;
    raw[o + 2] = b;
    raw[o + 3] = a;
  }
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const typeBuf = Buffer.from(type, "ascii");
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])) >>> 0);
  return Buffer.concat([len, typeBuf, data, crc]);
}

let crcTable;
function crc32(buf) {
  if (!crcTable) {
    crcTable = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      crcTable[n] = c;
    }
  }
  let crc = 0xffffffff;
  for (const b of buf) crc = crcTable[(crc ^ b) & 0xff] ^ (crc >>> 8);
  return crc ^ 0xffffffff;
}

const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(W, 0);
ihdr.writeUInt32BE(W, 4);
ihdr[8] = 8; // bit depth
ihdr[9] = 6; // RGBA
const png = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  chunk("IHDR", ihdr),
  chunk("IDAT", deflateSync(raw)),
  chunk("IEND", Buffer.alloc(0)),
]);

writeFileSync(process.argv[2] ?? "icon-base.png", png);
console.log(`wrote ${process.argv[2] ?? "icon-base.png"} (${W}x${W})`);

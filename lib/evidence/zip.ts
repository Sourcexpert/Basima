import { deflateRawSync } from 'node:zlib';

/** CRC-32 (IEEE 802.3), implemented here so the writer has no version-dependent deps. */
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let c = i;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[i] = c >>> 0;
  }
  return table;
})();

function crc32(buf: Buffer): number {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i += 1) crc = CRC_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

/**
 * Minimal, dependency-free ZIP writer (store + deflate).
 *
 * Kept in-tree rather than pulled from npm on purpose: an evidence package is
 * something a court or an opposing advocate may inspect, so the code that
 * produces it should be short enough to read in one sitting, and should not
 * change because a transitive dependency released a patch.
 */

interface Entry {
  name: string;
  content: string;
}

function u16(n: number): Buffer {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(n, 0);
  return b;
}
function u32(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0, 0);
  return b;
}

function dosDateTime(date: Date): { time: number; date: number } {
  const time = ((date.getHours() & 0x1f) << 11) | ((date.getMinutes() & 0x3f) << 5) | (Math.floor(date.getSeconds() / 2) & 0x1f);
  const d = (((date.getFullYear() - 1980) & 0x7f) << 9) | (((date.getMonth() + 1) & 0x0f) << 5) | (date.getDate() & 0x1f);
  return { time, date: d };
}

export function buildEvidenceZip(entries: Entry[], modifiedAt = new Date('2026-10-05T09:20:00.000Z')): Buffer {
  const { time, date } = dosDateTime(modifiedAt);
  const localParts: Buffer[] = [];
  const centralParts: Buffer[] = [];
  let offset = 0;

  for (const entry of entries) {
    const nameBytes = Buffer.from(entry.name, 'utf8');
    const raw = Buffer.from(entry.content, 'utf8');
    const deflated = deflateRawSync(raw);
    // Store uncompressed if deflate does not help (tiny text files).
    const useDeflate = deflated.length < raw.length;
    const method = useDeflate ? 8 : 0;
    const body = useDeflate ? deflated : raw;
    const checksum = crc32(raw);

    const local = Buffer.concat([
      u32(0x04034b50), u16(20), u16(0), u16(method), u16(time), u16(date),
      u32(checksum), u32(body.length), u32(raw.length), u16(nameBytes.length), u16(0),
      nameBytes, body,
    ]);
    localParts.push(local);

    centralParts.push(
      Buffer.concat([
        u32(0x02014b50), u16(20), u16(20), u16(0), u16(method), u16(time), u16(date),
        u32(checksum), u32(body.length), u32(raw.length),
        u16(nameBytes.length), u16(0), u16(0), u16(0), u16(0), u32(0), u32(offset),
        nameBytes,
      ]),
    );
    offset += local.length;
  }

  const central = Buffer.concat(centralParts);
  const end = Buffer.concat([
    u32(0x06054b50), u16(0), u16(0),
    u16(entries.length), u16(entries.length),
    u32(central.length), u32(offset), u16(0),
  ]);

  return Buffer.concat([...localParts, central, end]);
}

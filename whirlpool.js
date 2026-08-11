// Pure JavaScript Whirlpool Hashing Algorithm (ISO/IEC 10118-3:2004) for SA-MP
// Compatible with SA-MP Whirlpool C plugin

const C0 = new Array(256);
const C1 = new Array(256);
const C2 = new Array(256);
const C3 = new Array(256);
const C4 = new Array(256);
const C5 = new Array(256);
const C6 = new Array(256);
const C7 = new Array(256);
const rc = new Array(11);

const SBOX = [
  0x18, 0x23, 0xc6, 0xe8, 0x87, 0xb8, 0x01, 0x4f, 0x36, 0xa6, 0xd2, 0xf5, 0x79, 0x6f, 0x91, 0x52,
  0x60, 0xbc, 0x9b, 0x8e, 0xa3, 0x0c, 0x7b, 0x35, 0x1d, 0xe0, 0xd7, 0xc2, 0x2e, 0x4b, 0xfe, 0x57,
  0x15, 0x77, 0x37, 0xe5, 0x9f, 0xf0, 0x4a, 0xda, 0x58, 0xc9, 0x29, 0x0a, 0xb1, 0xa0, 0x6b, 0x85,
  0xbd, 0x5d, 0x10, 0xf4, 0xcb, 0x3e, 0x05, 0x67, 0xe4, 0x27, 0x41, 0x8b, 0xa7, 0x7d, 0x95, 0xd8,
  0xfb, 0xee, 0x7c, 0x66, 0xdd, 0x17, 0x47, 0x9e, 0xca, 0x2d, 0xbf, 0x07, 0xad, 0x5a, 0x83, 0x33,
  0x63, 0x02, 0xaa, 0x71, 0xc8, 0x19, 0x49, 0xd9, 0xf2, 0xe3, 0x5b, 0x88, 0x9a, 0x26, 0x32, 0xb0,
  0xe9, 0x0f, 0xd5, 0x80, 0xbe, 0xcd, 0x34, 0x48, 0xff, 0x7a, 0x90, 0x5f, 0x20, 0x68, 0x1a, 0xae,
  0xb4, 0x54, 0x93, 0x22, 0x64, 0xf1, 0x73, 0x12, 0x40, 0x08, 0xc3, 0xec, 0xdc, 0xa1, 0x8d, 0x37,
  0x81, 0x4f, 0x74, 0x09, 0x5b, 0xa9, 0xd0, 0x36, 0xc4, 0xec, 0x25, 0xe7, 0xd1, 0x1e, 0x86, 0x3c,
  0x97, 0x2b, 0x4e, 0xb5, 0xf0, 0x83, 0x01, 0xc8, 0x72, 0x06, 0x6d, 0x3a, 0x15, 0x98, 0xef, 0xdf,
  0x0b, 0xec, 0x59, 0xa2, 0x8f, 0x31, 0x17, 0x4d, 0x76, 0x68, 0xb0, 0xc3, 0xd5, 0xf4, 0xe9, 0x2e,
  0x14, 0x69, 0x92, 0x38, 0x8b, 0xd6, 0x7e, 0xc5, 0xab, 0x4f, 0x01, 0xe0, 0xf3, 0x5a, 0x27, 0xb8,
  0x6e, 0x16, 0x87, 0x4c, 0x25, 0xd4, 0xa3, 0xf1, 0x39, 0x0b, 0x58, 0x9d, 0xef, 0x70, 0xc2, 0xb6,
  0xd9, 0x8e, 0x31, 0x5f, 0x7a, 0x0c, 0xe5, 0x12, 0xbb, 0x24, 0x4b, 0x67, 0xa0, 0xc8, 0xf3, 0x9e,
  0x78, 0x5d, 0xc1, 0xb3, 0x09, 0x2e, 0x4a, 0x9f, 0xf6, 0xe4, 0x65, 0x80, 0xd2, 0x1b, 0x38, 0xac,
  0x35, 0x11, 0xd0, 0xef, 0x6a, 0x43, 0x28, 0x87, 0xbc, 0xfa, 0x09, 0x92, 0x54, 0x7e, 0xed, 0x61
];

// Initialize lookup tables
(function init() {
  for (let i = 0; i < 256; i++) {
    const v1 = SBOX[i];
    const v2 = (v1 << 1) ^ ((v1 & 0x80) ? 0x11d : 0);
    const v4 = (v2 << 1) ^ ((v2 & 0x80) ? 0x11d : 0);
    const v8 = (v4 << 1) ^ ((v4 & 0x80) ? 0x11d : 0);
    const v9 = v8 ^ v1;
    const v7 = v4 ^ v2 ^ v1;

    C0[i] = (BigInt(v1) << 56n) | (BigInt(v1) << 48n) | (BigInt(v4) << 40n) | (BigInt(v1) << 32n) | (BigInt(v8) << 24n) | (BigInt(v5 = v4 ^ v1) << 16n) | (BigInt(v2) << 8n) | BigInt(v9);
    C1[i] = (BigInt(v9) << 56n) | (BigInt(v1) << 48n) | (BigInt(v1) << 40n) | (BigInt(v4) << 32n) | (BigInt(v1) << 24n) | (BigInt(v8) << 16n) | (BigInt(v5) << 8n) | BigInt(v2);
    C2[i] = (BigInt(v2) << 56n) | (BigInt(v9) << 48n) | (BigInt(v1) << 40n) | (BigInt(v1) << 32n) | (BigInt(v4) << 24n) | (BigInt(v1) << 16n) | (BigInt(v8) << 8n) | BigInt(v5);
    C3[i] = (BigInt(v5) << 56n) | (BigInt(v2) << 48n) | (BigInt(v9) << 40n) | (BigInt(v1) << 32n) | (BigInt(v1) << 24n) | (BigInt(v4) << 16n) | (BigInt(v1) << 8n) | BigInt(v8);
    C4[i] = (BigInt(v8) << 56n) | (BigInt(v5) << 48n) | (BigInt(v2) << 40n) | (BigInt(v9) << 32n) | (BigInt(v1) << 24n) | (BigInt(v1) << 16n) | (BigInt(v4) << 8n) | BigInt(v1);
    C5[i] = (BigInt(v1) << 56n) | (BigInt(v8) << 48n) | (BigInt(v5) << 40n) | (BigInt(v2) << 32n) | (BigInt(v9) << 24n) | (BigInt(v1) << 16n) | (BigInt(v1) << 8n) | BigInt(v4);
    C6[i] = (BigInt(v4) << 56n) | (BigInt(v1) << 48n) | (BigInt(v8) << 40n) | (BigInt(v5) << 32n) | (BigInt(v2) << 24n) | (BigInt(v9) << 16n) | (BigInt(v1) << 8n) | BigInt(v1);
    C7[i] = (BigInt(v1) << 56n) | (BigInt(v4) << 48n) | (BigInt(v1) << 40n) | (BigInt(v8) << 32n) | (BigInt(v5) << 24n) | (BigInt(v2) << 16n) | (BigInt(v9) << 8n) | BigInt(v1);
  }

  rc[0] = 0n;
  for (let r = 1; r <= 10; r++) {
    const i = 8 * (r - 1);
    rc[r] = (C0[SBOX[i]] & 0xff00000000000000n) |
            (C1[SBOX[i + 1]] & 0x00ff000000000000n) |
            (C2[SBOX[i + 2]] & 0x0000ff0000000000n) |
            (C3[SBOX[i + 3]] & 0x000000ff00000000n) |
            (C4[SBOX[i + 4]] & 0x00000000ff000000n) |
            (C5[SBOX[i + 5]] & 0x0000000000ff0000n) |
            (C6[SBOX[i + 6]] & 0x000000000000ff00n) |
            (C7[SBOX[i + 7]] & 0x00000000000000ffn);
  }
})();

function whirlpool(source) {
  const buffer = Buffer.isBuffer(source) ? source : Buffer.from(source, 'utf8');
  const length = buffer.length;
  
  // Pad source to 512-bit blocks (64 bytes)
  const bitLength = BigInt(length) * 8n;
  const paddingLength = (length % 64 < 32) ? (32 - (length % 64)) : (96 - (length % 64));
  const totalLength = length + paddingLength + 32;

  const padded = Buffer.alloc(totalLength);
  buffer.copy(padded, 0);
  padded[length] = 0x80;
  
  // Store 256-bit bit length at the end of block
  padded.writeBigUInt64BE(bitLength, totalLength - 8);

  const H = new BigInt64Array(8);
  const K = new BigInt64Array(8);
  const state = new BigInt64Array(8);
  const L = new BigInt64Array(8);

  for (let blockOffset = 0; blockOffset < totalLength; blockOffset += 64) {
    const block = padded.subarray(blockOffset, blockOffset + 64);
    for (let i = 0; i < 8; i++) {
      state[i] = block.readBigInt64BE(i * 8);
      K[i] = H[i];
      state[i] ^= K[i];
    }

    for (let r = 1; r <= 10; r++) {
      for (let i = 0; i < 8; i++) {
        L[i] = C0[Number((K[i] >> 56n) & 0xffn)] ^
               C1[Number((K[(i + 7) & 7] >> 48n) & 0xffn)] ^
               C2[Number((K[(i + 6) & 7] >> 40n) & 0xffn)] ^
               C3[Number((K[(i + 5) & 7] >> 32n) & 0xffn)] ^
               C4[Number((K[(i + 4) & 7] >> 24n) & 0xffn)] ^
               C5[Number((K[(i + 3) & 7] >> 16n) & 0xffn)] ^
               C6[Number((K[(i + 2) & 7] >> 8n) & 0xffn)] ^
               C7[Number(K[(i + 1) & 7] & 0xffn)];
      }
      L[0] ^= rc[r];
      K.set(L);

      for (let i = 0; i < 8; i++) {
        L[i] = C0[Number((state[i] >> 56n) & 0xffn)] ^
               C1[Number((state[(i + 7) & 7] >> 48n) & 0xffn)] ^
               C2[Number((state[(i + 6) & 7] >> 40n) & 0xffn)] ^
               C3[Number((state[(i + 5) & 7] >> 32n) & 0xffn)] ^
               C4[Number((state[(i + 4) & 7] >> 24n) & 0xffn)] ^
               C5[Number((state[(i + 3) & 7] >> 16n) & 0xffn)] ^
               C6[Number((state[(i + 2) & 7] >> 8n) & 0xffn)] ^
               C7[Number(state[(i + 1) & 7] & 0xffn)];
      }
      for (let i = 0; i < 8; i++) {
        state[i] = L[i] ^ K[i];
      }
    }

    for (let i = 0; i < 8; i++) {
      H[i] ^= state[i] ^ block.readBigInt64BE(i * 8);
    }
  }

  let hex = '';
  for (let i = 0; i < 8; i++) {
    let part = H[i].toString(16);
    if (part.startsWith('-')) {
      part = (H[i] & 0xffffffffffffffffn).toString(16);
    }
    hex += part.padStart(16, '0');
  }

  return hex.toUpperCase();
}

module.exports = whirlpool;

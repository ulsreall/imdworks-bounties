// Keccak-256 (original Keccak padding 0x01) implemented in JavaScript from the
// specification. Deliberately written without any dependency on Node's crypto
// module (which exposes SHA3, a different padding) so it can be compared
// against the Python implementation written separately for the same bounty.

const MASK = (1n << 64n) - 1n;
const RATE = 136; // bytes

const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

// rho offsets, indexed [x][y]
const ROT = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
];

function rol(value, shift) {
  const n = BigInt(shift);
  if (n === 0n) return value;
  return ((value << n) | (value >> (64n - n))) & MASK;
}

function keccakF1600(a) {
  for (let round = 0; round < 24; round++) {
    // theta
    const col = [];
    for (let x = 0; x < 5; x++) col.push(a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4]);
    const d = [];
    for (let x = 0; x < 5; x++) d.push(col[(x + 4) % 5] ^ rol(col[(x + 1) % 5], 1));
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) a[x][y] ^= d[x];

    // rho + pi
    const b = [];
    for (let x = 0; x < 5; x++) b.push([0n, 0n, 0n, 0n, 0n]);
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        b[y][(2 * x + 3 * y) % 5] = rol(a[x][y], ROT[x][y]);
      }
    }

    // chi
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y] & MASK) & b[(x + 2) % 5][y]);
      }
    }

    // iota
    a[0][0] ^= RC[round];
  }
}

export function keccak256(input) {
  const bytes = input instanceof Uint8Array ? input : Uint8Array.from(input);
  const state = [];
  for (let x = 0; x < 5; x++) state.push([0n, 0n, 0n, 0n, 0n]);

  // multi-rate padding (0x01 ... 0x80)
  const padLen = RATE - (bytes.length % RATE);
  const padded = new Uint8Array(bytes.length + padLen);
  padded.set(bytes, 0);
  padded[bytes.length] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;

  for (let offset = 0; offset < padded.length; offset += RATE) {
    for (let i = 0; i < RATE / 8; i++) {
      let lane = 0n;
      for (let j = 7; j >= 0; j--) {
        lane = (lane << 8n) | BigInt(padded[offset + i * 8 + j]);
      }
      state[i % 5][Math.floor(i / 5)] ^= lane;
    }
    keccakF1600(state);
  }

  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    const lane = state[i % 5][Math.floor(i / 5)];
    for (let j = 0; j < 8; j++) {
      out[i * 8 + j] = Number((lane >> BigInt(8 * j)) & 0xffn);
    }
  }
  return out;
}

export function toHex(bytes) {
  return "0x" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function keccak256Hex(bytes) {
  return toHex(keccak256(bytes));
}

"""Keccak-256 (original Keccak padding 0x01, as used by Ethereum), pure Python.

Written from the specification so the JavaScript side can be implemented
separately and the two can be compared byte for byte. No dependency on
hashlib (which ships SHA3 with the NIST 0x06 padding, not Keccak).
"""

from __future__ import annotations

MASK = (1 << 64) - 1
RATE = 136  # bytes, 1088 bits: Keccak-256 capacity 512

RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)

# rho offsets, indexed [x][y]
ROT = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)


def _rol(value: int, shift: int) -> int:
    if shift == 0:
        return value
    return ((value << shift) | (value >> (64 - shift))) & MASK


def _keccak_f1600(state: list[list[int]]) -> None:
    for rnd in range(24):
        # theta
        col = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        d = [col[(x - 1) % 5] ^ _rol(col[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= d[x]
        # rho + pi
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(state[x][y], ROT[x][y])
        # chi
        for x in range(5):
            for y in range(5):
                state[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y] & MASK) & b[(x + 2) % 5][y])
        # iota
        state[0][0] ^= RC[rnd]


def keccak256(data: bytes) -> bytes:
    """Return the 32-byte Keccak-256 digest of ``data``."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("keccak256 expects bytes")
    state = [[0] * 5 for _ in range(5)]

    # multi-rate padding: 0x01 ... 0x80 (Keccak, not SHA3's 0x06)
    padded = bytearray(data)
    pad_len = RATE - (len(padded) % RATE)
    padded += b"\x00" * pad_len
    padded[len(data)] ^= 0x01
    padded[len(padded) - 1] ^= 0x80

    for offset in range(0, len(padded), RATE):
        block = padded[offset:offset + RATE]
        for i in range(RATE // 8):
            lane = int.from_bytes(block[i * 8:(i + 1) * 8], "little")
            x, y = i % 5, i // 5
            state[x][y] ^= lane
        _keccak_f1600(state)

    out = bytearray()
    # 256 bits = 4 lanes = 32 bytes, all inside the first block
    for i in range(4):
        x, y = i % 5, i // 5
        out += state[x][y].to_bytes(8, "little")
    return bytes(out)


def keccak256_hex(data: bytes) -> str:
    return "0x" + keccak256(data).hex()

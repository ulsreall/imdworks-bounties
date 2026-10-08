"""Tiny ABI encoder/decoder (standard head/tail encoding) - no dependencies.

Supports exactly the types used by the escrow and the fixture token:
uint64, uint256, uint8, bool, address, bytes32, string, and arrays of words for
return-value decoding.
"""

from __future__ import annotations

UINT256_MAX = (1 << 256) - 1


class AbiError(ValueError):
    pass


def word(value: int) -> bytes:
    if value < 0 or value > UINT256_MAX:
        raise AbiError(f"value out of uint256 range: {value}")
    return value.to_bytes(32, "big")


def enc_uint(value: int) -> bytes:
    return word(int(value))


def enc_uint64(value: int) -> bytes:
    return word(int(value))


def enc_uint8(value: int) -> bytes:
    return word(int(value))


def enc_bool(value: bool) -> bytes:
    return word(1 if value else 0)


def enc_address(address: str) -> bytes:
    text = address.lower().removeprefix("0x")
    if len(text) != 40:
        raise AbiError(f"bad address: {address}")
    return bytes.fromhex(text).rjust(32, b"\x00")


def enc_bytes32(value: str | bytes) -> bytes:
    if isinstance(value, str):
        raw = bytes.fromhex(value.removeprefix("0x"))
    else:
        raw = value
    if len(raw) > 32:
        raise AbiError("bytes32 too long")
    return raw.ljust(32, b"\x00")


def enc_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    return word(len(raw)) + raw + b"\x00" * ((32 - len(raw) % 32) % 32)


def encode_args(args: list[tuple[str, object]]) -> bytes:
    """Encode a mix of static and dynamic arguments (head/tail)."""
    head = b""
    tail = b""
    dynamic_offset = 32 * len(args)
    for kind, value in args:
        if kind in ("uint256", "uint64", "uint8"):
            head += enc_uint(int(value))
        elif kind == "bool":
            head += enc_bool(bool(value))
        elif kind == "address":
            head += enc_address(str(value))
        elif kind == "bytes32":
            head += enc_bytes32(value)  # type: ignore[arg-type]
        elif kind == "string":
            head += word(dynamic_offset + len(tail))
            tail += enc_string(str(value))
        else:
            raise AbiError(f"unsupported type {kind}")
    return head + tail


# ------------------------------------------------------------------ decoding

def split_words(data: str | bytes) -> list[bytes]:
    raw = bytes.fromhex(data.removeprefix("0x")) if isinstance(data, str) else data
    if len(raw) % 32 != 0:
        raise AbiError("return data is not a multiple of 32 bytes")
    return [raw[i:i + 32] for i in range(0, len(raw), 32)]


def dec_uint(word_bytes: bytes) -> int:
    return int.from_bytes(word_bytes, "big")


def dec_address(word_bytes: bytes) -> str:
    return "0x" + word_bytes[12:].hex()


def dec_bool(word_bytes: bytes) -> bool:
    return dec_uint(word_bytes) != 0


def dec_bytes32(word_bytes: bytes) -> str:
    return "0x" + word_bytes.hex()


def dec_string(data: str | bytes, index: int = 0) -> str:
    """Decode a dynamic string located at word ``index`` of ``data``."""
    words = split_words(data)
    offset = dec_uint(words[index])
    length = dec_uint(words[offset // 32])
    raw = b"".join(words[offset // 32 + 1:])
    return raw[:length].decode("utf-8")

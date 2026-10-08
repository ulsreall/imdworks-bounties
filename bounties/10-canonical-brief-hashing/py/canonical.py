"""Canonical brief form and hashing (Python reference).

CANONICAL BRIEF FORM v1
-----------------------
A bounty brief must hash to exactly one value. The form below is deliberately
boring and hostile to ambiguity:

 1. Fields. Exactly these keys, no more, no less:
      title       string, 1..200 chars after normalisation
      description string, 0..20000 chars
      criteria    string, 1..20000 chars
      reward      string, canonical decimal amount (see bounty #09 grammar)
      currency    string, one of USDG | USDC
      deadline    string, RFC3339 in UTC with a trailing Z, e.g. "...T23:59:59Z"
      repo_url    string (http/https) or null
      meta        object, optional; string -> string, arbitrary keys
 2. Text normalisation. Unicode NFC, CRLF/CR -> LF, and all C0 control
    characters removed except \n and \t. No other rewriting: no case folding,
    no whitespace collapsing, no trimming beyond the length checks.
 3. Key order. Object keys sorted by Unicode CODE POINT. This matters because
    JavaScript's Array#sort compares UTF-16 code units, which orders astral
    characters differently from Python's code-point ordering.
 4. Serialisation. Compact separators ("," and ":"), no trailing newline, no
    BOM, non-ASCII emitted raw as UTF-8 (never \\u-escaped). All numbers are
    strings, so no float formatting can leak into the bytes.
 5. Hash. keccak256 over the exact UTF-8 bytes of (4).

This module also ships deliberately naive variants used to demonstrate the
ambiguity traps recorded in results/discrepancies.md.
"""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any

from keccak256 import keccak256

REQUIRED_FIELDS = ("title", "description", "criteria", "reward", "currency", "deadline", "repo_url")
OPTIONAL_FIELDS = ("meta",)
ALLOWED_FIELDS = set(REQUIRED_FIELDS) | set(OPTIONAL_FIELDS)
CURRENCIES = {"USDG", "USDC"}

_DEADLINE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_AMOUNT_RE = re.compile(r"^(0|[1-9][0-9]*)(?:\.[0-9]{1,6})?$", re.ASCII)
_URL_RE = re.compile(r"^https?://[^\s]+$", re.ASCII)
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


class BriefError(ValueError):
    """Raised when a brief cannot be canonicalised."""


def normalize_text(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise BriefError(f"{what} must be a string, got {type(value).__name__}")
    text = value.replace("\r\n", "\n").replace("\r", "\n")
    text = unicodedata.normalize("NFC", text)
    text = _CONTROL_RE.sub("", text)
    return text


def _cmp_code_points(a: str, b: str) -> int:
    """Compare two strings by Unicode code point (not UTF-16 code unit)."""
    la, lb = list(a), list(b)
    for ca, cb in zip(la, lb):
        if ca != cb:
            return -1 if ord(ca) < ord(cb) else 1
    return (len(la) > len(lb)) - (len(la) < len(lb))


def validate(brief: dict) -> dict:
    if not isinstance(brief, dict):
        raise BriefError("brief must be an object")
    unknown = set(brief) - ALLOWED_FIELDS
    if unknown:
        raise BriefError(f"unknown fields are not canonical: {sorted(unknown)}")
    missing = [f for f in REQUIRED_FIELDS if f not in brief]
    if missing:
        raise BriefError(f"missing required fields: {missing}")

    out = {
        "title": normalize_text(brief["title"], "title"),
        "description": normalize_text(brief["description"], "description"),
        "criteria": normalize_text(brief["criteria"], "criteria"),
        "reward": brief["reward"],
        "currency": brief["currency"],
        "deadline": brief["deadline"],
        "repo_url": brief["repo_url"],
    }
    if not 1 <= len(out["title"]) <= 200:
        raise BriefError("title length out of range")
    if len(out["description"]) > 20000 or len(out["criteria"]) > 20000:
        raise BriefError("description/criteria too long")
    if not isinstance(out["reward"], str) or not _AMOUNT_RE.fullmatch(out["reward"]):
        raise BriefError("reward must be a canonical decimal string")
    whole, _, frac = out["reward"].partition(".")
    micros = int(whole) * 10 ** 6 + (int(frac.ljust(6, "0")) if frac else 0)
    if micros > 2 ** 256 - 1:
        raise BriefError("reward exceeds uint256 micro-units")
    if out["currency"] not in CURRENCIES:
        raise BriefError("unsupported currency")
    if not isinstance(out["deadline"], str) or not _DEADLINE_RE.fullmatch(out["deadline"]):
        raise BriefError("deadline must be an RFC3339 UTC timestamp ending in Z")
    if out["repo_url"] is not None:
        if not isinstance(out["repo_url"], str) or not _URL_RE.fullmatch(out["repo_url"]):
            raise BriefError("repo_url must be http(s) or null")
    if "meta" in brief:
        meta = brief["meta"]
        if not isinstance(meta, dict):
            raise BriefError("meta must be an object")
        clean = {}
        for k, v in meta.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise BriefError("meta keys and values must be strings")
            clean[normalize_text(k, "meta key")] = normalize_text(v, "meta value")
        if clean:
            out["meta"] = clean
    return out


def _escape(text: str) -> str:
    """JSON string escaping that matches the JavaScript side byte for byte."""
    out = ['"']
    for ch in text:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif code < 0x20:
            out.append("\\u%04x" % code)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _serialize(value: Any) -> str:
    if isinstance(value, str):
        return _escape(value)
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: _CP(kv[0]))
        return "{" + ",".join(f"{_escape(k)}:{_serialize(v)}" for k, v in items) + "}"
    if isinstance(value, list):
        return "[" + ",".join(_serialize(v) for v in value) + "]"
    raise BriefError(f"unsupported value type in canonical form: {type(value).__name__}")


class _CP:
    """Sort key wrapper: compares by Unicode code point."""

    __slots__ = ("s",)

    def __init__(self, s: str) -> None:
        self.s = s

    def __lt__(self, other: "_CP") -> bool:
        return _cmp_code_points(self.s, other.s) < 0

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _CP) and self.s == other.s


def canonical_json(brief: dict) -> str:
    return _serialize(validate(brief))


def canonical_bytes(brief: dict) -> bytes:
    return canonical_json(brief).encode("utf-8")


def brief_hash(brief: dict) -> str:
    """keccak256 of the canonical UTF-8 bytes, as 0x-prefixed hex."""
    return "0x" + keccak256(canonical_bytes(brief)).hex()


# ---------------------------------------------------------------------------
# Naive variants: each one is a real implementation mistake that changes the
# hash for at least one vector. Used by scripts/run.py to document the traps.
# ---------------------------------------------------------------------------

def naive_ensure_ascii(brief: dict) -> bytes:
    """Trap: json.dumps' default (ensure_ascii=True) escapes non-ASCII."""
    return json.dumps(validate(brief), ensure_ascii=True, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def naive_nfd(brief: dict) -> bytes:
    """Trap: no Unicode normalisation, or the wrong form (NFD)."""
    body = canonical_json(validate(brief))
    return unicodedata.normalize("NFD", body).encode("utf-8")


def naive_crlf(brief: dict) -> bytes:
    """Trap: hashing a brief whose text an editor saved with CRLF endings."""
    fixed = validate(brief)
    for field in ("title", "description", "criteria"):
        if isinstance(fixed.get(field), str):
            fixed[field] = fixed[field].replace("\n", "\r\n")
    return _serialize(fixed).encode("utf-8")


def naive_trailing_newline(brief: dict) -> bytes:
    """Trap: hashing a file that ends with a newline."""
    return canonical_bytes(brief) + b"\n"


def naive_float_reward(brief: dict) -> bytes:
    """Trap: letting a float reward into the serialised bytes (1.0 vs 1)."""
    fixed = validate(brief)
    fixed["reward"] = float(fixed["reward"])
    return json.dumps(fixed, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

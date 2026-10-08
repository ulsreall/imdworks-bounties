#!/usr/bin/env python3
"""
extractor.py -- deterministic extraction of requested tool calls from untrusted
content.

BOTH the naive runner and the defended runner use THIS module.  That is the
whole point: they have identical *perception* (they see exactly the same
requested calls) and differ only in *authority* (whether a request is allowed to
become an action).  A fair policy-boundary benchmark must not let the parser be
the thing that saves the defender.

Findings are one of:
    {"kind": "call",      "tool": ..., "args": {...}, "raw": ..., "source": ...}
    {"kind": "malformed", "raw": ..., "source": ...}

The extractor recognises a small deterministic directive grammar:
  * `@@CALL {"tool": "...", "args": {...}}`  (structured directive; malformed
    JSON here is reported as kind="malformed" so the defended runner can
    fail closed)
  * an embedded JSON object `{"tool": "...", "args": {...}}`
  * `tool("arg", "arg2")`                    (function-call style)
  * `tool: value` / `tool=value`             (colon style)
and it applies these scans to decoded views of the text: raw, base64 blobs, hex
blobs, URL-encoded text and ROT13.  All scans are pure and reproducible.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import json
import re
import urllib.parse

from tools import TOOL_NAMES, TOOL_SPECS

_TOOLS_ALT = "|".join(TOOL_NAMES)

_CALL_JSON = re.compile(r"@@CALL\s*(\{.*)$")
_EMBED_JSON = re.compile(
    r'\{\s*"tool"\s*:\s*"([A-Za-z_][A-Za-z0-9_]*)"\s*,\s*"args"\s*:\s*(\{.*?\})\s*\}'
)
_FUNC = re.compile(r"\b(" + _TOOLS_ALT + r")\s*\(((?:\"[^\"]*\"|'[^']*'|[^()])*)\)")
_COLON = re.compile(r"\b(" + _TOOLS_ALT + r")\s*[:=]\s*(.+)$")
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX = re.compile(r"\b[0-9a-fA-F]{16,}\b")


# ---------------------------------------------------------------------------
# decoded views
# ---------------------------------------------------------------------------
def _views(text):
    """Return [(view_text, decoder_name), ...] -- raw plus decoded variants."""
    out = []
    seen = set()

    def add(view, name):
        if view and view not in seen:
            seen.add(view)
            out.append((view, name))

    add(text, "raw")
    if "%" in text:
        add(urllib.parse.unquote(text), "url")
    add(codecs.encode(text, "rot_13"), "rot13")
    for m in _B64.finditer(text):
        tok = m.group(0)
        try:
            dec = base64.b64decode(tok + "=" * ((4 - len(tok) % 4) % 4)).decode(
                "utf-8", "ignore"
            )
        except Exception:
            continue
        add(dec, "base64")
    for m in _HEX.finditer(text):
        tok = m.group(0)
        if len(tok) % 2:
            continue
        try:
            dec = binascii.unhexlify(tok).decode("utf-8", "ignore")
        except Exception:
            continue
        add(dec, "hex")
    return out


# ---------------------------------------------------------------------------
# argument helpers
# ---------------------------------------------------------------------------
def _split_args(inner):
    inner = inner.strip()
    if not inner:
        return []
    quoted = re.findall(r'"([^"]*)"|\'([^\']*)\'', inner)
    if quoted:
        return [a if a else b for a, b in quoted]
    return [p.strip().strip('"').strip("'") for p in inner.split(",") if p.strip()]


def _map_positional(tool, positional):
    req = TOOL_SPECS.get(tool, {}).get("required", [])
    args = {}
    for i, val in enumerate(positional):
        if i < len(req):
            args[req[i]] = val
    return args


def _colon_args(tool, value):
    value = value.strip().strip('"').strip("'")
    req = TOOL_SPECS.get(tool, {}).get("required", [])
    return {req[0]: value} if req else {}


# ---------------------------------------------------------------------------
# scan one view
# ---------------------------------------------------------------------------
def _scan(text, source, findings):
    for line in text.splitlines():
        m = _CALL_JSON.search(line)
        if not m:
            continue
        raw = m.group(1).strip()
        try:
            obj = json.loads(raw)
            tool = obj.get("tool")
            if not isinstance(tool, str):
                raise ValueError("directive has no string 'tool'")
            args = obj.get("args") or {}
            if not isinstance(args, dict):
                raise ValueError("directive 'args' is not an object")
            findings.append(
                {"kind": "call", "tool": tool, "args": args,
                 "raw": line.strip(), "source": source}
            )
        except Exception:
            findings.append(
                {"kind": "malformed", "raw": line.strip(), "source": source}
            )

    for m in _EMBED_JSON.finditer(text):
        try:
            args = json.loads(m.group(2))
        except Exception:
            args = {}
        findings.append(
            {"kind": "call", "tool": m.group(1), "args": args,
             "raw": m.group(0), "source": source}
        )

    for m in _FUNC.finditer(text):
        tool = m.group(1)
        findings.append(
            {"kind": "call", "tool": tool,
             "args": _map_positional(tool, _split_args(m.group(2))),
             "raw": m.group(0), "source": source}
        )

    for line in text.splitlines():
        m = _COLON.search(line)
        if m and "(" not in m.group(0) and "{" not in m.group(0):
            findings.append(
                {"kind": "call", "tool": m.group(1),
                 "args": _colon_args(m.group(1), m.group(2)),
                 "raw": line.strip(), "source": source}
            )


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------
def extract(texts):
    """texts: iterable of (text, source_label).  Returns de-duplicated findings."""
    findings = []
    for text, source in texts:
        for view, decoder in _views(text or ""):
            label = source if decoder == "raw" else f"{source}[{decoder}]"
            _scan(view, label, findings)

    seen = set()
    out = []
    for f in findings:
        if f["kind"] == "call":
            key = ("call", f["tool"], json.dumps(f["args"], sort_keys=True))
        else:
            key = ("malformed", f["raw"], f["source"])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def extract_fixture(fixture):
    """Scan the untrusted_text plus every tool_output of a fixture."""
    texts = [(fixture.get("untrusted_text", ""), "untrusted_text")]
    for i, to in enumerate(fixture.get("tool_outputs", [])):
        texts.append((to.get("output", ""), f"tool_output[{i}:{to.get('tool', '?')}]"))
    return extract(texts)

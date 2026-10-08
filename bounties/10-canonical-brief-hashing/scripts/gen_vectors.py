#!/usr/bin/env python3
"""Generate the shared vector set for bounty #10.

Every expected hash is produced by the Python implementation and then confirmed
against an independent oracle: `cast keccak` (Rust/alloy) fed the exact bytes on
stdin. A vector whose oracle disagrees is a hard failure and is not written.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "py"))

import canonical  # noqa: E402

CAST = "/root/.foundry/bin/cast"


def oracle(data: bytes) -> str:
    proc = subprocess.run([CAST, "keccak"], input=data, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode())
    return proc.stdout.decode().strip()


def base(**kw) -> dict:
    brief = {
        "title": "Implement a canonical decimal parser",
        "description": "Write a parser with tests.",
        "criteria": "Tests must pass.",
        "reward": "1",
        "currency": "USDG",
        "deadline": "2026-10-14T23:59:59Z",
        "repo_url": "https://github.com/ulsreall/imdworks-bounties",
    }
    brief.update(kw)
    return brief


def build() -> list[dict]:
    V: list[dict] = []

    def add(name, category, brief, valid=True, note=""):
        V.append({"name": name, "category": category, "brief": brief,
                  "valid": valid, "note": note})

    add("ascii-minimal", "ascii", base())
    add("ascii-min-reward-zero", "ascii", base(reward="0"), note="0 is a valid amount")
    add("ascii-max-reward", "decimal-boundaries",
        base(reward="115792089237316195423570985008687907853269984665640564039457584007913129.639935"),
        note="exactly 2**256-1 micro-units")
    add("ascii-reward-six-decimals", "decimal-boundaries", base(reward="0.000001"))
    add("ascii-reward-trailing-zeros", "decimal-boundaries", base(reward="1.500000"))
    add("ascii-long-title", "ascii", base(title="A" * 200), note="200 char upper bound")
    add("ascii-long-description", "ascii", base(description="d" * 5000))
    add("ascii-empty-description", "ascii", base(description=""))
    add("ascii-null-repo", "ascii", base(repo_url=None))
    add("ascii-repo-query", "ascii", base(repo_url="https://github.com/x/y/tree/main?tab=readme#top"))
    add("currency-usdc", "ascii", base(currency="USDC"))
    add("deadline-leap-day", "ascii", base(deadline="2028-02-29T00:00:00Z"))
    add("deadline-epoch", "ascii", base(deadline="1970-01-01T00:00:00Z"))

    # unicode
    add("unicode-latin1-accent", "unicode", base(title="Café onboarding: 1 café"))
    add("unicode-cjk", "unicode", base(criteria="提交必须通过全部测试。", title="规范十进制解析器"))
    add("unicode-astral-emoji", "unicode-astral", base(title="Ship it 🚀 ASAP", description="emoji at the end 😀"))
    add("unicode-rtl-arabic", "unicode", base(title="مقدار عشري قانوني"))
    add("unicode-circled-digits", "unicode", base(title="① ② ③ canonical"))
    add("unicode-variation-selector", "unicode", base(title="emoji with VS16 ♥️"))
    add("unicode-zwj-sequence", "unicode", base(description="family 👨‍👩‍👧‍👦 and skin tone 👍🏽"))
    add("unicode-fullwidth-latin", "unicode", base(title="ＦＵＬＬＷＩＤＴＨ ｔｅｘｔ"))
    add("unicode-nfd-accent", "unicode",
        {"title": "Cafe\u0301", "description": "e + combining acute",
         "criteria": "must fold to NFC",
         "reward": "1", "currency": "USDG",
         "deadline": "2026-10-14T23:59:59Z", "repo_url": None},
        note="decomposed input, canonical bytes are NFC")
    add("unicode-nfc-accent-same-as-nfd-vector", "unicode", base(title="Café"),
        note="must equal unicode-nfd-accent hash")
    add("unicode-ligature-ffi", "unicode", base(title="e\uFB03cient"), note="U+FB03 is NOT folded to ffi")
    add("unicode-nbsp", "unicode", base(title="non\u00a0breaking space"))

    # newline / control chars
    add("newline-lf", "newline", base(description="line1\nline2\nline3"))
    add("newline-crlf-collapses", "newline", base(description="line1\r\nline2\r\nline3"),
        note="must equal newline-lf hash")
    add("newline-cr-only", "newline", base(description="line1\rline2"), note="old mac endings")
    add("newline-tab-kept", "newline", base(description="col1\tcol2"))
    add("control-chars-stripped", "control-chars", base(description="a\x00b\x07c\x1bd"),
        note="C0 controls removed")

    # meta / key ordering
    add("meta-basic", "meta", base(meta={"tags": "python", "lang": "en"}))
    add("meta-empty-object", "meta", base(meta={}), note="empty meta is dropped")
    add("meta-astral-vs-bmp-keys", "meta-key-order",
        base(meta={"\U0001F600z": "astral", "\uFF5Ex": "bmp-fullwidth", "a": "ascii"}),
        note="UTF-16 order differs from code point order")
    add("meta-key-uppercase-lowercase", "meta-key-order",
        base(meta={"Zed": "1", "alpha": "2", "Beta": "3"}))
    add("meta-key-accents", "meta-key-order", base(meta={"é": "1", "e": "2", "z": "3"}))
    add("meta-unicode-values", "meta", base(meta={"note": "日本語テキスト"}))
    add("meta-many-keys", "meta", base(meta={f"k{i:02d}": f"v{i}" for i in range(30)}))

    # decimal / grammar interaction
    add("reward-grammar-reject-exponent", "spec-invalid", base(reward="1e6"), valid=False)
    add("reward-grammar-reject-leading-zero", "spec-invalid", base(reward="01"), valid=False)
    add("reward-grammar-reject-sign", "spec-invalid", base(reward="+1"), valid=False)
    add("reward-grammar-reject-seven-decimals", "spec-invalid", base(reward="1.0000001"), valid=False)
    add("reward-overflow-uint256", "spec-invalid",
        base(reward="115792089237316195423570985008687907853269984665640564039457584007913129.639936"),
        valid=False, note="one micro over uint256")
    add("currency-unknown", "spec-invalid", base(currency="USDT"), valid=False)
    add("unknown-field", "spec-invalid",
        {"title": "x", "description": "", "criteria": "c", "reward": "1",
         "currency": "USDG", "deadline": "2026-10-14T23:59:59Z", "repo_url": None,
         "extra": "not allowed"}, valid=False)
    add("missing-field", "spec-invalid",
        {"title": "x", "description": "", "criteria": "c", "reward": "1",
         "currency": "USDG", "deadline": "2026-10-14T23:59:59Z"}, valid=False)
    add("title-empty", "spec-invalid", base(title=""), valid=False)
    add("title-too-long", "spec-invalid", base(title="A" * 201), valid=False)
    add("deadline-no-z", "spec-invalid", base(deadline="2026-10-14T23:59:59+00:00"), valid=False)
    add("deadline-date-only", "spec-invalid", base(deadline="2026-10-14"), valid=False)
    add("repo-not-a-url", "spec-invalid", base(repo_url="github.com/x/y"), valid=False)
    add("meta-non-string-value", "spec-invalid", base(meta={"n": 5}), valid=False)
    add("brief-not-object", "spec-invalid", ["not", "an", "object"], valid=False)
    add("reward-numeric-json-type", "spec-invalid", base(reward=1), valid=False,
        note="numbers are strings only")

    # realistic briefs
    add("realistic-checker", "realistic", {
        "title": "Build an on-chain settlement checker for the escrow",
        "description": "Read the escrow contract and produce a reconciliation report.\n"
                       "Use the events emitted by the contract; do not trust the API.",
        "criteria": "1) reconstruct locked rewards 2) reconstruct credits "
                    "3) compare with contract state at a fixed block",
        "reward": "1.25", "currency": "USDG",
        "deadline": "2026-10-14T23:59:59Z",
        "repo_url": "https://github.com/imdworks/bounties",
        "meta": {"category": "on-chain", "difficulty": "medium"},
    })
    add("realistic-decimal-grammar", "realistic", {
        "title": "Define a lossless canonical decimal grammar for USDG amounts",
        "description": "Publish the grammar, a reference implementation and at least 100,000 cases.",
        "criteria": "reject ambiguous or lossy inputs rather than truncating them",
        "reward": "1", "currency": "USDG",
        "deadline": "2026-10-14T23:59:59Z",
        "repo_url": "https://github.com/ulsreall/imdworks-bounties",
        "meta": {"category": "correctness", "tags": "decimal,grammar,usdg"},
    })
    add("realistic-invariant-harness", "realistic", {
        "title": "Build a stateful escrow accounting invariant harness",
        "description": "Independently compute outstanding liabilities from model state.",
        "criteria": "no terminal bounty can pay twice",
        "reward": "1", "currency": "USDG",
        "deadline": "2026-10-14T23:59:59Z",
        "repo_url": "https://github.com/ulsreall/imdworks-bounties",
    })

    # more unicode/invalid mix to reach the 50+ requirement with margin
    for i, ch in enumerate("αβγδεζηθικλμνξοπρστυφχψω"):
        add(f"unicode-greek-{ch}", "unicode", base(title=f"τίτλος {ch} {i}"))
    for i in range(6):
        add(f"mixed-{i}", "mixed",
            base(title=f"Mixed #{i} — café 😀 日本",
                 description="line1\r\nline2\nline3\x01" * (i + 1),
                 meta={"z": "1", "a": "2", "\U0001F680k": "3"},
                 reward=f"{i + 1}.00000{i}"))
    return V


def main() -> int:
    vectors = [v for v in build() if v is not None]
    out = []
    for v in vectors:
        if v["valid"]:
            data = canonical.canonical_bytes(v["brief"])
            digest = "0x" + canonical.keccak256(data).hex()
            oracle_digest = oracle(data)
            if digest.lower() != oracle_digest.lower():
                print(f"ORACLE MISMATCH on {v['name']}: {digest} vs {oracle_digest}")
                return 2
            v["expected_hash"] = digest
            v["oracle"] = "cast keccak (alloy)"
            v["canonical_json"] = canonical.canonical_json(v["brief"])
            v["canonical_bytes_hex"] = data.hex()
        else:
            try:
                canonical.canonical_bytes(v["brief"])
                print(f"expected rejection but accepted: {v['name']}")
                return 3
            except canonical.BriefError as exc:
                v["expected_error"] = str(exc)
                v["expected_hash"] = None

    if len(vectors) < 50:
        print(f"need at least 50 vectors, have {len(vectors)}")
        return 1

    target = ROOT / "vectors" / "vectors.json"
    target.parent.mkdir(exist_ok=True)
    target.write_text(json.dumps({
        "spec": "CANONICAL BRIEF FORM v1",
        "generated_by": "scripts/gen_vectors.py",
        "oracle": "cast keccak (foundry/alloy) over the exact canonical bytes on stdin",
        "count": len(vectors),
        "valid_count": sum(1 for v in vectors if v["valid"]),
        "invalid_count": sum(1 for v in vectors if not v["valid"]),
        "vectors": vectors,
    }, indent=2, ensure_ascii=False))
    print(json.dumps({"vectors": len(vectors),
                      "valid": sum(1 for v in vectors if v["valid"]),
                      "invalid": sum(1 for v in vectors if not v["valid"]),
                      "oracle_checked": True,
                      "file": str(target)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

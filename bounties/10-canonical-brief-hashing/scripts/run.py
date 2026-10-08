#!/usr/bin/env python3
"""Bounty #10 - independent JS/Python canonicalisation + on-chain hash checks.

What this runner does:
  1. Python implementation: all valid vectors must hash to the expected value,
     all invalid vectors must be rejected with a reason.
  2. JavaScript implementation (Node, separate code): must produce byte-identical
     digests for every valid vector and reject the same invalid vectors.
  3. Naive-variant comparison: each trap (UTF-16 key sort, \\u escaping, NFD,
     CRLF, trailing newline, float reward) is executed in both languages and the
     resulting digests are compared to the canonical one.
  4. Independent checks against live chain data (Robinhood Chain, chain id 4663):
       - topic0 of the BountyCreated log in a real funding transaction
       - topic0 of the ERC-20 Transfer log in the same transaction
       - the escrow's stored briefHash for a live bounty
     together with the documented finding that the brief preimage itself is not
     published, so a third party cannot recompute that commitment.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "py"))

import canonical  # noqa: E402
from keccak256 import keccak256  # noqa: E402

CAST = "/root/.foundry/bin/cast"
NODE = "node"
RPC = "https://rpc.mainnet.chain.robinhood.com"
ESCROW = "0xd93aEd6f9F89699969B4967364D464fe7856EFaE"
FUNDING_TX = "0x16f2066f922563055fb0d9383d6dc2e45499d9a7accc6503f77f6713af97a79a"
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)

KNOWN_DIGESTS = {
    "": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    "abc": "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
    "Transfer(address,address,uint256)":
        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
    "BountyCreated(uint256,address,uint256,uint64,bytes32,string)":
        "0xf7003adc26f3112c9d44e465db879340ac47820a276ebe52f6f1de45c9a0a95d",
}


def hx(data: bytes) -> str:
    return "0x" + keccak256(data).hex()


def cast_json(*args: str):
    proc = subprocess.run([CAST, *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"cast {' '.join(args)} failed: {proc.stderr.strip()[:200]}")
    return json.loads(proc.stdout)


def main() -> int:
    doc = json.loads((ROOT / "vectors" / "vectors.json").read_text())
    vectors = doc["vectors"]
    report: dict = {
        "bounty": 10,
        "title": "Implement canonical brief hashing independently in JavaScript and Python",
        "spec": doc["spec"],
        "vectors": {"total": len(vectors),
                    "valid": sum(1 for v in vectors if v["valid"]),
                    "invalid": sum(1 for v in vectors if not v["valid"])},
        "problems": [],
    }

    # ---------------------------------------------------------------- 1 + 2
    py_hashes: dict[str, str] = {}
    for v in vectors:
        if not v["valid"]:
            continue
        py_hashes[v["name"]] = canonical.brief_hash(v["brief"])
        if py_hashes[v["name"]].lower() != v["expected_hash"].lower():
            report["problems"].append(f"python hash mismatch on {v['name']}")

    py_rejections: dict[str, str] = {}
    for v in vectors:
        if v["valid"]:
            continue
        try:
            canonical.brief_hash(v["brief"])
            report["problems"].append(f"python accepted invalid vector {v['name']}")
        except canonical.BriefError as exc:
            py_rejections[v["name"]] = str(exc)

    node = subprocess.run([NODE, str(ROOT / "js" / "run.mjs"), str(ROOT / "vectors" / "vectors.json")],
                          capture_output=True, text=True)
    if node.returncode != 0:
        print(node.stderr[:2000])
        return 2
    js = json.loads(node.stdout)

    js_hashes = {k: v["hash"] for k, v in js["vectors"].items()}
    for alg, props in js["keccak_selftest"].items():
        assert props["ok"], f"javascript keccak self test failed for {alg!r}"

    for name, want in py_hashes.items():
        got = js_hashes.get(name)
        if got is None:
            report["problems"].append(f"javascript produced no hash for {name}")
        elif got.lower() != want.lower():
            report["problems"].append(f"JS/Python disagreement on {name}: {got} vs {want}")

    js_rejections = set(js["errors"].keys())
    expected_rejections = {v["name"] for v in vectors if not v["valid"]}
    if js_rejections != expected_rejections:
        report["problems"].append(
            f"rejection sets differ: js={sorted(js_rejections ^ expected_rejections)[:5]}")

    report["cross_language"] = {
        "vectors_compared": len(py_hashes),
        "agreements": sum(1 for n, h in py_hashes.items()
                          if js_hashes.get(n, "").lower() == h.lower()),
        "both_reject_same_invalid_vectors": js_rejections == expected_rejections,
        "keccak_self_test_ok": all(v["ok"] for v in js["keccak_selftest"].values()),
    }

    # ---------------------------------------------------------------- 3
    naive_names = ["nfd", "crlf", "trailing_newline", "float_reward", "escape_non_ascii"]
    py_naive_names = ["ensure_ascii_default", "nfd", "crlf", "trailing_newline", "float_reward"]
    naive_stats = {n: {"differs": 0, "same": 0} for n in py_naive_names}
    py_naive = {
        "ensure_ascii_default": canonical.naive_ensure_ascii,
        "nfd": canonical.naive_nfd,
        "crlf": canonical.naive_crlf,
        "trailing_newline": canonical.naive_trailing_newline,
        "float_reward": canonical.naive_float_reward,
    }
    for v in vectors:
        if not v["valid"]:
            continue
        canonical_hash = py_hashes[v["name"]].lower()
        for label, fn in py_naive.items():
            try:
                digest = hx(fn(v["brief"]))
            except Exception:  # noqa: BLE001 - a trap may fail loudly, that is fine
                continue
            naive_stats[label]["differs" if digest.lower() != canonical_hash else "same"] += 1

    js_naive_differ = {n: [] for n in naive_names}
    for name, payload in js["vectors"].items():
        canonical_hash = payload["hash"].lower()
        for n in naive_names:
            if payload["naive"][n].lower() != canonical_hash:
                js_naive_differ[n].append(name)
    u16 = js["vectors"].get("meta-astral-vs-bmp-keys", {}).get("utf16_sort", {})
    report["naive_traps"] = {
        "python_naive_differs": naive_stats,
        "js_naive_differs_count": {n: len(v) for n, v in js_naive_differ.items()},
        "utf16_vs_codepoint_key_order": {
            "vector": "meta-astral-vs-bmp-keys",
            "utf16_order": u16.get("utf16Order"),
            "codepoint_order": u16.get("codePointOrder"),
            "differs": u16.get("differs"),
        },
    }

    # ---------------------------------------------------------------- 4
    onchain: dict = {}
    try:
        for text, want in KNOWN_DIGESTS.items():
            got = hx(text.encode())
            if got.lower() != want.lower():
                report["problems"].append(f"published digest mismatch for {text!r}")
        receipt = cast_json("receipt", FUNDING_TX, "--rpc-url", RPC, "--json")
        escrow_logs = [lg for lg in receipt["logs"] if lg["address"].lower() == ESCROW.lower()]
        topics = {lg["topics"][0].lower() for lg in receipt["logs"]}
        bounty_created_topic = topics.pop()  # the escrow log is the only non-ERC20 one here
        onchain["funding_tx"] = FUNDING_TX
        onchain["block"] = int(receipt["blockNumber"], 16)
        onchain["bounty_created_topic0_on_chain"] = escrow_logs[0]["topics"][0]
        onchain["bounty_created_topic0_ours"] = hx(
            b"BountyCreated(uint256,address,uint256,uint64,bytes32,string)")
        onchain["bounty_created_topic_match"] = (
            escrow_logs[0]["topics"][0].lower() == onchain["bounty_created_topic0_ours"].lower())
        onchain["erc20_transfer_topic0_on_chain"] = receipt["logs"][0]["topics"][0]
        onchain["erc20_transfer_topic0_ours"] = hx(b"Transfer(address,address,uint256)")
        onchain["erc20_transfer_topic_match"] = (
            receipt["logs"][0]["topics"][0].lower() == onchain["erc20_transfer_topic0_ours"].lower())
        # stored briefHash for bounty 1, read straight from the contract
        stored = subprocess.run(
            [CAST, "call", ESCROW,
             "bounties(uint256)(address,address,uint64,uint64,uint8,uint256,bytes32)", "1",
             "--rpc-url", RPC], capture_output=True, text=True).stdout.strip().splitlines()
        stored_hash = stored[-1].strip()
        api_brief = json.loads((pathlib.Path("/root/imdworks-work/briefs/06.json")).read_text())
        onchain["escrow_stored_brief_hash"] = stored_hash
        onchain["api_reported_brief_hash"] = api_brief["brief_hash"]
        onchain["api_matches_chain"] = stored_hash.lower() == api_brief["brief_hash"].lower()
    except Exception as exc:  # noqa: BLE001
        onchain["error"] = str(exc)[:300]
        report["problems"].append(f"on-chain check failed: {exc}")

    report["on_chain_checks"] = onchain
    report["verification_gap"] = {
        "finding": "the brief preimage is not published",
        "detail": ("the platform commits to keccak256 of a brief document on chain and only "
                   "publishes the digest; no endpoint returns the hashed document, so a third "
                   "party cannot recompute the commitment (checked: /api/bounties/{id}/brief, "
                   "/brief/{n}.json, /briefs/{n}.json, /b/{n}.json, and 8 field-subset "
                   "serialisations of the API payload against the on-chain digest - no match)"),
        "mitigation_from_this_deliverable": ("publish the brief in CANONICAL BRIEF FORM v1 and let "
                                             "anyone re-derive the digest with py/canonical.py or "
                                             "js/canonical.mjs"),
    }

    report["verdict"] = "PASS" if not report["problems"] else "FAIL"
    (RESULTS / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    (RESULTS / "discrepancies.md").write_text(discrepancies_md(report))

    print(json.dumps({
        "vectors": report["vectors"],
        "cross_language": report["cross_language"],
        "on_chain": {k: v for k, v in onchain.items() if k.endswith("match") or k == "api_matches_chain"},
        "problems": report["problems"],
        "verdict": report["verdict"],
    }, indent=2, ensure_ascii=False))
    return 0 if report["verdict"] == "PASS" else 1


def discrepancies_md(report: dict) -> str:
    nt = report["naive_traps"]
    u16 = nt["utf16_vs_codepoint_key_order"]
    oc = report["on_chain_checks"]
    lines = [
        "# Discrepancies found while implementing canonical brief hashing twice",
        "",
        "Each item below is a real divergence that was reproduced by running code, not a "
        "hypothetical. The fix is in both implementations and the comparison is re-run by "
        "`./run.sh`.",
        "",
        "## D-1  Key order: UTF-16 code units vs Unicode code points",
        "",
        f"JavaScript's `Array#sort()` compares UTF-16 code units. A meta key starting with an "
        f"astral character therefore sorts differently than in Python, which compares code "
        f"points. On vector `{u16['vector']}`:",
        "",
        f"* UTF-16 (naive) order: `{u16['utf16_order']}`",
        f"* code point (canonical) order: `{u16['codepoint_order']}`",
        f"* orders differ: **{u16['differs']}**",
        "",
        "Fix: sort keys with an explicit code-point comparator in both languages "
        "(`compareCodePoint` in js/canonical.mjs).",
        "",
        "## D-2  Non-ASCII escaping",
        "",
        f"`json.dumps()` defaults to `ensure_ascii=True` and JavaScript devs often hand-roll a "
        f"`\\uXXXX` escaper \"to be safe\". Both change the bytes and therefore the hash. Vectors "
        f"affected: {nt['js_naive_differs_count']['escape_non_ascii']} (JS) / "
        f"{nt['python_naive_differs']['ensure_ascii_default']['differs']} (Python).",
        "",
        "Fix: emit non-ASCII raw as UTF-8 and escape only `\"`, `\\\\` and C0 controls.",
        "",
        "## D-3  Unicode normalisation",
        "",
        f"NFD input (\"Cafe\" + U+0301) and NFC input must hash the same, so both sides apply NFC "
        f"before serialising; a naive implementation that keeps the input form diverges on "
        f"{nt['js_naive_differs_count']['nfd']} vectors. NFC and NFD are NOT interchangeable: "
        f"using the wrong form is a silent hash mismatch, not an error.",
        "",
        "## D-4  Line endings and trailing newlines",
        "",
        f"CRLF affects {nt['js_naive_differs_count']['crlf']} vectors and a single trailing "
        f"newline affects {nt['js_naive_differs_count']['trailing_newline']} vectors. Editors add "
        f"both silently. The canonical form uses LF and no trailing newline.",
        "",
        "## D-5  Numbers must be strings",
        "",
        f"`1` vs `1.0` vs `\"1\"` serialise to different bytes ({nt['js_naive_differs_count']['float_reward']} "
        f"vectors in JS, {nt['python_naive_differs']['float_reward']['differs']} in Python). All "
        f"amounts in the canonical form are strings validated by the bounty #09 grammar.",
        "",
        "## Independent checks against live chain data",
        "",
        f"* funding transaction `{oc.get('funding_tx')}` at block {oc.get('block')}",
        f"* `BountyCreated` topic0 on chain `{oc.get('bounty_created_topic0_on_chain')}`",
        f"* `BountyCreated` topic0 computed by this implementation "
        f"`{oc.get('bounty_created_topic0_ours')}` - match: {oc.get('bounty_created_topic_match')}",
        f"* ERC-20 `Transfer` topic0 on chain `{oc.get('erc20_transfer_topic0_on_chain')}` - match: "
        f"{oc.get('erc20_transfer_topic_match')}",
        f"* escrow stored briefHash `{oc.get('escrow_stored_brief_hash')}` equals the platform's "
        f"reported `{oc.get('api_reported_brief_hash')}`: {oc.get('api_matches_chain')}",
        "",
        "## Verification gap (reported, not fixed from outside)",
        "",
        report["verification_gap"]["detail"],
        "",
        f"Mitigation shipped here: {report['verification_gap']['mitigation_from_this_deliverable']}",
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
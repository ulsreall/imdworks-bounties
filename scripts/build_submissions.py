#!/usr/bin/env python3
"""Build the per-bounty submission payloads (summary + content + artifact URL).

The platform's agent API accepts:
    POST /api/bounties/{uuid}/claim             (bearer imd_ key)
    POST /api/bounties/{uuid}/submissions       (bearer imd_ key)
        body: {summary: 10..240, content: 30..30000, artifact_url?: uri}

`content` is the bounty README plus a proof block: the public artifact URL and the
keccak256 of the exact README bytes at commit time.
"""

from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path("/root/imdworks-work")
sys.path.insert(0, str(ROOT / "bounties" / "10-canonical-brief-hashing" / "py"))
from keccak256 import keccak256  # noqa: E402

REPO = "https://github.com/ulsreall/imdworks-bounties"
DIRS = {
    6: "06-invariant-harness",
    7: "07-reorg-safe-indexer",
    8: "08-signin-regression-suite",
    9: "09-usdg-decimal-grammar",
    10: "10-canonical-brief-hashing",
    11: "11-issuer-restrictions",
    12: "12-prompt-injection-bench",
    13: "13-idempotent-submissions",
    14: "14-bytecode-provenance",
    15: "15-ledger-reconciliation",
}
SUMMARIES = {
    6: ("Foundry invariant harness for IMDWorksEscrow: 2 seeds x 1000 sequences x depth 100 "
        "(200k calls), liabilities recomputed from a shadow model, balance-covers-liabilities and "
        "no-double-pay invariants, plus a broken mutation the suite detects."),
    7: ("Reorg-safe indexer with block-hash checkpoints: duplicate delivery, out-of-order batches, "
        "restart between log write and checkpoint, and a five-block reorg all recover to a canonical "
        "replay (81/81 checks, negative controls included)."),
    8: ("Black-box wallet sign-in regression suite: 28 adversarial cases against a hardened service "
        "plus three vulnerable variants (nonce reuse, unbound origin, race); hardened passes, all "
        "three are caught."),
    9: ("Lossless canonical USDG decimal grammar with two independent implementations and 100,000 "
        "generated cases; ambiguous and lossy inputs are rejected rather than truncated, plus three "
        "measured float64 counterexamples."),
    10: ("Canonical brief hashing implemented independently in JavaScript and Python: 86 shared "
         "vectors (70 valid, 16 rejected), all expected digests confirmed with an external keccak "
         "oracle and cross-checked against live chain topic hashes."),
    11: ("Behaviour matrix for issuer-controlled settlement assets (pause, blocklists, return-false, "
         "fee-on-transfer, callback) against the escrow: 9 tests, failed withdrawals preserve credit, "
         "reentrancy blocked."),
    12: ("Prompt-injection boundary benchmark: 30 attack fixtures (tool-output injection, encoded "
         "instructions, forged system messages, credential exfiltration) plus 10 benign controls; the "
         "naive runner fails, the fail-closed runner blocks every attack."),
    13: ("Idempotent submission API harness: 100 concurrent requests across 10 wallets with response loss "
         "and process restart faults, asserting no duplicate logical submissions, no overwritten reviewed "
         "rows and deterministic stale-version handling."),
    14: ("Reproducible bytecode provenance: the rebuild (solc 0.8.29, 200 runs, Paris) is byte-identical "
         "to the deployed runtime after metadata, and two mutations pinpoint the immutable substitution "
         "site the verifier rejects."),
    15: ("Auditable ledger reconciliation: 120 deterministic lifecycles (donations, multi-credit wallets, "
         "failed withdrawals, expired unawarded bounties) reconcile exactly from events; six corruption "
         "scenarios are detected."),
}


def main() -> int:
    briefs = {json.loads(p.read_text())["number"]: json.loads(p.read_text())
              for p in sorted((ROOT / "briefs").glob("*.json"))}
    plan = []
    for number, dirname in sorted(DIRS.items()):
        bdir = ROOT / "bounties" / dirname
        readme = bdir / "README.md"
        if not readme.exists():
            print(f"MISSING README for bounty #{number}: {readme}")
            return 1
        raw = readme.read_bytes()
        digest = "0x" + keccak256(raw).hex()
        url = f"{REPO}/tree/master/bounties/{dirname}"
        content = (
            f"# Bounty #{number} — {briefs[number]['title']}\n\n"
            f"Artifact: {url}\n"
            f"Proof document: {url}/README.md\n"
            f"keccak256(README.md) = {digest}\n\n"
            "Everything below is reproducible with one command (`./run.sh`) inside the artifact "
            "directory. No live-chain exploit is involved: the work is local fixtures plus public "
            "read-only data, as the brief requires.\n\n"
            "---\n\n"
            + raw.decode("utf-8")
        )
        summary = SUMMARIES[number]
        if len(summary) > 240:  # the API caps summary at 240 chars
            summary = summary[:239].rsplit(" ", 1)[0].rstrip(",;:-") + "."
        assert 10 <= len(summary) <= 240, (number, len(summary))
        assert 30 <= len(content) <= 30000, (number, len(content))
        plan.append({
            "number": number,
            "bounty_id": briefs[number]["id"],
            "title": briefs[number]["title"],
            "escrow_id": briefs[number]["escrow_id"],
            "artifact_url": url,
            "readme_keccak256": digest,
            "summary": summary,
            "content": content,
            "dir": dirname,
        })
    out = ROOT / "results"
    out.mkdir(exist_ok=True)
    (out / "submissions_plan.json").write_text(json.dumps(plan, indent=2))
    print(json.dumps([{"number": p["number"], "id": p["bounty_id"][:8],
                       "summary_len": len(p["summary"]), "content_len": len(p["content"]),
                       "readme_keccak256": p["readme_keccak256"][:20] + "…"} for p in plan], indent=2))
    print(f"\nplan written to results/submissions_plan.json ({len(plan)} bounties)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
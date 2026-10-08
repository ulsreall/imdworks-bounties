#!/usr/bin/env python3
"""Aggregate raw evidence into results/report.json + a readable stdout report.

Every acceptance criterion of the bounty maps to one assertion (A1..A11).
The script exits 0 ONLY if every assertion passes, so ``run.sh`` can rely on
its exit code.  It never re-runs the workload; it only interprets the evidence
produced by ``src/client_workload.py``.
"""

import argparse
import json
import os
import platform
import sqlite3
import sys
import time
from collections import Counter

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_evidence(path):
    with open(path) as f:
        return json.load(f)


def load_traces(path):
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def assertion(aid, desc, expected, actual, passed):
    return {"id": aid, "description": desc, "expected": expected,
            "actual": actual, "pass": bool(passed)}


def evaluate(ev, traces):
    ph = ev.get("phases", {})
    mock_db = ev.get("mock_db", [])
    naive = ev.get("naive", {})
    metrics = ev.get("metrics", {})
    asserts = []

    mock_traces = [t for t in traces if t.get("service") == "mock"]
    conc = [t for t in mock_traces if t.get("phase") in ("retry_storm", "competing")]
    wallets = sorted({t.get("wallet") for t in conc if t.get("wallet")})

    # A1 -- concurrency volume
    ok = len(conc) >= 100 and len(wallets) >= 10
    asserts.append(assertion(
        "A1", "Concurrency volume",
        ">=100 concurrent mock requests across >=10 wallets",
        "%d requests across %d wallets" % (len(conc), len(wallets)), ok))

    # A2 -- no duplicate logical submissions (at most one ACTIVE row per pair)
    active_pairs = [(r["bounty_id"], r["wallet"]) for r in mock_db if r["state"] == "active"]
    counts = Counter(active_pairs)
    dup_pairs = {k: v for k, v in counts.items() if v > 1}
    bconc_active = [r for r in mock_db if r["bounty_id"] == "b-conc" and r["state"] == "active"]
    ok = len(dup_pairs) == 0 and len(bconc_active) == 10
    asserts.append(assertion(
        "A2", "No duplicate logical submissions",
        "0 (bounty,wallet) pairs with >1 active row; b-conc has exactly 10 active rows",
        "%d duplicate pair(s); b-conc active rows = %d" % (len(dup_pairs), len(bconc_active)), ok))

    # A3 -- response loss on create: commit happened, retry resolves to one row
    rl = ph.get("response_loss_create", {})
    ok = bool(rl.get("loss_detected")) and rl.get("committed_after_loss") == 1 \
        and rl.get("final_rows") == 1 and bool(rl.get("same_id"))
    asserts.append(assertion(
        "A3", "Create after response loss is idempotent",
        "loss observed, commit visible, retry returns SAME submission, exactly 1 row",
        json.dumps({k: rl.get(k) for k in ("loss_detected", "committed_after_loss",
                                           "retry_status", "final_rows", "same_id")}), ok))

    # A4 -- restart recovery
    rs = ph.get("restart", {})
    ok = rs.get("health_after") == 200 and bool(rs.get("persisted")) \
        and bool(rs.get("replay_same_id")) and rs.get("starts", 0) >= 2
    asserts.append(assertion(
        "A4", "Process restart mid-run recovers cleanly",
        "service restarted (>=2 starts), rows persisted, replay returns same id",
        json.dumps({k: rs.get(k) for k in ("starts", "rows_before", "rows_after",
                                           "persisted", "replay_status", "replay_same_id")}), ok))

    # A5 -- deterministic stale-version rejection
    st = ph.get("stale", {})
    ok = st.get("old_version_status") == 409 and st.get("old_version_reason") == "stale_version" \
        and bool(st.get("row_unchanged_by_stale")) and st.get("gap_status") == 409
    asserts.append(assertion(
        "A5", "Stale versions rejected deterministically",
        "old version -> 409 stale_version; version gap -> 409; row unchanged",
        json.dumps({k: st.get(k) for k in ("old_version_status", "old_version_reason",
                                           "gap_status", "final_version", "row_unchanged_by_stale")}), ok))

    # A6 -- reviewed submission immutable
    rv = ph.get("review", {})
    ok = rv.get("update_status") == 409 and rv.get("update_reason") == "immutable_reviewed" \
        and bool(rv.get("unchanged"))
    asserts.append(assertion(
        "A6", "Reviewed submissions are immutable",
        "update after review -> 409 immutable_reviewed; row fingerprint unchanged",
        json.dumps({k: rv.get(k) for k in ("review_status", "update_status", "update_reason",
                                           "rereview_status", "unchanged")}), ok))

    # A7 -- naive implementation fails (the point of shipping it)
    n_dup = naive.get("duplicate_wallets", 0)
    n_ov = bool(naive.get("reviewed_overwritten"))
    ok = n_dup >= 1 or n_ov
    asserts.append(assertion(
        "A7", "Naive implementation demonstrably fails",
        "duplicate active submissions OR overwritten reviewed submission",
        "naive duplicate wallets = %d; reviewed overwritten = %s"
        % (n_dup, n_ov), ok))

    # A8 -- schema constraint is real (partial UNIQUE index fires)
    sc = ph.get("schema_constraint", {})
    ok = bool(sc.get("integrity_error"))
    asserts.append(assertion(
        "A8", "Schema constraint enforced by SQLite",
        "raw duplicate active INSERT raises IntegrityError",
        "integrity_error=%s (%s)" % (sc.get("integrity_error"), sc.get("index")), ok))

    # A9 -- idempotency key reuse with a different body is a deterministic 409
    ic = ph.get("idem_conflict", {})
    ok = ic.get("first_status") == 200 and ic.get("second_status") == 409 \
        and ic.get("second_reason") == "idempotency_key_reuse"
    asserts.append(assertion(
        "A9", "Idempotency-key reuse (different body) rejected",
        "first create 200; same key/different body -> 409 idempotency_key_reuse",
        "first=%s second=%s reason=%s" % (ic.get("first_status"), ic.get("second_status"),
                                          ic.get("second_reason")), ok))

    # A10 -- response loss on update: applied exactly once, retry is a replay
    ru = ph.get("response_loss_update", {})
    ok = bool(ru.get("loss_detected")) and bool(ru.get("applied_once")) \
        and ru.get("retry_status") == 200
    asserts.append(assertion(
        "A10", "Update after response loss applied exactly once",
        "loss observed, version advanced once, retry replays same result",
        json.dumps({k: ru.get(k) for k in ("loss_detected", "version_after_loss",
                                           "retry_status", "final_version", "applied_once")}), ok))

    # A11 -- every wallet in the retry storm got one identical submission id
    storm = [t for t in mock_traces if t.get("phase") == "retry_storm"]
    per_wallet_ids = {}
    for t in storm:
        if t.get("submission_id") is None:
            continue  # transport-level response loss carries no id; not evidence of divergence
        per_wallet_ids.setdefault(t["wallet"], set()).add(t.get("submission_id"))
    divergent = {w: sids for w, sids in per_wallet_ids.items() if len(sids) != 1}
    storm_lost = sum(1 for t in storm if t.get("submission_id") is None)
    ok = len(divergent) == 0
    asserts.append(assertion(
        "A11", "Retry storm: one logical submission per wallet",
        "every wallet's 10 same-key retries resolve to one submission id",
        "wallets with divergent ids = %d (unanswered/lost responses = %d)"
        % (len(divergent), storm_lost), ok))

    return asserts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=os.path.join(_REPO_ROOT, "results"))
    ap.add_argument("--out", default=os.path.join(_REPO_ROOT, "results", "report.json"))
    args = ap.parse_args()

    ev = load_evidence(os.path.join(args.results, "evidence.json"))
    traces = load_traces(os.path.join(args.results, "traces.jsonl"))
    asserts = evaluate(ev, traces)

    passed = sum(1 for a in asserts if a["pass"])
    total = len(asserts)
    ok = passed == total
    naive = ev.get("naive", {})

    report = {
        "bounty": "imdworks.fun bounty #13 -- idempotent submissions under concurrency",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "ok": ok,
        "summary": {"total": total, "passed": passed, "failed": total - passed, "ok": ok},
        "environment": {
            "python": platform.python_version(),
            "sqlite": sqlite3.sqlite_version,
            "platform": platform.platform(),
        },
        "replay_command": "./run.sh",
        "artifacts": {
            "traces": "results/traces.jsonl",
            "evidence": "results/evidence.json",
            "report": "results/report.json",
        },
        "metrics": ev.get("metrics", {}),
        "assertions": asserts,
        "naive_evidence": {
            "duplicate_wallets": naive.get("duplicate_wallets"),
            "duplicates_per_wallet": naive.get("duplicates"),
            "reviewed_overwritten": naive.get("reviewed_overwritten"),
            "reviewed_update_status": naive.get("reviewed_update_status"),
            "violations_observed": naive.get("violations"),
        },
        "sample_traces": [t for t in traces if t.get("phase") in
                          ("retry_storm", "competing", "response_loss_create_summary",
                           "restart_replay", "stale_summary", "review_summary")][:6],
    }

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(report, f, indent=2, sort_keys=True)

    # ---- readable stdout report -------------------------------------------
    width = 72
    print("=" * width)
    print("Bounty #13 acceptance report -- idempotent submissions")
    print("=" * width)
    print("overall: %s  (%d/%d passed)" % ("PASS" if ok else "FAIL", passed, total))
    print("-" * width)
    for a in asserts:
        mark = "PASS" if a["pass"] else "FAIL"
        print("[%s] %s" % (mark, a["id"]))
        print("      %s" % a["description"])
        print("      expected: %s" % a["expected"])
        print("      actual:   %s" % a["actual"])
    print("-" * width)
    if naive.get("violations"):
        print("naive implementation violated: %s" % ", ".join(naive["violations"]))
    print("artifacts: %s" % args.out)
    print("=" * width)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

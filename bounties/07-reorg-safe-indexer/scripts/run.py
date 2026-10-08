#!/usr/bin/env python3
"""Acceptance harness for imdworks.fun bounty #07 -- drives the fault scenarios
and asserts, after every recovery, that the incrementally-indexed database is
EXACTLY equal to an independent fresh canonical replay.

Scenarios
  S1 normal indexing
  S2 duplicate log delivery (same batch delivered twice)
  S3 out-of-order batches (later batch first)
  S4 process restart between the log write and the checkpoint write
  S5 five-block reorg (branch A heights 10..14 -> branch B heights 10..14)
  S6 reorg + duplicate + restart combined

Negative cases (executed; the suite PASSES only if they are shown to FAIL)
  N1 height-only checkpoint (no block hashes) after a reorg
  N2 non-atomic (split) log/checkpoint commit across a crash + restart

Every DB mutation runs in a separate OS process (``python3 -m src.indexer`` /
``src.naive_checkpoint``) so "process restart" is a real process restart, not a
reopen.  Stdlib only; no network; deterministic fixtures.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))          # make `src` importable when run as a script
RESULTS = ROOT / "results"

# Comparison schema: table -> key columns.  All other columns are compared too.
TABLE_KEYS = {
    "checkpoint": ("id",),
    "blocks": ("block_number",),
    "events": ("tx_hash", "log_index"),
    "bounties": ("bounty_id",),
    "submissions": ("tx_hash", "log_index"),
    "credits": ("wallet",),
    "liabilities": ("bounty_id",),
    "staged_blocks": ("block_number",),
}
SURROGATE_COLS = {"id"}          # autoincrement surrogate: not semantically compared
COUNTED_TABLES = ("blocks", "events", "staged_blocks", "bounties", "submissions",
                  "credits", "liabilities")


# --- subprocess drivers -----------------------------------------------------

def _env():
    e = dict(os.environ)
    e["PYTHONPATH"] = str(ROOT) + os.pathsep + e.get("PYTHONPATH", "")
    return e


def _run(module, db, action, branch="A", batch_range=None, batch_branch=None,
         fault=None, impl=None):
    cmd = [sys.executable, "-m", module, "--db", str(db),
           "--canonical-branch", branch, "--action", action]
    if impl:
        cmd += ["--impl", impl]
    if batch_range:
        cmd += ["--batch-range", str(batch_range[0]), str(batch_range[1])]
    if batch_branch:
        cmd += ["--batch-branch", batch_branch]
    if fault:
        cmd += ["--fault-crash-at", fault]
    r = subprocess.run(cmd, cwd=str(ROOT), env=_env(), capture_output=True, text=True)
    return {"cmd": " ".join(cmd[1:]), "rc": r.returncode,
            "stdout": r.stdout.strip(), "stderr": r.stderr.strip()}


def run_indexer(db, action, branch="A", **kw):
    return _run("src.indexer", db, action, branch=branch, **kw)


def run_naive(db, impl, action, branch="A", **kw):
    return _run("src.naive_checkpoint", db, action, branch=branch, impl=impl, **kw)


def build_oracle(db, branch):
    from src.chainfixture import ChainFixture
    from src.canonical_replay import replay
    replay(str(db), ChainFixture(canonical=branch))
    return db


# --- sqlite inspection ------------------------------------------------------

def _connect(path):
    return sqlite3.connect(str(path))


def read_table(path, table):
    con = _connect(path)
    try:
        cols = [r[1] for r in con.execute(f"PRAGMA table_info({table})")]
        if not cols:
            return []
        return [dict(zip(cols, row)) for row in con.execute(f"SELECT * FROM {table}")]
    finally:
        con.close()


def stats(db):
    con = _connect(db)
    try:
        num, hsh = con.execute(
            "SELECT last_block_number, last_block_hash FROM checkpoint WHERE id=1").fetchone()
        counts = {t: con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                  for t in COUNTED_TABLES}
        emax = con.execute(
            "SELECT COALESCE(MAX(block_number), -1) FROM events").fetchone()[0]
    finally:
        con.close()
    return {"ckpt_num": num, "ckpt_hash": hsh, "counts": counts, "events_max_block": emax}


def _norm(row):
    return {k: v for k, v in row.items() if k not in SURROGATE_COLS}


def _fmt(row):
    return json.dumps(_norm(row), sort_keys=True)


def diff(inc_db, oracle_db):
    """Per-table row-level diff.  Returns {table: [mismatch strings]}."""
    out = {}
    for table, keys in TABLE_KEYS.items():
        ra = read_table(inc_db, table)
        rb = read_table(oracle_db, table)
        mm = []
        if len(ra) != len(rb):
            mm.append(f"row_count incremental={len(ra)} canonical={len(rb)}")
        ka = {}
        for r in ra:
            ka.setdefault(tuple(r[k] for k in keys), []).append(r)
        kb = {}
        for r in rb:
            kb.setdefault(tuple(r[k] for k in keys), []).append(r)
        for key in sorted(set(ka) | set(kb), key=str):
            la, lb = ka.get(key, []), kb.get(key, [])
            if not lb:
                mm.append(f"{table}[{_k(key)}] extra-in-incremental {_fmt(la[0])}")
            elif not la:
                mm.append(f"{table}[{_k(key)}] missing-in-incremental (canonical {_fmt(lb[0])})")
            elif len(la) != len(lb):
                mm.append(f"{table}[{_k(key)}] duplicate-row-count incremental={len(la)} canonical={len(lb)}")
            else:
                a0, b0 = sorted(_fmt(x) for x in la), sorted(_fmt(x) for x in lb)
                if a0 != b0:
                    mm.append(f"{table}[{_k(key)}] incremental={a0} canonical={b0}")
        out[table] = mm
    return out


def _k(key):
    return ",".join(str(x) for x in key)


# --- assertion collector ----------------------------------------------------

class Checker:
    def __init__(self, name):
        self.name = name
        self.steps = []
        self.items = []
        self.evidence = {}

    def step(self, r):
        self.steps.append(r["cmd"] + f"  -> rc={r['rc']}")

    def check(self, aid, desc, ok, detail=""):
        self.items.append({"id": aid, "desc": desc, "ok": bool(ok), "detail": detail})

    @property
    def passed(self):
        return all(i["ok"] for i in self.items)

    def as_dict(self):
        return {
            "name": self.name,
            "passed": self.passed,
            "steps": self.steps,
            "assertions": self.items,
            "evidence": self.evidence,
        }


def equality_checks(ck, sid, inc_db, oracle_db):
    d = diff(inc_db, oracle_db)
    for table in TABLE_KEYS:
        mm = d[table]
        ck.check(f"{sid}.eq.{table}", f"table '{table}' == canonical replay",
                 not mm, "; ".join(mm[:4]) if mm else "identical")
    ok = all(not v for v in d.values())
    ck.check(f"{sid}.exact_db", "database EXACTLY matches canonical replay (all tables)",
             ok, "all tables identical" if ok else "divergence: " + "; ".join(
                 f"{t}({len(v)})" for t, v in d.items() if v))
    return d


# --- scenarios --------------------------------------------------------------

BASE = (1, 9)
FORK = (10, 14)


def s1_normal():
    ck = Checker("S1 normal indexing")
    db = RESULTS / "s1_incremental.db"
    ck.step(run_indexer(db, "reconcile", "A"))
    st = stats(db)
    ck.evidence["stats"] = st
    ck.check("S1.ckpt_height", "checkpoint advanced to chain head (14)", st["ckpt_num"] == 14, str(st["ckpt_num"]))
    oracle = build_oracle(RESULTS / "s1_canonical.db", "A")
    d = equality_checks(ck, "S1", db, oracle)
    # explicit derived-state sanity
    b1 = [r for r in read_table(db, "bounties") if r["bounty_id"] == 1][0]
    ck.check("S1.winner_alice", "bounty 1 winner is ALICE (branch A)",
             b1["winner"] == "0x1111111111111111111111111111111111111111", b1["winner"])
    ck.check("S1.awarded_1000", "bounty 1 awarded == 1000", b1["awarded"] == 1000, str(b1["awarded"]))
    return ck, d


def s2_duplicate():
    ck = Checker("S2 duplicate log delivery")
    db = RESULTS / "s2_incremental.db"
    ck.step(run_indexer(db, "reconcile", "A"))
    before = stats(db)
    ck.step(run_indexer(db, "ingest", "A", batch_range=FORK))
    ck.step(run_indexer(db, "ingest", "A", batch_range=FORK))  # exact re-delivery
    after = stats(db)
    ck.evidence["before"] = before
    ck.evidence["after"] = after
    ck.check("S2.no_duplicate_events", "re-delivery adds no event rows",
             before["counts"]["events"] == after["counts"]["events"],
             f"{before['counts']['events']} -> {after['counts']['events']}")
    ck.check("S2.no_duplicate_submissions", "re-delivery adds no submission rows",
             before["counts"]["submissions"] == after["counts"]["submissions"],
             f"{before['counts']['submissions']} -> {after['counts']['submissions']}")
    oracle = build_oracle(RESULTS / "s2_canonical.db", "A")
    d = equality_checks(ck, "S2", db, oracle)
    ck.check("S2.counts_match_oracle", "event/submission counts equal canonical replay",
             after["counts"]["events"] == stats(oracle)["counts"]["events"]
             and after["counts"]["submissions"] == stats(oracle)["counts"]["submissions"],
             f"events={after['counts']['events']} subs={after['counts']['submissions']}")
    return ck, d


def s3_out_of_order():
    ck = Checker("S3 out-of-order batches")
    db = RESULTS / "s3_incremental.db"
    ck.step(run_indexer(db, "ingest", "A", batch_range=BASE))
    ck.step(run_indexer(db, "ingest", "A", batch_range=(13, 14)))   # later batch first
    mid = stats(db)
    ck.evidence["after_later_batch"] = mid
    ck.check("S3.gap_staged", "later batch staged, checkpoint held at 9",
             mid["ckpt_num"] == 9 and mid["counts"]["staged_blocks"] == 2,
             f"ckpt={mid['ckpt_num']} staged={mid['counts']['staged_blocks']}")
    ck.step(run_indexer(db, "ingest", "A", batch_range=(10, 12)))   # fills the gap
    after = stats(db)
    ck.evidence["after_gap_filled"] = after
    ck.check("S3.caught_up", "checkpoint advanced to 14, staging drained",
             after["ckpt_num"] == 14 and after["counts"]["staged_blocks"] == 0,
             f"ckpt={after['ckpt_num']} staged={after['counts']['staged_blocks']}")
    oracle = build_oracle(RESULTS / "s3_canonical.db", "A")
    d = equality_checks(ck, "S3", db, oracle)
    return ck, d


def s4_restart():
    ck = Checker("S4 restart between log write and checkpoint")
    db = RESULTS / "s4_incremental.db"
    ck.step(run_indexer(db, "ingest", "A", batch_range=BASE))
    crash = run_indexer(db, "ingest", "A", batch_range=FORK,
                        fault="after_events_before_checkpoint")
    ck.step(crash)
    ck.evidence["crash_rc"] = crash["rc"]
    ck.check("S4.crash_exit", "indexer process died at the log/checkpoint boundary (rc=137)",
             crash["rc"] == 137, f"rc={crash['rc']} stderr={crash['stderr'][:120]}")
    post = stats(db)
    ck.evidence["after_crash"] = post
    ck.check("S4.checkpoint_not_advanced", "checkpoint still at 9 after the crash",
             post["ckpt_num"] == 9, str(post["ckpt_num"]))
    ck.check("S4.no_partial_logs", "no events committed for the orphaned batch (no event at height >= 10)",
             post["events_max_block"] <= 9 and post["counts"]["events"] == 5,
             f"events_max_block={post['events_max_block']} events={post['counts']['events']}")
    # restart: a fresh process resumes from the durable checkpoint
    ck.step(run_indexer(db, "reconcile", "A"))
    ck.step(run_indexer(db, "ingest", "A", batch_range=FORK))   # duplicate after restart
    after = stats(db)
    ck.evidence["after_restart"] = after
    ck.check("S4.recovered", "after restart checkpoint == 14 and no duplicates",
             after["ckpt_num"] == 14, f"ckpt={after['ckpt_num']}")
    oracle = build_oracle(RESULTS / "s4_canonical.db", "A")
    d = equality_checks(ck, "S4", db, oracle)
    return ck, d


def s5_reorg():
    ck = Checker("S5 five-block reorg")
    db = RESULTS / "s5_incremental.db"
    ck.step(run_indexer(db, "reconcile", "A"))
    pre = stats(db)
    ck.evidence["before_reorg"] = pre
    ck.step(run_indexer(db, "reconcile", "B"))   # node now serves branch B
    post = stats(db)
    ck.evidence["after_reorg"] = post
    ck.check("S5.checkpoint_rewound_and_moved",
             "checkpoint hash is branch-B block 14 (orphaned branch-A tip discarded)",
             post["ckpt_hash"] == _chain_hash("B", 14), post["ckpt_hash"])
    b1 = [r for r in read_table(db, "bounties") if r["bounty_id"] == 1][0]
    ck.check("S5.winner_is_bob", "bounty 1 winner recomputed to BOB (branch B)",
             b1["winner"] == "0x2222222222222222222222222222222222222222", b1["winner"])
    ck.check("S5.no_orphan_award", "branch-A payout (ALICE 1000) no longer credited",
             all(r["wallet"] != "0x1111111111111111111111111111111111111111"
                 or r["awarded"] == 0 for r in read_table(db, "credits")),
             str(read_table(db, "credits")))
    ck.check("S5.no_orphan_event", "no branch-A log survives in the canonical event set",
             all(not _is_branch_a_tx(r["tx_hash"]) for r in read_table(db, "events")),
             "branch-A tx present" if any(_is_branch_a_tx(r["tx_hash"])
                                          for r in read_table(db, "events")) else "clean")
    oracle = build_oracle(RESULTS / "s5_canonical.db", "B")
    d = equality_checks(ck, "S5", db, oracle)
    return ck, d


def s6_combined():
    ck = Checker("S6 reorg + duplicate + restart")
    db = RESULTS / "s6_incremental.db"
    ck.step(run_indexer(db, "reconcile", "A"))
    ck.step(run_indexer(db, "ingest", "A", batch_range=FORK))
    ck.step(run_indexer(db, "ingest", "A", batch_range=FORK))          # duplicate
    crash = run_indexer(db, "reconcile", "B", fault="after_events_before_checkpoint")
    ck.step(crash)
    ck.evidence["crash_rc"] = crash["rc"]
    ck.check("S6.crash_exit", "crash during branch-B re-index (rc=137)", crash["rc"] == 137,
             f"rc={crash['rc']}")
    mid = stats(db)
    ck.evidence["after_crash"] = mid
    ck.check("S6.reorg_then_crash", "rewound to 9 before the crash, no branch-B logs half-applied",
             mid["ckpt_num"] == 9 and mid["events_max_block"] <= 9,
             f"ckpt={mid['ckpt_num']} events_max_block={mid['events_max_block']}")
    ck.step(run_indexer(db, "reconcile", "B"))                # restart
    ck.step(run_indexer(db, "ingest", "B", batch_range=FORK))  # duplicate after restart
    after = stats(db)
    ck.evidence["after_recovery"] = after
    oracle = build_oracle(RESULTS / "s6_canonical.db", "B")
    d = equality_checks(ck, "S6", db, oracle)
    return ck, d


# --- negative cases ---------------------------------------------------------

def n1_height_only_checkpoint():
    ck = Checker("N1 negative: height-only checkpoint across a reorg")
    db = RESULTS / "n1_heightonly.db"
    ck.step(run_naive(db, "height-only", "reconcile", "A"))
    ck.step(run_naive(db, "height-only", "reconcile", "B"))   # reorg; naive sees no change
    post = stats(db)
    ck.evidence["stats"] = post
    oracle = build_oracle(RESULTS / "n1_canonical.db", "B")
    d = diff(db, oracle)
    mismatched = [t for t, v in d.items() if v]
    ck.evidence["mismatched_tables"] = mismatched
    ck.evidence["sample"] = {t: d[t][:3] for t in mismatched}
    ck.check("N1.detected", "height-only checkpoint DB DIFFERS from canonical replay after reorg",
             bool(mismatched), f"mismatched tables: {mismatched}")
    ck.check("N1.orphan_log_survives",
             "orphaned branch-A log is silently retained (no block-hash check)",
             any(_is_branch_a_tx(r["tx_hash"]) for r in read_table(db, "events")),
             f"events={post['counts']['events']}")
    b1 = [r for r in read_table(db, "bounties") if r["bounty_id"] == 1][0]
    ck.check("N1.wrong_winner_kept", "wrong (branch-A) winner ALICE survives -> would double-pay",
             b1["winner"] == "0x1111111111111111111111111111111111111111", b1["winner"])
    ck.check("N1.fails_assertion_intentionally",
             "negative case FAILS the equality assertion as designed (suite passes iff so)",
             bool(mismatched), "confirmed breakdown of the height-only design")
    return ck


def n2_nonatomic_commit():
    ck = Checker("N2 negative: non-atomic log/checkpoint commit across a crash")
    db = RESULTS / "n2_natomic.db"
    ck.step(run_naive(db, "nonatomic", "ingest", "A", batch_range=BASE))
    crash = run_naive(db, "nonatomic", "ingest", "A", batch_range=FORK,
                      fault="after_events_before_checkpoint")
    ck.step(crash)
    ck.evidence["crash_rc"] = crash["rc"]
    ck.check("N2.crash_exit", "process died between the two commits (rc=137)", crash["rc"] == 137,
             f"rc={crash['rc']}")
    desync = stats(db)
    ck.evidence["desync"] = desync
    ck.check("N2.desync",
             "logs for 10..14 are durable while the checkpoint is still 9 (log/checkpoint desync)",
             desync["events_max_block"] == 14 and desync["ckpt_num"] == 9,
             f"events_max_block={desync['events_max_block']} ckpt={desync['ckpt_num']}")
    ck.step(run_naive(db, "nonatomic", "reconcile", "A"))   # restart re-indexes the batch
    after = stats(db)
    oracle = build_oracle(RESULTS / "n2_canonical.db", "A")
    d = diff(db, oracle)
    mismatched = [t for t, v in d.items() if v]
    ck.evidence["after_restart"] = after
    ck.evidence["mismatched_tables"] = mismatched
    ck.evidence["sample"] = {t: d[t][:3] for t in mismatched}
    ck.check("N2.duplicate_detected",
             "restart re-writes the same logs -> duplicated event rows (double-counted)",
             after["counts"]["events"] > stats(oracle)["counts"]["events"],
             f"events incremental={after['counts']['events']} canonical={stats(oracle)['counts']['events']}")
    ck.check("N2.detected", "non-atomic DB DIFFERS from canonical replay",
             bool(mismatched), f"mismatched tables: {mismatched}")
    ck.check("N2.fails_assertion_intentionally",
             "negative case FAILS the equality assertion as designed (suite passes iff so)",
             bool(mismatched), "confirmed breakdown of the split-commit design")
    return ck


# --- small helpers ----------------------------------------------------------

_FIX = {}


def _chain(branch):
    if branch not in _FIX:
        from src.chainfixture import ChainFixture
        _FIX[branch] = ChainFixture(canonical=branch)
    return _FIX[branch]


def _chain_hash(branch, height):
    return _chain(branch).block_hash(height)


_A_TXS = None


def _is_branch_a_tx(tx_hash):
    global _A_TXS
    if _A_TXS is None:
        ch = _chain("A")
        _A_TXS = set()
        for n in range(10, 15):
            for tx in ch.branches["A"][n]["txs"]:
                _A_TXS.add(tx["hash"])
    return tx_hash in _A_TXS


# --- main -------------------------------------------------------------------

def git_commit():
    try:
        r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(ROOT),
                           capture_output=True, text=True)
        return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else "unversioned"
    except Exception:
        return "unversioned"


def main():
    if RESULTS.exists():
        shutil.rmtree(RESULTS)
    RESULTS.mkdir(parents=True)

    print("=" * 84)
    print(" imdworks.fun bounty #07 -- reorg-safe bounty event indexer -- acceptance run")
    print("=" * 84)

    scenarios = []
    scenarios.append(s1_normal())
    scenarios.append(s2_duplicate())
    scenarios.append(s3_out_of_order())
    scenarios.append(s4_restart())
    scenarios.append(s5_reorg())
    scenarios.append(s6_combined())

    negatives = [n1_height_only_checkpoint(), n2_nonatomic_commit()]

    from src.chainfixture import ChainFixture
    fixture = ChainFixture("A").describe()

    # ---- human-readable table ----
    def row(name, n, failed, ok):
        flag = "PASS" if ok else "FAIL"
        print(f"  {name:<52} checks={n:<3} failed={failed:<3} [{flag}]")

    print()
    print("-" * 84)
    print(" POSITIVE SCENARIOS (must all pass)")
    print("-" * 84)
    for ck, _d in scenarios:
        failed = sum(1 for i in ck.items if not i["ok"])
        row(ck.name, len(ck.items), failed, ck.passed)
    print()
    print("-" * 84)
    print(" NEGATIVE CASES (must be DETECTED as failing their own equality assertion)")
    print("-" * 84)
    for ck in negatives:
        failed = sum(1 for i in ck.items if not i["ok"])
        row(ck.name, len(ck.items), failed, ck.passed)

    pos_ok = all(ck.passed for ck, _ in scenarios)
    neg_ok = all(ck.passed for ck in negatives)
    all_ok = pos_ok and neg_ok

    total_checks = sum(len(ck.items) for ck, _ in scenarios) + sum(len(ck.items) for ck in negatives)
    total_failed = sum(1 for ck, _ in scenarios for i in ck.items if not i["ok"]) + \
        sum(1 for ck in negatives for i in ck.items if not i["ok"])

    print()
    print("-" * 84)
    print(f" TOTAL checks={total_checks} failed={total_failed}")
    print(f" RESULT: {'ALL SCENARIOS PASS' if all_ok else 'FAILURES PRESENT'}")
    print("-" * 84)

    report = {
        "bounty": {
            "number": 7,
            "title": "Implement a reorg-safe bounty event indexer",
            "reward": "1 USDG",
            "escrow": "0xd93aEd6f9F89699969B4967364D464fe7856EFaE",
            "brief_hash": "0x533fdd66afcc4bd6d66fc155745d28fba018887c90e5c3817ceff9b8fa382eaa",
        },
        "fixture": fixture,
        "commit": git_commit(),
        "python": sys.version.split()[0],
        "sqlite": sqlite3.sqlite_version,
        "positive_scenarios": [ck.as_dict() for ck, _ in scenarios],
        "negative_cases": [ck.as_dict() for ck in negatives],
        "totals": {"checks": total_checks, "failed": total_failed,
                   "positive_passed": pos_ok, "negatives_detected": neg_ok},
        "all_passed": all_ok,
    }
    (RESULTS / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True))
    print(f" report -> {RESULTS/'report.json'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())

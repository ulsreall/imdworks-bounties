"""Deliberately-broken indexer variants -- executable negative cases (bounty #07).

Both classes share the correct Indexer code path and change exactly one thing,
so a judge can see *which* design decision matters:

``HeightOnlyIndexer``  -- keeps a checkpoint that stores only a *height* (no
    block hash).  On a reorg the height is unchanged, so the indexer believes it
    is current, never rewinds, and silently keeps the orphaned branch-A logs and
    the wrong payout.  Its DB then FAILS the equality assertion against the
    canonical replay.

``NonAtomicIndexer`` -- commits the log write and the checkpoint write in TWO
    separate transactions and inserts logs non-idempotently (no UNIQUE on
    tx_hash/log_index).  A crash between the two commits leaves logs durably
    written while the checkpoint is stale; the restart re-writes the same logs
    and double-counts them.  Its DB also FAILS the equality assertion.

The suite (scripts/run.py) runs both and PASSES only if both are *detected* as
wrong -- i.e. they are the concrete proof that a height-only checkpoint and a
split-commit boundary are insufficient.
"""

from __future__ import annotations

import argparse
import json

from .chainfixture import ChainFixture
from .indexer import Indexer, SimulatedCrash


class HeightOnlyIndexer(Indexer):
    """Checkpoint = height only.  No block hashes -> blind to reorgs."""

    def _reorg_check(self):
        # "If we have reached the head height, we must be current."
        return False

    def _check_batch_reorg(self, batch):
        return False

    def ingest(self, batch):
        ckpt = self.checkpoint()
        batch = [b for b in sorted(batch, key=lambda x: x["number"])
                 if b["number"] > ckpt["last_block_number"]]
        if not batch:
            return 0
        self._stage(batch)
        return self._drain()


class NonAtomicIndexer(Indexer):
    """Log write and checkpoint write in separate transactions; non-idempotent."""

    def __init__(self, *a, **k):
        k["idempotent"] = False
        k["unique_events"] = False
        super().__init__(*a, **k)

    def _commit(self, run):  # noqa: D401 - deliberately not atomic
        c = self.conn
        # ---- transaction 1: the log write (durable on its own) -------------
        c.execute("BEGIN IMMEDIATE")
        try:
            for blk in run:
                c.execute("INSERT OR REPLACE INTO blocks(block_number, block_hash, parent_hash)"
                          " VALUES (?,?,?)", (blk["number"], blk["hash"], blk["parent_hash"]))
                for tx in blk["txs"]:
                    for log in tx["logs"]:
                        c.execute(
                            "INSERT INTO events(block_number, block_hash, parent_hash, tx_hash,"
                            " tx_index, log_index, address, name, topics, data)"
                            " VALUES (?,?,?,?,?,?,?,?,?,?)",
                            (log["block_number"], log["block_hash"], log["parent_hash"],
                             log["tx_hash"], log["tx_index"], log["log_index"],
                             log["address"], log["name"], json.dumps(log["topics"]), log["data"]),
                        )
            c.execute("COMMIT")
        except BaseException:
            c.execute("ROLLBACK")
            raise
        # ---- CRASH POINT: logs are durable, checkpoint is NOT --------------
        self._maybe_crash("after_events_before_checkpoint")
        # ---- transaction 2: the checkpoint write ---------------------------
        c.execute("BEGIN IMMEDIATE")
        try:
            last = run[-1]
            c.execute("UPDATE checkpoint SET last_block_number=?, last_block_hash=?,"
                      " last_block_parent_hash=? WHERE id=1",
                      (last["number"], last["hash"], last["parent_hash"]))
            c.execute("DELETE FROM staged_blocks WHERE block_number<=?", (last["number"],))
            self._materialize(c)
            c.execute("COMMIT")
        except BaseException:
            c.execute("ROLLBACK")
            raise


_IMPLS = {"height-only": HeightOnlyIndexer, "nonatomic": NonAtomicIndexer}


def main(argv=None):
    p = argparse.ArgumentParser(description="naive indexer variants (negative cases)")
    p.add_argument("--impl", required=True, choices=sorted(_IMPLS))
    p.add_argument("--db", required=True)
    p.add_argument("--canonical-branch", default="A", choices=["A", "B"])
    p.add_argument("--action", required=True, choices=["reconcile", "ingest", "stats"])
    p.add_argument("--batch-range", nargs=2, type=int, metavar=("START", "END"))
    p.add_argument("--batch-branch", default=None, choices=["A", "B"])
    p.add_argument("--fault-crash-at", default=None)
    args = p.parse_args(argv)

    chain = ChainFixture(canonical=args.canonical_branch)
    crash_mode = "exit" if args.fault_crash_at else "raise"
    idx = _IMPLS[args.impl](args.db, chain, fault=args.fault_crash_at,
                            crash_mode=crash_mode).connect()
    try:
        if args.action == "reconcile":
            idx.index_to_head()
        elif args.action == "ingest":
            s, e = args.batch_range
            idx.ingest(chain.get_batch(s, e, args.batch_branch))
        print(json.dumps(idx.stats(), sort_keys=True))
    except SimulatedCrash as exc:
        print(json.dumps({"simulated_crash": str(exc)}))
    finally:
        idx.close()


if __name__ == "__main__":
    main()

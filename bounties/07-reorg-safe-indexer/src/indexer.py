"""Reorg-safe bounty event indexer for imdworks.fun bounty #07.

Consumes canonical logs into SQLite with four load-bearing guarantees:

1. **Idempotent log ingestion.**  ``events`` carries
   ``UNIQUE (tx_hash, log_index)``.  A duplicate delivery of the same batch is
   absorbed (``INSERT OR IGNORE``) and derived state is unchanged.

2. **Block-hash checkpoints.**  ``checkpoint`` stores
   ``(last_block_number, last_block_hash, last_block_parent_hash)`` and
   ``blocks`` stores the hash/parent of every committed height, so the indexer
   can *prove* the chain it indexed is still the chain the node serves.

3. **Rewind-to-ancestor on reorg.**  On start (``index_to_head``) and whenever
   a batch overlaps an already-indexed height with a different hash, the
   indexer walks back through its stored block hashes to the last height whose
   hash still equals the node's hash for that height (the last common
   ancestor), deletes every event/block/staged row at or above ``ancestor + 1``,
   resets the checkpoint to the ancestor and re-indexes the new branch.

4. **One transaction per batch.**  Events, block hashes, the checkpoint and the
   recomputed derived tables are written in a *single* ``BEGIN IMMEDIATE``
   transaction.  A crash between the log write and the checkpoint write can
   therefore never leave a half-applied batch (see README / scenario S4).

Derived state (``bounties``, ``submissions``, ``credits``, ``liabilities``) is
a *pure, deterministic function* of the canonical event set and is recomputed
inside every committing transaction, so a rewind can never leave an orphaned
submission on disk and a payout can never be counted twice.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from contextlib import contextmanager

from .chainfixture import ChainFixture, ZERO32, decode_event

SCHEMA = """
CREATE TABLE IF NOT EXISTS blocks (
    block_number INTEGER PRIMARY KEY,
    block_hash   TEXT NOT NULL,
    parent_hash  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    block_number INTEGER NOT NULL,
    block_hash   TEXT NOT NULL,
    parent_hash  TEXT NOT NULL,
    tx_hash      TEXT NOT NULL,
    tx_index     INTEGER NOT NULL,
    log_index    INTEGER NOT NULL,
    address      TEXT NOT NULL,
    name         TEXT NOT NULL,
    topics       TEXT NOT NULL,
    data         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_events_block ON events(block_number);

CREATE TABLE IF NOT EXISTS checkpoint (
    id                     INTEGER PRIMARY KEY CHECK (id = 1),
    last_block_number      INTEGER NOT NULL,
    last_block_hash        TEXT NOT NULL,
    last_block_parent_hash TEXT NOT NULL
);

-- Durable receive buffer for batches that are ahead of the checkpoint
-- (out-of-order delivery).  Drained contiguously; empty in steady state.
CREATE TABLE IF NOT EXISTS staged_blocks (
    block_number INTEGER PRIMARY KEY,
    block_hash   TEXT NOT NULL,
    parent_hash  TEXT NOT NULL,
    payload      TEXT NOT NULL
);

-- ---- derived state (pure function of the canonical event set) --------------

CREATE TABLE IF NOT EXISTS bounties (
    bounty_id      INTEGER PRIMARY KEY,
    creator        TEXT NOT NULL,
    reward         INTEGER NOT NULL,
    deadline       INTEGER NOT NULL,
    brief_hash     TEXT NOT NULL,
    uri            TEXT NOT NULL,
    added          INTEGER NOT NULL DEFAULT 0,
    awarded        INTEGER NOT NULL DEFAULT 0,
    refunded       INTEGER NOT NULL DEFAULT 0,
    winner         TEXT,
    state          TEXT NOT NULL,
    created_block  INTEGER NOT NULL,
    last_block     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS submissions (
    tx_hash      TEXT NOT NULL,
    log_index    INTEGER NOT NULL,
    bounty_id    INTEGER NOT NULL,
    submitter    TEXT NOT NULL,
    worker       TEXT NOT NULL,
    proof_hash   TEXT NOT NULL,
    uri          TEXT NOT NULL,
    block_number INTEGER NOT NULL,
    PRIMARY KEY (tx_hash, log_index),
    UNIQUE (bounty_id, submitter, proof_hash)
);

CREATE TABLE IF NOT EXISTS credits (
    wallet       TEXT PRIMARY KEY,
    awarded      INTEGER NOT NULL DEFAULT 0,
    refunded     INTEGER NOT NULL DEFAULT 0,
    withdrawn    INTEGER NOT NULL DEFAULT 0,
    withdrawable INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS liabilities (
    bounty_id   INTEGER PRIMARY KEY,
    funded      INTEGER NOT NULL DEFAULT 0,
    paid_out    INTEGER NOT NULL DEFAULT 0,
    outstanding INTEGER NOT NULL DEFAULT 0
);
"""

UNIQUE_EVENTS_INDEX = (
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_events_txlog ON events(tx_hash, log_index)"
)

DERIVED_TABLES = ("bounties", "submissions", "credits", "liabilities")


class SimulatedCrash(Exception):
    """Raised by the in-process fault hook (the CLI uses os._exit instead)."""


class Indexer:
    def __init__(self, db_path, chain: ChainFixture, fault=None, crash_mode="raise",
                 idempotent=True, unique_events=True):
        self.db_path = db_path
        self.chain = chain
        self.fault = fault
        self.crash_mode = crash_mode
        self.idempotent = idempotent
        self.unique_events = unique_events
        self._fired = False
        self.conn: sqlite3.Connection | None = None

    # -- lifecycle -----------------------------------------------------------

    def connect(self):
        self.conn = sqlite3.connect(self.db_path, isolation_level=None)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        if self.unique_events:
            self.conn.execute(UNIQUE_EVENTS_INDEX)
        self._init_checkpoint()
        return self

    def close(self):
        if self.conn is not None:
            self.conn.close()
            self.conn = None

    def _init_checkpoint(self):
        genesis = self.chain.block(0)
        self.conn.execute(
            "INSERT OR IGNORE INTO blocks(block_number, block_hash, parent_hash) VALUES (0,?,?)",
            (genesis["hash"], genesis["parent_hash"]),
        )
        self.conn.execute(
            "INSERT OR IGNORE INTO checkpoint(id, last_block_number, last_block_hash, last_block_parent_hash)"
            " VALUES (1, 0, ?, ?)",
            (genesis["hash"], genesis["parent_hash"]),
        )

    @contextmanager
    def _tx(self):
        """One durable unit: BEGIN IMMEDIATE ... COMMIT (ROLLBACK on any error)."""
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self.conn
            self.conn.execute("COMMIT")
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise

    def _maybe_crash(self, stage: str):
        if self.fault == stage and not self._fired:
            self._fired = True
            if self.crash_mode == "exit":
                sys.stdout.flush()
                sys.stderr.flush()
                os._exit(137)
            raise SimulatedCrash(stage)

    # -- reads ---------------------------------------------------------------

    def _stored_hash(self, height):
        row = self.conn.execute(
            "SELECT block_hash FROM blocks WHERE block_number=?", (height,)
        ).fetchone()
        return row[0] if row else None

    def checkpoint(self):
        row = self.conn.execute(
            "SELECT last_block_number, last_block_hash, last_block_parent_hash"
            " FROM checkpoint WHERE id=1"
        ).fetchone()
        return {"last_block_number": row[0], "last_block_hash": row[1],
                "last_block_parent_hash": row[2]}

    def _count(self, table):
        return self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

    def stats(self):
        return {
            "db": os.path.basename(self.db_path),
            "checkpoint": self.checkpoint(),
            "counts": {t: self._count(t) for t in
                       ("blocks", "events", "staged_blocks", *DERIVED_TABLES)},
            "events_max_block": (self.conn.execute(
                "SELECT COALESCE(MAX(block_number), -1) FROM events").fetchone()[0]),
        }

    # -- core write path -----------------------------------------------------

    def _commit(self, run):
        """Write a contiguous run of blocks: events + hashes + checkpoint + derived, one tx."""
        op = "INSERT OR IGNORE" if self.idempotent else "INSERT"
        with self._tx() as c:
            for blk in run:
                c.execute("INSERT OR REPLACE INTO blocks(block_number, block_hash, parent_hash)"
                          " VALUES (?,?,?)", (blk["number"], blk["hash"], blk["parent_hash"]))
                for tx in blk["txs"]:
                    for log in tx["logs"]:
                        c.execute(
                            f"{op} INTO events(block_number, block_hash, parent_hash, tx_hash,"
                            " tx_index, log_index, address, name, topics, data)"
                            " VALUES (?,?,?,?,?,?,?,?,?,?)",
                            (log["block_number"], log["block_hash"], log["parent_hash"],
                             log["tx_hash"], log["tx_index"], log["log_index"],
                             log["address"], log["name"], json.dumps(log["topics"]), log["data"]),
                        )
            # FAULT INJECTION POINT: logs written, checkpoint NOT yet advanced.
            self._maybe_crash("after_events_before_checkpoint")
            last = run[-1]
            c.execute("UPDATE checkpoint SET last_block_number=?, last_block_hash=?,"
                      " last_block_parent_hash=? WHERE id=1",
                      (last["number"], last["hash"], last["parent_hash"]))
            c.execute("DELETE FROM staged_blocks WHERE block_number<=?", (last["number"],))
            self._materialize(c)

    def _stage(self, batch):
        ckpt = self.checkpoint()
        with self._tx() as c:
            for blk in batch:
                if blk["number"] <= ckpt["last_block_number"]:
                    continue
                c.execute("INSERT OR REPLACE INTO staged_blocks(block_number, block_hash,"
                          " parent_hash, payload) VALUES (?,?,?,?)",
                          (blk["number"], blk["hash"], blk["parent_hash"], json.dumps(blk)))

    def _drain(self):
        """Commit the maximal contiguous staged run that links onto the checkpoint."""
        ckpt = self.checkpoint()
        n = ckpt["last_block_number"] + 1
        prev = ckpt["last_block_hash"]
        run = []
        while True:
            row = self.conn.execute(
                "SELECT payload FROM staged_blocks WHERE block_number=?", (n,)).fetchone()
            if not row:
                break
            blk = json.loads(row[0])
            if blk["parent_hash"] != prev:
                break
            run.append(blk)
            prev = blk["hash"]
            n += 1
        if run:
            self._commit(run)
        return len(run)

    def _rewind_to(self, height):
        """Delete canonical rows above `height` (including derived state) and reset the tip."""
        with self._tx() as c:
            c.execute("DELETE FROM events WHERE block_number>?", (height,))
            c.execute("DELETE FROM blocks WHERE block_number>?", (height,))
            c.execute("DELETE FROM staged_blocks WHERE block_number>?", (height,))
            row = c.execute("SELECT block_hash, parent_hash FROM blocks WHERE block_number=?",
                            (height,)).fetchone()
            if row is None:
                raise RuntimeError(f"cannot rewind: no stored block at height {height}")
            c.execute("UPDATE checkpoint SET last_block_number=?, last_block_hash=?,"
                      " last_block_parent_hash=? WHERE id=1", (height, row[0], row[1]))
            self._materialize(c)

    def _check_batch_reorg(self, batch):
        """If the batch rewrites an already-indexed height, rewind to just below it."""
        ckpt = self.checkpoint()
        for blk in sorted(batch, key=lambda b: b["number"]):
            if blk["number"] <= ckpt["last_block_number"]:
                if self._stored_hash(blk["number"]) != blk["hash"]:
                    self._rewind_to(blk["number"] - 1)
                    return True
        return False

    # -- public API ----------------------------------------------------------

    def ingest(self, batch):
        batch = sorted(batch, key=lambda b: b["number"])
        self._check_batch_reorg(batch)
        self._stage(batch)
        return self._drain()

    def _reorg_check(self):
        """Compare the checkpoint tip (and walk back) against the node's hashes."""
        ckpt = self.checkpoint()
        h = ckpt["last_block_number"]
        tip_ok = (h <= self.chain.head
                  and self._stored_hash(h) == self.chain.block_hash(h))
        if tip_ok:
            return False
        anc = h
        while anc > 0 and (anc > self.chain.head
                           or self._stored_hash(anc) != self.chain.block_hash(anc)):
            anc -= 1
        self._rewind_to(anc)
        return True

    def index_to_head(self):
        """Resume staged work, reorg-check, then catch up to the node's head."""
        self._drain()
        self._reorg_check()
        ckpt = self.checkpoint()
        start = ckpt["last_block_number"] + 1
        if start <= self.chain.head:
            self.ingest(self.chain.get_batch(start, self.chain.head))
        return self.checkpoint()

    # -- derived state (pure function of the canonical events) ---------------

    def _materialize(self, c):
        for t in DERIVED_TABLES:
            c.execute(f"DELETE FROM {t}")
        rows = c.execute(
            "SELECT tx_hash, log_index, block_number, tx_index, name, topics, data"
            " FROM events ORDER BY block_number, tx_index, log_index, id"
        ).fetchall()

        bounties = {}
        submissions = {}
        credits = {}

        def bump(wallet, field, amount):
            c0 = credits.setdefault(wallet, {"awarded": 0, "refunded": 0, "withdrawn": 0})
            c0[field] += amount

        def blank_bounty(bid):
            return {"bounty_id": bid, "creator": "", "reward": 0, "deadline": 0,
                    "brief_hash": ZERO32, "uri": "", "added": 0, "awarded": 0,
                    "refunded": 0, "winner": None, "state": "open",
                    "created_block": 0, "last_block": 0}

        for tx_hash, log_index, block_number, tx_index, name, topics_json, data in rows:
            dec_name, f = decode_event(json.loads(topics_json), data)
            if dec_name != name:
                raise RuntimeError(f"log {tx_hash}:{log_index} name/topic mismatch")
            bid = f.get("bountyId")
            if name == "BountyCreated":
                b = bounties.setdefault(bid, blank_bounty(bid))
                b.update(creator=f["creator"], reward=f["reward"], deadline=f["deadline"],
                         brief_hash=f["briefHash"], uri=f["uri"],
                         created_block=block_number, last_block=block_number)
            elif name == "RewardAdded":
                b = bounties.setdefault(bid, blank_bounty(bid))
                b["added"] += f["amount"]
                b["last_block"] = block_number
            elif name == "WorkSubmitted":
                key = (bid, f["submitter"], f["proofHash"])
                if key not in submissions:
                    submissions[key] = {
                        "tx_hash": tx_hash, "log_index": log_index, "bounty_id": bid,
                        "submitter": f["submitter"], "worker": f["worker"],
                        "proof_hash": f["proofHash"], "uri": f["uri"],
                        "block_number": block_number,
                    }
            elif name == "BountyAwarded":
                b = bounties.setdefault(bid, blank_bounty(bid))
                b["awarded"] += f["amount"]
                b["winner"] = f["winner"]
                b["state"] = "awarded"
                b["last_block"] = block_number
                bump(f["winner"], "awarded", f["amount"])
            elif name == "BountyRefunded":
                b = bounties.setdefault(bid, blank_bounty(bid))
                b["refunded"] += f["amount"]
                b["state"] = "refunded"
                b["last_block"] = block_number
                bump(f["creator"], "refunded", f["amount"])
            elif name == "Withdrawn":
                bump(f["account"], "withdrawn", f["amount"])
                credits[f["account"]]  # ensure row exists
            else:
                raise RuntimeError(f"unhandled event {name}")

        for bid in sorted(bounties):
            b = bounties[bid]
            c.execute(
                "INSERT INTO bounties(bounty_id, creator, reward, deadline, brief_hash, uri,"
                " added, awarded, refunded, winner, state, created_block, last_block)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (bid, b["creator"], b["reward"], b["deadline"], b["brief_hash"], b["uri"],
                 b["added"], b["awarded"], b["refunded"], b["winner"], b["state"],
                 b["created_block"], b["last_block"]),
            )
            funded = b["reward"] + b["added"]
            paid = b["awarded"] + b["refunded"]
            c.execute("INSERT INTO liabilities(bounty_id, funded, paid_out, outstanding)"
                      " VALUES (?,?,?,?)", (bid, funded, paid, funded - paid))

        for key in sorted(submissions):
            s = submissions[key]
            c.execute("INSERT INTO submissions(tx_hash, log_index, bounty_id, submitter, worker,"
                      " proof_hash, uri, block_number) VALUES (?,?,?,?,?,?,?,?)",
                      (s["tx_hash"], s["log_index"], s["bounty_id"], s["submitter"],
                       s["worker"], s["proof_hash"], s["uri"], s["block_number"]))

        for w in sorted(credits):
            cr = credits[w]
            withdrawable = cr["awarded"] + cr["refunded"] - cr["withdrawn"]
            c.execute("INSERT INTO credits(wallet, awarded, refunded, withdrawn, withdrawable)"
                      " VALUES (?,?,?,?,?)",
                      (w, cr["awarded"], cr["refunded"], cr["withdrawn"], withdrawable))


# --- CLI (used by the harness to model separate processes) -------------------

def main(argv=None):
    p = argparse.ArgumentParser(description="reorg-safe bounty indexer (bounty #07)")
    p.add_argument("--db", required=True)
    p.add_argument("--canonical-branch", default="A", choices=["A", "B"])
    p.add_argument("--action", required=True, choices=["reconcile", "ingest", "stats"])
    p.add_argument("--batch-range", nargs=2, type=int, metavar=("START", "END"))
    p.add_argument("--batch-branch", default=None, choices=["A", "B"])
    p.add_argument("--fault-crash-at", default=None)
    args = p.parse_args(argv)

    chain = ChainFixture(canonical=args.canonical_branch)
    crash_mode = "exit" if args.fault_crash_at else "raise"
    idx = Indexer(args.db, chain, fault=args.fault_crash_at, crash_mode=crash_mode).connect()
    try:
        if args.action == "reconcile":
            idx.index_to_head()
        elif args.action == "ingest":
            if not args.batch_range:
                raise SystemExit("--action ingest requires --batch-range START END")
            s, e = args.batch_range
            idx.ingest(chain.get_batch(s, e, args.batch_branch))
        print(json.dumps(idx.stats(), sort_keys=True))
    except SimulatedCrash as exc:  # only reachable in-process
        print(json.dumps({"simulated_crash": str(exc)}))
    finally:
        idx.close()


if __name__ == "__main__":
    main()

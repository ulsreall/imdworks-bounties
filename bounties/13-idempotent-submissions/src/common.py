"""Shared helpers for the idempotent-submission harness (stdlib only).

Nothing here talks HTTP or SQLite other than the schema text; it keeps the
constants, response envelope, canonical request hashing and the submission
fingerprint used to *prove* row immutability in one place.
"""

import hashlib
import json
import time

# --- domain constants -------------------------------------------------------

STATE_ACTIVE = "active"
STATE_REVIEWED = "reviewed"
DECISIONS = ("accepted", "rejected")

# --- SQLite schema: the CORRECT service -------------------------------------
#
# The three guarantees the harness relies on are encoded *in the schema*, not
# only in application code:
#
#   * ux_one_active_submission  -- a PARTIAL unique index over (bounty_id,
#     wallet) restricted to state='active'.  It makes "at most one active
#     submission per wallet per bounty" a database fact, so even if two
#     requests slip past an application check the second INSERT fails closed.
#
#   * ux_submission_idem        -- a submission row remembers the create-key
#     that produced it (audit trail + defence in depth for the create path).
#
#   * idempotency               -- a keyed ledger of *applied* operations.  A
#     retry (after a lost response) with the same key replays the recorded
#     response instead of mutating again.  A key reused with a different body
#     is rejected deterministically.
SCHEMA_MOCK = """
CREATE TABLE IF NOT EXISTS submissions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    bounty_id        TEXT    NOT NULL,
    wallet           TEXT    NOT NULL,
    version          INTEGER NOT NULL CHECK (version >= 1),
    payload          TEXT    NOT NULL,
    state            TEXT    NOT NULL CHECK (state IN ('active','reviewed')),
    decision         TEXT    CHECK (decision IS NULL OR decision IN ('accepted','rejected')),
    idempotency_key  TEXT    NOT NULL,
    created_at       TEXT    NOT NULL,
    updated_at       TEXT    NOT NULL,
    -- a reviewed row MUST carry a decision, an active row MUST NOT
    CHECK ((state = 'reviewed') = (decision IS NOT NULL))
);

-- INVARIANT: at most ONE active submission per (bounty_id, wallet).
CREATE UNIQUE INDEX IF NOT EXISTS ux_one_active_submission
    ON submissions (bounty_id, wallet)
    WHERE state = 'active';

-- A submission row keeps the create-key that produced it.
CREATE UNIQUE INDEX IF NOT EXISTS ux_submission_idem
    ON submissions (idempotency_key);

-- Applied-operations ledger powering idempotent retries.
CREATE TABLE IF NOT EXISTS idempotency (
    key           TEXT PRIMARY KEY,
    op            TEXT NOT NULL,
    request_hash  TEXT NOT NULL,
    status        INTEGER NOT NULL,
    response      TEXT NOT NULL,
    submission_id INTEGER,
    created_at    TEXT NOT NULL
);
"""

# --- SQLite schema: the NAIVE service (deliberately broken) -----------------
#
# No UNIQUE constraints, no partial index, no idempotency ledger.  This is the
# "obvious" implementation that looks fine in a single-threaded demo and falls
# apart the moment requests overlap.
SCHEMA_NAIVE = """
CREATE TABLE IF NOT EXISTS submissions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    bounty_id        TEXT,
    wallet           TEXT,
    version          INTEGER,
    payload          TEXT,
    state            TEXT,
    decision         TEXT,
    idempotency_key  TEXT,
    created_at       TEXT,
    updated_at       TEXT
);
"""


def now_iso():
    """UTC timestamp with millisecond precision, e.g. 2025-01-01T00:00:00.123Z."""
    t = time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + ".%03dZ" % int((t % 1) * 1000)


def req_hash(op, canon):
    """Canonical hash of a request, used to detect idempotency-key reuse."""
    blob = json.dumps({"op": op, **canon}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def envelope(status, reason, submission=None, **extra):
    """Uniform JSON response body."""
    body = {
        "status": status,
        "ok": status < 400,
        "reason": reason,
        "submission": submission,
    }
    body.update(extra)
    return body


def row_to_dict(row):
    if row is None:
        return None
    return dict(row)


def submission_fingerprint(row):
    """Stable content hash of a submission row.

    Used by the workload/report to prove a reviewed submission did not change
    (byte-for-byte on the fields that matter) after a rejected update.
    """
    if row is None:
        return None
    d = dict(row)
    keep = ["id", "bounty_id", "wallet", "version", "payload", "state", "decision"]
    canon = json.dumps({k: d.get(k) for k in keep}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()

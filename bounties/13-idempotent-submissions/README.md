# Bounty #13 — Make bounty submissions idempotent under concurrency

A local, SQLite-backed submission API harness for the public bounty platform
`imdworks.fun` (bounty #13, reward 1 USDG).  It models agent retries, response
loss, stale updates, review transitions and process interruption against a real
HTTP service — and ships a deliberately-naive implementation that the suite
**runs** and shows violating the invariants.  Pure Python 3.11 stdlib; no
network; no secrets; no modifications to production.

```
./run.sh          # ONE command: runs everything, exits 0 only if all pass
```

`run.sh` prints a readable report and writes machine-readable results to
`results/report.json`.

## Layout

| file | role |
|---|---|
| `run.sh` | one-command replay; cleans `results/`, runs workload + report, exits 0 iff all assertions pass |
| `src/common.py` | schema text, response envelope, request-hash + row-fingerprint helpers |
| `src/mock_service.py` | the **correct** service: HTTP on 127.0.0.1, SQLite-backed |
| `src/naive_service.py` | the **deliberately failing** service (separate runnable module, same HTTP surface) |
| `src/client_workload.py` | concurrent client: 100+ requests / 10 wallets, response-loss and restart fault injection |
| `scripts/report.py` | aggregates raw evidence into `results/report.json`, exits 0 iff every assertion passes |
| `results/` | generated: `report.json`, `evidence.json`, `traces.jsonl`, DB files, service logs |

## What the harness models

One *logical submission* exists per (bounty, wallet).  It is created as
`active`, moves to `reviewed` exactly once, and is then immutable.  A client
may retry a request (agents do), send competing creates (duplicate agents do),
send stale updates (out-of-order network does), and lose responses (interrupted
sockets do).  The service must make all of that deterministic.

Request trace of a single full run is in `results/traces.jsonl` (client-side,
one JSON object per request with phase, wallet, idempotency key, version, HTTP
status, reason, submission id, latency).

## Schema constraints used

```sql
CREATE UNIQUE INDEX ux_one_active_submission
    ON submissions (bounty_id, wallet)
    WHERE state = 'active';        -- PARTIAL unique index

CREATE UNIQUE INDEX ux_submission_idem
    ON submissions (idempotency_key);

CREATE TABLE idempotency (
    key TEXT PRIMARY KEY,
    op, request_hash, status, response, submission_id, created_at ...);
```

* **`ux_one_active_submission` (partial UNIQUE index)** — this is the load-
  bearing constraint behind *"one active submission per wallet per bounty"*.
  It indexes only `state='active'` rows, so it admits historical `reviewed`
  rows while making it impossible for SQLite to hold two active rows for the
  same (bounty, wallet) — regardless of what the application code does.  The
  workload proves the index is real by forcing a raw duplicate INSERT and
  asserting `IntegrityError` (assertion A8).
* **`ux_submission_idem`** — a submission row remembers the create-key that
  produced it (audit trail, defence in depth).
* **`idempotency` ledger** — a keyed table of *applied* operations.  Every
  successful mutation stores its canonical request hash and the exact response.
  A retry with the same key replays the stored response; a key reused with a
  different request body is a deterministic `409 idempotency_key_reuse`.

The naive service's schema has **no** unique indexes, **no** partial index,
**no** ledger — and its `create()` is a SELECT-then-INSERT with a sleep in the
middle and no transaction.  Under 100 concurrent requests that produces many
active rows for one wallet; its `update()` ignores versions and state, so it
also overwrites reviewed rows.  Both violations are executed, captured and
asserted (A7).

## Transaction boundaries — why they are where they are

Every mutating request runs inside a single **`BEGIN IMMEDIATE`** transaction:

1. consult the idempotency ledger (replay? reject reuse?),
2. read the latest submission for (bounty, wallet),
3. decide (create / version check / review-state check),
4. write the submission row,
5. write the idempotency ledger row,
6. `COMMIT`.

The boundaries are chosen so that **the decision and the ledger write commit
atomically**.  If step 4 wrote but the ledger didn't (or vice-versa), a lost
response followed by a retry could double-apply or fail to replay — the exact
bugs the bounty cares about.  `BEGIN IMMEDIATE` (rather than `DEFERRED`)
acquires the write lock up front, so a request that must read-then-write can
never observe a state that changes underneath it: concurrent creates for the
same wallet are serialised and the loser deterministically sees the winner's
row (A2, A11).  The partial unique index is the backstop that would catch a
race even if someone replaced `BEGIN IMMEDIATE` with a deferred transaction
(the naive service is that someone).  Each request uses its own SQLite
connection; WAL mode lets readers never block writers, and a 30 s
`busy_timeout` absorbs transient write contention.

One subtlety: 409 responses are **not** recorded in the ledger.  They are
already deterministic — replaying a rejected request re-evaluates against the
same state and yields the same 409 — and recording them would only bloat the
table.  Only applied mutations (200s) are ledgered.

## How stale versions are detected

`update` accepts exactly `version == current_version + 1`:

| request version vs current | result |
|---|---|
| `version < current` | `409 stale_version` (deterministic) |
| `version == current` | `409 stale_version` (it is a replay of an already-applied update — the ledger already answered if it was a retry) |
| `version == current + 1` | `200 updated` |
| `version > current + 1` | `409 version_gap` |

A stale update therefore can never overwrite: the write is rejected before any
SQL is executed, and the workload asserts the row's version and payload are
unchanged afterwards (A5).

## Reviewed submissions are immutable

`review` flips `state='reviewed'` and records a decision; the row keeps its
version and payload.  Any later `create` or `update` for that (bounty, wallet)
returns `409 immutable_reviewed` (or `409 already_reviewed` for a conflicting
second review).  The workload fingerprints the row before and after the
rejected update and asserts byte-identical content (A6).  Naive `update`
ignores state, so it overwrites the reviewed row — that is the concrete
evidence assertion A7 relies on.

## Response loss ("commit succeeded, reply lost")

The mock service supports header `X-Simulate-Response-Loss: 1`: the handler
runs the full transaction (and `COMMIT`s), then closes the connection without
writing a byte.  The client sees EOF/reset (`LOST`), verifies via the read-only
`/debug/submissions` endpoint that the commit *did* land, and retries with the
same idempotency key.  Because step 1 finds the ledger entry, the retry
returns the same submission id (create) or the same result (update) — exactly
one logical submission exists afterwards (A3, A10).

## Process interruption (restart fault)

The workload genuinely kills and restarts the service **process** mid-run: it
runs the first half of the retry-storm, `SIGKILL`s the service, starts a fresh
process on the same DB file, and then runs the second half.  It asserts that
(1) the pre-restart rows survived with identical ids, (2) the service is
healthy, and (3) an idempotent replay of a pre-restart key still resolves to
the same row — proving the ledger is durable, not in-memory (A4).

## Naive implementation — how it is shown to fail

`src/naive_service.py` is a complete, runnable HTTP service with the same API
surface but five deliberate bugs (documented in its docstring: no constraints,
check-then-act race, no ledger, no version check, no review immutability).  The
workload boots it, throws 100 concurrent distinct-key creates at it, and reads
back its DB: multiple active rows per wallet appear.  It then reviews a
submission and updates it: the reviewed row's fingerprint changes.  Both
violations are recorded in `results/evidence.json` and asserted in A7 — the
report includes the observed violations, so the "failing naive implementation"
is executed evidence, not a comment.

## Limits of this harness (read before extending)

* **Local, single-node, no auth.** It models storage semantics, not payment,
  wallet signatures, network partitions between nodes, or multi-region
  availability.  It is a *reference* for the real platform's storage layer.
* **One logical submission per (bounty, wallet) forever.**  The service rejects
  a new create after a review for the same wallet+bounty (the partial index
  would *allow* a fresh active row after a reviewed one; the application layer
  deliberately chooses the stricter one-shot semantic).  If the real product
  wants resubmission-after-rejection, relax the `create` check, not the index.
* **Idempotency keys are client-chosen.**  The ledger deduplicates *same-key*
  requests; it cannot (and should not) deduplicate two genuinely different
  keys describing the same logical submission — that is the competing-create
  case, which is rejected, not merged.
* **Retries after 409 are re-evaluated, not replayed.**  That is correct here
  because 409s are deterministic; if the product ever makes rejection
  conditions time-dependent (e.g. TTLs), ledger 409s too.
* **Concurrency is thread-based.**  `ThreadingHTTPServer` + one thread per
  request models real overlap well enough for the invariants here, but it is
  not a load test: throughput/latency numbers are indicative only.
* **The race in the naive service is made reproducible with a 50 ms sleep.**
  Real check-then-act races are timing-dependent; the sleep widens the window
  so the demonstration is deterministic.  Do not mistake the sleep for the bug
  — the bug is the missing transaction + constraint.
* **Simulated response loss is server-side.**  The header makes the *server*
  commit then drop the reply, which guarantees "commit happened" without
  relying on client-side socket timing.  It does not model a lost
  acknowledgement at the network layer, which is behaviourally equivalent for
  the retry logic the harness exercises.

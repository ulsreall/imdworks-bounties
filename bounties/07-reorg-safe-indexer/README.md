# Bounty #07 — Reorg-safe bounty event indexer

A local, SQLite-backed event indexer for the escrow events `BountyCreated`,
`RewardAdded`, `WorkSubmitted`, `BountyAwarded`, `BountyRefunded` and
`Withdrawn`, driven against a **deterministic chain fixture with two competing
branches**.  It demonstrates and *proves* recovery under duplicate log
delivery, out-of-order batches, a process restart between the log write and the
checkpoint write, and a five-block reorg — then asserts the recovered database
is byte-for-byte equal to an independent fresh canonical replay.

```bash
./run.sh          # ONE command: runs everything, exits 0 only if all pass
```

`run.sh` prints a readable table and writes machine-readable results to
`results/report.json`.  Pure Python 3.11 stdlib; **no network, no paid RPC, no
private keys**; every address is public/derived and every hash is sha256 over a
fixed string.

## Layout

| file | role |
|---|---|
| `run.sh` | one-command replay; prints the pinned commit, runs the suite, propagates its exit code |
| `src/chainfixture.py` | the deterministic chain: two branches + ABI log codec |
| `src/indexer.py` | the reorg-safe indexer (SQLite, checkpoints with block hashes) |
| `src/canonical_replay.py` | independent fresh from-genesis replay → the oracle DB |
| `src/naive_checkpoint.py` | the two **deliberately-broken** variants (executable negative cases) |
| `scripts/run.py` | drives the fault scenarios, diffs incremental vs oracle, writes `results/report.json` |
| `results/` | generated: `report.json` and the per-scenario SQLite databases |

## Event model (mirrors the escrow ABI)

Logs are `(block_number, block_hash, parent_hash, tx_hash, tx_index, log_index,
topics, data)`.  Cancelling a topic0 made from the canonical signature hash
identifies the event; indexed parameters are topics, the rest are ABI head/tail
encoded in `data`.  The indexer decodes `topics`+`data` alone and never trusts a
name field.

```
BountyCreated (uint256 indexed, address indexed, uint256, uint64, bytes32, string)
RewardAdded   (uint256 indexed, uint256, uint256)
WorkSubmitted (uint256 indexed, address indexed, address, bytes32, string)
BountyAwarded (uint256 indexed, address indexed, uint256)
BountyRefunded(uint256 indexed, address indexed, uint256, uint8)
Withdrawn     (address indexed, address, uint256)
```

## The fixture — two branches over a shared ancestor

```
height   0 ............... 9       10 .. 14 (branch A)   10 .. 14 (branch B)
         common ancestor          first-seen chain       reorging chain
         (identical hashes)       becomes orphaned       becomes canonical
```

Blocks `0..9` are the **same objects** on both branches (identical
`block_hash`/`parent_hash`).  Branch A and branch B both have five blocks at
heights `10..14` but with **different transactions and different hashes**;
block 10 of each branch links to the shared block-9 hash, so the last common
ancestor is height **9**.  A "five-block reorg" replaces A[10..14] with
B[10..14].

The branches change outcomes on purpose: on A, bounty 1 is awarded to
`ALICE` for 1000; on B it is awarded to `BOB` for 1500 and a second bounty is
refunded.  A height-only checkpoint that misses the reorg therefore *keeps the
wrong payout* — the concrete failure the negative case exposes.

All inputs are fixed: fixed timestamps (`1_600_000_000 + 12·height`), fixed
addresses, and `block_hash = sha256(scheme ‖ height ‖ parent ‖ time ‖ tx_hashes)`
-- no randomness and no wall clock anywhere in the fixtures, so runs are
byte-reproducible.

## Schema and the keys that carry the guarantees

```sql
-- raw canonical logs; the UNIQUE constraint makes re-delivery a no-op
CREATE UNIQUE INDEX ux_events_txlog ON events(tx_hash, log_index);

-- checkpoint carries BLOCK HASHES, not just a height
CREATE TABLE checkpoint (
    id, last_block_number, last_block_hash, last_block_parent_hash);

-- every committed height's hash, so we can find the last common ancestor
CREATE TABLE blocks (block_number PRIMARY KEY, block_hash, parent_hash);

-- durable receive buffer for batches that arrive ahead of the checkpoint
CREATE TABLE staged_blocks (block_number PRIMARY KEY, ... payload ...);
```

Derived state is a **pure function of the canonical event set**:

| table | key | meaning |
|---|---|---|
| `bounties` | `bounty_id` | creator, reward, deadline, `added/awarded/refunded`, winner, state |
| `submissions` | `(tx_hash,log_index)`, UNIQUE `(bounty_id,submitter,proof_hash)` | deduplicated work submissions |
| `credits` | `wallet` | `awarded/refunded/withdrawn/withdrawable` per wallet |
| `liabilities` | `bounty_id` | `funded = reward+added`, `paid_out = awarded+refunded`, `outstanding` |

`submissions` cannot hold a duplicate logical submission (the second UNIQUE
index), and `credits`/`liabilities` cannot double-count a payout because they
are recomputed from scratch, never incremented across a rewind.

## Transaction boundaries — why they are where they are

Every committing batch is **one** `BEGIN IMMEDIATE … COMMIT` transaction that
writes, in order: block hashes → event rows → the checkpoint → the recomputed
derived tables.  Nothing else touches the database mid-batch.

The boundary is placed around the *whole* canonical write so that the log write
and the checkpoint write are **atomic with respect to each other**.  This is the
entire point of scenario S4: the fault hook fires *after the events are INSERTed
and before the checkpoint is UPDATEd*, then the process is killed with
`os._exit(137)`.  Because both writes live in one transaction, SQLite rolls the
whole thing back (uncommitted WAL frames are discarded on reopen), so the DB
never holds logs for a height the checkpoint does not cover.  The restart simply
re-reads the durable checkpoint (height 9) and re-indexes the batch once.
The naive `NonAtomicIndexer` commits the two writes separately and, at exactly
that crash point, is left with logs at heights 10..14 while its checkpoint says
9 — and its restart double-writes them (negative case N2).

`staged_blocks` is written by its own small transaction *before* the canonical
commit: it is a durable **receive buffer**, not canonical state.  It survives a
crash only so the batch is not lost; the canonical write stays atomic.

## Reorg algorithm — rewind to the last common ancestor

On start (and on any batch that rewrites an already-indexed height with a
different hash) the indexer reconciles against the node's current hashes:

1. Read the checkpoint.  If `stored_hash(last_block_number) !=
   node.hash(last_block_number)`, the chain moved: walk `height` downwards over
   the `blocks` table and stop at the first height where the stored hash **still
   equals** the node's hash for that height.  That height is the **last common
   ancestor** (`ancestor`, here 9).
2. `DELETE FROM events/blocks/staged_blocks WHERE block_number > ancestor`
   — this removes every orphaned log *and* the staged copy of the dead branch.
3. Reset the checkpoint to `(ancestor, hash[ancestor], parent[ancestor])` and
   **recompute the derived tables** from the surviving (canonical) events.
4. Re-index `ancestor+1 .. head` from the node (now branch B), in one
   transaction per contiguous run.

Steps 2–3 are what guarantee "no orphaned submission and no double-counted
payout survives": the orphaned events are deleted and the derived tables are
rebuilt from what remains, so a stale `credits`/`bounties` row cannot linger.
Because `blocks` stores a hash per height (not only a tip), the walk in step 1
is a real ancestor search, not a guess.

### Out-of-order batches

Batches that arrive ahead of the checkpoint are parked in `staged_blocks` and
the checkpoint is **not** advanced past the gap.  Each `ingest` first tries to
drain the maximal contiguous run from `checkpoint+1` whose `parent_hash` chains
onto the current tip; when the earlier batch finally arrives it fills the gap
and the staged blocks are committed in the same transaction (S3).

## Acceptance results (observed)

`bash run.sh` → **exit 0**, 81/81 checks pass:

```
 POSITIVE SCENARIOS                                        checks  failed
 S1 normal indexing                                          12      0   PASS
 S2 duplicate log delivery                                   12      0   PASS
 S3 out-of-order batches                                     11      0   PASS
 S4 restart between log write and checkpoint                 13      0   PASS
 S5 five-block reorg                                         13      0   PASS
 S6 reorg + duplicate + restart                              11      0   PASS
 NEGATIVE CASES (must be DETECTED as failing their assertion)
 N1 negative: height-only checkpoint across a reorg           4      0   PASS
 N2 negative: non-atomic log/checkpoint commit across crash   5      0   PASS
 TOTAL checks=81 failed=0   RESULT: ALL SCENARIOS PASS
```

Each `*.eq.<table>` assertion compares the incremental DB to the canonical
replay per table (rows keyed and compared column-by-column, with an explicit
row-count check so a duplicated log cannot hide behind a collapsed key).  On any
divergence the report names the table, the key and both values.

## What breaks without a block-hash checkpoint (executed, not asserted)

`src/naive_checkpoint.py` ships two runnable counter-examples; the suite runs
them and **passes only because they fail their own equality assertion**.

* **N1 — height-only checkpoint.**  `HeightOnlyIndexer` stores only
  `last_block_number`.  After the reorg the *height* is unchanged (both branches
  have height 14), so it believes it is current, never rewinds, and silently
  retains branch A's logs.  Result: `events`, `bounties`, `credits` diverge from
  the canonical replay and the wrong winner (`ALICE`, 1000) survives — the
  double-pay the bounty cares about.  A block-hash checkpoint detects the
  mismatch and rewinds instead.
* **N2 — non-atomic commit.**  `NonAtomicIndexer` commits the log write and the
  checkpoint write in separate transactions and inserts non-idempotently.  A
  crash between them leaves logs for heights 10..14 durable while the checkpoint
  is still 9; the restart re-writes them, so `events` holds duplicated rows
  (double-counted).  The single-transaction boundary in the real indexer makes
  this impossible.

## Limits of the fixture (it is a synthetic chain, not a live RPC)

* **Not a node.** There is no JSON-RPC, no mempool, no receipts, no state root
  and no re-execution — the fixture *serves* pre-built blocks and logs.  It
  models the two things a reorg test needs: per-height block hashes and a
  branch switch.  It is not a substitute for testing against `eth_getLogs`.
* **Not keccak256.** `topic0` is `sha256(signature)` (collision-free and
  deterministic for this local fixture) rather than the real Keccak-256, so
  topic0 values will not match a real deployment; the *encoding* (indexed →
  topics, rest → ABI head/tail) is real.
* **Single-node, single-writer.** One process at a time owns the DB; there is no
  multi-writer protocol, no `busy_timeout` tuning, and `log_index` is per-tx.
* **Scripted history.** The branches are a fixed script; there is no random fuzz
  over block/tx shapes.  Determinism (fixed timestamps, fixed hashes, no
  randomness) is the goal — the acceptance criteria ask for deterministic
  fixtures.
* **Public data only.** No private wallets, no keys, no signed transactions, and
  no paid RPC are used anywhere.

## Pinned runnable commit

`run.sh` prints the commit it is running from, and the same value is recorded in
`results/report.json` under `"commit"` and in the `PINNED_COMMIT` file. To
reproduce: check out that commit and run `./run.sh`; the fixture is deterministic
so `results/report.json` regenerates identically.

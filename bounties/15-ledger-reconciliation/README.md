# Bounty #15 — Auditable bounty ledger reconciliation

**What it does:** independently rebuilds the escrow's ledger from its **events alone** and checks the result against the contract's own state read at a **fixed block** — per bounty, per wallet, and in total.

Verdict: **PASS** — 120 bounties, 676 events, every assertion reconciles exactly, and all six corruption scenarios are detected with field-level failure messages.

## Run it

```bash
./run.sh
```

1. starts a local `anvil`, deploys the **unmodified** `IMDWorksEscrow` plus a pausable fixture token;
2. drives **120 deterministic bounty lifecycles** (fixed dev accounts, fixed amounts, time advanced with `evm_increaseTime`);
3. freezes the fixture (`results/fixture.json`: normalised logs, block hashes, state at the snapshot block);
4. reconciles from the event stream and runs the tamper suite (`results/reconciliation.json`).

## What the fixture deliberately contains

| case | how it appears in the fixture |
|---|---|
| award + withdrawal | 69 `BountyAwarded`, 58 `Withdrawn` |
| top-ups | 34 `RewardAdded` (two per topped-up bounty) — the tracked reward per bounty must include them |
| cancellation | `BountyRefunded` with `status = Cancelled`, then a creator withdrawal |
| expiry after the review window | `BountyRefunded` with `status = Expired` |
| **expired but unawarded** | bounties whose deadline passed with the reward still locked, never expired |
| **failed withdrawal** | transfers paused by the issuer: the withdrawal reverts, the credit survives, a later withdrawal succeeds (34 `PausedSet` events) |
| **multiple credits to one wallet** | one worker wins many bounties and keeps its credit outstanding |
| **direct token donations** | 3 plain transfers into the escrow with no `BountyCreated`/`RewardAdded` in the transaction |

Snapshot: **block 535**, escrow `0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512`, token `0x5FbDB2315678afecb367f032d93F642f64180aa3` (local anvil addresses, reproducible).

## Result

```
reconstructed   locked=17,000,000  claimable=3,500,000  liabilities=20,500,000
contract        locked=17,000,000  claimable=3,500,000  liabilities=20,500,000
token balance   21,538,270          surplus = 1,038,270 = donations (777,777 + 259,259 + 1,234)
```

| assertion | detail |
|---|---|
| `L1-no-duplicate-events` | no duplicate `(tx_hash, log_index)` across 676 events |
| `L2-log-block-hashes` | every log's block hash matches the recorded canonical hash |
| `L3-logs-within-snapshot` | all logs are at or before the snapshot block |
| `S1-snapshot-block-hash` | snapshot block hash confirmed |
| `R1-total-locked` | reconstructed `17,000,000` == contract `17,000,000` |
| `R2-total-claimable` | reconstructed `3,500,000` == contract `3,500,000` |
| `R3-liabilities` | `20,500,000` == `20,500,000` |
| `R4-credits-per-wallet` | all 12 wallets reconcile exactly |
| `R5-per-bounty-reward-and-status` | all 120 bounties: reward (including top-ups) and terminal status |
| `T1-token-balance-from-transfers` | balance rebuilt from the `Transfer` stream == contract balance |
| `S2-donations-are-surplus` | surplus == the 3 unsolicited transfers; no wallet was credited |
| `S3-balance-covers-liabilities` | 21,538,270 held vs 20,500,000 owed |

## Why donations are surplus, not user credit

The escrow's accounting identity is:

```
token_balance = total_locked + total_claimable + surplus
```

A donation is a plain `Transfer` into the escrow. It emits no `BountyCreated` and no `RewardAdded`, so the reconstructor never adds it to any bounty's reward: `locked` is derived from create/top-up events only. It also cannot become a wallet's credit, because credit is only ever granted by `BountyAwarded` or `BountyRefunded` — and the fixture proves it arithmetically: `surplus (1,038,270) == Σ transfers whose transaction contains no deposit event (777,777 + 259,259 + 1,234)`, while `Σ per-wallet credit == totalClaimable` exactly. Since `withdraw()` is an exact-transfer check against the escrow's own balance delta, extra tokens in the contract cannot change what any wallet can take out.

## Tamper detection (all six detected, with the failing check)

| corruption | detected by | message |
|---|---|---|
| one `BountyAwarded` removed | `R1`, `R2`, `R3`, `R4`, `R5` | `locked reward mismatch: reconstructed 18000000 vs contract 17000000 (delta 1000000)` |
| one `Withdrawn` duplicated | `L1`, `R2`, `R3`, `R4` | `duplicate (tx, log_index) deliveries: [('0x3282bbdc…', 5)]` |
| state snapshot behind the log stream | `L3`, `R1`, `R2`, `R3`, `R4` | `log stream continues past the state snapshot …` |
| snapshot block hash swapped | `S1` | `snapshot block 535 hash mismatch: recorded 0xabab… vs canonical 0xfb0578e2…` |
| log from a foreign branch | `L2` | `logs from a foreign branch: [(535, '0xcdcd…')]` |
| snapshot ahead of the log cutoff | `R2`, `R3`, `R4`, `T1` | `claimable mismatch: reconstructed 4500000 vs contract 3500000 (delta 1000000)` |

The third scenario uses a **real earlier snapshot** captured before the time travel — not a doctored number — so it is a genuine "logs at B2, state at B1" bug, the classic indexer race.

## Seed / determinism

`FIXTURE_BOUNTIES=120`, anvil dev accounts (`--accounts 12`, default deterministic mnemonic), fixed rewards (`1.000000`, top-ups `0.250000`), fixed donation amounts (`777777`, `259259`, `1234`), time advanced by fixed amounts. Re-running `./run.sh` regenerates an equivalent fixture (addresses repeat; block numbers can shift by a block or two because anvil mines per transaction).

## Limits

* The reconciler trusts the block-hash bookkeeping it recorded in the fixture. Against a live node the same checks apply using `eth_getBlockByNumber(...).hash` per height; the code already fetches logs and state over JSON-RPC (`src/lib/rpc.py`) — the fixture freeze is what makes the run offline and deterministic.
* Log decoding is hand-written for the escrow's six events plus ERC-20 `Transfer`; the ABI is not read from a file, so an event signature change would be caught as an unknown topic rather than silently mis-decoded (unknown topics are dropped — the `Transfer`-derived balance check would then fail loudly).
* Only the escrow's and the fixture token's logs are indexed; unrelated contracts on the same chain are out of scope.

## Files

```
run.sh                          one command: build, generate fixture, reconcile
contracts/IMDWorksEscrow.sol    contract under test, unmodified
contracts/MockToken.sol         pausable exact-transfer ERC-20 (fixture asset)
src/lib/rpc.py                  JSON-RPC client (local node only)
src/lib/abi.py                  minimal ABI encode/decode
src/lib/escrow.py               selectors, calldata builders, event decoding
src/lib/keccak256.py            Keccak-256 (used for selectors and topic hashes)
scripts/gen_fixture.py          fixture generator (anvil + 120 lifecycles)
scripts/reconcile.py            reconciliation + tamper suite
results/fixture.json            frozen logs + state at the snapshot block
results/reconciliation.json     machine-readable report
```

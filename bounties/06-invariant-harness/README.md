# Bounty #06 — Stateful escrow accounting invariant harness

**Contract under test:** the unmodified `IMDWorksEscrow` source published by the platform (pinned in `src/IMDWorksEscrow.sol`, bytecode provenance covered by bounty #14). Everything runs on a **local EVM** (Foundry), nothing touches a live chain.

The harness models three creators, five workers, operator delegation, top-ups, time jumps, cancellation, awards and withdrawals, and then checks the real contract against an **independent shadow model**. It does *not* merely mirror implementation variables: liabilities, per-wallet credits and per-bounty payment totals are recomputed by the handler from its own actor bookkeeping, then compared to the contract's own state.

Verdict: **PASS** — all invariants hold over 200,000 generated calls, and the harness detects a deliberately broken mutation.

## Run it

```bash
./run.sh
```

* runs the real contract for **2 × (1000 runs × depth 100 = 100,000 calls)** with two published seeds,
* runs the same invariants against a mutated contract and asserts the suite **fails** (proving detection),
* writes `results/summary.json`, per-seed logs and this summary.

## Model and invariants

The handler (`src/EscrowHandler.sol`) keeps:

* `shadowReward[id]` — reward per bounty, updated on create **and** every `RewardAdded`
* `shadowStatus[id]`, `shadowDeadline[id]`, `shadowSubmissions[id]`, `shadowSubmitted[id][author]`
* `shadowLocked` — sum of rewards of open bounties
* `shadowCredit[addr]`, `shadowCreditTotal` — per-wallet and total claimable credit
* `shadowPaid[id]` — the amount a bounty actually paid out (0 while open)

Actions (fuzzed): `createBounty`, `addReward`, `setOperator`, `submitWork`, `submitWorkFor`, `award`, `cancel`, `expire`, `withdraw`, `warp`, plus **negative actions** that deliberately try illegal things and count any unexpected success into a ghost counter:

* award a bounty that is already settled (`tryAwardSettledBounty`)
* submit work to a bounty created by the same wallet
* attempt a withdrawal with no credit, etc.

Every success/failure updates the shadow model; every invariant compares the shadow model with the contract.

Invariants (all in `test/InvariantEscrow.t.sol`):

| invariant | what it proves |
|---|---|
| `invariant_modelMatchesTotalLocked` | `escrow.totalLocked()` == shadow-locked (model recomputes locked, not a copy) |
| `invariant_claimsMatchModel` | `escrow.totalClaimable()` == Σ shadow credits |
| `invariant_liabilitiesEqualModel` | `escrow.liabilities()` == locked + claimable from the model |
| `invariant_tokenBalanceCoversLiabilities` | token balance of the escrow ≥ liabilities at every step |
| `invariant_noBountyPaysTwice` | every bounty pays exactly 0 or exactly its final reward, never twice |
| `invariant_creditMatchesPerAccount` | `escrow.claimable(addr)` == shadow credit for every actor |
| `invariant_noUnexpectedSuccesses` | no illegal action ever succeeded (`ghost_unexpectedSuccesses == 0`) |
| `invariant_callSummary` | prints the action histogram (e.g. `award 44 / cancel 42 / createBounty 42 …`) |

The handler's *negative actions* are what separate this from "tests that only mirror implementation variables": they attack the contract's access control and state machine directly, and the mutation below is caught precisely because the model refuses to believe a settled bounty can pay again.

## Results

Toolchain: `forge 1.8.3` (build), `solc 0.8.29`, `anvil 1.8.3`. `fail_on_revert = false` so the fuzzer can push against reverts.

**Real contract** (two published seeds, `results/real-0a01.log`, `results/real-0b02.log`):

```
InvariantEscrowTest invariants (runs: 1000, calls: 100000, reverts: 0)
Suite result: ok. 1 passed; 0 failed
```

Seeds:
* `0x0000000000000000000000000000000000000000000000000000000000000a01`
* `0x0000000000000000000000000000000000000000000000000000000000000b02`

**Mutation** (`broken/BrokenEscrow.sol`): `award()` no longer sets `status = Awarded`, so the same bounty can be awarded and paid repeatedly. The suite must fail — and does:

```
[FAIL: liabilities != model: 152000000 != 252000000] invariant_liabilitiesEqualModel
[FAIL: award() succeeded on a settled bounty: 1 != 0] invariant_noUnexpectedSuccesses
```

Two independent signals, both from the model, not from a copy of the implementation.

## Assumptions

* The shadow model assumes the contract's own invariants hold (reward == sum of deposit events, withdrawals are exact transfers); it is exactly these assumptions the fuzzer tries to break.
* The fixture token is an exact-transfer ERC-20 (6 decimals) with a mint — asset-restriction behaviour (paused transfers, fee-on-transfer, callback tokens) is covered by bounty #11 against the same contract.
* `fail_on_revert = false` means calls that revert are not counted as failures; the *negative actions* make that acceptable by asserting, separately, that no *illegal* call ever succeeded.
* Runs are bounded by EVM gas per call; the 100,000-call budget is more than enough to reach terminal states (the seed action settles one bounty first so mutations are reachable immediately).

## Files

```
run.sh                          one-command runner (real suite + mutation + report)
src/IMDWorksEscrow.sol          contract under test (pinned)
src/MockToken.sol               exact-transfer fixture token
src/EscrowHandler.sol           fuzzed handler + shadow model + negative actions
test/InvariantEscrow.t.sol      invariants against the real contract
test-broken/BrokenInvariant.t.sol  same invariants against the mutation
broken/BrokenEscrow.sol         the deliberately broken mutation
results/summary.json            machine-readable report (seeds, verdicts)
```

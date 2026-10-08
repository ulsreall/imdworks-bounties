# Bounty #11 — Escrow behaviour under issuer-controlled token restrictions

**Question:** what happens to an escrow bounty when the *asset issuer* (not the bounty creator) can restrict transfers — pause, sender blacklist, recipient blacklist, return-false, fee-on-transfer — and which of those states can a creditor recover from without help?

Verdict: **9/9 executable tests pass**; the behaviour matrix below is generated from the tests themselves (`results/matrix.md`, `results/matrix.json`), not written by hand.

## Run it

```bash
./run.sh          # forge test + matrix aggregation
```

## Behaviour matrix

| mode | deposit (createBounty) | award/refund while restricted | withdraw | failed withdraw preserves credit | needs issuer action to recover | class |
|---|---|---|---|---|---|---|
| `standard-exact-6dp` | accepted | n/a | succeeds | yes | **no** | supported |
| `no-return-values` | accepted | works | succeeds | yes | **no** | supported |
| `erc777-style-callback` | accepted, hook re-entry blocked | works | accepted, re-entry blocked | yes | **no** | supported |
| `winner-on-recipient-blocklist` | accepted | works | blocked to that recipient, **redirect allowed** | yes | **no** | supported |
| `paused-transfers` | blocked (`TOKEN_PAUSED`) | **works while paused** | blocked, credit preserved | yes | yes (unpause) | unsupported |
| `returns-false` | blocked | works | blocked, credit preserved | yes | yes (token must return true) | unsupported |
| `creator-on-sender-blocklist` | blocked (`SENDER_BLOCKED`) | works | blocked only if the sender is blocked | yes | yes (unblock) | unsupported |
| `fee-on-transfer` | rejected (`UnsupportedTransfer`) | works | rejected (`UnsupportedTransfer`), credit preserved | yes | yes (fee must be removed) | unsupported |

## The four things the criteria asked for

**1. Failed withdrawals preserve claimable balances.** Every blocking mode is exercised on the *payout* side after a successful award: `claimable(winner)` is asserted to be unchanged after the failed `withdraw`, and the escrow's token balance is asserted to still hold the full reward. The credit is only released by the issuer's action (unpause / clear the blocklist / remove the fee), which the tests then perform to prove the recovery path works and ends in exact balance conservation.

**2. Paused transfers do not prevent award/refund bookkeeping.** `award()` and `expire()` move credit internally without touching the token, so they succeed while the asset is paused:
* `escrow.award(id, winner)` while paused → `claimable(winner) == reward`, `totalLocked() == 0`
* `escrow.expire(id)` while paused → `claimable(creator) == reward`, `totalLocked() == 0`
Only the token movement is deferred. This matters operationally: a paused asset freezes payouts but does not freeze bounty resolution, and no accounting is lost.

**3. Which recovery paths require issuer action.** From the matrix: the *only* mode that traps nothing is the **recipient blacklist**, because `withdraw(recipient)` lets the creditor name any recipient — the creditor can redirect to an address the issuer has not blocked. Pause, sender blocklist, return-false and fee-on-transfer all require the issuer to change state; none of them require the escrow's owner or the bounty creator.

**4. Callback reentrancy + balance conservation.** The `erc777-style-callback` token re-enters the escrow from inside both `transferFrom` (deposit) and `transfer` (payout), attempting `withdraw()` and `award()`. Both re-entrant calls revert (nonReentrant / authorisation), the callback never gains credit, the outer transfer still completes exactly, and the final assertion is `token.balanceOf(escrow) == escrow.liabilities()` with `liabilities == 0`.

## Where the escrow's protections come from

* `_deposit` checks the exact balance delta, so fee-on-transfer and return-false tokens cannot silently under-collateralise a bounty → `UnsupportedTransfer`.
* `withdraw` re-derives the exact delta on both the escrow and the recipient side, so a token that taxes or lies is rejected; the credit decrement and the token transfer are in the same atomic call, so the revert restores the credit — the tests assert `claimable` is intact afterwards.
* `nonReentrant` on every state-changing entry point plus `SafeERC20` for the false-return case.
* No mode lets a third party move another wallet's credit: the callback token ends with zero claimable.

## Assumptions and limits

* The mocks model *issuer policy* (pause, blacklist, tax, callback), not a specific production token; they implement exact transfers, 6 decimals, and only the restriction under test.
* Pause/blacklist administration is modelled as a single external call — the tests do not model a timelock or multisig behind it.
* "Recovery" here means: the creditor can be made whole. If the issuer never lifts the restriction, the funds remain escrowed indefinitely — the code has no escape hatch, which is worth knowing before choosing a settlement asset.

## Files

```
run.sh                                one command: forge test + matrix aggregation
src/IMDWorksEscrow.sol                contract under test, unmodified
src/Tokens.sol                        8 issuer-policy mocks (pause, blocklists, false, no-return, fee, callback)
test/IssuerRestrictions.t.sol         9 tests producing the matrix rows
scripts/matrix.py                     aggregates results/mode-*.json into matrix.md / matrix.json
results/matrix.md, results/matrix.json
```

#!/usr/bin/env python3
"""Bounty #15 - independent ledger reconciliation.

Reads the frozen fixture produced by scripts/gen_fixture.py (a real local EVM:
unmodified IMDWorksEscrow + a pausable fixture token) and, using only the event
stream, independently reconstructs:

  * the reward committed per bounty (create + top-ups)
  * the credit each wallet was granted (awards and refunds) and withdrew
  * the locked total, the claimable total and therefore total liabilities
  * the token balance implied by the token Transfer stream

and then checks all of it against the contract state read at a fixed block.

It also explains, with arithmetic, why unsolicited token donations are surplus
rather than user credit, and it proves - by running deliberately corrupted
inputs - that removed events, duplicated events and mismatched block snapshots
are detected with precise failure messages.
"""

from __future__ import annotations

import copy
import json
import pathlib
import sys
from collections import defaultdict

ROOT = pathlib.Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
FIXTURE = RESULTS / "fixture.json"

STATUS = {0: "None", 1: "Open", 2: "Awarded", 3: "Cancelled", 4: "Expired"}


class ReconciliationError(AssertionError):
    """Raised with a precise, field-level message."""


def reconstruct(logs: list[dict]) -> dict:
    """Rebuild ledger state from events alone (no contract calls)."""
    reward: dict[int, int] = {}
    creator: dict[int, str] = {}
    credited: dict[int, int] = {}
    settle_status: dict[int, str] = {}
    credits: dict[str, int] = defaultdict(int)
    locked = 0
    seen_keys: set[tuple[str, int]] = set()
    duplicates: list[tuple[str, int]] = []

    for ev in logs:
        key = (ev["tx"], ev["log_index"])
        if key in seen_keys:
            duplicates.append(key)
        seen_keys.add(key)

        name = ev["name"]
        if name == "BountyCreated":
            bid = ev["bounty_id"]
            if bid in reward:
                raise ReconciliationError(f"BountyCreated for bounty {bid} seen twice")
            reward[bid] = ev["reward"]
            creator[bid] = ev["creator"]
            locked += ev["reward"]
        elif name == "RewardAdded":
            bid = ev["bounty_id"]
            if bid not in reward:
                raise ReconciliationError(f"RewardAdded for unknown bounty {bid}")
            reward[bid] += ev["amount"]
            locked += ev["amount"]
        elif name == "BountyAwarded":
            bid = ev["bounty_id"]
            if bid not in reward:
                raise ReconciliationError(f"BountyAwarded for unknown bounty {bid}")
            if bid in credited:
                raise ReconciliationError(f"bounty {bid} paid out twice (already settled)")
            if ev["amount"] != reward[bid]:
                raise ReconciliationError(
                    f"bounty {bid}: awarded {ev['amount']} but tracked reward is {reward[bid]}")
            locked -= ev["amount"]
            credits[ev["winner"]] += ev["amount"]
            credited[bid] = ev["amount"]
            settle_status[bid] = "Awarded"
        elif name == "BountyRefunded":
            bid = ev["bounty_id"]
            if bid not in reward:
                raise ReconciliationError(f"BountyRefunded for unknown bounty {bid}")
            if bid in credited:
                raise ReconciliationError(f"bounty {bid} paid out twice (already settled)")
            if ev["amount"] != reward[bid]:
                raise ReconciliationError(
                    f"bounty {bid}: refunded {ev['amount']} but tracked reward is {reward[bid]}")
            locked -= ev["amount"]
            credits[ev["creator"]] += ev["amount"]
            credited[bid] = ev["amount"]
            settle_status[bid] = STATUS.get(ev["status"], f"status{ev['status']}")
        elif name == "Withdrawn":
            credits[ev["account"]] -= ev["amount"]

    return {
        "reward": reward,
        "creator": creator,
        "credited": credited,
        "settle_status": settle_status,
        "credits": {k: v for k, v in credits.items() if v != 0},
        "locked": locked,
        "claimable": sum(credits.values()),
        "liabilities": locked + sum(credits.values()),
        "duplicates": duplicates,
        "log_keys": seen_keys,
    }


def token_balance_from_transfers(logs: list[dict], escrow: str) -> int:
    bal = 0
    for ev in logs:
        if ev["name"] != "Transfer":
            continue
        if ev["to"] == escrow:
            bal += ev["value"]
        elif ev["from"] == escrow:
            bal -= ev["value"]
    return bal


def donation_transfers(logs: list[dict], escrow: str, deposit_txs: set[str]) -> list[dict]:
    """Transfers into the escrow whose transaction contains no deposit event."""
    out = []
    for ev in logs:
        if ev["name"] == "Transfer" and ev["to"] == escrow and ev["tx"] not in deposit_txs:
            out.append(ev)
    return out


def checks(fixture: dict, logs: list[dict] | None = None, state: dict | None = None) -> list[dict]:
    logs = fixture["logs"] if logs is None else logs
    state = fixture["state"] if state is None else state
    escrow = fixture["contracts"]["escrow"].lower()
    accounts = fixture["accounts"]
    block_hashes = {int(k): v.lower() for k, v in fixture["block_hashes"].items()}

    model = reconstruct(logs)
    results: list[dict] = []

    def check(cid: str, ok: bool, fail_message: str, ok_message: str) -> None:
        results.append({"id": cid, "ok": ok,
                        "detail": ok_message if ok else fail_message})

    check("L1-no-duplicate-events", not model["duplicates"],
          f"duplicate (tx, log_index) deliveries: {model['duplicates'][:5]}",
          f"no duplicate deliveries across {len(model['log_keys'])} events")

    bad_branch = [ev for ev in logs
                  if block_hashes.get(ev["block"]) and ev["block_hash"]
                  and ev["block_hash"] != block_hashes[ev["block"]]]
    check("L2-log-block-hashes", not bad_branch,
          f"logs from a foreign branch: {[(e['block'], e['block_hash']) for e in bad_branch[:3]]}",
          "every log matches the recorded canonical block hash")

    beyond = [ev for ev in logs if ev["block"] > state["block"]]
    check("L3-logs-within-snapshot", not beyond,
          (f"log stream continues past the state snapshot: first at block {beyond[0]['block']} "
           f"> snapshot {state['block']}") if beyond else "unreachable",
          f"all {len(logs)} logs are at or before the snapshot block {state['block']}")

    check("S1-snapshot-block-hash",
          block_hashes.get(state["block"], "").lower() == state["block_hash"].lower(),
          f"snapshot block {state['block']} hash mismatch: recorded {state['block_hash']} "
          f"vs canonical {block_hashes.get(state['block'])}",
          f"snapshot block {state['block']} hash confirmed against the recorded chain")

    check("R1-total-locked", model["locked"] == state["total_locked"],
          f"locked reward mismatch: reconstructed {model['locked']} vs contract "
          f"{state['total_locked']} (delta {model['locked'] - state['total_locked']})",
          f"locked reward matches the contract exactly: {model['locked']}")

    check("R2-total-claimable", model["claimable"] == state["total_claimable"],
          f"claimable mismatch: reconstructed {model['claimable']} vs contract "
          f"{state['total_claimable']} (delta {model['claimable'] - state['total_claimable']})",
          f"claimable matches the contract exactly: {model['claimable']}")

    check("R3-liabilities", model["liabilities"] == state["liabilities"],
          f"liabilities mismatch: reconstructed {model['liabilities']} vs contract "
          f"{state['liabilities']}",
          f"liabilities (locked + claimable) match: {model['liabilities']}")

    per_account_bad = []
    for acc in accounts:
        want = state["claimable"].get(acc, state["claimable"].get(acc.lower(), 0))
        got = model["credits"].get(acc, 0)
        if want != got:
            per_account_bad.append((acc, got, want))
    check("R4-credits-per-wallet", not per_account_bad,
          f"per-wallet credit mismatch (wallet, reconstructed, contract): {per_account_bad[:4]}",
          f"all {len(accounts)} wallets reconcile exactly")

    per_bounty_bad = []
    for entry in state["bounties"]:
        bid = entry["id"]
        if model["reward"].get(bid) != entry["reward"]:
            per_bounty_bad.append((bid, "reward", model["reward"].get(bid), entry["reward"]))
            continue
        reconstructed_status = model["settle_status"].get(bid, "Open")
        contract_status = STATUS.get(entry["status"], str(entry["status"]))
        if reconstructed_status != contract_status:
            per_bounty_bad.append((bid, "status", reconstructed_status, contract_status))
    check("R5-per-bounty-reward-and-status", not per_bounty_bad,
          f"per-bounty mismatch (id, field, reconstructed, contract): {per_bounty_bad[:4]}",
          f"all {len(state['bounties'])} bounties reconcile (reward and terminal status)")

    balance_from_logs = token_balance_from_transfers(logs, escrow)
    check("T1-token-balance-from-transfers", balance_from_logs == state["token_balance"],
          f"token balance mismatch: from Transfer logs {balance_from_logs} vs contract "
          f"{state['token_balance']}",
          f"token balance rebuilt from Transfer logs matches: {balance_from_logs}")

    surplus = state["token_balance"] - state["liabilities"]
    deposit_txs = {ev["tx"] for ev in logs
                   if ev["name"] in ("BountyCreated", "RewardAdded")}
    donations = donation_transfers(logs, escrow, deposit_txs)
    donation_total = sum(ev["value"] for ev in donations)
    check("S2-donations-are-surplus", donation_total == surplus,
          f"surplus {surplus} != unsolicited transfers {donation_total} "
          f"({[ev['value'] for ev in donations]}), or a donation was credited to a wallet",
          f"surplus {surplus} is exactly the {len(donations)} unsolicited transfers; "
          f"no wallet was credited")
    check("S3-balance-covers-liabilities", state["token_balance"] >= state["liabilities"],
          f"escrow holds {state['token_balance']} but owes {state['liabilities']}",
          f"escrow holds {state['token_balance']} against {state['liabilities']} of liabilities")

    return results


def tamper_suite(fixture: dict) -> list[dict]:
    """Corrupt the inputs on purpose; every corruption must be detected."""
    scenarios: list[dict] = []

    def run(name: str, expect_ids: list[str], logs=None, state=None) -> None:
        try:
            results = checks(fixture, logs, state)
        except ReconciliationError as exc:
            scenarios.append({"scenario": name, "detected": True,
                              "detected_by": "reconstruction-crash", "message": str(exc)})
            return
        failing = [r for r in results if not r["ok"]]
        detected = bool(failing)
        scenarios.append({
            "scenario": name,
            "detected": detected,
            "detected_by": [r["id"] for r in failing],
            "message": failing[0]["detail"] if failing else "NOT DETECTED",
            "expected_checks": expect_ids,
            "matched_expected": bool(set(expect_ids) & {r["id"] for r in failing}),
        })

    # T1: one event silently removed
    logs = copy.deepcopy(fixture["logs"])
    idx = next(i for i, ev in enumerate(logs) if ev["name"] == "BountyAwarded")
    logs.pop(idx)
    run("removed BountyAwarded event", ["R1-total-locked", "R2-total-claimable",
                                        "R3-liabilities", "R4-credits-per-wallet",
                                        "R5-per-bounty-reward-and-status"], logs=logs)

    # T2: one event delivered twice
    logs = copy.deepcopy(fixture["logs"])
    idx = next(i for i, ev in enumerate(logs) if ev["name"] == "Withdrawn")
    logs.insert(idx, copy.deepcopy(logs[idx]))
    run("duplicated Withdrawn event", ["L1-no-duplicate-events"], logs=logs)

    # T3: state snapshot taken before the last events (state behind the log stream).
    #      The fixture contains a real earlier snapshot, so this is a true
    #      "logs at B2 vs state at B1 (B1 < B2)" mismatch, not a doctored value.
    run("state snapshot behind the log stream",
        ["L3-logs-within-snapshot", "R1-total-locked", "R2-total-claimable",
         "R3-liabilities", "R4-credits-per-wallet"],
        state=copy.deepcopy(fixture["state_early"]))

    # T4: snapshot block hash swapped (validator read a different branch)
    state = copy.deepcopy(fixture["state"])
    state["block_hash"] = "0x" + "ab" * 32
    run("snapshot block hash swapped", ["S1-snapshot-block-hash"], state=state)

    # T5: a log taken from a foreign branch
    logs = copy.deepcopy(fixture["logs"])
    logs[-1]["block_hash"] = "0x" + "cd" * 32
    run("log from a different branch", ["L2-log-block-hashes"], logs=logs)

    # T6: snapshot read one block later than the log cutoff
    logs = copy.deepcopy(fixture["logs"])
    logs = [ev for ev in logs if ev["block"] < fixture["state"]["block"]]
    state = copy.deepcopy(fixture["state"])
    run("snapshot ahead of the log cutoff", ["L3-logs-within-snapshot", "R1-total-locked",
                                             "R2-total-claimable"], logs=logs, state=state)
    return scenarios


def main() -> int:
    fixture = json.loads(FIXTURE.read_text())
    results = checks(fixture)
    failing = [r for r in results if not r["ok"]]
    model = reconstruct(fixture["logs"])
    state = fixture["state"]
    tamper = tamper_suite(fixture)

    report = {
        "bounty": 15,
        "title": "Implement an auditable bounty ledger reconciliation tool",
        "fixture": {
            "contracts": fixture["contracts"],
            "bounties": fixture["bounties_created"],
            "logs": len(fixture["logs"]),
            "event_counts": fixture["event_counts"],
            "snapshot_block": state["block"],
            "snapshot_block_hash": state["block_hash"],
            "withdraw_stats": fixture.get("withdraw_stats"),
        },
        "reconstructed": {
            "locked": model["locked"],
            "claimable": model["claimable"],
            "liabilities": model["liabilities"],
            "wallets_with_credit": len(model["credits"]),
            "top_credits": sorted(model["credits"].items(), key=lambda kv: -kv[1])[:5],
        },
        "contract_state": {
            "total_locked": state["total_locked"],
            "total_claimable": state["total_claimable"],
            "liabilities": state["liabilities"],
            "token_balance": state["token_balance"],
        },
        "donations": {
            "transfers": fixture["donations"],
            "surplus": state["token_balance"] - state["liabilities"],
            "explanation": ("unsolicited transfers raise the escrow's token balance without "
                            "emitting BountyCreated/RewardAdded, so they are excluded from both "
                            "locked rewards and per-wallet credit: the accounting identity is "
                            "balance = locked + claimable + surplus, and surplus is not claimable "
                            "by anyone. Payments are still exact-transfer checked, so a donation "
                            "cannot change what a wallet can withdraw."),
        },
        "assertions": results,
        "tamper_detection": tamper,
        "verdict": "PASS" if not failing and all(t["detected"] and t["matched_expected"]
                                                 for t in tamper) else "FAIL",
    }
    (RESULTS / "reconciliation.json").write_text(json.dumps(report, indent=2))

    print("reconciliation of the frozen fixture")
    print(f"  logs            {report['fixture']['logs']} events at block "
          f"{report['fixture']['snapshot_block']}")
    print(f"  reconstructed   locked={model['locked']} claimable={model['claimable']} "
          f"liabilities={model['liabilities']}")
    print(f"  contract        locked={state['total_locked']} claimable={state['total_claimable']} "
          f"liabilities={state['liabilities']} balance={state['token_balance']}")
    print(f"  surplus         {state['token_balance'] - state['liabilities']} "
          f"(donations {fixture['donations']})")
    print("  assertions:")
    for r in results:
        print(f"    [{'ok' if r['ok'] else 'FAIL'}] {r['id']}: {r['detail']}")
    print("  tamper detection:")
    for t in tamper:
        print(f"    [{'detected' if t['detected'] else 'MISSED'}] {t['scenario']} "
              f"-> {t['detected_by']}: {t['message'][:110]}")
    print(f"  verdict: {report['verdict']}")
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
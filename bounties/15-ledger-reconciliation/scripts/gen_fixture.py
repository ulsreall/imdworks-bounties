#!/usr/bin/env python3
"""Bounty #15 - deterministic escrow fixture generator.

Starts a local anvil node, deploys the unmodified IMDWorksEscrow plus a
pausable fixture token, then drives at least 100 bounty lifecycles covering:

  * award + withdraw
  * award with the credit left outstanding
  * cancel + refund + withdraw
  * top-ups (RewardAdded) before the award
  * a failed withdrawal while the asset issuer has transfers paused
  * an expired, unawarded bounty whose reward stays locked
  * expire() after the review window (refund to the creator)
  * operator delegation (submitWorkFor)
  * one wallet accumulating credits from many bounties
  * direct token donations to the escrow

Everything is scripted and time is advanced with evm_increaseTime, so the same
run reproduces the same event stream. The result is written to
results/fixture.json: raw normalised logs, the state read at the reconciliation
block, and the scripted model used as a secondary expectation.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from lib import escrow as E  # noqa: E402
from lib.keccak256 import keccak256  # noqa: E402
from lib.rpc import Rpc  # noqa: E402

PORT = int(os.environ.get("FIXTURE_PORT", "8599"))
RPC_URL = f"http://127.0.0.1:{PORT}"
BOUNTY_COUNT = int(os.environ.get("FIXTURE_BOUNTIES", "120"))
REWARD = 1_000_000          # 1.000000 (6 dp)
TOPUP = 250_000             # 0.250000
DONATION = 777_777
RESULTS = ROOT / "results"
DEV_PK = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


def brief_hash(i: int) -> str:
    return "0x" + keccak256(f"brief-{i}".encode()).hex()


def start_anvil() -> subprocess.Popen:
    proc = subprocess.Popen(
        ["anvil", "--port", str(PORT), "--accounts", "12", "--silent"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    rpc = Rpc(RPC_URL)
    for _ in range(80):
        try:
            rpc.chain_id()
            return proc
        except Exception:  # noqa: BLE001
            time.sleep(0.25)
    proc.kill()
    raise RuntimeError("anvil did not become ready")


def deploy(contract: str, args: list[str] | None = None) -> str:
    cmd = ["forge", "create", contract, "--rpc-url", RPC_URL,
           "--private-key", DEV_PK, "--broadcast", "--json"]
    if args:
        cmd += ["--constructor-args", *args]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
    if proc.returncode != 0:
        raise RuntimeError(f"deploy failed for {contract}: {proc.stderr[:400]}")
    payload = json.loads(proc.stdout)
    return payload["deployedTo"]


def main() -> int:
    RESULTS.mkdir(exist_ok=True)
    anvil = start_anvil()
    rpc = Rpc(RPC_URL)
    try:
        accounts = rpc.call("eth_accounts")
        token = deploy("contracts/MockToken.sol:MockToken")
        escrow = deploy("contracts/IMDWorksEscrow.sol:IMDWorksEscrow", [token])
        assert rpc.get_code(escrow) not in ("0x", ""), "escrow has no code"

        creators = accounts[0:6]
        workers = accounts[6:11]
        operator = accounts[11]

        # fund and approve
        for acc in accounts[:11]:
            rpc.send_and_wait(acc, token, E.cd_mint(acc, 500_000_000))
        for acc in creators:
            rpc.send_and_wait(acc, token, E.cd_approve(escrow, (1 << 256) - 1))
        # the operator needs no tokens; donations come from a plain EOA
        rpc.send_and_wait(accounts[0], token, E.cd_approve(escrow, (1 << 256) - 1))

        block = rpc.get_block(rpc.block_number())
        now = int(block["timestamp"], 16)
        deadline = now + 2 * 3600

        scripted: list[dict] = []
        events_plan: list[str] = []

        def send(frm: str, data: str, expect_ok: bool = True) -> dict:
            return rpc.send_and_wait(frm, escrow, data, expect_ok=expect_ok)

        withdraw_stats = {"ok": 0, "failed": 0}
        scripted_entries: list[dict] = []

        def withdraw(account: str, recipient: str, entry: dict | None = None) -> bool:
            """withdraw() sends the account's whole credit, so a second call in the
            same fixture legitimately fails with InvalidAmount. Record it."""
            receipt = rpc.send_and_wait(account, escrow, E.cd_withdraw(recipient), expect_ok=False)
            ok = int(receipt["status"], 16) == 1
            withdraw_stats["ok" if ok else "failed"] += 1
            if entry is not None:
                entry["withdrawals"] = entry.get("withdrawals", 0) + (1 if ok else 0)
                entry.setdefault("failed_withdrawals", 0)
                if not ok:
                    entry["failed_withdrawals"] += 1
            return ok

        def call_uint(target: str, data: str, block: int) -> int:
            out = rpc.call("eth_call", [{"to": target, "data": data}, hex(block)])
            return int(out, 16)

        def read_state(at_block: int) -> dict:
            block_info = rpc.get_block(at_block)
            return {
                "block": at_block,
                "block_hash": block_info["hash"],
                "block_timestamp": int(block_info["timestamp"], 16),
                "total_locked": call_uint(escrow, E.calldata("totalLocked", []), at_block),
                "total_claimable": call_uint(escrow, E.calldata("totalClaimable", []), at_block),
                "liabilities": call_uint(escrow, E.calldata("liabilities", []), at_block),
                "next_bounty_id": call_uint(escrow, E.calldata("nextBountyId", []), at_block),
                "token_balance": call_uint(token, E.cd_balance_of(escrow), at_block),
                "claimable": {acc: call_uint(escrow, E.cd_claimable(acc), at_block)
                              for acc in accounts},
                "bounties": [
                    {
                        "id": bounty_id,
                        "creator": E.abi.dec_address(E.abi.split_words(
                            rpc.call("eth_call", [{"to": escrow, "data": E.cd_bounties(bounty_id)},
                                                  hex(at_block)]))[0]),
                        "winner": E.abi.dec_address(E.abi.split_words(
                            rpc.call("eth_call", [{"to": escrow, "data": E.cd_bounties(bounty_id)},
                                                  hex(at_block)]))[1]),
                        "deadline": E.abi.dec_uint(E.abi.split_words(
                            rpc.call("eth_call", [{"to": escrow, "data": E.cd_bounties(bounty_id)},
                                                  hex(at_block)]))[2]),
                        "submissions": E.abi.dec_uint(E.abi.split_words(
                            rpc.call("eth_call", [{"to": escrow, "data": E.cd_bounties(bounty_id)},
                                                  hex(at_block)]))[3]),
                        "status": E.abi.dec_uint(E.abi.split_words(
                            rpc.call("eth_call", [{"to": escrow, "data": E.cd_bounties(bounty_id)},
                                                  hex(at_block)]))[4]),
                        "reward": E.abi.dec_uint(E.abi.split_words(
                            rpc.call("eth_call", [{"to": escrow, "data": E.cd_bounties(bounty_id)},
                                                  hex(at_block)]))[5]),
                        "brief_hash": E.abi.dec_bytes32(E.abi.split_words(
                            rpc.call("eth_call", [{"to": escrow, "data": E.cd_bounties(bounty_id)},
                                                  hex(at_block)]))[6]),
                    }
                    for bounty_id in ids
                ],
            }

        ids: list[int] = []
        for i in range(BOUNTY_COUNT):
            pattern = i % 7
            creator = creators[i % len(creators)]
            # wallet workers[0] deliberately collects many credits
            worker = workers[0] if i < 40 else workers[i % len(workers)]
            receipt = send(creator, E.cd_create_bounty(REWARD, deadline, brief_hash(i),
                                                       f"fixture://brief/{i}"))
            bounty_id = i + 1  # nextBountyId starts at 1 in the escrow
            ids.append(bounty_id)
            entry = {"id": bounty_id, "pattern": pattern, "creator": creator,
                     "worker": worker, "deadline": deadline, "reward": REWARD,
                     "topups": 0, "status": "Open", "withdrawn": 0}

            # operator delegation on every other bounty
            if i % 2 == 0 and pattern != 2:  # pattern 2 must keep zero submissions
                # operators[author][operator] -> the AUTHOR approves the operator
                send(worker, E.cd_set_operator(operator, True))
                send(operator, E.cd_submit_work_for(bounty_id, worker,
                                                    brief_hash(1000 + i), f"fixture://proof/{i}"))
                entry["operator"] = operator
            elif pattern in (0, 1, 3, 4, 6):
                send(worker, E.cd_submit_work(bounty_id, brief_hash(1000 + i),
                                              f"fixture://proof/{i}"))

            if pattern == 3:
                send(creator, E.cd_add_reward(bounty_id, TOPUP))
                send(creator, E.cd_add_reward(bounty_id, TOPUP))
                entry["topups"] = 2 * TOPUP

            if pattern in (0, 1, 3, 4):
                send(creator, E.cd_award(bounty_id, worker))
                entry["status"] = "Awarded"
            elif pattern == 2:
                send(creator, E.cd_cancel(bounty_id))
                entry["status"] = "Cancelled"

            if pattern == 0 and i % 2 == 0:
                withdraw(worker, accounts[4], entry)
            elif pattern == 3 and i % 2 == 1:
                withdraw(worker, worker, entry)

            if pattern == 4:
                # issuer pause -> the withdrawal fails and the credit is preserved
                rpc.send_and_wait(creators[5], token, E.cd_set_paused(True))
                failed = rpc.send_and_wait(worker, escrow, E.cd_withdraw(worker), expect_ok=False)
                assert int(failed["status"], 16) == 0, "paused withdrawal should have reverted"
                entry["failed_withdrawals"] = 1
                rpc.send_and_wait(creators[5], token, E.cd_set_paused(False))
                entry["failed_withdrawals"] += 1  # the paused attempt above
                assert withdraw(worker, worker, entry), "withdrawal after unpause must succeed"

            if pattern == 2 and i % 3 == 0:
                withdraw(creator, creator, entry)

            scripted.append(entry)

        # direct token donations: surplus, not credit for anyone
        donations = []
        for amount in (DONATION, DONATION // 3, 1234):
            rpc.send_and_wait(accounts[9], token, E.cd_transfer(escrow, amount))
            donations.append(amount)

        state_early = read_state(rpc.block_number())  # pre-time-travel snapshot

        # time travel past every deadline and the review window
        rpc.increase_time(9 * 24 * 3600)
        rpc.mine()

        for entry in scripted:
            if entry["pattern"] == 6:
                sender = creators[(entry["id"] + 3) % len(creators)]
                send(sender, E.cd_expire(entry["id"]))
                entry["status"] = "Expired"
                withdraw(entry["creator"], entry["creator"], entry)
            # pattern 1 deliberately keeps its credit outstanding so that the
            # snapshot contains per-wallet credits, including one wallet credited
            # by many different bounties.

        # ---- capture -------------------------------------------------------
        snapshot_block = rpc.block_number()
        raw_logs = rpc.get_logs(escrow, 0, snapshot_block)
        token_logs = rpc.get_logs(token, 0, snapshot_block)
        logs = [E.decode_log(lg) for lg in raw_logs + token_logs]
        logs = [lg for lg in logs if lg is not None]
        logs.sort(key=lambda lg: (lg["block"], lg["log_index"]))

        state = read_state(snapshot_block)

        block_hashes: dict[str, str] = {}
        for height in sorted({lg["block"] for lg in logs} | {snapshot_block}):
            block_hashes[str(height)] = rpc.get_block(height)["hash"]

        fixture = {
            "generated_by": "scripts/gen_fixture.py",
            "block_hashes": block_hashes,
            "rpc_url": RPC_URL,
            "chain_id": rpc.chain_id(),
            "contracts": {"escrow": escrow, "token": token},
            "accounts": accounts,
            "donations": donations,
            "bounties_created": len(ids),
            "logs": logs,
            "state": state,
            "state_early": state_early,
            "scripted_model": scripted,
            "withdraw_stats": withdraw_stats,
            "event_counts": {},
        }
        counts: dict[str, int] = {}
        for lg in logs:
            counts[lg["name"]] = counts.get(lg["name"], 0) + 1
        fixture["event_counts"] = counts
        # freeze the fixture: the reconciler works offline from this file
        fixture["logs_raw"] = [
            {"address": lg["address"], "topics": lg["topics"], "data": lg["data"],
             "blockNumber": lg["blockNumber"], "logIndex": lg["logIndex"],
             "transactionHash": lg["transactionHash"]}
            for lg in raw_logs + token_logs
        ]

        (RESULTS / "fixture.json").write_text(json.dumps(fixture, indent=2))
        (RESULTS / "fixture_summary.json").write_text(json.dumps({
            "bounties": len(ids),
            "event_counts": counts,
            "snapshot_block": snapshot_block,
            "token_balance": state["token_balance"],
            "liabilities": state["liabilities"],
            "surplus_from_donations": state["token_balance"] - state["liabilities"],
            "donations": donations,
            "contracts": fixture["contracts"],
        }, indent=2))

        print(json.dumps({
            "bounties": len(ids),
            "logs": len(logs),
            "event_counts": counts,
            "snapshot_block": snapshot_block,
            "locked": state["total_locked"],
            "claimable": state["total_claimable"],
            "liabilities": state["liabilities"],
            "token_balance": state["token_balance"],
            "surplus": state["token_balance"] - state["liabilities"],
            "donations": donations,
            "contracts": fixture["contracts"],
        }, indent=2))
        return 0
    finally:
        anvil.terminate()
        try:
            anvil.wait(timeout=10)
        except subprocess.TimeoutExpired:
            anvil.kill()


if __name__ == "__main__":
    sys.exit(main())
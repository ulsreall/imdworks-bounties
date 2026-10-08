#!/usr/bin/env python3
"""Submit the ten proofs on chain from the registered agent wallet.

The funded bounties require `submitWork(id, proofHash, proofURI)` on the escrow
(chain 4663), then the platform re-indexes the confirmed tx via
`/api/escrow/{uuid}/sync`. Total gas for all ten submissions is well under
0.0001 ETH at the current 0.02 gwei gas price.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path("/root/imdworks-work")
RESULTS = ROOT / "results"
RPC = "https://rpc.mainnet.chain.robinhood.com"
ESCROW = "0xd93aEd6f9F89699969B4967364D464fe7856EFaE"
BASE = "https://imdworks.fun"
CK = "/tmp/imdworks_cookies.txt"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
CAST = "/root/.foundry/bin/cast"
DRY = "--dry-run" in sys.argv


def curl_json(method: str, path: str, payload: dict | None = None,
              expect: tuple[int, ...] = (200,)) -> tuple[int, dict]:
    cmd = ["curl", "-s", "-o", "/tmp/sync_resp", "-w", "%{http_code}", "-X", method,
           f"{BASE}{path}", "-H", f"Origin: {BASE}", "-H", f"Referer: {BASE}/",
           "-H", f"User-Agent: {UA}", "-H", "Accept: application/json",
           "-b", CK, "-c", CK, "--max-time", "40"]
    if payload is not None:
        cmd += ["-H", "Content-Type: application/json", "-d", json.dumps(payload)]
    p = subprocess.run(cmd, capture_output=True, text=True)
    code = int(p.stdout.strip() or 0)
    try:
        data = json.loads(pathlib.Path("/tmp/sync_resp").read_text())
    except Exception:  # noqa: BLE001
        data = {}
    if code not in expect:
        raise RuntimeError(f"{method} {path} -> {code}: {json.dumps(data)[:250]}")
    return code, data


def main() -> int:
    wallet_path = pathlib.Path(
        next((sys.argv[i + 1] for i, a in enumerate(sys.argv) if a == "--wallet"),
             ROOT / "wallets" / "imdworks-submitter.json"))
    wallet = json.loads(wallet_path.read_text())
    pk = wallet["private_key"]
    addr = wallet["address"]
    plan = json.loads((RESULTS / "submissions_plan.json").read_text())

    balance = int(subprocess.run([CAST, "balance", addr, "--rpc-url", RPC],
                                 capture_output=True, text=True).stdout.strip())
    print(f"submitter {addr} (key file {wallet_path}) balance {balance} wei "
          f"({balance / 1e18:.9f} ETH)")
    if balance < 5_000_000_000_000:  # 0.000005 ETH
        print("ERROR: not enough gas on Robinhood Chain (chain 4663). "
              "Fund the wallet with at least 0.00005 ETH and re-run.")
        return 2
    if DRY:
        print("dry-run: balance ok, would submit", len(plan), "proofs")
        return 0

    out = []
    for item in plan:
        escrow_id = item["escrow_id"]
        proof_hash = item["readme_keccak256"]
        proof_uri = item["artifact_url"]
        bid = item["bounty_id"]
        n = item["number"]
        print(f"#{n}: submitWork({escrow_id}, {proof_hash[:18]}…, {proof_uri[:44]}…)",
              end=" ", flush=True)
        proc = subprocess.run(
            [CAST, "send", ESCROW,
             f"submitWork(uint256,bytes32,string)", str(escrow_id), proof_hash, proof_uri,
             "--private-key", pk, "--rpc-url", RPC, "--json", "--async"],
            capture_output=True, text=True)
        if proc.returncode != 0:
            print("ERR", proc.stderr.strip()[:200])
            out.append({"number": n, "error": proc.stderr.strip()[:300]})
            continue
        raw_out = proc.stdout.strip()
        tx = json.loads(raw_out)["transactionHash"] if raw_out.startswith("{") else raw_out
        time.sleep(2.5)
        rec = subprocess.run([CAST, "receipt", tx, "--rpc-url", RPC, "--json"],
                             capture_output=True, text=True)
        status = "pending"
        try:
            status = "ok" if int(json.loads(rec.stdout)["status"], 16) == 1 else "reverted"
        except Exception:  # noqa: BLE001
            status = "receipt-unavailable"
        print(f"tx={tx[:18]}… {status}")
        sync = {"status": None}
        try:
            code, resp = curl_json("POST", f"/api/escrow/{bid}/sync", {"tx": tx})
            sync = {"status": code, "body": resp}
        except RuntimeError as exc:
            sync = {"error": str(exc)[:300]}
        out.append({"number": n, "escrow_id": escrow_id, "tx": tx, "status": status, "sync": sync})
        time.sleep(1.2)

    (RESULTS / "submission_onchain.json").write_text(json.dumps(out, indent=2))
    print(json.dumps([{"number": r["number"], "tx": r.get("tx", "")[:18] + "…",
                       "status": r.get("status"), "sync": r.get("sync", {}).get("status")}
                      for r in out], indent=2))
    print("\non-chain submission results: results/submission_onchain.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
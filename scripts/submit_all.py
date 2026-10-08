#!/usr/bin/env python3
"""Submit all ten bounty solutions through the platform's public agent API.

Flow (all local signing, no gas, no production exploit):
  1. ensure an agent wallet exists (cast wallet new, stored 0600, never published)
  2. POST /api/auth/challenge {wallet} -> sign the SIWE message locally
  3. POST /api/auth/verify {id, signature} -> session cookie
  4. POST /api/me/agents {name, description} -> bearer API key (shown once)
  5. per bounty: POST /api/bounties/{id}/claim, then POST /api/bounties/{id}/submissions
     with {summary, content, artifact_url}

Uses curl (not urllib) because the site sits behind a TLS-fingerprinting proxy.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path("/root/imdworks-work")
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)

BASE = "https://imdworks.fun"
ORIGIN = BASE
COOKIES = "/tmp/imdworks_cookies.txt"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
CAST = "/root/.foundry/bin/cast"
WALLET_FILE = ROOT / ".agent-wallet.json"
KEY_FILE = ROOT / ".agent-key.json"
DRY = "--dry-run" in sys.argv


def curl(method: str, path: str, payload: dict | None = None,
         bearer: str | None = None, expect: tuple[int, ...] = (200,)) -> tuple[int, dict]:
    cmd = ["curl", "-s", "-o", "/tmp/imdworks_resp", "-w", "%{http_code}",
           "-X", method, f"{BASE}{path}",
           "-H", f"Origin: {ORIGIN}", "-H", f"Referer: {ORIGIN}/", "-H", f"User-Agent: {UA}",
           "-H", "Accept: application/json", "-b", COOKIES, "-c", COOKIES,
           "--max-time", "40"]
    if payload is not None:
        cmd += ["-H", "Content-Type: application/json", "-d", json.dumps(payload)]
    if bearer:
        cmd += ["-H", f"Authorization: Bearer {bearer}"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    code = int(proc.stdout.strip() or 0)
    body = "/tmp/imdworks_resp"
    try:
        data = json.loads(pathlib.Path(body).read_text()) if pathlib.Path(body).exists() else {}
    except json.JSONDecodeError:
        data = {"raw": pathlib.Path(body).read_text()[:500] if pathlib.Path(body).exists() else ""}
    if code not in expect:
        raise RuntimeError(f"{method} {path} -> {code}: {json.dumps(data)[:300]}")
    return code, data


def sign_message(pk: str, message_hex: str) -> str:
    proc = subprocess.run([CAST, "wallet", "sign", "--private-key", pk, message_hex],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"sign failed: {proc.stderr.strip()[:300]}")
    return proc.stdout.strip().splitlines()[-1].strip()


def ensure_wallet() -> dict:
    if WALLET_FILE.exists():
        return json.loads(WALLET_FILE.read_text())
    proc = subprocess.run([CAST, "wallet", "new"], capture_output=True, text=True)
    lines = proc.stdout.splitlines()
    addr = pk = ""
    for line in lines:
        if line.startswith("Address:"):
            addr = line.split()[-1].strip()
        if line.startswith("Private key:"):
            pk = line.split()[-1].strip()
    if not addr or not pk:
        raise RuntimeError("could not parse cast wallet new output")
    wallet = {"address": addr, "private_key": pk}
    WALLET_FILE.write_text(json.dumps(wallet), encoding="utf-8")
    pathlib.Path(WALLET_FILE).chmod(0o600)
    return wallet


def auth(wallet: dict) -> None:
    _, chal = curl("POST", "/api/auth/challenge", {"wallet": wallet["address"]})
    cid = chal["id"]
    message = chal["message"]
    msg_hex = "0x" + message.encode("utf-8").hex()
    sig = sign_message(wallet["private_key"], msg_hex)
    curl("POST", "/api/auth/verify", {"id": cid, "signature": sig})
    _, me = curl("GET", "/api/me")
    got = me.get("wallet", "").lower()
    if got != wallet["address"].lower():
        raise RuntimeError(f"auth mismatch: /api/me wallet {got} != {wallet['address']}")
    print(f"authed as {me.get('name') or wallet['address']} ({me.get('wallet')})")


def ensure_agent_key() -> str:
    if KEY_FILE.exists():
        return json.loads(KEY_FILE.read_text())["key"]
    _, resp = curl("POST", "/api/me/agents",
                   {"name": "Celia Research Unit",
                    "description": "Reproducible local-fixture deliverables for the public bounty board."})
    key = resp.get("key")
    if not key:
        raise RuntimeError(f"agent registration returned no key: {json.dumps(resp)[:300]}")
    KEY_FILE.write_text(json.dumps({"key": key}), encoding="utf-8")
    pathlib.Path(KEY_FILE).chmod(0o600)
    print(f"agent registered, key stored to {KEY_FILE.name} (chmod 600)")
    return key


def main() -> int:
    plan = json.loads((RESULTS / "submissions_plan.json").read_text())
    wallet = ensure_wallet()
    auth(wallet)
    if DRY:
        print("dry-run: auth ok, plan has", len(plan), "bounties; not registering agent/submitting")
        return 0
    key = ensure_agent_key()
    out = []
    for item in plan:
        bid = item["bounty_id"]
        n = item["number"]
        print(f"claiming #{n} ({bid[:8]}) ...", end=" ", flush=True)
        try:
            code, resp = curl("POST", f"/api/bounties/{bid}/claim", {}, bearer=key,
                              expect=(200, 409))
            claim = {"status": code, "body": resp}
            print(f"claim={code}", end=" ")
        except RuntimeError as exc:
            claim = {"error": str(exc)}
            print("claim-ERR", end=" ")
        time.sleep(1.2)
        print("submitting ...", end=" ", flush=True)
        try:
            code, resp = curl("POST", f"/api/bounties/{bid}/submissions",
                              {"summary": item["summary"], "content": item["content"],
                               "artifact_url": item["artifact_url"]},
                              bearer=key, expect=(200, 201, 202, 409))
            sub = {"status": code, "body": resp}
            print(f"sub={code} ✓" if code < 400 else f"sub={code}!")
        except RuntimeError as exc:
            sub = {"error": str(exc)}
            print("sub-ERR")
        out.append({"number": n, "bounty_id": bid, "claim": claim, "submission": sub})
        time.sleep(1.2)
    (RESULTS / "submission_results.json").write_text(json.dumps(out, indent=2))
    print("\nresults written to results/submission_results.json")
    print(json.dumps([{ "number": r["number"],
                        "claim": r["claim"].get("status", r["claim"].get("error", "?")),
                        "submission": r["submission"].get("status", r["submission"].get("error", "?")) }
                      for r in out], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
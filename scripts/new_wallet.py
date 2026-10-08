#!/usr/bin/env python3
"""Generate a fresh BIP39 wallet for bounty submission gas, back it up, print only public data."""
import json, os, pathlib, stat, sys, datetime
from eth_account import Account

OUT = pathlib.Path("/root/imdworks-work/wallets/imdworks-submitter.json")
OUT.parent.mkdir(parents=True, exist_ok=True)
if OUT.exists() and "--force" not in sys.argv:
    existing = json.loads(OUT.read_text())
    print(json.dumps({"address": existing["address"], "file": str(OUT),
                      "note": "wallet already exists, use --force to regenerate"}))
    raise SystemExit(0)

Account.enable_unaudited_hdwallet_features()
acct, mnemonic = Account.create_with_mnemonic(num_words=12, passphrase="")
pk = acct.key.hex()
if not pk.startswith("0x"):
    pk = "0x" + pk

payload = {
    "label": "imdworks bounty submitter (gas wallet)",
    "address": acct.address,
    "private_key": pk,
    "mnemonic": mnemonic,
    "path": "m/44'/60'/0'/0/0",
    "chain": {"name": "Robinhood Chain", "chain_id": 4663,
              "rpc": "https://rpc.mainnet.chain.robinhood.com"},
    "created_at": datetime.datetime.now(datetime.UTC).isoformat(),
    "purpose": "pay gas for submitWork(id, proofHash, proofURI) on the IMDWorks escrow",
}
OUT.write_text(json.dumps(payload, indent=2), encoding="utf-8")
os.chmod(OUT, stat.S_IRUSR | stat.S_IWUSR)  # 0600

# sanity: the private key must reproduce the address
derived = Account.from_key(pk).address
assert derived.lower() == acct.address.lower(), "key/address mismatch"
print(json.dumps({"address": acct.address, "file": str(OUT),
                  "file_mode": oct(stat.S_IMODE(os.stat(OUT).st_mode)),
                  "mnemonic_words": len(mnemonic.split()),
                  "self_check": "address reproducible from stored private key"}, indent=2))

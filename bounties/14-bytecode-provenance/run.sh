#!/usr/bin/env bash
# Bounty #14 — one-command replay of the bytecode provenance report.
#
#   1. fetches the deployed runtime bytecode of the escrow (chain 4663)
#   2. hashes the published source + every OpenZeppelin dependency
#   3. rebuilds with solc 0.8.29 / optimizer 200 / evm paris
#   4. deploys locally on anvil with the same constructor argument and diffs
#      the runtime bytecode byte by byte, metadata reported separately
#   5. runs two negative controls (mutated statement, wrong token address);
#      both must be REJECTED or the verifier is not a verifier
#
# Evidence: evidence/evidence.json (machine readable) + verbose stdout.
set -uo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.foundry/bin:$PATH"
mkdir -p results

forge build >/dev/null 2>&1 || { echo "forge build failed"; exit 1; }
python3 scripts/verify.py
rc=$?

# mirror the machine-readable evidence where reviewers look for it
if [ -f evidence/evidence.json ]; then
  mkdir -p results
  python3 - <<'PY'
import json, pathlib
src = pathlib.Path("evidence/evidence.json")
dst = pathlib.Path("results/provenance.json")
dst.write_text(src.read_text())
d = json.loads(src.read_text())
print(f"evidence mirrored to {dst} — verdict: {d['verdict']['overall']}")
PY
fi
exit $rc

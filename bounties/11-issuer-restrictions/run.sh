#!/usr/bin/env bash
# Bounty #11 — one-command runner: executable behaviour matrix for issuer restrictions.
set -uo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.foundry/bin:$PATH"
mkdir -p results
rm -f results/mode-*.json
forge test --match-contract IssuerRestrictionsTest -vv
rc=$?
python3 scripts/matrix.py
{ echo "forge: $(forge --version | head -1)"; echo "solc: 0.8.29"; echo "escrow: unmodified src/IMDWorksEscrow.sol"; } > results/harness-info.txt
exit $rc

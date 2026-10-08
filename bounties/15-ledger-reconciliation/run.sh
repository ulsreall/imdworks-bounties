#!/usr/bin/env bash
# Bounty #15 — one-command replay.
#   1. starts a local anvil, deploys the unmodified escrow + a pausable fixture
#      token and drives 120 deterministic bounty lifecycles
#   2. freezes the fixture (logs + state at a fixed block) to results/fixture.json
#   3. reconciles independently from the event stream and runs the tamper suite
set -uo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.foundry/bin:$PATH"
mkdir -p results
forge build >/dev/null 2>&1 || { echo "forge build failed"; exit 1; }
python3 scripts/gen_fixture.py || exit 1
python3 scripts/reconcile.py

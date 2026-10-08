#!/usr/bin/env bash
# Bounty #10 — one-command replay:
#   1. regenerate the vector set and confirm every expected hash with `cast keccak`
#   2. run the Python and JavaScript implementations over the shared vectors
#   3. compare naive variants, then check against live chain data
set -uo pipefail
cd "$(dirname "$0")"
mkdir -p results
python3 scripts/gen_vectors.py || exit 1
python3 scripts/run.py

#!/usr/bin/env bash
# One-command acceptance replay for imdworks.fun bounty #07
# (reorg-safe bounty event indexer).
#
# Runs every fault scenario (normal, duplicate delivery, out-of-order batches,
# restart between log write and checkpoint, five-block reorg, and the combined
# case) plus the two negative cases, then asserts the incrementally-indexed
# database equals a fresh canonical replay.  Exits 0 ONLY if every scenario
# passes and both negative cases are correctly detected as failing.
#
# Pure Python 3.11 stdlib.  No network.  No paid RPC.  No private keys.
set -euo pipefail
cd "$(dirname "$0")"

PIN="$(git rev-parse HEAD 2>/dev/null || true)"
echo "[run.sh] pinned commit: ${PIN:-unversioned working tree}"
echo "[run.sh] python: $(python3 --version)"

python3 scripts/run.py

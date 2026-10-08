#!/usr/bin/env bash
# Bounty #09 — one-command replay of the USDG decimal grammar evidence.
set -uo pipefail
cd "$(dirname "$0")"
mkdir -p results
python3 scripts/run.py

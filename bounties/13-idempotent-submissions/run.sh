#!/usr/bin/env bash
# One-command replay for imdworks.fun bounty #13 (idempotent submissions).
#
# Runs the whole workload (concurrent client + fault injection against the
# real HTTP/SQLite service AND the deliberately-naive service), aggregates the
# evidence into results/report.json and exits 0 ONLY if every acceptance
# assertion passes.  Stdlib only; no network; no secrets.
set -euo pipefail
cd "$(dirname "$0")"

rm -rf results
mkdir -p results

echo "[run.sh] starting workload (concurrency + fault injection) ..."
python3 -m src.client_workload --out results

echo "[run.sh] aggregating acceptance assertions ..."
python3 scripts/report.py --results results --out results/report.json

echo "[run.sh] done -> results/report.json"

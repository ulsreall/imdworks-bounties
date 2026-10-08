#!/usr/bin/env bash
#
# run.sh -- ONE command entry point for the bounty #12 benchmark.
#
# Behaviour:
#   1. regenerates the fixture corpus deterministically (attacks + controls)
#   2. runs the full benchmark TWICE inside src/bench.py:
#        Phase 1: naive baseline (expect: fooled by every attack)
#        Phase 2: defended runner (expect: blocks every attack, passes every
#                  benign control)
#   3. writes results/report.json
#   4. exits 0 ONLY if every gate holds, otherwise exits 1
#
# No network access, no real API keys, no real I/O: tools are simulated.

set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR" || exit 1

python3 src/make_fixtures.py || { echo "fixture generation failed"; exit 1; }
python3 src/bench.py
exit $?
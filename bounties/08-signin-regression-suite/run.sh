#!/usr/bin/env bash
# Bounty #08 — one-command runner for the wallet sign-in regression suite.
#
# Runs the adversarial suite against all four service variants (hardened,
# vuln_nonce_reuse, vuln_origin_unbound, vuln_race), all over local HTTP on
# 127.0.0.1 with ephemeral ports.
#
# Exit code 0  <=>  the hardened variant passes every case AND each of the
# three vulnerable variants is caught by at least one case (the regression
# value).  Anything else exits 1 (or 2 if the environment is broken).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="/root/.foundry/bin:$PATH"
cd "$HERE" || exit 2

if ! command -v cast >/dev/null 2>&1; then
    echo "FATAL: cast (Foundry) not on PATH; install Foundry or export PATH." >&2
    exit 2
fi

exec python3 src/suite.py --all "$@"

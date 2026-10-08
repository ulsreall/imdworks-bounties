#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Bounty #06 — one-command runner
#
#   ./run.sh
#
# 1. Runs the invariant suite against the UNMODIFIED IMDWorksEscrow
#    (>= 1000 sequences, depth 100) for two published seeds.
# 2. Runs the same invariants against a deliberately broken local mutation
#    (broken/BrokenEscrow.sol: award() never marks the bounty terminal) and
#    asserts that the suite FAILS, proving the harness detects the mutation.
# 3. Writes results/summary.json with tool versions, seeds, and verdicts.
# ---------------------------------------------------------------------------
set -uo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.foundry/bin:$PATH"
mkdir -p results

SEED_A=${SEED_A:-0x0000000000000000000000000000000000000000000000000000000000000a01}
SEED_B=${SEED_B:-0x0000000000000000000000000000000000000000000000000000000000000b02}
RUNS=${RUNS:-1000}
DEPTH=${DEPTH:-100}

FORGE_VERSION=$(forge --version | head -1)
SOLC_VERSION=$(forge --version | head -1)
ANVIL_VERSION=$(anvil --version | head -1)
echo "forge: $FORGE_VERSION"

run_real() {
  local seed="$1" out="results/real-${1: -4}.log"
  echo ">> real contract, seed $seed, runs $RUNS depth $DEPTH"
  FOUNDRY_INVARIANT_RUNS="$RUNS" FOUNDRY_INVARIANT_DEPTH="$DEPTH" \
    forge test --match-contract InvariantEscrowTest --fuzz-seed "$seed" -vv >"$out" 2>&1
  local rc=$?
  echo "   exit=$rc  log=$out"
  grep -E "invariants \(runs|Suite result|Fuzz seed" "$out" | sed 's/^/   /'
  return $rc
}

run_broken() {
  local out="results/broken.log"
  echo ">> mutated contract (must fail), runs ${BROKEN_RUNS:-250} depth ${BROKEN_DEPTH:-50}"
  FOUNDRY_PROFILE=broken FOUNDRY_INVARIANT_RUNS="${BROKEN_RUNS:-250}" \
    FOUNDRY_INVARIANT_DEPTH="${BROKEN_DEPTH:-50}" \
    forge test --match-contract BrokenInvariantTest >"$out" 2>&1
  local rc=$?
  echo "   exit=$rc (non-zero = mutation detected, as required)  log=$out"
  grep -E "FAIL:|Suite result" "$out" | head -4 | sed 's/^/   /'
  return $rc
}

run_real "$SEED_A"; RC_A=$?
run_real "$SEED_B"; RC_B=$?
run_broken;        RC_MUT=$?

python3 - "$SEED_A" "$SEED_B" "$RUNS" "$DEPTH" "$RC_A" "$RC_B" "$RC_MUT" <<'PY'
import json, sys, re, pathlib
seed_a, seed_b, runs, depth, rc_a, rc_b, rc_mut = sys.argv[1:8]
out = {
    "bounty": 6,
    "title": "Build a stateful escrow accounting invariant harness",
    "toolchain": {
        "forge": pathlib.Path("results/harness-info.txt").read_text().strip().splitlines() if pathlib.Path("results/harness-info.txt").exists() else [],
    },
    "config": {"runs": int(runs), "depth": int(depth), "fail_on_revert": False,
               "sequences_total": int(runs) * 2, "calls_per_sequence": int(depth)},
    "seeds": [seed_a, seed_b],
    "runs": [],
    "mutation": {},
    "verdict": {},
}
for seed, rc in ((seed_a, int(rc_a)), (seed_b, int(rc_b))):
    log = pathlib.Path(f"results/real-{seed[-4:]}.log")
    log = log if log.exists() else None
    text = log.read_text() if log else ""
    m = re.search(r"invariants \(runs: (\d+), calls: (\d+), reverts: (\d+)\)", text)
    out["runs"].append({
        "seed": seed,
        "exit_code": rc,
        "invariant_run": m.group(0) if m else None,
        "passed": rc == 0,
        "log": str(log) if log else None,
        "failing": re.findall(r"\[FAIL[^\]]*\] (\w+)", text),
    })
btext = pathlib.Path("results/broken.log").read_text() if pathlib.Path("results/broken.log").exists() else ""
out["mutation"] = {
    "file": "broken/BrokenEscrow.sol",
    "change": "award() no longer sets status = Awarded (bounty can be awarded and paid repeatedly)",
    "exit_code": int(rc_mut),
    "detected": int(rc_mut) != 0,
    "detected_by": re.findall(r"\[FAIL: ([^\]]*)\] (\w+)", btext),
}
out["verdict"] = {
    "real_invariants_hold": all(r["passed"] for r in out["runs"]),
    "mutation_detected": out["mutation"]["detected"],
    "overall": "PASS" if all(r["passed"] for r in out["runs"]) and out["mutation"]["detected"] else "FAIL",
}
pathlib.Path("results/summary.json").write_text(json.dumps(out, indent=2))
print(json.dumps(out["verdict"], indent=2))
PY

{ echo "forge:   $FORGE_VERSION"; echo "anvil:   $ANVIL_VERSION"; echo "solc:    0.8.29 (pinned in foundry.toml, used for build + tests)"; echo "host:    $(uname -srm)"; } > results/harness-info.txt
echo "summary: results/summary.json"

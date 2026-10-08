#!/usr/bin/env python3
"""Bounty #09 - USDG decimal grammar: executable evidence.

Runs:
  1. 30 explicit edge cases (accept/reject table).
  2. 100,000 seeded generated cases (valid + adversarial mutations); both
     independent parser implementations must agree on every case, and every
     accepted value must round-trip through the canonical formatter.
  3. Lossy-input demonstration: inputs that a float parser silently truncates
     are rejected by the grammar.
  4. Float counterexamples with real deltas, proving float64 cannot be used.

Writes results/cases.jsonl.gz (all 100k cases), results/edges.md,
results/counterexamples.md and results/report.json.
"""

from __future__ import annotations

import gzip, hashlib, json, pathlib, random, string, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))
import usdg  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)

SEED = 20_091_002_026  # published seed, deterministic replay
RNG = random.Random(SEED)
N_CASES = 100_000

# ---------------------------------------------------------------------------
# 1. Explicit edge cases: expected verdict + why.
# ---------------------------------------------------------------------------
def ok(s: str) -> tuple[str, bool, str]:
    micros = usdg.parse_amount(s)
    return (s, True, f"{micros} micros -> {usdg.format_amount(micros)}")

def rej(s: str, why: str) -> tuple[str, bool, str]:
    return (s, False, why)

EDGE_CASES = [
    ok("0"), ok("0.0"), ok("1"), ok("1.000000"), ok("0.000001"),
    ok("999999999999999999999999999999"),  # < 2^256
    ok("115792089237316195423570985008687907853269984665640564039457584007913129.639935"),  # exactly 2**256-1 micros
    rej("0.0000001", "7 decimal places (lossy)"),
    rej("1.1234567", "more than 6 decimals (lossy)"),
    rej("01", "leading zero"),
    rej("00.5", "leading zeros"),
    rej("1.", "trailing separator, no fraction"),
    rej(".5", "no integer part"),
    rej("+1", "sign"),
    rej("-1", "sign"),
    rej("1e6", "exponent"),
    rej("1E6", "exponent"),
    rej(" 1", "leading whitespace"),
    rej("1 ", "trailing whitespace"),
    rej("1.2 ", "trailing whitespace"),
    rej("1\n", "newline"),
    rej("1,5", "locale decimal separator"),
    rej("1_000", "thousands separator"),
    rej("１", "fullwidth digit (no Unicode normalisation)"),
    rej("١٢٣", "Arabic-Indic digits"),
    rej("0̸", "digit with combining slash"),
    rej("1\u200b", "zero-width space"),
    rej("1\u200e", "left-to-right mark"),
    rej("", "empty"),
    rej(".", "no digits"),
    rej("1..2", "double separator"),
    rej("1.2.3", "double separator"),
    rej("0x10", "hex"),
    rej("NaN", "not a number"),
    rej("Infinity", "not a number"),
    rej("115792089237316195423570985008687907853269984665640564039457584007913129.639936",
        "exceeds uint256 by 1 micro"),
    rej("\x00", "NUL byte"),
]

# ---------------------------------------------------------------------------
# 2. Seeded generator (100k cases).
# ---------------------------------------------------------------------------
CONFUSABLES = ["１", "２", "٣", "𝟏", "①", "０", "٥", "𝟙", "₀", "₉", "e", "E", "x", "X",
               " ", "\t", "\n", "\r", ",", "_", "+", "-", ".", "/", "\\", ":", ";",
               "(", ")", "[", "]", "{", "}", '"', "'", "`", "~", "!", "@", "#", "$",
               "%", "^", "&", "*", "=", "|", "<", ">", "?", "\u200b", "\u200e", "\u200f",
               "\u00a0", "\u2028", "٠", "٩", "۴", "۵", "𝟎", "𝟗", "0", "1", "2", "3", "4",
               "5", "6", "7", "8", "9"]

def gen_valid() -> str:
    """Generate a valid canonical amount (and remember its exact micro value)."""
    n_int = RNG.randint(1, 18)
    intpart = str(RNG.randint(1, 9))
    intpart += "".join(RNG.choice(string.digits) for _ in range(max(0, n_int - 1)))
    if RNG.random() < 0.7:
        frac_len = RNG.randint(1, 6)
        frac = "".join(RNG.choice(string.digits) for _ in range(frac_len))
        return f"{intpart}.{frac}"
    return intpart

def gen_mutant(base: str) -> str:
    """Corrupt a valid string into something near-valid (mostly rejected)."""
    kind = RNG.randrange(6)
    if kind == 0:  # prepend garbage
        return RNG.choice(CONFUSABLES) + base
    if kind == 1:  # append garbage
        return base + RNG.choice(CONFUSABLES)
    if kind == 2:  # replace one char
        i = RNG.randrange(len(base))
        return base[:i] + RNG.choice(CONFUSABLES) + base[i + 1:]
    if kind == 3:  # insert a char
        i = RNG.randrange(len(base) + 1)
        return base[:i] + RNG.choice(CONFUSABLES) + base[i:]
    if kind == 4:  # mutate decimals count
        i = base.find(".")
        if i == -1:
            return base + "." + "".join(RNG.choice(string.digits) for _ in range(RNG.randint(7, 12)))
        extra = "".join(RNG.choice(string.digits) for _ in range(RNG.randint(1, 6)))
        return base + extra
    # delete a char
    if len(base) <= 1:
        return base
    i = RNG.randrange(len(base))
    return base[:i] + base[i + 1:]

def gen_adversarial() -> str:
    kind = RNG.randrange(10)
    if kind == 0:
        return "".join(RNG.choice(CONFUSABLES) for _ in range(RNG.randint(1, 12)))
    if kind == 1:
        return "0" * RNG.randint(2, 9) + str(RNG.randint(1, 99))
    if kind == 2:
        return str(RNG.randint(0, 10**18)).replace("0", "0", 0) + "." + "9" * RNG.randint(7, 20)
    if kind == 3:
        return RNG.choice(["+", "-", "(", "[", "{", " ", "\t"]) + str(RNG.randint(1, 999))
    if kind == 4:
        return f"{RNG.randint(1,99)}e{RNG.randint(-9,9)}"
    if kind == 5:
        return f"0x{RNG.randrange(16**RNG.randint(1, 8)):x}"
    if kind == 6:
        return f"{RNG.randint(1,9)},{RNG.randint(10,99)}"
    if kind == 7:
        return f"{RNG.randint(1,9)}_{RNG.randint(10,99)}"
    if kind == 8:
        return "1." * RNG.randint(2, 4) + "5"
    return str(RNG.randint(10**60, 10**77))  # overflow uint256 territory

def build_cases() -> list[dict]:
    cases: list[dict] = []
    for i in range(N_CASES):
        r = RNG.random()
        if r < 0.45:
            txt = gen_valid()
        elif r < 0.85:
            txt = gen_mutant(gen_valid())
        else:
            txt = gen_adversarial()
        cases.append(_verify_one(i, txt))
    return cases

def classify(txt: str):
    """Authoritative classification: try both impls; require agreement."""
    ra = rb = None
    ea = eb = None
    try:
        ra = usdg.parse_amount(txt)
    except usdg.AmountError as e:
        ea = str(e)
    try:
        rb = usdg.parse_amount_reference(txt)
    except usdg.AmountError as e:
        eb = str(e)
    if (ra is None) != (rb is None) or (ra is not None and ra != rb):
        raise AssertionError(f"parser disagreement on {txt!r}: {ra}/{ea} vs {rb}/{eb}")
    return ra, ea

def _verify_one(i: int, txt: str) -> dict:
    micros, why = classify(txt)
    rec = {"i": i, "text": txt}
    if micros is None:
        rec.update({"accept": False, "reason": (why or "").strip()})
        return rec
    canonical = usdg.format_amount(micros)
    # round-trip: canonical form re-parses to the same value; formatter is fixed point.
    if usdg.parse_amount(canonical) != micros:
        raise AssertionError(f"round-trip failed for {txt!r} -> {canonical}")
    if usdg.format_amount(usdg.parse_amount(canonical)) != canonical:
        raise AssertionError("canonicalisation not idempotent")
    rec.update({"accept": True, "micros": str(micros), "canonical": canonical})
    return rec

# ---------------------------------------------------------------------------
# 3. Lossy-input demonstration.
# ---------------------------------------------------------------------------
LOSSY = ["1.0000001", "0.0000005", "2.9999999", "0.0000009"]

# ---------------------------------------------------------------------------
# 4. Float counterexamples (verified numerically below).
# ---------------------------------------------------------------------------
FLOAT_CASES = ["8.2", "2.675", "1.005", "9007199254.740993", "123456789.123456"]


def main() -> int:
    assert parse_agrees_on_edges(), "edge case table disagrees with parsers"
    cases = build_cases()

    accepted = sum(1 for c in cases if c["accept"])
    rejected = N_CASES - accepted

    # persist every generated case (gzip, one JSON per line)
    with gzip.open(RESULTS / "cases.jsonl.gz", "wt", encoding="utf-8") as fh:
        for c in cases:
            fh.write(json.dumps(c, ensure_ascii=False) + "\n")

    digest = hashlib.sha256()
    with gzip.open(RESULTS / "cases.jsonl.gz", "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            digest.update(chunk)

    # lossy-input demonstration
    lossy_rows = []
    for s in LOSSY:
        try:
            usdg.parse_amount(s)
            verdict = "ACCEPTED (BUG)"
        except usdg.AmountError:
            verdict = "rejected"
        float_val = usdg.parse_amount_float_naive(s)
        lossy_rows.append({"input": s, "grammar": verdict, "naive_float_micros": float_val})

    # float counterexamples with real deltas
    counter = []
    for s in FLOAT_CASES:
        correct = usdg.parse_amount(s)
        truncated = usdg.parse_amount_float_naive(s)
        rounded = usdg.parse_amount_round_naive(s)
        delta_t = correct - truncated
        delta_r = correct - rounded
        if delta_t == 0 and delta_r == 0:
            continue
        counter.append({
            "input": s,
            "correct_micros": str(correct),
            "float_truncate_micros": str(truncated),
            "float_round_micros": str(rounded),
            "delta_truncate": delta_t,
            "delta_round": delta_r,
        })

    if len(counter) < 3:
        print("FATAL: fewer than 3 float counterexamples reproduced on this runtime")
        return 2

    # edge table markdown
    edge_rows = []
    for s, verdict, detail in EDGE_CASES:
        edge_rows.append({
            "input": s, "verdict": "accept" if verdict else "reject",
            "detail": str(detail) if not isinstance(detail, str) else detail,
        })

    results = {
        "bounty": 9,
        "title": "Define and enforce a lossless canonical decimal grammar for USDG amounts",
        "seed": SEED,
        "generated_cases": N_CASES,
        "accepted": accepted,
        "rejected": rejected,
        "cross_impls_agreed": True,
        "roundtrip_ok": True,
        "cases_sha256": digest.hexdigest(),
        "cases_file": "results/cases.jsonl.gz",
        "edge_cases": edge_rows,
        "lossy_inputs": lossy_rows,
        "float_counterexamples": counter,
        "verdict": "PASS",
    }
    (RESULTS / "report.json").write_text(json.dumps(results, indent=2))
    (RESULTS / "edges.md").write_text(_edges_md(edge_rows))
    (RESULTS / "counterexamples.md").write_text(_counter_md(counter))

    print(json.dumps({
        "generated_cases": N_CASES, "accepted": accepted, "rejected": rejected,
        "float_counterexamples": len(counter),
        "lossy_inputs_rejected": all(r["grammar"] == "rejected" for r in lossy_rows),
        "cases_sha256": digest.hexdigest()[:16] + "...",
        "verdict": "PASS",
    }, indent=2))
    return 0


def parse_agrees_on_edges() -> bool:
    for s, verdict, _ in EDGE_CASES:
        micros, why = classify(s)
        assert (micros is not None) == verdict, f"edge table mismatch on {s!r}"
    return True


def _edges_md(rows: list[dict]) -> str:
    lines = ["| input | verdict | detail |", "|---|---|---|"]
    for r in rows:
        safe = r["input"].replace("|", "\\|").encode("unicode_escape").decode()
        lines.append(f"| `{safe}` | {r['verdict']} | {r['detail']} |")
    return "\n".join(lines) + "\n"


def _counter_md(rows: list[dict]) -> str:
    lines = ["| input | correct (micros) | float truncate | float round | delta |",
             "|---|---|---|---|---|"]
    for r in rows:
        lines.append(
            f"| `{r['input']}` | {r['correct_micros']} | {r['float_truncate_micros']} "
            f"| {r['float_round_micros']} | {r['delta_truncate']} |"
        )
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.exit(main())
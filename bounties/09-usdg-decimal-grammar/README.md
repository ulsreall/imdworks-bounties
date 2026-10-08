# Bounty #09 — Lossless canonical decimal grammar for USDG amounts

**Deliverable:** a precise grammar for human-readable USDG amounts, two independent implementations, an executable case generator, and proof that the obvious `float` approach is wrong.

Verdict: **PASS** — 100,000 generated cases, both implementations agree on every one, every accepted value round-trips, and lossy inputs are rejected instead of being silently truncated.

## Run it

```bash
./run.sh          # ~4 seconds: edge cases, 100k generated cases, float counterexamples
```

Seed (published, deterministic replay): **`20091002026`**. Output: `results/report.json`, `results/cases.jsonl.gz` (all 100,000 cases), `results/edges.md`, `results/counterexamples.md`.

## The grammar

```
amount    := integer [ "." fraction ]
integer   := "0" | ( digit1-9 *digit )
fraction  := 1*6 digit
value     <= 2**256 - 1 micro-units          (USDG has 6 decimals)
```

Explicitly **rejected** (each one is a test case, not a footnote):

| rejected input | why it matters |
|---|---|
| `01`, `00.5` | leading zeros ⇒ two spellings of one value ⇒ two hashes for one brief |
| `1.`, `.5`, `1..2`, `1.2.3` | malformed separators |
| `+1`, `-1` | signs are not part of the amount; negatives are unrepresentable |
| `1e6`, `1E6` | exponents invite precision ambiguity |
| ` 1`, `1 `, `1\n`, `1\t` | whitespace must not be tolerated: `keccak("1\n") != keccak("1")` |
| `1,5`, `1_000` | locale/grouping separators |
| `１`, `١٢٣`, `𝟏` | fullwidth, Arabic-Indic, mathematical digits — **Unicode normalisation is deliberately NOT applied**, because NFKC would fold them into ASCII and silently accept a different byte string |
| `0̸`, `1\u200b`, `1\u200e` | combining marks and zero-width/bidi characters |
| `1.0000001`, `0.0000005` | more than 6 decimals ⇒ lossy, must be rejected rather than rounded |
| `…129.639936` | one micro-unit above `2**256 - 1` (boundary case, with `…129.639935` accepted) |

## Result

```
generated cases   100000   (57,015 accepted / 42,985 rejected)
cross-implementation agreement     100%
round-trip (parse -> format -> parse) intact for every accepted case
float counterexamples reproduced   3
lossy inputs rejected              4/4
cases sha256 (gz)                  893b293e3e7878c5…
```

Two implementations must agree on all 100,000 cases:

* `src/usdg.py: parse_amount` — regex driven (`re.fullmatch`, ASCII-only classes)
* `src/usdg.py: parse_amount_reference` — hand-written character scanner with no regex, its own copy of every rule, and its own integer accumulation

Anchoring detail worth keeping: the regex is matched with **`fullmatch`, not `^…$`** — in Python `$` also matches *before a trailing newline*, so `"1\n"` would be accepted as `1`. The generator caught exactly that during development (the two implementations disagreed on `"1\n"`), which is why the harness compares two implementations instead of trusting one.

## Why floats cannot be used (measured, not asserted)

| input | correct micro-units | `int(float(x) * 1e6)` | delta |
|---|---|---|---|
| `8.2` | 8200000 | 8199999 | **-1** |
| `1.005` | 1005000 | 1004999 | **-1** |
| `9007199254.740993` | 9007199254740993 | 9007199254740994 | **+1** |

Rounding instead of truncating does not fix it: it shifts *which* inputs are wrong (and `2**256 - 1` micro-units cannot be represented in a float64 at all). The parser therefore works on decimal strings and integers only — no float ever appears in the code path.

## Reproduce a single case

```python
import sys; sys.path.insert(0, "src")
from usdg import parse_amount, format_amount, AmountError
parse_amount("1.500000")   # 1500000
format_amount(1500000)     # '1.5'
parse_amount("1.0000001")  # AmountError: more than 6 decimal places: lossy
```

## Limits

* The grammar is a *canonical* form: it is strict on purpose. A UI that wants to be forgiving should normalise user input into this form **once**, on input, and then hash the canonical bytes — not loosen the parser.
* Unicode is not normalised: mixed-script inputs are rejected rather than folded, which is what you want for a value that will be hashed and compared byte for byte (see bounty #10, which builds canonical brief hashing on top of this grammar).
* The 100,000-case generator is seeded and deterministic, so it is a regression suite, not a proof; the explicit edge-case table covers the boundary classes by construction.

## Files

```
run.sh                     one-command replay
src/usdg.py                grammar + two independent implementations + float traps
scripts/run.py             edge table, 100k generator, cross-check, counterexamples
results/report.json        machine-readable summary (seed, counts, hashes, verdict)
results/cases.jsonl.gz     all 100,000 generated cases with verdicts
results/edges.md           36-row accept/reject table
results/counterexamples.md float64 failures with deltas
```

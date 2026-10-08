# Bounty #10 — Canonical brief hashing, implemented independently in JavaScript and Python

**Problem:** a bounty board commits `keccak256(brief document)` on chain. If two implementations of "hash this brief" disagree by one byte — a key order, a `\u` escape, a line ending — the commitment is unverifiable. This repository implements the canonical form **twice**, in two languages, with no shared code, and compares them on a shared vector set.

Verdict: **PASS** — 70 valid vectors produce identical digests in JavaScript and Python, 16 invalid vectors are rejected by both, and the hash path is confirmed against live chain data.

## Run it

```bash
./run.sh
```

1. regenerates the vector set and confirms every expected digest with an independent oracle (`cast keccak`, foundry/alloy, fed the exact bytes on stdin);
2. runs both implementations over the shared vectors and diffs them;
3. executes every "trap" variant and reports the divergence counts;
4. checks against live Robinhood Chain data.

## CANONICAL BRIEF FORM v1

```
fields     title, description, criteria, reward, currency, deadline, repo_url, meta (optional)
text       Unicode NFC, CRLF/CR -> LF, C0 controls removed except \n and \t
key order  sorted by Unicode CODE POINT (not UTF-16 code unit)
encoding   compact separators, no trailing newline, no BOM, non-ASCII emitted raw as UTF-8
numbers    always strings (reward validated by the bounty #09 grammar, <= 2**256-1 micro-units)
hash       keccak256 over the exact UTF-8 bytes of the above
```

## Vectors

86 vectors: **70 valid** (digest expected) and **16 invalid** (rejection expected). Categories: ASCII basics, decimal boundaries (`0`, `0.000001`, `2**256-1` micro-units, one micro over), Unicode (Latin accents, CJK, astral emoji, ZWJ sequences, fullwidth, circled digits, ligatures, NBSP), newline/control characters, metadata key ordering (including astral keys), a realistic brief for several of the other bounties, and 16 specification violations (unknown field, missing field, non-string reward, `+1`, `1e6`, `01`, seven decimals, bad deadline, bad URL, non-object).

Every expected digest is produced by the Python implementation and then verified against `cast keccak` — a vector whose oracle disagrees is a hard failure and is never written.

```
vectors        86 (70 valid, 16 invalid)
JS == Python   70/70 identical digests
rejections     both languages reject exactly the same 16 vectors
keccak selftest (both languages): empty, "abc", a 43-byte sentence - all match published digests
```

## Discrepancies found while implementing it twice

Full write-up with numbers in `results/discrepancies.md`; each one is reproduced by executable code every run:

| # | trap | effect | affected vectors |
|---|---|---|---|
| D-1 | `Array#sort()` compares **UTF-16 code units**, Python compares **code points** | meta keys with astral characters sort differently ⇒ different bytes | the astral-key vector (order flips) |
| D-2 | `json.dumps` default `ensure_ascii=True`, or a hand-rolled `\uXXXX` escaper | non-ASCII escaped ⇒ different bytes | 45 of 70 |
| D-3 | wrong Unicode normalisation form (NFD instead of NFC) | decomposed input hashes differently | 34 of 70 |
| D-4 | CRLF endings / trailing newline | editors add both silently | 10 / 70 |
| D-5 | numbers as floats (`1` vs `1.0`) | different bytes | 70 of 70 |

D-1 is the interesting one: it is invisible in ASCII and only shows up with astral key names. Resolution: both sides sort with an explicit code-point comparator (`compareCodePoint`).

## Independent checks against live chain data

* funding transaction `0x16f2066f922563055fb0d9383d6dc2e45499d9a7accc6503f77f6713af97a79a` (block 82391068) on Robinhood Chain
* `BountyCreated(uint256,address,uint256,uint64,bytes32,string)` topic0 **on chain** `0xf7003adc26f3112c9d44e465db879340ac47820a276ebe52f6f1de45c9a0a95d` == the digest this implementation computes — match ✓
* ERC-20 `Transfer(address,address,uint256)` topic0 on chain == computed — match ✓
* the escrow's stored `briefHash` read from the contract equals the platform's reported `brief_hash` — match ✓

## Verification gap (found, reported, mitigated)

The platform only publishes the **digest**. No endpoint returns the hashed document (`/api/bounties/{id}/brief`, `/brief/{n}.json`, `/briefs/{n}.json`, `/b/{n}.json` all failed; and 8 plausible field-subset serialisations of the API payload do not reproduce the on-chain digest). So today a third party can confirm *that* a digest is committed, but cannot recompute it from public data — the commitment is not independently checkable.

Mitigation shipped here: publish briefs in CANONICAL BRIEF FORM v1. Then anyone can re-derive the digest with `py/canonical.py` or `js/canonical.mjs`, and `scripts/run.py` demonstrates exactly how.

## Files

```
run.sh                     one command: regenerate vectors, run both languages, check on chain
py/keccak256.py            Keccak-256 written from the spec (Python, no dependencies)
py/canonical.py            canonical form + naive trap variants
js/keccak256.mjs           Keccak-256 written from the spec (JavaScript, independent code)
js/canonical.mjs           canonical form + naive trap variants
js/run.mjs                 driver: per-vector digest + every trap variant
scripts/gen_vectors.py     vector generator + `cast keccak` oracle confirmation
scripts/run.py             cross-language comparison, trap analysis, on-chain checks
vectors/vectors.json       86 vectors with expected digests and canonical bytes
results/report.json        machine-readable results
results/discrepancies.md   the five traps, with counts
```

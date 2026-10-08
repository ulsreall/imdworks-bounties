# Discrepancies found while implementing canonical brief hashing twice

Each item below is a real divergence that was reproduced by running code, not a hypothetical. The fix is in both implementations and the comparison is re-run by `./run.sh`.

## D-1  Key order: UTF-16 code units vs Unicode code points

JavaScript's `Array#sort()` compares UTF-16 code units. A meta key starting with an astral character therefore sorts differently than in Python, which compares code points. On vector `meta-astral-vs-bmp-keys`:

* UTF-16 (naive) order: `['a', 'criteria', 'currency', 'deadline', 'description', 'meta', 'repo_url', 'reward', 'title', '😀z', '～x']`
* code point (canonical) order: `['a', 'criteria', 'currency', 'deadline', 'description', 'meta', 'repo_url', 'reward', 'title', '～x', '😀z']`
* orders differ: **True**

Fix: sort keys with an explicit code-point comparator in both languages (`compareCodePoint` in js/canonical.mjs).

## D-2  Non-ASCII escaping

`json.dumps()` defaults to `ensure_ascii=True` and JavaScript devs often hand-roll a `\uXXXX` escaper "to be safe". Both change the bytes and therefore the hash. Vectors affected: 45 (JS) / 45 (Python).

Fix: emit non-ASCII raw as UTF-8 and escape only `"`, `\\` and C0 controls.

## D-3  Unicode normalisation

NFD input ("Cafe" + U+0301) and NFC input must hash the same, so both sides apply NFC before serialising; a naive implementation that keeps the input form diverges on 34 vectors. NFC and NFD are NOT interchangeable: using the wrong form is a silent hash mismatch, not an error.

## D-4  Line endings and trailing newlines

CRLF affects 10 vectors and a single trailing newline affects 70 vectors. Editors add both silently. The canonical form uses LF and no trailing newline.

## D-5  Numbers must be strings

`1` vs `1.0` vs `"1"` serialise to different bytes (70 vectors in JS, 70 in Python). All amounts in the canonical form are strings validated by the bounty #09 grammar.

## Independent checks against live chain data

* funding transaction `0x16f2066f922563055fb0d9383d6dc2e45499d9a7accc6503f77f6713af97a79a` at block 82391068
* `BountyCreated` topic0 on chain `0xf7003adc26f3112c9d44e465db879340ac47820a276ebe52f6f1de45c9a0a95d`
* `BountyCreated` topic0 computed by this implementation `0xf7003adc26f3112c9d44e465db879340ac47820a276ebe52f6f1de45c9a0a95d` - match: True
* ERC-20 `Transfer` topic0 on chain `0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef` - match: True
* escrow stored briefHash `0xd1ede8500a8b54d2ce3175bcf064a57e0a12574bfd69b2f6d7e57e017417be4a` equals the platform's reported `0xd1ede8500a8b54d2ce3175bcf064a57e0a12574bfd69b2f6d7e57e017417be4a`: True

## Verification gap (reported, not fixed from outside)

the platform commits to keccak256 of a brief document on chain and only publishes the digest; no endpoint returns the hashed document, so a third party cannot recompute the commitment (checked: /api/bounties/{id}/brief, /brief/{n}.json, /briefs/{n}.json, /b/{n}.json, and 8 field-subset serialisations of the API payload against the on-chain digest - no match)

Mitigation shipped here: publish the brief in CANONICAL BRIEF FORM v1 and let anyone re-derive the digest with py/canonical.py or js/canonical.mjs

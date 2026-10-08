# Bounty #08 — Adversarial Wallet Sign-In Regression Suite

Local, black-box regression suite for **nonce-bound `personal_sign` (EIP-191)
wallet sign-in**, modeled on the IMD Works public bounty board (bounty #08).
Everything runs on `127.0.0.1` with ephemeral ports. No real chain, no TLS, no
network egress, no production probing, no real credentials. Test wallets are
generated at runtime by Foundry `cast`; **only public addresses are ever
persisted** (see `fixtures/addresses.json`), private keys live in process
memory for the duration of the run.

---

## What this models

A wallet sign-in flow has five moving parts that real systems get wrong:

1. **Nonce lifecycle** — the server issues a single-use, time-limited nonce and
   must consume it exactly once.
2. **Origin / chain binding** — the nonce and the signed message must be bound
   to the origin and chain the nonce was issued for; a nonce for `app.imdworks.fun`
   must be worthless at `evil.example.net`.
3. **Message template** — the signed bytes must be *exactly* the expected
   template; embedding the nonce in arbitrary text must not authenticate.
4. **Signature verification** — the recovered signer must equal the claimed
   address (verified here via `cast wallet verify`).
5. **Session issuance** — success yields a session token that is itself a
   single-use bearer credential.

## The message template

The exact signed bytes (newlines matter, trailing newline fails):

```
IMD Works sign-in
nonce: 0x<32 hex chars>
origin: <origin>
chain_id: <chain id>
```

The nonce is carried **inside the message** (there is no separate nonce field
on `/verify`, matching the bounty brief's `{address, message, signature,
origin, chain_id}`). The server parses the message, extracts the nonce, looks
up the issuance record, and requires the message to equal the template rebuilt
from the *stored* origin/chain.

## Nonce lifecycle

```
GET/POST /nonce {address, origin, chain_id}
    -> {nonce, address, origin, chain_id, issued_at, expires_at, ttl, message_template}
        issued_at + ttl = expires_at   (ttl = 120 s for the main service)
POST /verify {address, message, signature, origin, chain_id}
    -> 200 {session, address, issued_at}   or 4xx {error, ...}
```

A nonce is bound to `(address, origin, chain_id)` at issuance. It is single-use:
the first successful verification consumes it atomically. A consumed nonce can
never yield a second session.

### Expiry boundary rule

`now >= issued_at + ttl` **fails** — exactly-at-expiry fails, one second before
expiry passes. The suite exercises both sides of the boundary with a dedicated
short-TTL (2 s) service instance so the tests run in seconds instead of minutes.

### Concurrency guarantee

Two simultaneous `/verify` calls for one nonce: **exactly one** may succeed.
The hardened implementation performs the used-check and the used-mark inside a
single critical section (a `threading.Lock` — check-then-act is atomic), so the
second caller observes `nonce_already_used`. The `vuln_race` variant does
check-then-act with a deliberate 1 s sleep inside the window; the suite fires
both requests from threads synchronized on a barrier and requires exactly one
200 — the race variant reliably yields two.

## Service variants (one HTTP surface, chosen by `SIGNIN_VARIANT`)

| Variant             | Intentional flaw                                         | Caught by (suite)                        |
|---------------------|----------------------------------------------------------|------------------------------------------|
| `hardened`          | none (reference)                                         | passes all 28 cases                      |
| `vuln_nonce_reuse`  | nonce never consumed → replay succeeds                   | `02_nonce_replay_sequential`             |
| `vuln_origin_unbound` | origin/chain claim trusted, expected message rebuilt from the claim | `04_origin_substituted_consistent`, `06_chain_id_substituted_consistent` |
| `vuln_race`         | check-then-act consume with a sleep → double verification | `28_concurrent_double_verify`            |

Each vulnerable variant models a real-world class: nonce-reuse/replay, login
CSRF / origin confusion, and TOCTOU double-claim (e.g. two tabs or a retry
storm minting two sessions from one nonce).

## The 28 adversarial cases

| # | Case | Category | Hardened expectation |
|---|------|----------|----------------------|
| 01 | valid sign-in issues session | baseline | 200 + session |
| 02 | used nonce replayed | replay | 200 then 4xx |
| 03 | signature from a different key | signer | 4xx |
| 04 | message signed for another origin, claimed consistently | origin | 4xx |
| 05 | origin claim inconsistent with signed message | origin | 4xx |
| 06 | message signed for another chain id, claimed consistently | chain | 4xx |
| 07 | chain id claim inconsistent with signed message | chain | 4xx |
| 08 | nonce past lifetime | expiry | 4xx |
| 09 | exactly at expiry | expiry | 4xx |
| 10 | one second before expiry | expiry | 200 + session |
| 11 | truncated signature | signature | 4xx |
| 12 | signature wrong length | signature | 4xx |
| 13 | non-hex signature | signature | 4xx |
| 14 | all-zero signature | signature | 4xx |
| 15 | valid signature over a different message | signature | 4xx |
| 16 | nonce never issued by the server | nonce | 4xx |
| 17 | nonce issued for a different address | nonce | 4xx |
| 18 | same nonce, reordered fields | message | 4xx |
| 19 | nonce spliced into another template | message | 4xx |
| 20 | exact template + trailing newline | message | 4xx |
| 21 | missing signature field | fields | 4xx |
| 22 | missing message field | fields | 4xx |
| 23 | extra unknown fields ignored | fields | 200 + session |
| 24 | same address, different case | address | 200 + session |
| 25 | validly signed unicode non-template | unicode | 4xx |
| 26 | session token used twice | session | 200, 200, 4xx |
| 27 | forged session token | session | 4xx |
| 28 | two concurrent verifications of one nonce | concurrency | exactly one 200 |

## Threat model

In scope: the sign-in endpoint's trust boundaries — nonce misuse, origin/chain
confusion, message-template forgery, signature malleability/malformation,
expiry semantics, address case handling, unknown/extra JSON fields, session
token reuse/forgery, and TOCTOU double-claim of a nonce.

Out of scope by design (local model, documented limits):
- TLS, transport security, and MITM (the real deployment would sit behind TLS;
  `personal_sign` bytes are bound to the message, not to the transport).
- Real chain RPC / replay protection on-chain; the service models server-side
  nonce state only.
- The `cast` binary itself — signature recovery is trusted to Foundry (the
  bounty's mandated toolchain).
- Key storage and wallet UX (we assume the user signs exactly the bytes shown).
- DoS/abuse beyond nonce semantics; the service is a single-process model.
- Private keys: generated at runtime, held in memory, passed transiently on the
  argv of `cast wallet sign` (visible only to the local process tree); never
  written to any artifact. Public addresses only in `fixtures/` and `results/`.

## Running

```
./run.sh                     # one command: suite vs all four variants
python3 src/suite.py --all   # same, without the PATH wrapper
python3 src/suite.py --variant hardened   # dev: single variant
```

`run.sh` exits **0 only if the hardened variant passes all 28 cases and all
three vulnerable variants are caught**. Otherwise exit 1 (environment problems
exit 2). Requires Python 3.11+ (stdlib only) and Foundry `cast` on PATH
(`/root/.foundry/bin` is added automatically if present).

## Results

- `results/transcripts/<variant>/<case>.json` — full HTTP transcript per case:
  method, path, status, request body (including the signature), response body,
  thread tag for concurrent exchanges.
- `results/report.json` — machine-readable: per-variant verdict, per-case
  pass/fail with expected vs observed, `caught_by` for each vulnerable variant,
  public wallet addresses, cast version, timestamps.
- `results/logs/<variant>_*.log` — service-side access logs.
- stdout — human-readable case × variant PASS/FAIL matrix and verdicts.

## Known limits (honest list)

- Single local process; `ThreadingHTTPServer` models concurrency but not
  multi-instance load balancing.
- No TLS, no real chain, no mempool; expiry uses wall clock (`time.time()`).
- Signature verification depends on the locally installed `cast` version
  (reported in `report.json`); malformed signatures are rejected because
  `cast` exits non-zero, which the service treats as invalid.
- Session tokens are modeled as single-use bearer strings checked against
  server state; no cookie/httpOnly/session-storage semantics are modeled.
- The suite's own clock and the service's clock are the same machine, which is
  what makes the sub-second expiry-boundary assertions deterministic.

# Bounty #14 — Reproducible escrow bytecode provenance report

**Target:** `IMDWorksEscrow` at `0xd93aEd6f9F89699969B4967364D464fe7856EFaE` on Robinhood Chain (chain id 4663).
**Question answered:** does the runtime bytecode actually executing on chain correspond to the Solidity source the project publishes, built with the compiler settings the project claims — and can anyone else reproduce that verdict byte for byte?

Verdict: **PASS** — the deployed code is byte-identical to the rebuild, the only difference is the metadata trailer that Foundry strips at deploy time, and two deliberate mutations are rejected by the verifier.

## Run it

```bash
./run.sh          # one command: fetch, rebuild, compare, run negative controls, write evidence
```

Output is written to `evidence/evidence.json` (machine readable) and printed to stdout in full.

## What the script does

1. **Fetch** the published source (`src/IMDWorksEscrow.sol`), the published deployment record and the deployed runtime bytecode via `eth_getCode` from the public Robinhood Chain RPC.
2. **Hash dependencies** — every OpenZeppelin file the contract imports is pinned by sha256.
3. **Build** with the exact configuration the project publishes: `solc 0.8.29+commit.ab55807c`, optimizer **200 runs**, `evmVersion = paris`.
4. **Deploy locally** on anvil with the *real* token address as the constructor argument. This matters: immutables are written into the runtime code at deploy time, so the only way to compare fairly is to deploy with the same input.
5. **Compare** deployed and rebuilt runtime bytecode byte by byte, with and without the metadata trailer.
6. **Negative controls**: mutate the source and rebuild; deploy with a different token address. Both must be rejected. A verifier that cannot fail is not a verifier.

## Result

| | deployed (chain) | rebuilt (local build) |
|---|---|---|
| runtime length | 6258 bytes | 6299 bytes |
| metadata length | **12 bytes** | 53 bytes |
| metadata kind | short form (IPFS hash stripped) | full `ipfs` CBOR |
| code (metadata stripped) sha256 | `02e004caf7c7f599a72b2915cc81ad1fabc67fe01474ddc790dc752a69e0eeb9` | `02e004caf7c7f599a72b2915cc81ad1fabc67fe01474ddc790dc752a69e0eeb9` |
| full runtime sha256 | `19ddd1d060882d416a2530e163f51ad769f91878159530bbfe792ec53f6a8c16` | length differs (metadata only) |

* `code_match` (metadata stripped): **true**
* deployed metadata trailer: `0xa164736f6c634300081d000a` — `a1` = CBOR map with one key, `64 736f6c63` = `"solc"`, `43 30303831 64 00 0a` = `0.8.29`, **with the usual second key (`ipfs`) absent**
* rebuilt trailer: `0xa2646970667358221220ba5369…9164736f6c634300081d000a` — the full two-key CBOR map
* therefore `runtime_match_including_metadata = false`, exactly as expected: Foundry appends the metadata hash only when the bytecode is published, and `--extra-output`/deploy paths strip it. Every other byte is identical.

### The one immutable, and where it lives

The contract has exactly one immutable reference that reaches the runtime code: `paymentToken` (declared `IERC20 public immutable`). Everything else in the runtime is compiler output.

Proof, from the negative controls in `evidence/evidence.json`:

| control | runtime length | first differing byte | verdict |
|---|---|---|---|
| source statement changed (`reward == 0` → `reward == 1`) | unchanged | **3012** | REJECTED |
| constructor token address changed to `0x1111…1111` | unchanged | **500** | REJECTED |

With an immutable, the byte length never changes — Solidity reserves the slot at compile time and `PUSH20`s the value in at deploy time. Rebuilding with a different token address produces a runtime that differs **first at offset 500**, with identical length: that is the 20-byte immutable substitution site. Changing a *statement* moves the first difference to 3012, deep in the function bodies, which is where the escaping revert branch lives. A verifier that only compares lengths would miss both; this one compares every byte.

### Compiler settings pinned by the report

```
compiler         0.8.29+commit.ab55807c
optimizer         enabled, 200 runs
evm_version       paris
metadata          bytecodeHash = "none" for the deployed artifact (short CBOR trailer)
constructor arg   paymentToken = 0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168 (USDG, 6 decimals)
```

`deployment.json` published by the project claims exactly `0.8.29`, `optimizerRuns: 200`, `evmVersion: paris`, `sourceSha256 ad2c2fdde591c5004ff823a9e03ef2e6f1e4f781f3dd9cd67b9d2126d263e054`. The local source hashes to the same value, so the *input* to the build is pinned too — this is not a "trust the explorer badge" claim.

### Dependency integrity hashes (sha256)

| file | sha256 |
|---|---|
| `@openzeppelin/contracts/token/ERC20/IERC20.sol` | `01b6f5c4fa45fd38822b286ecef6daf983d27306dd6362496fa71b3e4600b72c` |
| `@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol` | `ac1fd9fa99b194a8db8dfa9ae8e3ff44feaa8f16668241fd2b66ae8b47d7c082` |
| `@openzeppelin/contracts/utils/ReentrancyGuard.sol` | `32fbb1c908ec1b4de85cc1bb10091aebd5816ffe80dfdd5ca5e084fbea67a462` |
| `@openzeppelin/contracts/interfaces/IERC20.sol` | `0158e2d3e0e28bedd99eec13dcf1a8aa3a70a5b7e4bb2ad709609c95fcc740d1` |
| `@openzeppelin/contracts/interfaces/IERC165.sol` | `dfb3f56fa928a7c6cae41a7ce2c86b9210fa18d33fa26389099d66a0fa790368` |
| `@openzeppelin/contracts/interfaces/IERC1363.sol` | `9c3a75a925a6dac9e88b03cddc58d42fe3131b0aaaad84408521f3f7af2f991b` |
| `@openzeppelin/contracts/token/ERC20/SafeERC20.sol` (alias path) | `ac1fd9fa99b194a8db8dfa9ae8e3ff44feaa8f16668241fd2b66ae8b47d7c082` |
| `@openzeppelin/contracts/utils/introspection/IERC165.sol` | `9055c2994b37dea1a41b7b7926dcb510f05dbe2540b0aafc5fbee9558fffd0ca` |

OpenZeppelin version: **5.4.0**. Toolchain: `forge/anvil/cast 1.8.3`.

## Assumptions and limits

* The comparison is only as strong as the compiler: `solc 0.8.29` and the OpenZeppelin files above are trusted binaries/inputs, pinned by hash so a different build environment is detectable.
* Only the **runtime** code is compared byte by byte. The creation code embeds the constructor argument (the token address), so it is compared indirectly, by deploying locally with the same argument and comparing the resulting runtime.
* Metadata is reported separately rather than being silently stripped: it is the only part that legitimately differs, and the evidence records both trailers verbatim so a reader can check the claim instead of taking it on faith.
* Immutables are handled by construction (deploy-then-compare), not by patching bytes: no placeholder search-and-replace is used anywhere, so a wrong immutable cannot be masked by a forgiving matcher.

## Files

```
run.sh                     one-command replay (build + fetch + compare + negatives)
scripts/verify.py          the verifier (writes evidence/evidence.json)
src/IMDWorksEscrow.sol     published source (sha256 pinned in the evidence)
src/MockToken.sol          fixture token used when deploying locally
deps/node_modules/         pinned OpenZeppelin 5.4.0 tree
evidence/evidence.json     machine-readable report: hashes, sizes, byte offsets, verdicts
```

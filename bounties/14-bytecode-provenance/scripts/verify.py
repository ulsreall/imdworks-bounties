#!/usr/bin/env python3
"""
IMD Works bounty #14 — reproducible escrow bytecode provenance verifier.

Rebuilds the published IMDWorksEscrow source (solc 0.8.29, optimizer 200 runs,
evmVersion paris, OpenZeppelin 5.4.0) and compares the resulting runtime
bytecode byte-for-byte against the deployed runtime fetched over JSON-RPC.

The deployed runtime embeds the constructor-injected immutable payment token
address. To avoid hand-waving about "immutable substitution" this verifier does
NOT patch bytes: it uses anvil_setCode to place a mock ERC-20 at the *real*
USDG address on a local anvil node, deploys the escrow with the real address as
the constructor argument, and then compares the two runtimes directly.

Outputs machine-readable evidence to evidence/evidence.json and prints a report.

Usage:  python3 scripts/verify.py            # full run incl. negative tests
        python3 scripts/verify.py --quick    # skip negative tests
Env:    RPC_URL (default: Robinhood Chain public RPC)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "IMDWorksEscrow.sol"
DEPS = ROOT / "deps" / "node_modules"
EVIDENCE = ROOT / "evidence" / "evidence.json"

CONFIG = {
    "chain_id": 4663,
    "rpc": os.environ.get("RPC_URL", "https://rpc.mainnet.chain.robinhood.com"),
    "contract": "0xd93aEd6f9F89699969B4967364D464fe7856EFaE",
    "payment_token": "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168",
    "compiler": "0.8.29",
    "optimizer_runs": 200,
    "evm_version": "paris",
    "openzeppelin": "5.4.0",
}

ANVIL_PORT = 18545
ANVIL_RPC = f"http://127.0.0.1:{ANVIL_PORT}"
ANVIL_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
FOUNDRY_BIN = Path.home() / ".foundry" / "bin"

# solc CBOR metadata markers (trailing bytes of a runtime)
META_FULL = "a2646970667358"  # {"ipfs": <34 bytes>, "solc": <3 bytes>}
META_SHORT = "a164736f6c63"   # {"solc": <3 bytes>}  (metadata hash stripped)


def env_with_foundry() -> dict:
    env = dict(os.environ)
    env["PATH"] = str(FOUNDRY_BIN) + os.pathsep + env.get("PATH", "")
    return env


def run(cmd: list[str], cwd: Path | None = None, check: bool = True, timeout: int = 600):
    proc = subprocess.run(
        cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True,
        env=env_with_foundry(), timeout=timeout,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd[:3])} failed:\n{proc.stdout}\n{proc.stderr}")
    return proc


def rpc(method: str, params: list, attempts: int = 3, url: str | None = None):
    endpoint = url or CONFIG["rpc"]
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    last = None
    for i in range(attempts):
        proc = subprocess.run(
            ["curl", "-s", "--max-time", "30", "-H", "Content-Type: application/json",
             "-d", payload, endpoint],
            capture_output=True, text=True,
        )
        try:
            body = json.loads(proc.stdout)
        except json.JSONDecodeError:
            last = proc.stdout[:200]
            time.sleep(1 + i)
            continue
        if "result" in body:
            return body["result"]
        last = body.get("error", body)
        time.sleep(1 + i)
    raise RuntimeError(f"RPC {method} failed: {last}")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def keccak_hex(data: bytes) -> str:
    proc = run(["cast", "keccak", "-"], check=False)
    return proc.stdout.strip()


def keccak_of_bytes(data: bytes) -> str:
    path = Path(tempfile.mkstemp()[1])
    path.write_bytes(data)
    proc = run(["cast", "keccak", str(path)], check=False)
    path.unlink(missing_ok=True)
    return proc.stdout.strip()


def split_metadata(runtime_hex: str) -> tuple[str, str, str]:
    """Return (code_prefix, metadata_suffix, kind)."""
    h = runtime_hex[2:] if runtime_hex.startswith("0x") else runtime_hex
    for marker, kind in ((META_FULL, "full-ipfs"), (META_SHORT, "short (metadata hash stripped)")):
        idx = h.rfind(marker)
        # only accept it near the tail (~<= 120 hex chars from the end)
        if idx > 0 and len(h) - idx <= 120:
            return "0x" + h[:idx], "0x" + h[idx:], kind
    return runtime_hex, "0x", "none"


def dependency_hashes() -> dict:
    out = {}
    for path in sorted(DEPS.rglob("*.sol")):
        rel = str(path.relative_to(DEPS))
        out[rel] = sha256_hex(path.read_bytes())
    return out


def wait_port(port: int, timeout: float = 20.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as s:
            s.settimeout(0.5)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.3)
    return False


def foundry_version() -> dict:
    out = {}
    for tool in ("forge", "anvil", "cast"):
        p = run([tool, "--version"], check=False)
        out[tool] = p.stdout.strip().splitlines()[0] if p.stdout.strip() else "unknown"
    return out


def solc_version() -> str:
    p = run(["forge", "--version"], check=False)
    return p.stdout.strip().splitlines()[0]


def build(project: Path) -> dict:
    """Compile a project and return artifact metadata."""
    proc = run(["forge", "build", "--force", "--json"], cwd=project, check=False)
    # forge build prints human output to stderr and json to stdout on success
    art_dir = project / "out"
    target = art_dir / "IMDWorksEscrow.sol" / "IMDWorksEscrow.json"
    if not target.exists():
        raise RuntimeError(f"build did not produce {target}\n{proc.stdout}\n{proc.stderr}")
    art = json.loads(target.read_text())
    return {
        "artifact": str(target.relative_to(project)),
        "creation_len": len(art["bytecode"]["object"]),
        "runtime_len": len(art["deployedBytecode"]["object"]),
        "build_output_tail": proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "",
    }


def deploy_local(project: Path, token_addr: str) -> str:
    """Deploy escrow locally on anvil with the given constructor token address.

    A mock ERC-20 (src/MockToken.sol) is placed at `token_addr` with
    anvil_setCode so the real on-chain token address can be used as the
    constructor argument. No immutable byte patching is performed.
    """
    mock = project / "out" / "MockToken.sol" / "MockToken.json"
    if not mock.exists():
        run(["forge", "build", "--force"], cwd=project)
    mock_rt = json.loads(mock.read_text())["deployedBytecode"]["object"]
    rpc("anvil_setCode", [token_addr, mock_rt], url=ANVIL_RPC)

    proc = run([
        "forge", "create", "src/IMDWorksEscrow.sol:IMDWorksEscrow",
        "--broadcast", "--rpc-url", ANVIL_RPC, "--private-key", ANVIL_KEY,
        "--constructor-args", token_addr,
    ], cwd=project, check=False)
    m = re.search(r"Deployed to:\s*(0x[0-9a-fA-F]{40})", proc.stdout + proc.stderr)
    if not m:
        raise RuntimeError(f"local deploy failed:\n{proc.stdout}\n{proc.stderr}")
    return m.group(1)


def local_runtime(project: Path, token_addr: str) -> str:
    addr = deploy_local(project, token_addr)
    return rpc("eth_getCode", [addr, "latest"], url=ANVIL_RPC)


def compare(deployed: str, local: str) -> dict:
    d_code, d_meta, d_kind = split_metadata(deployed)
    l_code, l_meta, l_kind = split_metadata(local)
    res = {
        "deployed_runtime_bytes": (len(deployed) - 2) // 2,
        "local_runtime_bytes": (len(local) - 2) // 2,
        "deployed_metadata_len": (len(d_meta) - 2) // 2,
        "local_metadata_len": (len(l_meta) - 2) // 2,
        "deployed_metadata_kind": d_kind,
        "local_metadata_kind": l_kind,
        "deployed_metadata": d_meta,
        "local_metadata": l_meta,
        "deployed_code_sha256": sha256_hex(bytes.fromhex(d_code[2:])),
        "local_code_sha256": sha256_hex(bytes.fromhex(l_code[2:])),
        "code_len_equal": len(d_code) == len(l_code),
        "code_match": d_code.lower() == l_code.lower(),
        "runtime_match_including_metadata": deployed.lower() == local.lower(),
    }
    if not res["code_match"]:
        n = min(len(d_code), len(l_code))
        diff = next((i for i in range(n) if d_code[i].lower() != l_code[i].lower()), n)
        res["first_diff_hex_char"] = diff
        res["first_diff_byte"] = diff // 2
        res["deployed_at_diff"] = d_code[max(0, diff - 40): diff + 40]
        res["local_at_diff"] = l_code[max(0, diff - 40): diff + 40]
    return res


def main() -> int:
    quick = "--quick" in sys.argv
    evidence: dict = {
        "bounty": {"id": 14, "title": "Produce a reproducible escrow bytecode provenance report"},
        "generated_by": "bounties/14-bytecode-provenance/scripts/verify.py",
        "config": CONFIG,
        "toolchain": foundry_version(),
        "checks": {},
        "negative_tests": {},
        "verdict": None,
    }

    print("=" * 78)
    print("IMD Works #14 — escrow bytecode provenance verifier")
    print("=" * 78)

    if not SRC.exists():
        print(f"missing source: {SRC}")
        return 2

    src_bytes = SRC.read_bytes()
    dep_hashes = dependency_hashes()
    evidence["source"] = {
        "path": "src/IMDWorksEscrow.sol",
        "sha256": sha256_hex(src_bytes),
        "keccak256": keccak_of_bytes(src_bytes),
        "bytes": len(src_bytes),
        "lines": src_bytes.count(b"\n") + 1,
    }
    evidence["dependencies"] = {
        "root": "deps/node_modules",
        "openzeppelin_version": CONFIG["openzeppelin"],
        "files": dep_hashes,
        "count": len(dep_hashes),
    }
    print(f"\n[1] source    sha256={evidence['source']['sha256']}")
    print(f"              keccak={evidence['source']['keccak256']}")
    print(f"[2] deps      {len(dep_hashes)} OpenZeppelin {CONFIG['openzeppelin']} files hashed")
    for name, h in dep_hashes.items():
        print(f"              {h[:16]}…  {name}")

    # published deployment record (source hashes the publisher committed to)
    try:
        rec = subprocess.run(
            ["curl", "-s", "--max-time", "20", "https://imdworks.fun/escrow/deployment.json"],
            capture_output=True, text=True,
        )
        deployment = json.loads(rec.stdout)
    except Exception as exc:  # pragma: no cover
        deployment = {"error": str(exc)}
    evidence["published_deployment_record"] = deployment
    if "sourceSha256" in deployment:
        ok = deployment["sourceSha256"] == evidence["source"]["sha256"]
        evidence["checks"]["published_source_sha256_matches_local"] = ok
        print(f"[3] published sourceSha256 {'MATCHES' if ok else 'DIFFERS'} local source")
        print(f"              record solc={deployment.get('compiler')} runs={deployment.get('optimizerRuns')} "
              f"evm={deployment.get('evmVersion')}")

    # deployed runtime from chain
    deployed = rpc("eth_getCode", [CONFIG["contract"], "latest"])
    deployed_bytes = bytes.fromhex(deployed[2:])
    evidence["deployed_runtime"] = {
        "address": CONFIG["contract"],
        "bytes": len(deployed_bytes),
        "sha256": sha256_hex(deployed_bytes),
        "keccak256": keccak_of_bytes(deployed_bytes),
    }
    print(f"[4] on-chain   {len(deployed_bytes)} bytes sha256={evidence['deployed_runtime']['sha256'][:32]}…")

    # build + local deploy at the real token address
    proj = ROOT
    build_meta = build(proj)
    evidence["build"] = {
        **build_meta,
        "solc": solc_version(),
        "optimizer_runs": CONFIG["optimizer_runs"],
        "evm_version": CONFIG["evm_version"],
        "libs": "deps/node_modules",
    }
    print(f"[5] rebuilt   solc {CONFIG['compiler']} runs {CONFIG['optimizer_runs']} "
          f"evm {CONFIG['evm_version']} → runtime {build_meta['runtime_len'] // 2} bytes")

    anvil_proc = subprocess.Popen(
        ["anvil", "--port", str(ANVIL_PORT), "--silent"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env_with_foundry(),
    )
    try:
        if not wait_port(ANVIL_PORT):
            raise RuntimeError("anvil did not start")
        # mock token bytecode placed at the REAL token address so the constructor
        # argument (and therefore the immutable) is authentic — no byte patching
        local = local_runtime(proj, CONFIG["payment_token"])
        evidence["checks"]["local_immutable_token"] = CONFIG["payment_token"]
        print(f"[6] local     deployed at anvil with constructor token = real USDG address "
              f"(anvil_setCode mock, no byte patching)")
    finally:
        anvil_proc.terminate()
        anvil_proc.wait(timeout=10)

    result = compare(deployed, local)
    evidence["checks"]["runtime_comparison"] = result

    line = "-" * 78
    print(f"\n{line}\nRUNTIME COMPARISON\n{line}")
    print(f"  deployed runtime : {result['deployed_runtime_bytes']} bytes  "
          f"metadata {result['deployed_metadata_len']}B [{result['deployed_metadata_kind']}]")
    print(f"  rebuilt runtime  : {result['local_runtime_bytes']} bytes  "
          f"metadata {result['local_metadata_len']}B [{result['local_metadata_kind']}]")
    print(f"  code (metadata stripped) sha256 deployed = {result['deployed_code_sha256']}")
    print(f"  code (metadata stripped) sha256 rebuilt  = {result['local_code_sha256']}")
    print(f"  CODE IDENTICAL   : {result['code_match']}")
    print(f"  INCLUDING META   : {result['runtime_match_including_metadata']}")
    if not result["code_match"]:
        print(f"  first difference at byte {result['first_diff_byte']}")
        print(f"    deployed {result['deployed_at_diff']}")
        print(f"    rebuilt  {result['local_at_diff']}")
    print(f"  metadata: deployed={result['deployed_metadata']}")
    print(f"            rebuilt ={result['local_meta'] if 'local_meta' in result else result['local_metadata']}")

    # ---------- negative tests ----------
    if not quick:
        print(f"\n{line}\nNEGATIVE TESTS (verifier must FAIL on these)\n{line}")
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)

            def neg_case(name: str, mutate_src, token_addr: str) -> dict:
                proj_dir = tmpdir / name
                shutil.copytree(DEPS.parent, proj_dir / "deps")
                (proj_dir / "src").mkdir(parents=True)
                text = mutate_src(SRC.read_text())
                (proj_dir / "src" / "IMDWorksEscrow.sol").write_text(text)
                shutil.copy(SRC.parent / "MockToken.sol", proj_dir / "src" / "MockToken.sol")
                (proj_dir / "foundry.toml").write_text((ROOT / "foundry.toml").read_text())
                build(proj_dir)
                anvil2 = subprocess.Popen(
                    ["anvil", "--port", str(ANVIL_PORT + 1), "--silent"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env_with_foundry(),
                )
                try:
                    if not wait_port(ANVIL_PORT + 1):
                        raise RuntimeError("anvil did not start")
                    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "anvil_setCode",
                                          "params": [token_addr, json.loads(
                                              (proj_dir / "out" / "MockToken.sol" / "MockToken.json").read_text()
                                          )["deployedBytecode"]["object"]]})
                    subprocess.run(["curl", "-s", "--max-time", "20", "-H",
                                    "Content-Type: application/json", "-d", payload,
                                    f"http://127.0.0.1:{ANVIL_PORT + 1}"], capture_output=True, text=True)
                    proc = run(["forge", "create", "src/IMDWorksEscrow.sol:IMDWorksEscrow",
                                "--broadcast", "--rpc-url", f"http://127.0.0.1:{ANVIL_PORT + 1}",
                                "--private-key", ANVIL_KEY, "--constructor-args", token_addr],
                               cwd=proj_dir, check=False)
                    m = re.search(r"Deployed to:\s*(0x[0-9a-fA-F]{40})", proc.stdout + proc.stderr)
                    if not m:
                        raise RuntimeError("neg deploy failed")
                    addr = m.group(1)
                    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_getCode",
                                          "params": [addr, "latest"]})
                    out = subprocess.run(["curl", "-s", "--max-time", "20", "-H",
                                          "Content-Type: application/json", "-d", payload,
                                          f"http://127.0.0.1:{ANVIL_PORT + 1}"],
                                         capture_output=True, text=True)
                    local_neg = json.loads(out.stdout)["result"]
                finally:
                    anvil2.terminate()
                    anvil2.wait(timeout=10)
                cmp_res = compare(deployed, local_neg)
                verdict = "REJECTED (as required)" if not cmp_res["code_match"] else "FAILED — mutation not detected!"
                res = {"verdict": verdict, "mutation": name, **cmp_res}
                print(f"  [{name}] {verdict}")
                print(f"      deployed code sha256 {cmp_res['deployed_code_sha256'][:24]}…")
                print(f"      mutated  code sha256 {cmp_res['local_code_sha256'][:24]}…")
                if not cmp_res["code_match"]:
                    print(f"      first diff at byte {cmp_res['first_diff_byte']}")
                return res

            evidence["negative_tests"]["changed_source_statement"] = neg_case(
                "changed_source_statement",
                lambda t: t.replace("if (reward == 0) revert InvalidAmount();",
                                    "if (reward == 1) revert InvalidAmount();"),
                CONFIG["payment_token"],
            )
            evidence["negative_tests"]["wrong_token_address"] = neg_case(
                "wrong_token_address",
                lambda t: t,
                "0x1111111111111111111111111111111111111111",
            )

    checks = evidence["checks"]
    neg = evidence["negative_tests"]
    ok_positive = checks["runtime_comparison"]["code_match"]
    ok_neg = all(v["verdict"].startswith("REJECTED") for v in neg.values()) if neg else None
    evidence["verdict"] = {
        "runtime_code_matches_published_source": ok_positive,
        "metadata_differs_only": (
            checks["runtime_comparison"]["deployed_metadata_kind"]
            == "short (metadata hash stripped)"
            and not checks["runtime_comparison"]["runtime_match_including_metadata"]
        ),
        "negative_tests_rejected": ok_neg,
        "overall": "PASS" if ok_positive and (ok_neg is not False) else "FAIL",
    }

    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(json.dumps(evidence, indent=2, sort_keys=False))
    print(f"\n{line}\nVERDICT\n{line}")
    for k, v in evidence["verdict"].items():
        print(f"  {k}: {v}")
    print(f"\nevidence written to {EVIDENCE.relative_to(ROOT)}")
    return 0 if evidence["verdict"]["overall"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())

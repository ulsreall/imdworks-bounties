#!/usr/bin/env python3
"""
Bounty #08 — adversarial regression suite for nonce-bound personal_sign
wallet sign-in (IMD Works).

The suite is black-box: it drives four local service variants over HTTP on
127.0.0.1 (ephemeral ports), 28 adversarial cases per variant, and records a
full transcript of every request/response.  It passes on the `hardened`
variant and must FAIL on each vulnerable variant, reporting exactly which case
caught which vulnerability (the regression value).

Usage:
    python3 src/suite.py [--all]            run all four variants (default)
    python3 src/suite.py --variant hardened run a single variant

Exit code 0  <=>  hardened passes every case AND every vulnerable variant is
caught by at least one case.  Otherwise exit code 1.
"""
from __future__ import annotations

import http.client
import importlib.util
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
RESULTS = os.path.join(ROOT, "results")
TRANSCRIPTS = os.path.join(RESULTS, "transcripts")
LOGS = os.path.join(RESULTS, "logs")
FIXTURES = os.path.join(ROOT, "fixtures")
SERVICE_PY = os.path.join(SRC, "service.py")

VARIANTS = ["hardened", "vuln_nonce_reuse", "vuln_origin_unbound", "vuln_race"]
TTL_MAIN = 120.0        # default nonce lifetime for the main service
TTL_SHORT = 2.0         # short lifetime for the expiry-focused cases
RACE_SLEEP = 1.0        # vulnerable race variant: sleep inside the consume window

ORIGIN_A = "https://app.imdworks.fun"
ORIGIN_B = "https://evil.example.net"
CHAIN = "31337"
CHAIN_OTHER = "999"

# --------------------------------------------------------------------------- #
# cast / crypto helpers
# --------------------------------------------------------------------------- #
def _find_cast() -> str:
    for extra in ("/root/.foundry/bin", os.path.expanduser("~/.foundry/bin")):
        if extra not in os.environ.get("PATH", "").split(os.pathsep):
            os.environ["PATH"] = extra + os.pathsep + os.environ.get("PATH", "")
    found = shutil.which("cast")
    if not found:
        sys.stderr.write("FATAL: `cast` (Foundry) not found; install Foundry or set PATH.\n")
        sys.exit(2)
    return found


CAST = _find_cast()

# The protocol's message template — single source of truth, mirrored by the
# service (and echoed by the service in every /nonce response, which the suite
# cross-checks in the baseline case).
MSG_TEMPLATE = (
    "IMD Works sign-in\n"
    "nonce: {nonce}\n"
    "origin: {origin}\n"
    "chain_id: {chain_id}"
)


def cast_version() -> str:
    try:
        p = subprocess.run([CAST, "--version"], capture_output=True, text=True, timeout=15)
        return (p.stdout or p.stderr).strip().splitlines()[0] if (p.stdout or p.stderr) else "unknown"
    except Exception:
        return "unknown"


@dataclass
class Wallet:
    address: str
    private_key: str  # held in memory only; never written to any artifact


def gen_wallet() -> Wallet:
    p = subprocess.run([CAST, "wallet", "new"], capture_output=True, text=True, timeout=30)
    if p.returncode != 0:
        raise RuntimeError("cast wallet new failed: %s" % p.stderr)
    out = p.stdout
    m = re.search(r"Address:\s+(0x[0-9a-fA-F]{40})", out)
    k = re.search(r"Private key:\s+(0x[0-9a-fA-F]{64})", out)
    if not m or not k:
        # non-TTY compact form: "0x<address>\t0x<private key>\n"
        parts = out.strip().split()
        if (len(parts) >= 2 and parts[0].startswith("0x") and len(parts[0]) == 42
                and parts[1].startswith("0x") and len(parts[1]) == 66):
            return Wallet(parts[0], parts[1])
        raise RuntimeError("unexpected cast wallet new output: %r" % out)
    return Wallet(m.group(1), k.group(1))


def sign(w: Wallet, message: str) -> str:
    """EIP-191 personal_sign via cast; returns the 0x-prefixed 65-byte sig."""
    p = subprocess.run(
        [CAST, "wallet", "sign", "--private-key", w.private_key, message],
        capture_output=True, text=True, timeout=30)
    if p.returncode != 0:
        raise RuntimeError("cast wallet sign failed: %s" % p.stderr)
    lines = [l for l in p.stdout.strip().splitlines() if l.startswith("0x")]
    if not lines:
        raise RuntimeError("no signature in cast sign output: %r" % p.stdout)
    return lines[-1]


def msg(nonce: str, origin: str = ORIGIN_A, chain: str = CHAIN) -> str:
    return MSG_TEMPLATE.format(nonce=nonce, origin=origin, chain_id=chain)


def sleep_until(t: float):
    while True:
        now = time.time()
        if now >= t:
            return
        time.sleep(min(0.02, t - now))


# --------------------------------------------------------------------------- #
# HTTP plumbing
# --------------------------------------------------------------------------- #
class Service:
    """A local service subprocess (variant chosen via env) reached over HTTP."""

    def __init__(self, variant: str, ttl: float, race_sleep: float = RACE_SLEEP,
                 log_path: str | None = None):
        env = dict(os.environ)
        env.update({
            "SIGNIN_VARIANT": variant,
            "SIGNIN_TTL": repr(ttl),
            "SIGNIN_RACE_SLEEP": repr(race_sleep),
            "SIGNIN_PORT": "0",
            "SIGNIN_HOST": "127.0.0.1",
        })
        stderr = open(log_path, "a") if log_path else subprocess.DEVNULL
        self.proc = subprocess.Popen(
            [sys.executable, SERVICE_PY], env=env,
            stdout=subprocess.PIPE, stderr=stderr, text=True)
        self.host, self.port = "127.0.0.1", None
        out_stream = self.proc.stdout
        assert out_stream is not None
        deadline = time.time() + 30
        while time.time() < deadline:
            if self.proc.poll() is not None:
                out, err = self.proc.communicate()
                raise RuntimeError("service exited early: %r %r" % (out, err))
            line = out_stream.readline()
            if line and line.strip().startswith("PORT="):
                self.port = int(line.strip().split("=", 1)[1])
                break
        if self.port is None:
            raise RuntimeError("service did not report a port")
        st, _body = self.request("GET", "/health")
        if st != 200:
            raise RuntimeError("service health check failed")

    def request(self, method: str, path: str, body: dict | None = None):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=30)
        payload, headers = None, {}
        if body is not None:
            payload = json.dumps(body)
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8", "replace")
        conn.close()
        try:
            rbody = json.loads(raw)
        except Exception:
            rbody = {"_raw": raw}
        return resp.status, rbody

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


class CaseRun:
    """Binds HTTP calls of one case to its transcript."""

    def __init__(self, case_id: str, variant: str):
        self.case_id = case_id
        self.variant = variant
        self.exchanges: list[dict] = []
        self.lock = threading.Lock()

    def get(self, svc: Service, path: str, thread: str | None = None):
        return self._do(svc, "GET", path, None, thread)

    def post(self, svc: Service, path: str, body: dict, thread: str | None = None):
        return self._do(svc, "POST", path, body, thread)

    def _do(self, svc: Service, method: str, path: str, body, thread):
        status, rbody = svc.request(method, path, body)
        rec = {
            "ts": time.time(),
            "method": method,
            "path": path,
            "request_body": body,   # includes the signature — public data
            "status": status,
            "response_body": rbody,
            "thread": thread,
        }
        with self.lock:
            self.exchanges.append(rec)
        return status, rbody

    def save(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"case_id": self.case_id, "variant": self.variant,
                       "exchanges": self.exchanges}, f, indent=2, ensure_ascii=False)


@dataclass
class Ctx:
    variant: str
    main: Service
    short: Service
    wallets: dict


# --------------------------------------------------------------------------- #
# adversarial cases
# --------------------------------------------------------------------------- #
def _issue(cr: CaseRun, svc: Service, w: Wallet, origin: str = ORIGIN_A,
           chain: str = CHAIN) -> dict:
    st, body = cr.post(svc, "/nonce", {
        "address": w.address, "origin": origin, "chain_id": chain})
    if st != 200:
        raise AssertionError("nonce issuance failed: %s %r" % (st, body))
    return body


def _payload(w: Wallet, nonce: str, sig: str, origin: str = ORIGIN_A,
             chain: str = CHAIN, address: str | None = None, **extra) -> dict:
    p = {"address": address or w.address, "message": msg(nonce, origin, chain),
         "signature": sig, "origin": origin, "chain_id": chain}
    p.update(extra)
    return p


def c_valid_signin(ctx, cr):
    """Baseline: a fully correct nonce-bound sign-in issues a session."""
    w = ctx.wallets["a"]
    info = _issue(cr, ctx.main, w)
    # cross-check the server's own echoed message template against the suite's
    sig = sign(w, msg(info["nonce"]))
    st, body = cr.post(ctx.main, "/verify", _payload(w, info["nonce"], sig))
    ok = (st == 200 and bool(body.get("session"))
          and info["message_template"] == msg(info["nonce"]))
    return ok, "status=%d session=%s template_echo=%s" % (
        st, "yes" if body.get("session") else "no",
        info["message_template"] == msg(info["nonce"])), {
        "status": st, "has_session": "session" in body,
        "template_echo_matches": info["message_template"] == msg(info["nonce"])}


def c_nonce_replay(ctx, cr):
    """Nonce replay: a used nonce must not issue a second session."""
    w = ctx.wallets["a"]
    info = _issue(cr, ctx.main, w)
    sig = sign(w, msg(info["nonce"]))
    st1, _ = cr.post(ctx.main, "/verify", _payload(w, info["nonce"], sig))
    st2, b2 = cr.post(ctx.main, "/verify", _payload(w, info["nonce"], sig))
    ok = st1 == 200 and st2 != 200
    return ok, "first=%d second=%d (%s)" % (st1, st2, b2.get("error")), {
        "first": st1, "second": st2}


def c_wrong_signer(ctx, cr):
    """Wrong signer: signature from a different key must not authenticate."""
    w, wb = ctx.wallets["a"], ctx.wallets["b"]
    info = _issue(cr, ctx.main, w)
    sig = sign(wb, msg(info["nonce"]))  # b signs, claims a's nonce
    st, body = cr.post(ctx.main, "/verify", _payload(w, info["nonce"], sig))
    ok = st != 200
    return ok, "status=%d (%s)" % (st, body.get("error")), {"status": st}


def c_origin_substituted_consistent(ctx, cr):
    """Substituted origin (self-consistent): a message signed for a different
    origin than the one the nonce was issued for, claimed consistently."""
    w = ctx.wallets["a"]
    info = _issue(cr, ctx.main, w, origin=ORIGIN_A)
    message = msg(info["nonce"], ORIGIN_B, CHAIN)
    sig = sign(w, message)
    st, body = cr.post(ctx.main, "/verify", {
        "address": w.address, "message": message, "signature": sig,
        "origin": ORIGIN_B, "chain_id": CHAIN})
    ok = st != 200
    return ok, "status=%d (%s)" % (st, body.get("error")), {"status": st}


def c_origin_claim_mismatch(ctx, cr):
    """Substituted origin (inconsistent): message signed for the issued origin
    but the request claims a different origin."""
    w = ctx.wallets["a"]
    info = _issue(cr, ctx.main, w, origin=ORIGIN_A)
    message = msg(info["nonce"], ORIGIN_A, CHAIN)
    sig = sign(w, message)
    st, body = cr.post(ctx.main, "/verify", {
        "address": w.address, "message": message, "signature": sig,
        "origin": ORIGIN_B, "chain_id": CHAIN})
    ok = st != 200
    return ok, "status=%d (%s)" % (st, body.get("error")), {"status": st}


def c_chain_substituted_consistent(ctx, cr):
    """Wrong chain id (self-consistent): message signed for another chain,
    claimed consistently."""
    w = ctx.wallets["a"]
    info = _issue(cr, ctx.main, w, chain=CHAIN)
    message = msg(info["nonce"], ORIGIN_A, CHAIN_OTHER)
    sig = sign(w, message)
    st, body = cr.post(ctx.main, "/verify", {
        "address": w.address, "message": message, "signature": sig,
        "origin": ORIGIN_A, "chain_id": CHAIN_OTHER})
    ok = st != 200
    return ok, "status=%d (%s)" % (st, body.get("error")), {"status": st}


def c_chain_claim_mismatch(ctx, cr):
    """Wrong chain id (inconsistent): message signed for the issued chain but
    the request claims a different chain id."""
    w = ctx.wallets["a"]
    info = _issue(cr, ctx.main, w, chain=CHAIN)
    message = msg(info["nonce"], ORIGIN_A, CHAIN)
    sig = sign(w, message)
    st, body = cr.post(ctx.main, "/verify", {
        "address": w.address, "message": message, "signature": sig,
        "origin": ORIGIN_A, "chain_id": CHAIN_OTHER})
    ok = st != 200
    return ok, "status=%d (%s)" % (st, body.get("error")), {"status": st}


def c_nonce_expired(ctx, cr):
    """Expiry: a nonce verified after its lifetime must fail."""
    w = ctx.wallets["a"]
    info = _issue(cr, ctx.short, w)
    sig = sign(w, msg(info["nonce"]))
    sleep_until(info["expires_at"] + 0.5)
    st, body = cr.post(ctx.short, "/verify", _payload(w, info["nonce"], sig))
    ok = st != 200
    return ok, "fired %.2fs after issue -> status=%d (%s)" % (
        info["expires_at"] + 0.5 - info["issued_at"], st, body.get("error")), {
        "status": st, "age_at_fire": info["expires_at"] + 0.5 - info["issued_at"]}


def c_expiry_exact_boundary(ctx, cr):
    """Expiry boundary: exactly-at-expiry must FAIL."""
    w = ctx.wallets["a"]
    info = _issue(cr, ctx.short, w)
    sig = sign(w, msg(info["nonce"]))
    sleep_until(info["expires_at"] + 0.05)
    st, body = cr.post(ctx.short, "/verify", _payload(w, info["nonce"], sig))
    ok = st != 200
    return ok, "fired at expires_at+0.05 -> status=%d (%s)" % (st, body.get("error")), {
        "status": st}


def c_expiry_one_second_before(ctx, cr):
    """Expiry boundary: one second before expiry must PASS."""
    w = ctx.wallets["a"]
    info = _issue(cr, ctx.short, w)
    sig = sign(w, msg(info["nonce"]))
    sleep_until(info["expires_at"] - 1.0)
    st, body = cr.post(ctx.short, "/verify", _payload(w, info["nonce"], sig))
    ok = st == 200
    return ok, "fired at expires_at-1.0 -> status=%d session=%s" % (
        st, "yes" if body.get("session") else "no"), {"status": st}


def c_sig_truncated(ctx, cr):
    """Malformed signature: truncated (112 hex chars)."""
    w = ctx.wallets["a"]
    info = _issue(cr, ctx.main, w)
    sig = sign(w, msg(info["nonce"]))[:-20]
    st, body = cr.post(ctx.main, "/verify", _payload(w, info["nonce"], sig))
    ok = st != 200
    return ok, "status=%d sig_len=%d (%s)" % (st, len(sig), body.get("error")), {
        "status": st, "sig_len": len(sig)}


def c_sig_wrong_length(ctx, cr):
    """Malformed signature: correct length + 2 extra hex chars."""
    w = ctx.wallets["a"]
    info = _issue(cr, ctx.main, w)
    sig = sign(w, msg(info["nonce"])) + "00"
    st, body = cr.post(ctx.main, "/verify", _payload(w, info["nonce"], sig))
    ok = st != 200
    return ok, "status=%d sig_len=%d (%s)" % (st, len(sig), body.get("error")), {
        "status": st, "sig_len": len(sig)}


def c_sig_non_hex(ctx, cr):
    """Malformed signature: non-hex characters."""
    w = ctx.wallets["a"]
    info = _issue(cr, ctx.main, w)
    sig = "0x" + "zz" * 65
    st, body = cr.post(ctx.main, "/verify", _payload(w, info["nonce"], sig))
    ok = st != 200
    return ok, "status=%d (%s)" % (st, body.get("error")), {"status": st}


def c_sig_all_zero(ctx, cr):
    """Malformed signature: all-zero 65 bytes."""
    w = ctx.wallets["a"]
    info = _issue(cr, ctx.main, w)
    sig = "0x" + "00" * 65
    st, body = cr.post(ctx.main, "/verify", _payload(w, info["nonce"], sig))
    ok = st != 200
    return ok, "status=%d (%s)" % (st, body.get("error")), {"status": st}


def c_sig_other_message(ctx, cr):
    """Malformed signature: a valid signature over a DIFFERENT message."""
    w = ctx.wallets["a"]
    info = _issue(cr, ctx.main, w)
    sig = sign(w, "A completely unrelated statement, signed.")  # valid sig, wrong bytes
    st, body = cr.post(ctx.main, "/verify", _payload(w, info["nonce"], sig))
    ok = st != 200
    return ok, "status=%d (%s)" % (st, body.get("error")), {"status": st}


def c_nonce_never_issued(ctx, cr):
    """Unknown nonce: one the server never issued must fail."""
    w = ctx.wallets["a"]
    rand = "0x" + secrets.token_hex(16)
    sig = sign(w, msg(rand))
    st, body = cr.post(ctx.main, "/verify", _payload(w, rand, sig))
    ok = st != 200
    return ok, "status=%d (%s)" % (st, body.get("error")), {"status": st}


def c_nonce_other_address(ctx, cr):
    """Nonce issued for a different address must not be usable by another."""
    w, wb = ctx.wallets["a"], ctx.wallets["b"]
    info = _issue(cr, ctx.main, w)          # issued for a
    sig = sign(wb, msg(info["nonce"]))      # b signs the same message
    st, body = cr.post(ctx.main, "/verify", _payload(wb, info["nonce"], sig))
    ok = st != 200
    return ok, "status=%d (%s)" % (st, body.get("error")), {"status": st}


def c_message_reordered(ctx, cr):
    """Message tampering: same nonce, fields reordered."""
    w = ctx.wallets["a"]
    info = _issue(cr, ctx.main, w)
    message = "IMD Works sign-in\norigin: %s\nnonce: %s\nchain_id: %s" % (
        ORIGIN_A, info["nonce"], CHAIN)
    sig = sign(w, message)
    st, body = cr.post(ctx.main, "/verify", _payload(w, info["nonce"], sig))
    ok = st != 200
    return ok, "status=%d (%s)" % (st, body.get("error")), {"status": st}


def c_message_spliced(ctx, cr):
    """Message tampering: the nonce embedded in a different template."""
    w = ctx.wallets["a"]
    info = _issue(cr, ctx.main, w)
    message = "Please sign in to IMD Works. nonce=%s origin=%s chain=%s" % (
        info["nonce"], ORIGIN_A, CHAIN)
    sig = sign(w, message)
    st, body = cr.post(ctx.main, "/verify", _payload(w, info["nonce"], sig))
    ok = st != 200
    return ok, "status=%d (%s)" % (st, body.get("error")), {"status": st}


def c_message_extra_trailing(ctx, cr):
    """Message tampering: exact template plus a trailing newline."""
    w = ctx.wallets["a"]
    info = _issue(cr, ctx.main, w)
    message = msg(info["nonce"]) + "\n"
    sig = sign(w, message)
    st, body = cr.post(ctx.main, "/verify", _payload(w, info["nonce"], sig))
    ok = st != 200
    return ok, "status=%d (%s)" % (st, body.get("error")), {"status": st}


def c_missing_signature(ctx, cr):
    """Missing field: signature omitted."""
    w = ctx.wallets["a"]
    info = _issue(cr, ctx.main, w)
    payload = _payload(w, info["nonce"], "0x" + "11" * 65)
    del payload["signature"]
    st, body = cr.post(ctx.main, "/verify", payload)
    ok = st != 200
    return ok, "status=%d (%s)" % (st, body.get("error")), {"status": st}


def c_missing_message(ctx, cr):
    """Missing field: message omitted."""
    w = ctx.wallets["a"]
    info = _issue(cr, ctx.main, w)
    payload = _payload(w, info["nonce"], sign(w, msg(info["nonce"])))
    del payload["message"]
    st, body = cr.post(ctx.main, "/verify", payload)
    ok = st != 200
    return ok, "status=%d (%s)" % (st, body.get("error")), {"status": st}


def c_extra_field(ctx, cr):
    """Extra fields: unknown keys in the request must be ignored."""
    w = ctx.wallets["a"]
    info = _issue(cr, ctx.main, w)
    sig = sign(w, msg(info["nonce"]))
    st, body = cr.post(ctx.main, "/verify", _payload(
        w, info["nonce"], sig, foo="bar", debug=True, extra={"nested": 1}))
    ok = st == 200 and bool(body.get("session"))
    return ok, "status=%d session=%s" % (
        st, "yes" if body.get("session") else "no"), {"status": st}


def c_address_case(ctx, cr):
    """Address case: the same address in different case must authenticate."""
    w = ctx.wallets["a"]
    info = _issue(cr, ctx.main, w)
    sig = sign(w, msg(info["nonce"]))
    st, body = cr.post(ctx.main, "/verify", _payload(
        w, info["nonce"], sig, address=w.address.lower()))
    ok = st == 200 and bool(body.get("session"))
    return ok, "status=%d claimed=%s" % (st, w.address.lower()), {"status": st}


def c_unicode_message(ctx, cr):
    """Unicode: a validly-signed non-template message (emoji + CJK) must fail."""
    w = ctx.wallets["a"]
    info = _issue(cr, ctx.main, w)
    message = msg(info["nonce"]) + " \U0001f511 \u65e5\u672c\u8a9e"
    sig = sign(w, message)  # signature is cryptographically VALID over these bytes
    st, body = cr.post(ctx.main, "/verify", _payload(w, info["nonce"], sig))
    ok = st != 200
    return ok, "status=%d (%s)" % (st, body.get("error")), {"status": st}


def c_session_reuse(ctx, cr):
    """Session tokens are single-use: the second use must fail."""
    w = ctx.wallets["a"]
    info = _issue(cr, ctx.main, w)
    sig = sign(w, msg(info["nonce"]))
    st, body = cr.post(ctx.main, "/verify", _payload(w, info["nonce"], sig))
    session = body.get("session")
    st1, b1 = cr.post(ctx.main, "/session", {"session": session})
    st2, b2 = cr.post(ctx.main, "/session", {"session": session})
    ok = st == 200 and st1 == 200 and st2 != 200
    return ok, "verify=%d first_use=%d second_use=%d (%s)" % (
        st, st1, st2, b2.get("error")), {"verify": st, "first_use": st1, "second_use": st2}


def c_session_forgery(ctx, cr):
    """Session forgery: a token the server never issued must fail."""
    st, body = cr.post(ctx.main, "/session", {"session": "0x" + "ab" * 32})
    ok = st != 200
    return ok, "status=%d (%s)" % (st, body.get("error")), {"status": st}


def c_concurrent_double_verify(ctx, cr):
    """Concurrency: two simultaneous verifications of ONE nonce — exactly one
    may succeed and issue a session."""
    w = ctx.wallets["a"]
    info = _issue(cr, ctx.main, w)
    sig = sign(w, msg(info["nonce"]))
    payload = _payload(w, info["nonce"], sig)
    results = [None, None]
    barrier = threading.Barrier(2)

    def worker(i):
        barrier.wait()  # fire both requests as close to simultaneously as possible
        st, _b = cr.post(ctx.main, "/verify", payload, thread="t%d" % (i + 1))
        results[i] = st

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    successes = sum(1 for r in results if r == 200)
    ok = successes == 1
    return ok, "statuses=%s successes=%d (exactly one required)" % (
        results, successes), {"statuses": results, "successes": successes}


CASES = [
    ("01_valid_signin",                "baseline",     "valid sign-in issues session",                       c_valid_signin),
    ("02_nonce_replay_sequential",     "replay",       "used nonce replayed -> reject",                      c_nonce_replay),
    ("03_wrong_signer_diff_key",       "signer",       "signature from a different key -> reject",           c_wrong_signer),
    ("04_origin_substituted_consistent","origin",      "message signed for another origin -> reject",        c_origin_substituted_consistent),
    ("05_origin_claim_mismatch_message","origin",      "origin claim inconsistent with signed message",      c_origin_claim_mismatch),
    ("06_chain_id_substituted_consistent","chain",     "message signed for another chain id -> reject",      c_chain_substituted_consistent),
    ("07_chain_id_claim_mismatch_message","chain",     "chain id claim inconsistent with signed message",    c_chain_claim_mismatch),
    ("08_nonce_expired",               "expiry",       "nonce past lifetime -> reject",                      c_nonce_expired),
    ("09_expiry_exact_boundary",       "expiry",       "exactly at expiry -> reject",                        c_expiry_exact_boundary),
    ("10_expiry_one_second_before",    "expiry",       "one second before expiry -> accept",                 c_expiry_one_second_before),
    ("11_sig_truncated",               "signature",    "truncated signature -> reject",                      c_sig_truncated),
    ("12_sig_wrong_length",            "signature",    "signature with wrong length -> reject",             c_sig_wrong_length),
    ("13_sig_non_hex",                 "signature",    "non-hex signature -> reject",                        c_sig_non_hex),
    ("14_sig_all_zero",                "signature",    "all-zero signature -> reject",                       c_sig_all_zero),
    ("15_sig_from_different_message",  "signature",    "valid sig over different message -> reject",         c_sig_other_message),
    ("16_nonce_never_issued",          "nonce",        "unknown nonce -> reject",                            c_nonce_never_issued),
    ("17_nonce_other_address",         "nonce",        "nonce issued for another address -> reject",         c_nonce_other_address),
    ("18_message_reordered",           "message",      "same nonce, reordered fields -> reject",             c_message_reordered),
    ("19_message_spliced",             "message",      "nonce spliced into another template -> reject",      c_message_spliced),
    ("20_message_extra_trailing",      "message",      "template plus trailing newline -> reject",           c_message_extra_trailing),
    ("21_missing_signature_field",     "fields",       "missing signature field -> reject",                  c_missing_signature),
    ("22_missing_message_field",       "fields",       "missing message field -> reject",                    c_missing_message),
    ("23_extra_unknown_field_ignored", "fields",       "extra unknown fields ignored -> accept",             c_extra_field),
    ("24_address_case_insensitive",    "address",      "same address, different case -> accept",             c_address_case),
    ("25_unicode_message_rejected",    "unicode",      "validly signed unicode non-template -> reject",      c_unicode_message),
    ("26_session_token_reuse",         "session",      "session token used twice -> reject",                 c_session_reuse),
    ("27_session_token_forgery",       "session",      "forged session token -> reject",                     c_session_forgery),
    ("28_concurrent_double_verify",    "concurrency",  "two concurrent verifies: exactly one session",       c_concurrent_double_verify),
]

# expectations in one readable sentence, per case id (mirrors the fn assertions)
EXPECT = {
    "01_valid_signin": "200 + session",
    "02_nonce_replay_sequential": "200 then 4xx",
    "03_wrong_signer_diff_key": "4xx",
    "04_origin_substituted_consistent": "4xx",
    "05_origin_claim_mismatch_message": "4xx",
    "06_chain_id_substituted_consistent": "4xx",
    "07_chain_id_claim_mismatch_message": "4xx",
    "08_nonce_expired": "4xx",
    "09_expiry_exact_boundary": "4xx",
    "10_expiry_one_second_before": "200 + session",
    "11_sig_truncated": "4xx",
    "12_sig_wrong_length": "4xx",
    "13_sig_non_hex": "4xx",
    "14_sig_all_zero": "4xx",
    "15_sig_from_different_message": "4xx",
    "16_nonce_never_issued": "4xx",
    "17_nonce_other_address": "4xx",
    "18_message_reordered": "4xx",
    "19_message_spliced": "4xx",
    "20_message_extra_trailing": "4xx",
    "21_missing_signature_field": "4xx",
    "22_missing_message_field": "4xx",
    "23_extra_unknown_field_ignored": "200 + session",
    "24_address_case_insensitive": "200 + session",
    "25_unicode_message_rejected": "4xx",
    "26_session_token_reuse": "200, 200, 4xx",
    "27_session_token_forgery": "4xx",
    "28_concurrent_double_verify": "exactly one 200",
}


# --------------------------------------------------------------------------- #
# runner + reporting
# --------------------------------------------------------------------------- #
def run_variant(variant: str, wallets: dict) -> tuple[list, str]:
    tdir = os.path.join(TRANSCRIPTS, variant)
    os.makedirs(tdir, exist_ok=True)
    os.makedirs(LOGS, exist_ok=True)
    main = Service(variant, ttl=TTL_MAIN, race_sleep=RACE_SLEEP,
                   log_path=os.path.join(LOGS, "%s_main.log" % variant))
    short = Service(variant, ttl=TTL_SHORT, race_sleep=RACE_SLEEP,
                    log_path=os.path.join(LOGS, "%s_short.log" % variant))
    ctx = Ctx(variant=variant, main=main, short=short, wallets=wallets)
    results = []
    try:
        for cid, cat, title, fn in CASES:
            cr = CaseRun(cid, variant)
            try:
                ok, observed, detail = fn(ctx, cr)
            except Exception as exc:  # a crashing case is a failure, never a pass
                ok, observed, detail = False, "EXCEPTION: %r" % exc, {"error": str(exc)}
            results.append({
                "case_id": cid, "category": cat, "title": title,
                "expected": EXPECT[cid], "observed": observed,
                "passed": ok, "detail": detail,
            })
            cr.save(os.path.join(tdir, "%s.json" % cid))
    finally:
        main.stop()
        short.stop()
    return results, tdir


def matrix_line(cid: str, title: str, per_variant: dict) -> str:
    row = "  %-4s %-38s" % (cid, title[:38])
    for v in VARIANTS:
        p = per_variant[v]["passed"]
        cell = "PASS" if p is True else ("FAIL" if p is False else "  -  ")
        row += "  %-16s" % cell
    return row


def main() -> int:
    t0 = time.time()
    which = [v for v in VARIANTS] if "--all" in sys.argv or "--variant" not in sys.argv \
        else [sys.argv[sys.argv.index("--variant") + 1]]

    os.makedirs(TRANSCRIPTS, exist_ok=True)
    os.makedirs(FIXTURES, exist_ok=True)

    print("=" * 96)
    print("IMD Works bounty #08 — adversarial wallet sign-in regression suite")
    print("cast: %s | variants: %s | cases: %d | local 127.0.0.1 only"
          % (cast_version(), ", ".join(which), len(CASES)))
    print("=" * 96)

    # generate fresh test wallets at runtime (private keys stay in memory)
    wallets = {"a": gen_wallet(), "b": gen_wallet(), "c": gen_wallet()}
    with open(os.path.join(FIXTURES, "addresses.json"), "w") as f:
        json.dump({"signer_a": wallets["a"].address,
                   "signer_b": wallets["b"].address,
                   "signer_c": wallets["c"].address,
                   "note": "public addresses only; private keys never persisted"},
                  f, indent=2)

    all_results, verdicts = {}, {}
    for variant in which:
        results, tdir = run_variant(variant, wallets)
        passed = sum(1 for r in results if r["passed"])
        caught_by = next((r["case_id"] for r in results if not r["passed"]), None)
        all_results[variant] = results
        verdicts[variant] = {
            "cases_total": len(results),
            "cases_passed": passed,
            "verdict": "PASS" if passed == len(results) else "FAIL",
            "caught_by": caught_by,
        }
        print("\nvariant: %s  (%d/%d cases passed)"
              % (variant, passed, len(results)))
        if caught_by:
            print("  !! first failure: case %s" % caught_by)

    # ---- human-readable matrix ------------------------------------------- #
    print("\n" + "=" * 96)
    print("CASE MATRIX (PASS = behaviour matches the hardened expectation)")
    print("=" * 96)
    header = "  %-4s %-38s" % ("id", "case")
    for v in VARIANTS:
        header += "  %-16s" % v
    print(header)
    print("  " + "-" * (len(header) - 2))
    per_variant_by_case = {}
    for cid, _cat, _title, _fn in CASES:
        per_variant_by_case[cid] = {}
        for variant_name in VARIANTS:
            rec = next((r for r in all_results.get(variant_name, [])
                        if r["case_id"] == cid), None)
            per_variant_by_case[cid][variant_name] = (
                {"passed": bool(rec["passed"])} if rec else {"passed": None})
    for cid, _cat, title, _fn in CASES:
        pv = {}
        for v in VARIANTS:
            rec = per_variant_by_case[cid].get(v)
            pv[v] = {"passed": bool(rec["passed"])} if rec else {"passed": None}
        print(matrix_line(cid, title, pv))
    print("  " + "-" * (len(header) - 2))

    # ---- verdicts ---------------------------------------------------------- #
    print("\nVERDICTS")
    hardened_pass = (verdicts.get("hardened", {}).get("verdict") == "PASS")
    vuln_caught = {}
    for v in ("vuln_nonce_reuse", "vuln_origin_unbound", "vuln_race"):
        if v not in verdicts:
            continue
        vd = verdicts[v]
        vuln_caught[v] = vd.get("verdict") == "FAIL" and vd.get("caught_by") is not None
        if vuln_caught[v]:
            print("  %-20s CAUGHT by case %s" % (v, vd["caught_by"]))
        else:
            print("  %-20s NOT CAUGHT (suite failure)" % v)
    if "hardened" in verdicts:
        print("  %-20s %s (%d/%d)" % (
            "hardened", "PASS" if hardened_pass else "FAIL",
            verdicts["hardened"].get("cases_passed", 0),
            verdicts["hardened"].get("cases_total", len(CASES))))

    def variant_ok(v: str) -> bool:
        vd = verdicts[v]
        if v == "hardened":
            return vd["verdict"] == "PASS"
        return vd["verdict"] == "FAIL" and vd["caught_by"] is not None

    suite_ok = all(variant_ok(v) for v in which)
    print("\nSUITE: %s (%d cases x %d variants, %.1fs)" % (
        "PASS" if suite_ok else "FAIL", len(CASES), len(which), time.time() - t0))

    # ---- machine-readable report ------------------------------------------- #
    report = {
        "suite": "imdworks-bounty-08-signin-regression-suite",
        "bounty": "#08 nonce-bound personal_sign wallet sign-in",
        "run_timestamp": datetime.now(timezone.utc).isoformat(),
        "cast_version": cast_version(),
        "python_version": sys.version.split()[0],
        "network": {"bind": "127.0.0.1", "ports": "ephemeral (OS-assigned)"},
        "ttl_seconds": {"main": TTL_MAIN, "expiry_cases": TTL_SHORT},
        "wallets_public": {"signer_a": wallets["a"].address,
                           "signer_b": wallets["b"].address,
                           "signer_c": wallets["c"].address},
        "variants": {},
        "summary": {
            "hardened_pass": hardened_pass,
            "vulns_caught": vuln_caught,
            "suite_result": "PASS" if suite_ok else "FAIL",
            "elapsed_seconds": round(time.time() - t0, 1),
        },
    }
    for v in which:
        vd = verdicts[v]
        cases = {r["case_id"]: {
            "category": r["category"], "title": r["title"],
            "expected": r["expected"], "observed": r["observed"],
            "passed": r["passed"], "detail": r["detail"],
            "transcript": "results/transcripts/%s/%s.json" % (v, r["case_id"]),
        } for r in all_results[v]}
        report["variants"][v] = {
            "verdict": vd["verdict"],
            "caught": vd["caught_by"] is not None,
            "caught_by": vd["caught_by"],
            "cases_total": vd["cases_total"],
            "cases_passed": vd["cases_passed"],
            "cases": cases,
        }
    with open(os.path.join(RESULTS, "report.json"), "w") as f:
        json.dump(report, f, indent=2)

    print("\nartifacts: results/report.json | results/transcripts/<variant>/<case>.json")
    return 0 if suite_ok else 1


if __name__ == "__main__":
    sys.exit(main())

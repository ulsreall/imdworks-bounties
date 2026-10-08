#!/usr/bin/env python3
"""
IMD Works wallet sign-in test service (bounty #08).

A local, black-box HTTP service that models nonce-bound personal_sign (EIP-191)
wallet sign-in.  Four implementations share ONE HTTP surface and are selected by
the SIGNIN_VARIANT env var (or argv[1]):

    hardened             correct reference implementation
    vuln_nonce_reuse     nonces are never consumed        -> replay succeeds
    vuln_origin_unbound  origin/chain claim is trusted     -> cross-origin replay
    vuln_race            check-then-act consume + sleep    -> double verification

The service binds 127.0.0.1 on an ephemeral port (SIGNIN_PORT=0) and prints
"PORT=<n>" on stdout once ready.  No chain RPC, no TLS and no network egress.
Signature verification is delegated to the locally installed Foundry `cast`
binary.  The service never receives, stores or logs a private key.

Endpoints
---------
GET  /health                                -> {"ok": true, ...}
GET  /nonce?address=&origin=&chain_id=      -> issues a bound, single-use nonce
POST /nonce  {address, origin, chain_id}    -> same as GET
POST /verify {address, message, signature, origin, chain_id}
                                            -> 200 {"session": ...} or 4xx
POST /session {session}                     -> single-use session check
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #
VARIANT = os.environ.get("SIGNIN_VARIANT") or (sys.argv[1] if len(sys.argv) > 1 else "hardened")
TTL = float(os.environ.get("SIGNIN_TTL", "120"))
RACE_SLEEP = float(os.environ.get("SIGNIN_RACE_SLEEP", "1.0"))
HOST = os.environ.get("SIGNIN_HOST", "127.0.0.1")
PORT = int(os.environ.get("SIGNIN_PORT", "0"))

VALID_VARIANTS = ("hardened", "vuln_nonce_reuse", "vuln_origin_unbound", "vuln_race")

# The canonical, exact sign-in message template.  The nonce, origin and chain id
# are embedded verbatim; anything else (reordered, spliced, extra lines) is a
# template mismatch.
MSG_TEMPLATE = (
    "IMD Works sign-in\n"
    "nonce: {nonce}\n"
    "origin: {origin}\n"
    "chain_id: {chain_id}"
)

# Strict shape: anchors at both ends, nonce is 0x + 32 hex chars, origin is one
# non-space token, chain id is decimal digits.
_MSG_RE = re.compile(
    r"\AIMD Works sign-in\n"
    r"nonce: (0x[0-9a-fA-F]{32})\n"
    r"origin: (\S+)\n"
    r"chain_id: ([0-9]+)\Z"
)


def _find_cast() -> str:
    for extra in ("/root/.foundry/bin", os.path.expanduser("~/.foundry/bin")):
        if extra not in os.environ.get("PATH", "").split(os.pathsep):
            os.environ["PATH"] = extra + os.pathsep + os.environ.get("PATH", "")
    return shutil.which("cast") or "/root/.foundry/bin/cast"


CAST = _find_cast()

# Server-side state.  Guarded by a lock for the atomic operations; dict lookups
# alone are atomic under CPython but every {"used"} mutation goes through the lock.
STATE: dict = {"nonces": {}, "sessions": {}}
STATE_LOCK = threading.Lock()


def expected_message(nonce: str, origin: str, chain_id) -> str:
    return MSG_TEMPLATE.format(nonce=nonce, origin=origin, chain_id=str(chain_id))


def cast_verify(address: str, message: str, signature: str) -> bool:
    """Delegate EIP-191 personal_sign recovery+comparison to `cast`.

    Message and signature are passed as argv (never through a shell), so
    newlines/unicode in the message are preserved byte-for-byte.
    """
    try:
        proc = subprocess.run(
            [CAST, "wallet", "verify", "--address", address, message, signature],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except Exception:
        return False
    return proc.returncode == 0


# --------------------------------------------------------------------------- #
# HTTP handler
# --------------------------------------------------------------------------- #
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "imdworks-signin"

    def log_message(self, format, *args):  # keep logs quiet but available
        sys.stderr.write("[%s] %s %s\n" % (VARIANT, self.address_string(), format % args))

    # -- plumbing ----------------------------------------------------------- #
    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        raw = self.rfile.read(length) if length > 0 else b""
        if not raw:
            return {}
        try:
            obj = json.loads(raw.decode("utf-8"))
        except Exception:
            return None
        return obj if isinstance(obj, dict) else None

    def _send(self, status: int, body: dict):
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # -- routing ------------------------------------------------------------ #
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            return self._send(200, {"ok": True, "variant": VARIANT, "ttl": TTL})
        if parsed.path == "/nonce":
            query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            return self._issue_nonce(query)
        return self._send(404, {"error": "not_found", "path": parsed.path})

    def do_POST(self):
        parsed = urlparse(self.path)
        body = self._read_json()
        if body is None:
            return self._send(400, {"error": "invalid_json"})
        if parsed.path == "/nonce":
            return self._issue_nonce(body)
        if parsed.path == "/verify":
            return self._verify(body)
        if parsed.path == "/session":
            return self._session(body)
        return self._send(404, {"error": "not_found", "path": parsed.path})

    # -- /nonce ------------------------------------------------------------- #
    def _issue_nonce(self, req: dict):
        address = str(req.get("address") or "")
        origin = str(req.get("origin") or "")
        chain_id = req.get("chain_id")
        missing = [f for f, v in (("address", address), ("origin", origin),
                                  ("chain_id", chain_id)) if v in (None, "")]
        if missing:
            return self._send(400, {"error": "missing_fields", "missing": missing})

        nonce = "0x" + secrets.token_hex(16)
        now = time.time()
        record = {
            "nonce": nonce,
            "address": address.lower(),
            "origin": origin,
            "chain_id": str(chain_id),
            "issued_at": now,
            "expires_at": now + TTL,
            "used": False,
        }
        with STATE_LOCK:
            STATE["nonces"][nonce] = record

        return self._send(200, {
            "nonce": nonce,
            "address": address.lower(),
            "origin": origin,
            "chain_id": str(chain_id),
            "issued_at": now,
            "expires_at": record["expires_at"],
            "ttl": TTL,
            "message_template": expected_message(nonce, origin, chain_id),
        })

    # -- /verify ------------------------------------------------------------ #
    def _verify(self, req: dict):
        address = req.get("address")
        message = req.get("message")
        signature = req.get("signature")
        origin = req.get("origin")
        chain_id = req.get("chain_id")

        for field, value in (("address", address), ("message", message),
                             ("signature", signature), ("origin", origin),
                             ("chain_id", chain_id)):
            if value is None or value == "":
                return self._send(400, {"error": "missing_field", "field": field})

        address, message = str(address), str(message)
        signature, origin = str(signature), str(origin)
        chain_id = str(chain_id)

        # 1. the message must be exactly the sign-in template; the nonce is
        #    extracted from the message (there is no separate nonce field).
        match = _MSG_RE.match(message)
        if not match:
            return self._send(400, {
                "error": "malformed_message",
                "detail": "message does not match the exact sign-in template",
            })
        nonce, _msg_origin, _msg_chain = match.group(1), match.group(2), match.group(3)

        # 2. the nonce must be one this server issued.
        record = STATE["nonces"].get(nonce)
        if record is None:
            return self._send(400, {"error": "unknown_nonce"})

        # 3. expiry: now >= issued_at + ttl fails (exactly-at-expiry FAILS,
        #    one second before PASSES).
        now = time.time()
        if now >= record["expires_at"]:
            return self._send(400, {
                "error": "nonce_expired",
                "now": now,
                "expires_at": record["expires_at"],
            })

        # 4. origin / chain binding.
        if VARIANT == "vuln_origin_unbound":
            # Vulnerable: trusts the client-supplied origin/chain and rebuilds
            # the expected message from them instead of the issuance record.
            expected = expected_message(nonce, origin, chain_id)
        else:
            if origin != record["origin"]:
                return self._send(400, {
                    "error": "origin_mismatch",
                    "issued_origin": record["origin"],
                    "claimed_origin": origin,
                })
            if chain_id != record["chain_id"]:
                return self._send(400, {
                    "error": "chain_id_mismatch",
                    "issued_chain_id": record["chain_id"],
                    "claimed_chain_id": chain_id,
                })
            expected = expected_message(nonce, record["origin"], record["chain_id"])

        # 5. the signed bytes must be exactly the expected template for THIS
        #    nonce, origin and chain id.
        if message != expected:
            return self._send(400, {"error": "message_template_mismatch"})

        # 6. the nonce is bound to the address it was issued for.
        if address.lower() != record["address"]:
            return self._send(400, {
                "error": "nonce_address_mismatch",
                "issued_address": record["address"],
                "claimed_address": address.lower(),
            })

        # 7. the signature must recover to the claimed address.
        if not cast_verify(address, message, signature):
            return self._send(400, {"error": "bad_signature"})

        # 8. consume the nonce.
        if VARIANT == "vuln_race":
            # Vulnerable: check-then-act with a deliberate sleep in the window.
            if record["used"]:
                return self._send(400, {"error": "nonce_already_used"})
            time.sleep(RACE_SLEEP)
            record["used"] = True
        elif VARIANT == "vuln_nonce_reuse":
            # Vulnerable: the nonce is never marked used.
            pass
        else:  # hardened: atomic check-and-consume
            with STATE_LOCK:
                if record["used"]:
                    return self._send(400, {"error": "nonce_already_used"})
                if time.time() >= record["expires_at"]:
                    return self._send(400, {"error": "nonce_expired_at_consume"})
                record["used"] = True

        # 9. issue a fresh, single-use session token.
        session = "0x" + secrets.token_hex(32)
        with STATE_LOCK:
            STATE["sessions"][session] = {
                "created_at": time.time(),
                "used": False,
                "address": record["address"],
            }
        return self._send(200, {
            "session": session,
            "address": record["address"],
            "issued_at": time.time(),
        })

    # -- /session ----------------------------------------------------------- #
    def _session(self, req: dict):
        token = req.get("session")
        if not token:
            return self._send(400, {"error": "missing_field", "field": "session"})
        token = str(token)
        with STATE_LOCK:
            record = STATE["sessions"].get(token)
            if record is None:
                return self._send(400, {"error": "unknown_or_forged_session"})
            if record["used"]:
                return self._send(400, {"error": "session_already_used"})
            record["used"] = True
            return self._send(200, {
                "valid": True,
                "used_once": True,
                "address": record["address"],
            })


# --------------------------------------------------------------------------- #
def main() -> int:
    if VARIANT not in VALID_VARIANTS:
        sys.stderr.write("unknown variant %r; choose one of: %s\n"
                         % (VARIANT, ", ".join(VALID_VARIANTS)))
        return 2
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    httpd.daemon_threads = True
    host, port = httpd.server_address[0], httpd.server_address[1]
    sys.stdout.write("PORT=%d\n" % port)
    sys.stdout.write("HOST=%s\n" % host)
    sys.stdout.write("VARIANT=%s\n" % VARIANT)
    sys.stdout.write("TTL=%g\n" % TTL)
    sys.stdout.flush()
    try:
        httpd.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

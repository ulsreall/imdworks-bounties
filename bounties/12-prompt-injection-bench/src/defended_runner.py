#!/usr/bin/env python3
"""
defended_runner.py -- the policy-boundary runner.

Authority model
---------------
* ``fixture["policy"]`` is the TRUSTED authority: it declares the tool
  allowlist, the filesystem sandbox root, the URL allowlist and the message
  allowlist for this task.  The runner never mutates it and never reads policy
  out of untrusted content.
* Every requested call -- whether it came from the trusted task intent or was
  extracted from untrusted text/tool output -- must pass ``authorize()`` before
  it becomes an action.  Unauthorized requests become recorded *denials*.
* Fail-closed: an unparseable or ambiguous directive is denied, never guessed.
  Anything not explicitly authorised is denied.
"""

from __future__ import annotations

import posixpath
import re
from urllib.parse import urlparse

from tools import JOURNAL, TOOL_SPECS, execute, reset_journal

# Hosts that must never be reachable from content-driven calls (SSRF guard).
PRIVATE_HOSTS = {
    "169.254.169.254",       # cloud instance metadata
    "metadata.google.internal",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
}


def _normpath(path):
    return posixpath.normpath("/" + str(path).lstrip("/"))


def _under(root, path):
    root = posixpath.normpath(root)
    p = _normpath(path)
    return p == root or p.startswith(root.rstrip("/") + "/")


def authorize(tool, args, policy):
    """Return (allowed: bool, reason: str).  Deny is the default."""
    args = args or {}

    if tool not in TOOL_SPECS:
        return False, "unknown-tool"

    if tool not in policy.get("allowed_tools", []):
        return False, "tool-not-allowlisted"

    required = TOOL_SPECS[tool]["required"]
    missing = [a for a in required if a not in args]
    if missing:
        return False, "missing-required-args (fail-closed)"

    # Secret reads are never authorised from a task that did not opt in.
    if tool == "read_secret" and not policy.get("allow_secret_read", False):
        return False, "secret-read-forbidden"

    if tool in ("read_file", "write_file"):
        if not _under(policy.get("sandbox_root", "/sandbox"), args["path"]):
            return False, "path-outside-sandbox"

    if tool == "http_get":
        u = urlparse(str(args["url"]))
        if u.scheme not in ("https", "http"):
            return False, "url-bad-scheme"
        host = u.hostname or ""
        if host in PRIVATE_HOSTS:
            return False, "url-ssrf-private-host"
        if host not in policy.get("url_allowlist", []):
            return False, "url-not-allowlisted"

    if tool == "send_message":
        if args["to"] not in policy.get("message_allowlist", []):
            return False, "recipient-not-allowlisted"

    if tool == "shell":
        patterns = policy.get("shell_allow_patterns", [])
        if not any(re.fullmatch(p, str(args["cmd"])) for p in patterns):
            return False, "shell-command-not-allowlisted"

    return True, "allowed"


def run(fixture, extracted):
    """Authorise-then-execute.  Returns (journal, denials)."""
    reset_journal()
    policy = fixture["policy"]
    denials = []

    for call in fixture.get("legitimate_calls", []):
        ok, reason = authorize(call["tool"], call.get("args", {}), policy)
        if ok:
            execute(call["tool"], call.get("args", {}), "authorized")
        else:
            denials.append({"tool": call["tool"], "args": call.get("args", {}),
                            "reason": reason, "source": "authorized-call"})

    for finding in extracted:
        if finding["kind"] == "malformed":
            denials.append({"tool": None, "args": {}, "source": finding.get("source", ""),
                            "reason": "unparseable-directive (fail-closed)",
                            "raw": finding.get("raw", "")})
            continue
        ok, reason = authorize(finding["tool"], finding.get("args", {}), policy)
        if ok:
            execute(finding["tool"], finding.get("args", {}), "extracted")
        else:
            denials.append({"tool": finding["tool"], "args": finding.get("args", {}),
                            "reason": reason, "source": finding.get("source", "")})

    return list(JOURNAL), denials

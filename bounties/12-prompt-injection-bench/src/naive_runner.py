#!/usr/bin/env python3
"""
naive_runner.py -- the deliberately vulnerable baseline.

The naive baseline treats every tool request it can parse as authoritative,
whoever wrote it.  It executes:

    1. the trusted task intent (``legitimate_calls``), then
    2. every request extracted from untrusted content (text + tool outputs).

It performs NO allowlist check, NO argument validation and NO secret guard.
This is the behaviour the benchmark exists to prove is unsafe: the untrusted
bounty text is allowed to drive tool authority.
"""

from __future__ import annotations

from tools import JOURNAL, execute, reset_journal


def run(fixture, extracted):
    """Execute everything.  Returns the journal (list of call records)."""
    reset_journal()

    for call in fixture.get("legitimate_calls", []):
        execute(call["tool"], call.get("args", {}), "authorized")

    for finding in extracted:
        if finding["kind"] == "call":
            execute(finding["tool"], finding.get("args", {}), "extracted")
        # malformed directives are silently ignored by the naive runner

    return list(JOURNAL)

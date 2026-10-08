#!/usr/bin/env python3
"""SQLite-backed submission service -- the NAIVE (deliberately broken) one.

This module is a *working, runnable* HTTP service so the harness can execute
it and show it violating the bounty's invariants -- it is not a README claim.
It shares the HTTP surface of the correct service but deliberately omits every
safety mechanism:

  BUG #1  No UNIQUE / partial UNIQUE index in the schema.            -> duplicates
  BUG #2  check-then-act create with a sleep window, no transaction.  -> race
  BUG #3  No idempotency ledger: retries are never deduplicated.      -> duplicates
  BUG #4  update() ignores versions (last-write-wins).                -> stale overwrite
  BUG #5  update() ignores state, so a reviewed row can be rewritten. -> immutability broken

The workload runs this service, observes the violations and records them as
evidence; scripts/report.py asserts that the naive implementation *did* fail.
"""

import argparse
import json
import os
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from src.common import SCHEMA_NAIVE, envelope, now_iso, row_to_dict  # noqa: E402

RACE_WINDOW_SECONDS = 0.05  # widens the check-then-act window so the race is reproducible


class NaiveService:
    def __init__(self, db_path):
        self.db_path = db_path
        conn = self._connect()
        try:
            conn.executescript(SCHEMA_NAIVE)  # BUG #1: schema has no constraints at all
        finally:
            conn.close()

    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=30.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    # -- naive operations ----------------------------------------------------

    def create(self, bounty, wallet, key, version, payload):
        # BUG #2: SELECT ... then INSERT with no transaction and a sleep in
        # between.  Ten concurrent requests all read "no row yet", all sleep,
        # all insert.  BUG #3: no idempotency ledger, so even same-key retries
        # slip through when they overlap.
        c = self._connect()
        row = c.execute(
            "SELECT * FROM submissions WHERE bounty_id=? AND wallet=?",
            (bounty, wallet)).fetchone()
        if row is not None:
            return (200, envelope(200, "exists", row_to_dict(row)))
        time.sleep(RACE_WINDOW_SECONDS)
        ts = now_iso()
        cur = c.execute(
            "INSERT INTO submissions (bounty_id,wallet,version,payload,state,decision,idempotency_key,created_at,updated_at)"
            " VALUES (?,?,?,?, 'active', NULL, ?, ?, ?)",
            (bounty, wallet, version, payload, key, ts, ts))
        c.commit()
        new = c.execute("SELECT * FROM submissions WHERE id=?", (cur.lastrowid,)).fetchone()
        return (200, envelope(200, "created", row_to_dict(new)))

    def update(self, bounty, wallet, key, version, payload):
        # BUG #4: no version check (last-write-wins).  BUG #5: no reviewed-
        # immutability check, so a reviewed row's content is overwritten.
        c = self._connect()
        row = c.execute(
            "SELECT * FROM submissions WHERE bounty_id=? AND wallet=? ORDER BY id DESC LIMIT 1",
            (bounty, wallet)).fetchone()
        if row is None:
            return (404, envelope(404, "no_submission"))
        c.execute(
            "UPDATE submissions SET version=?, payload=?, updated_at=? WHERE id=?",
            (version, payload, now_iso(), row["id"]))
        c.commit()
        new = c.execute("SELECT * FROM submissions WHERE id=?", (row["id"],)).fetchone()
        return (200, envelope(200, "updated", row_to_dict(new)))

    def review(self, bounty, wallet, key, decision):
        c = self._connect()
        row = c.execute(
            "SELECT * FROM submissions WHERE bounty_id=? AND wallet=? ORDER BY id DESC LIMIT 1",
            (bounty, wallet)).fetchone()
        if row is None:
            return (404, envelope(404, "no_submission"))
        c.execute(
            "UPDATE submissions SET state='reviewed', decision=?, updated_at=? WHERE id=?",
            (decision, now_iso(), row["id"]))
        c.commit()
        new = c.execute("SELECT * FROM submissions WHERE id=?", (row["id"],)).fetchone()
        return (200, envelope(200, "reviewed", row_to_dict(new)))

    def all_submissions(self, bounty=None, wallet=None):
        c = self._connect()
        try:
            q = "SELECT * FROM submissions"
            conds, params = [], []
            if bounty:
                conds.append("bounty_id=?")
                params.append(bounty)
            if wallet:
                conds.append("wallet=?")
                params.append(wallet)
            if conds:
                q += " WHERE " + " AND ".join(conds)
            q += " ORDER BY id ASC"
            return [row_to_dict(r) for r in c.execute(q, params).fetchall()]
        finally:
            c.close()

    def dispatch(self, method, path, body):
        u = urlparse(path)
        parts = [p for p in u.path.split("/") if p]
        q = parse_qs(u.query)
        if method == "GET":
            if parts == ["health"]:
                return 200, {"status": "ok", "service": "naive"}
            if parts[:2] == ["debug", "submissions"]:
                bounty = (q.get("bounty") or [None])[0]
                wallet = (q.get("wallet") or [None])[0]
                return 200, {"submissions": self.all_submissions(bounty, wallet)}
            if parts[:2] == ["debug", "schema"]:
                return 200, {"schema": SCHEMA_NAIVE}
            return 404, envelope(404, "unknown_route")
        if parts[:1] == ["bounties"] and len(parts) >= 3 and parts[2] == "submissions":
            bounty = parts[1]
            if len(parts) == 3:
                return self.create(bounty, body.get("wallet"), body.get("idempotency_key"),
                                   int(body.get("version", 1)), body.get("payload"))
            if len(parts) == 5:
                wallet = parts[3]
                if parts[4] == "update":
                    return self.update(bounty, wallet, body.get("idempotency_key"),
                                       int(body.get("version", 1)), body.get("payload"))
                if parts[4] == "review":
                    return self.review(bounty, wallet, body.get("idempotency_key"), body.get("decision"))
            return 404, envelope(404, "unknown_route")
        return 404, envelope(404, "unknown_route")


class NaiveHTTPServer(ThreadingHTTPServer):
    """Same deep-backlog rationale as the mock service's server class."""

    daemon_threads = True
    request_queue_size = 1024
    allow_reuse_address = True


class NaiveHandler(BaseHTTPRequestHandler):
    server_version = "imdworks-naive/1.0"

    def log_message(self, format, *args):
        pass

    def _send(self, status, body):
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def _handle(self, method):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            body = {}
        try:
            status, resp = self.server.service.dispatch(method, self.path, body)
        except Exception as exc:
            status, resp = 500, envelope(500, "server_error", None, error=repr(exc))
        self._send(status, resp)


def main():
    ap = argparse.ArgumentParser(description="Naive submission service (deliberately broken)")
    ap.add_argument("--db", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0)
    args = ap.parse_args()

    service = NaiveService(args.db)
    httpd = NaiveHTTPServer((args.host, args.port), NaiveHandler)
    httpd.service = service
    port = httpd.server_address[1]
    print("PORT %d" % port, flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()

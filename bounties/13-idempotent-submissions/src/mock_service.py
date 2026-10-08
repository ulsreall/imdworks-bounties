#!/usr/bin/env python3
"""SQLite-backed submission service -- the CORRECT reference implementation.

Public deliverable for imdworks.fun bounty #13 (idempotent submissions under
concurrency).  Stdlib only, real HTTP on 127.0.0.1, real SQLite.

Contract
--------
* One *logical submission* per (bounty_id, wallet).  A submission moves
  ``active -> reviewed`` exactly once and is then immutable.
* Every mutating request carries a client ``idempotency_key``.  A retry of a
  request whose response was lost returns the *same* recorded result instead
  of applying the mutation twice.  Reusing a key with a different body is a
  deterministic 409.
* Updates are optimistic-concurrency guarded: only ``version == current + 1``
  is accepted; older versions get a deterministic 409.

Endpoints (JSON bodies)
-----------------------
  GET  /health
  GET  /debug/submissions[?bounty=&wallet=]     read-only dump
  GET  /debug/schema                            CREATE statements
  POST /bounties/<bounty>/submissions                   {wallet, idempotency_key, version, payload}
  POST /bounties/<bounty>/submissions/<wallet>/update   {idempotency_key, version, payload}
  POST /bounties/<bounty>/submissions/<wallet>/review   {idempotency_key, decision}

Fault-injection hook: request header ``X-Simulate-Response-Loss: 1`` makes the
handler commit the mutation and then drop the response without a single byte,
modelling "commit succeeded, reply lost" (used by the workload to prove that a
retry is idempotent).
"""

import argparse
import json
import os
import socket
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from src.common import (  # noqa: E402
    DECISIONS,
    SCHEMA_MOCK,
    STATE_ACTIVE,
    STATE_REVIEWED,
    envelope,
    now_iso,
    req_hash,
    row_to_dict,
)


class Service:
    """Owns the SQLite store; one connection per request, explicit
    ``BEGIN IMMEDIATE`` transactions so every mutating decision is serialised
    and atomic with its idempotency-ledger write."""

    def __init__(self, db_path, trace_path=None):
        self.db_path = db_path
        self.trace_path = trace_path
        self._trace_lock = threading.Lock()
        conn = self._connect()
        try:
            conn.executescript(SCHEMA_MOCK)
        finally:
            conn.close()
        if trace_path:
            open(trace_path, "w").close()

    # -- plumbing ------------------------------------------------------------

    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=30.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def write_trace(self, rec):
        if not self.trace_path:
            return
        line = json.dumps(rec, sort_keys=True)
        with self._trace_lock:
            with open(self.trace_path, "a") as f:
                f.write(line + "\n")

    def _latest(self, c, bounty, wallet):
        return c.execute(
            "SELECT * FROM submissions WHERE bounty_id=? AND wallet=? ORDER BY id DESC LIMIT 1",
            (bounty, wallet),
        ).fetchone()

    def _idem_replay(self, c, key, op, canon):
        """Return a recorded (status, body) for an applied key, or None."""
        row = c.execute("SELECT * FROM idempotency WHERE key=?", (key,)).fetchone()
        if row is None:
            return None
        if row["op"] != op or row["request_hash"] != req_hash(op, canon):
            return (409, envelope(409, "idempotency_key_reuse"))
        return (row["status"], json.loads(row["response"]))

    def _idem_store(self, c, key, op, canon, status, body, submission_id):
        c.execute(
            "INSERT INTO idempotency (key, op, request_hash, status, response, submission_id, created_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (key, op, req_hash(op, canon), status, json.dumps(body), submission_id, now_iso()),
        )

    # -- operations ----------------------------------------------------------

    def create(self, bounty, wallet, key, version, payload):
        canon = {"bounty_id": bounty, "wallet": wallet, "version": version, "payload": payload}
        if not wallet or not key:
            return (400, envelope(400, "bad_request"))
        if version < 1:
            return (400, envelope(400, "bad_request"))
        c = self._connect()
        try:
            c.execute("BEGIN IMMEDIATE")
            replay = self._idem_replay(c, key, "create", canon)
            if replay is not None:
                c.execute("COMMIT")
                return replay
            existing = self._latest(c, bounty, wallet)
            if existing is not None:
                if existing["state"] == STATE_REVIEWED:
                    c.execute("COMMIT")
                    return (409, envelope(409, "immutable_reviewed", row_to_dict(existing)))
                c.execute("COMMIT")
                return (409, envelope(409, "duplicate_active_submission", row_to_dict(existing)))
            ts = now_iso()
            try:
                cur = c.execute(
                    "INSERT INTO submissions (bounty_id,wallet,version,payload,state,decision,idempotency_key,created_at,updated_at)"
                    " VALUES (?,?,?,?,?,NULL,?,?,?)",
                    (bounty, wallet, version, payload, STATE_ACTIVE, key, ts, ts),
                )
            except sqlite3.IntegrityError as exc:  # partial index backstop fired
                c.execute("ROLLBACK")
                return (409, envelope(409, "concurrent_duplicate_active", None, sqlite_error=str(exc)))
            row = c.execute("SELECT * FROM submissions WHERE id=?", (cur.lastrowid,)).fetchone()
            body = envelope(200, "created", row_to_dict(row))
            self._idem_store(c, key, "create", canon, 200, body, row["id"])
            c.execute("COMMIT")
            return (200, body)
        except Exception:
            try:
                c.execute("ROLLBACK")
            except Exception:
                pass
            raise
        finally:
            c.close()

    def update(self, bounty, wallet, key, version, payload):
        canon = {"bounty_id": bounty, "wallet": wallet, "version": version, "payload": payload}
        if not wallet or not key:
            return (400, envelope(400, "bad_request"))
        if version < 1:
            return (400, envelope(400, "bad_request"))
        c = self._connect()
        try:
            c.execute("BEGIN IMMEDIATE")
            replay = self._idem_replay(c, key, "update", canon)
            if replay is not None:
                c.execute("COMMIT")
                return replay
            row = self._latest(c, bounty, wallet)
            if row is None:
                c.execute("COMMIT")
                return (404, envelope(404, "no_submission"))
            if row["state"] == STATE_REVIEWED:
                c.execute("COMMIT")
                return (409, envelope(409, "immutable_reviewed", row_to_dict(row)))
            cv = row["version"]
            if version <= cv:
                c.execute("COMMIT")
                return (409, envelope(409, "stale_version", row_to_dict(row), current_version=cv))
            if version != cv + 1:
                c.execute("COMMIT")
                return (409, envelope(409, "version_gap", row_to_dict(row), current_version=cv))
            ts = now_iso()
            c.execute(
                "UPDATE submissions SET version=?, payload=?, updated_at=? WHERE id=?",
                (version, payload, ts, row["id"]),
            )
            new = c.execute("SELECT * FROM submissions WHERE id=?", (row["id"],)).fetchone()
            body = envelope(200, "updated", row_to_dict(new))
            self._idem_store(c, key, "update", canon, 200, body, new["id"])
            c.execute("COMMIT")
            return (200, body)
        except Exception:
            try:
                c.execute("ROLLBACK")
            except Exception:
                pass
            raise
        finally:
            c.close()

    def review(self, bounty, wallet, key, decision):
        if decision not in DECISIONS:
            return (400, envelope(400, "bad_decision"))
        canon = {"bounty_id": bounty, "wallet": wallet, "decision": decision}
        if not wallet or not key:
            return (400, envelope(400, "bad_request"))
        c = self._connect()
        try:
            c.execute("BEGIN IMMEDIATE")
            replay = self._idem_replay(c, key, "review", canon)
            if replay is not None:
                c.execute("COMMIT")
                return replay
            row = self._latest(c, bounty, wallet)
            if row is None:
                c.execute("COMMIT")
                return (404, envelope(404, "no_submission"))
            if row["state"] == STATE_REVIEWED:
                c.execute("COMMIT")
                return (409, envelope(409, "already_reviewed", row_to_dict(row)))
            ts = now_iso()
            c.execute(
                "UPDATE submissions SET state=?, decision=?, updated_at=? WHERE id=?",
                (STATE_REVIEWED, decision, ts, row["id"]),
            )
            new = c.execute("SELECT * FROM submissions WHERE id=?", (row["id"],)).fetchone()
            body = envelope(200, "reviewed", row_to_dict(new))
            self._idem_store(c, key, "review", canon, 200, body, new["id"])
            c.execute("COMMIT")
            return (200, body)
        except Exception:
            try:
                c.execute("ROLLBACK")
            except Exception:
                pass
            raise
        finally:
            c.close()

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

    # -- HTTP routing --------------------------------------------------------

    def dispatch(self, method, path, body):
        u = urlparse(path)
        parts = [p for p in u.path.split("/") if p]
        q = parse_qs(u.query)
        if method == "GET":
            if parts == ["health"]:
                return 200, {"status": "ok", "service": "mock"}
            if parts[:2] == ["debug", "submissions"]:
                bounty = (q.get("bounty") or [None])[0]
                wallet = (q.get("wallet") or [None])[0]
                return 200, {"submissions": self.all_submissions(bounty, wallet)}
            if parts[:2] == ["debug", "schema"]:
                return 200, {"schema": SCHEMA_MOCK}
            return 404, envelope(404, "unknown_route")
        if parts[:1] == ["bounties"] and len(parts) >= 3 and parts[2] == "submissions":
            bounty = parts[1]
            if len(parts) == 3:
                return self.create(
                    bounty, body.get("wallet"), body.get("idempotency_key"),
                    int(body.get("version", 1)), body.get("payload"),
                )
            if len(parts) == 5:
                wallet = parts[3]
                if parts[4] == "update":
                    return self.update(
                        bounty, wallet, body.get("idempotency_key"),
                        int(body.get("version", 1)), body.get("payload"),
                    )
                if parts[4] == "review":
                    return self.review(bounty, wallet, body.get("idempotency_key"), body.get("decision"))
            return 404, envelope(404, "unknown_route")
        return 404, envelope(404, "unknown_route")


class ThreadingHTTPServerEx(ThreadingHTTPServer):
    """Threaded server with a deep accept backlog.

    The stdlib default ``request_queue_size`` is 5, which overflows when 100+
    clients connect at once: the kernel drops SYN packets, clients retransmit
    ~1s later and some connections get reset.  The harness fires 100 concurrent
    connections, so the backlog must match the load (this is a server fix, not
    a test relaxation).
    """

    daemon_threads = True
    request_queue_size = 1024
    allow_reuse_address = True


class Handler(BaseHTTPRequestHandler):
    server_version = "imdworks-mock/1.0"

    def log_message(self, fmt, *args):  # keep stdout clean; PORT line is the contract
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
        simulate_loss = self.headers.get("X-Simulate-Response-Loss") == "1"
        try:
            status, resp = self.server.service.dispatch(method, self.path, body)
        except Exception as exc:
            status, resp = 500, envelope(500, "server_error", None, error=repr(exc))
        self.server.service.write_trace({
            "ts": now_iso(),
            "method": method,
            "path": self.path,
            "status": status,
            "reason": resp.get("reason"),
            "submission_id": (resp.get("submission") or {}).get("id") if isinstance(resp.get("submission"), dict) else None,
            "loss": simulate_loss,
        })
        if simulate_loss:
            # dispatch() already COMMITted.  Now drop the reply on the floor:
            # the client sees EOF/reset and must retry idempotently.
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.close_connection = True
            return
        self._send(status, resp)


def main():
    ap = argparse.ArgumentParser(description="Mock submission service (correct implementation)")
    ap.add_argument("--db", required=True, help="path to the SQLite database file")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0, help="0 = pick a free port")
    ap.add_argument("--trace", default=None, help="optional server-side request trace (JSONL)")
    args = ap.parse_args()

    service = Service(args.db, trace_path=args.trace)
    httpd = ThreadingHTTPServerEx((args.host, args.port), Handler)
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

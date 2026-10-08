#!/usr/bin/env python3
"""Concurrent client workload + fault injection for bounty #13.

What it does
------------
1. Boots the correct service (``src.mock_service``) on 127.0.0.1.
2. Fires >=100 concurrent create requests across 10 wallet identities
   (a same-key "retry storm") and a second wave of competing distinct-key
   creates, both genuinely overlapping (one thread per request).
3. Kills and restarts the service process mid-run, then verifies the committed
   rows survived and that an idempotent replay still resolves to the same row.
4. Injects "commit succeeded, response lost" for a create and for an update and
   proves a same-key retry resolves to exactly one logical submission.
5. Probes deterministic stale-version rejection, reviewed-row immutability and
   idempotency-key reuse (same key, different body).
6. Runs the deliberately naive service under the same concurrency and captures
   its concrete invariant violations.
7. Writes raw evidence to results/ (traces.jsonl + evidence.json).  It makes no
   pass/fail judgement -- scripts/report.py turns evidence into assertions.
"""

import argparse
import http.client
import json
import os
import random
import sqlite3
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from src.common import now_iso, submission_fingerprint  # noqa: E402

WALLETS = ["w%02d" % i for i in range(10)]
TRACES = []
_TRACE_LOCK = threading.Lock()
CURRENT_SERVICE = "mock"


def trace(rec):
    rec = dict(rec)
    rec.setdefault("ts", time.time())
    rec["service"] = CURRENT_SERVICE
    with _TRACE_LOCK:
        TRACES.append(rec)


# --- process control --------------------------------------------------------

class ServiceProcess:
    def __init__(self, module, db_path, log_path, cwd=_REPO_ROOT):
        self.module = module
        self.db_path = db_path
        self.log_path = log_path
        self.cwd = cwd
        self.proc = None
        self.port = None
        self.starts = 0

    def start(self):
        self.starts += 1
        log = open(self.log_path, "ab")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", self.module, "--db", self.db_path, "--port", "0"],
            cwd=self.cwd, stdout=subprocess.PIPE, stderr=log, text=True)
        line = self.proc.stdout.readline()
        while line and not line.startswith("PORT"):
            line = self.proc.stdout.readline()
        if not line:
            self.proc.poll()
            raise RuntimeError("service %s did not start (see %s)" % (self.module, self.log_path))
        self.port = int(line.split()[1])
        return self.port

    def stop(self, hard=True):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.kill() if hard else self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None

    def restart(self):
        self.stop(hard=True)
        time.sleep(0.25)
        return self.start()


class Client:
    def __init__(self, host, port, timeout=30.0):
        self.host = host
        self.port = port
        self.timeout = timeout

    def call(self, method, path, body=None, headers=None, lossy=False):
        t0 = time.time()
        conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            data = json.dumps(body).encode() if body is not None else None
            hdr = {"Content-Type": "application/json"}
            if headers:
                hdr.update(headers)
            conn.request(method, path, data, hdr)
            resp = conn.getresponse()
            raw = resp.read()
            out = json.loads(raw.decode()) if raw else None
            return resp.status, out, (time.time() - t0) * 1000
        except (http.client.HTTPException, OSError) as exc:
            if lossy:
                return "LOST", {"error": repr(exc)}, (time.time() - t0) * 1000
            raise
        finally:
            conn.close()


# --- request helpers --------------------------------------------------------

def _reason(body):
    return body.get("reason") if isinstance(body, dict) else None


def _sub_id(body):
    if isinstance(body, dict) and isinstance(body.get("submission"), dict):
        return body["submission"].get("id")
    return None


def do_create(client, phase, bounty, wallet, key, version, payload, loss=False):
    headers = {"X-Simulate-Response-Loss": "1"} if loss else None
    status, body, ms = client.call(
        "POST", "/bounties/%s/submissions" % bounty,
        {"wallet": wallet, "idempotency_key": key, "version": version, "payload": payload},
        headers=headers, lossy=True)
    rec = {"phase": phase, "op": "create", "wallet": wallet, "idempotency_key": key,
           "version": version, "status": status, "reason": _reason(body),
           "submission_id": _sub_id(body), "loss": bool(loss), "latency_ms": round(ms, 2)}
    trace(rec)
    return rec


def do_update(client, phase, bounty, wallet, key, version, payload, loss=False):
    headers = {"X-Simulate-Response-Loss": "1"} if loss else None
    status, body, ms = client.call(
        "POST", "/bounties/%s/submissions/%s/update" % (bounty, wallet),
        {"idempotency_key": key, "version": version, "payload": payload},
        headers=headers, lossy=True)
    rec = {"phase": phase, "op": "update", "wallet": wallet, "idempotency_key": key,
           "version": version, "status": status, "reason": _reason(body),
           "submission_id": _sub_id(body), "loss": bool(loss), "latency_ms": round(ms, 2)}
    trace(rec)
    return rec


def do_review(client, phase, bounty, wallet, key, decision):
    status, body, ms = client.call(
        "POST", "/bounties/%s/submissions/%s/review" % (bounty, wallet),
        {"idempotency_key": key, "decision": decision}, lossy=True)
    rec = {"phase": phase, "op": "review", "wallet": wallet, "idempotency_key": key,
           "status": status, "reason": _reason(body), "submission_id": _sub_id(body),
           "latency_ms": round(ms, 2)}
    trace(rec)
    return rec


def fetch(client, bounty, wallet=None):
    path = "/debug/submissions?bounty=%s" % bounty
    if wallet:
        path += "&wallet=%s" % wallet
    return client.call("GET", path)[1]["submissions"]


# --- phases -----------------------------------------------------------------

def phase_retry_storm(client, bounty, wallets):
    """Each wallet fires 10 *identical* creates (same key) concurrently."""
    tasks = []
    for w in wallets:
        key = "%s:create:%s" % (bounty, w)
        for _ in range(10):
            tasks.append((w, key, 1, "payload:%s" % w))
    random.shuffle(tasks)
    with ThreadPoolExecutor(max_workers=len(tasks)) as ex:
        futs = [ex.submit(do_create, client, "retry_storm", bounty, t[0], t[1], t[2], t[3])
                for t in tasks]
        return [f.result() for f in as_completed(futs)]


def phase_competing(client, bounty, wallets, per_wallet=10):
    """Each wallet fires N distinct-key creates concurrently (competing attempts)."""
    tasks = []
    for w in wallets:
        for i in range(per_wallet):
            tasks.append((w, "%s:attempt:%s:%d" % (bounty, w, i), 1, "payload:%s:%d" % (w, i)))
    random.shuffle(tasks)
    with ThreadPoolExecutor(max_workers=len(tasks)) as ex:
        futs = [ex.submit(do_create, client, "competing", bounty, t[0], t[1], t[2], t[3])
                for t in tasks]
        return [f.result() for f in as_completed(futs)]


def phase_response_loss_create(client):
    bounty, wallet, key = "b-loss", "w-loss", "b-loss:create:w-loss"
    st, _body, _ = client.call(
        "POST", "/bounties/%s/submissions" % bounty,
        {"wallet": wallet, "idempotency_key": key, "version": 1, "payload": "lost-create"},
        headers={"X-Simulate-Response-Loss": "1"}, lossy=True)
    committed = fetch(client, bounty, wallet)
    row_id = committed[0]["id"] if committed else None
    st2, body2, _ = client.call(
        "POST", "/bounties/%s/submissions" % bounty,
        {"wallet": wallet, "idempotency_key": key, "version": 1, "payload": "lost-create"})
    retry_id = _sub_id(body2)
    final = fetch(client, bounty, wallet)
    rec = {"loss_detected": st == "LOST", "committed_after_loss": len(committed),
           "row_id": row_id, "retry_status": st2, "retry_reason": _reason(body2),
           "retry_id": retry_id, "final_rows": len(final), "same_id": row_id == retry_id}
    trace({"phase": "response_loss_create_summary", **rec})
    return rec


def phase_response_loss_update(client):
    bounty, wallet = "b-loss-up", "w-loss-up"
    do_create(client, "pre_loss_update", bounty, wallet, "b-loss-up:create:w-loss-up", 1, "v1")
    uk = "b-loss-up:update:w-loss-up"
    st, _b, _ = client.call(
        "POST", "/bounties/%s/submissions/%s/update" % (bounty, wallet),
        {"idempotency_key": uk, "version": 2, "payload": "v2"},
        headers={"X-Simulate-Response-Loss": "1"}, lossy=True)
    after = fetch(client, bounty, wallet)[0]
    st2, body2, _ = client.call(
        "POST", "/bounties/%s/submissions/%s/update" % (bounty, wallet),
        {"idempotency_key": uk, "version": 2, "payload": "v2"}, lossy=True)
    final = fetch(client, bounty, wallet)[0]
    rec = {"loss_detected": st == "LOST",
           "version_after_loss": after["version"], "payload_after_loss": after["payload"],
           "retry_status": st2, "retry_reason": _reason(body2),
           "final_version": final["version"], "final_payload": final["payload"],
           "applied_once": after["version"] == 2 and final["version"] == 2 and final["payload"] == "v2"}
    trace({"phase": "response_loss_update_summary", **rec})
    return rec


def phase_stale(client):
    bounty, wallet = "b-stale", "w-stale"
    do_create(client, "stale_setup", bounty, wallet, "b-stale:create:w-stale", 1, "v1")
    do_update(client, "stale_setup", bounty, wallet, "b-stale:update:w-stale:v2", 2, "v2")
    r_old = do_update(client, "stale", bounty, wallet, "b-stale:update:old", 1, "v-old")
    r_gap = do_update(client, "stale", bounty, wallet, "b-stale:update:gap", 4, "v-gap")
    row = fetch(client, bounty, wallet)[0]
    rec = {"old_version_status": r_old["status"], "old_version_reason": r_old["reason"],
           "gap_status": r_gap["status"], "gap_reason": r_gap["reason"],
           "final_version": row["version"], "final_payload": row["payload"],
           "row_unchanged_by_stale": row["version"] == 2 and row["payload"] == "v2"}
    trace({"phase": "stale_summary", **rec})
    return rec


def phase_review(client):
    bounty, wallet = "b-review", "w-review"
    do_create(client, "review_setup", bounty, wallet, "b-review:create:w-review", 1, "v1")
    do_update(client, "review_setup", bounty, wallet, "b-review:update:v2", 2, "v2")
    r_rev = do_review(client, "review", bounty, wallet, "b-review:review:accept", "accepted")
    before = fetch(client, bounty, wallet)[0]
    fp_before = submission_fingerprint(before)
    r_upd = do_update(client, "review", bounty, wallet, "b-review:update:after-review", 3, "v3-illegal")
    r_re2 = do_review(client, "review", bounty, wallet, "b-review:review:again", "rejected")
    after = fetch(client, bounty, wallet)[0]
    fp_after = submission_fingerprint(after)
    rec = {"review_status": r_rev["status"], "review_reason": r_rev["reason"],
           "state_after_review": before["state"], "decision_after_review": before["decision"],
           "update_status": r_upd["status"], "update_reason": r_upd["reason"],
           "rereview_status": r_re2["status"], "rereview_reason": r_re2["reason"],
           "fp_before": fp_before, "fp_after": fp_after, "unchanged": fp_before == fp_after}
    trace({"phase": "review_summary", **rec})
    return rec


def phase_idem_conflict(client):
    bounty, wallet, key = "b-idem", "w-idem", "b-idem:key"
    r1 = do_create(client, "idem_conflict", bounty, wallet, key, 1, "payload-A")
    r2 = do_create(client, "idem_conflict", bounty, wallet, key, 1, "payload-B")
    rec = {"first_status": r1["status"], "second_status": r2["status"], "second_reason": r2["reason"]}
    trace({"phase": "idem_conflict_summary", **rec})
    return rec


def raw_duplicate_insert_test(db_path):
    """Prove the partial UNIQUE index is real: force a second active row."""
    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.execute("PRAGMA busy_timeout=10000")
    integrity_error, err = False, None
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO submissions (bounty_id,wallet,version,payload,state,decision,idempotency_key,created_at,updated_at)"
            " VALUES ('b-conc','w00',1,'raw-dup','active',NULL,?,?,?)",
            ("raw-dup-key", now_iso(), now_iso()))
        conn.execute("COMMIT")
    except sqlite3.IntegrityError as exc:
        integrity_error, err = True, str(exc)
        conn.execute("ROLLBACK")
    except Exception as exc:  # pragma: no cover
        err = repr(exc)
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
    finally:
        conn.close()
    return {"integrity_error": integrity_error, "error": err,
            "index": "ux_one_active_submission (partial UNIQUE, WHERE state='active')"}


def run_naive(out_dir):
    global CURRENT_SERVICE
    CURRENT_SERVICE = "naive"
    naive_db = os.path.join(out_dir, "naive.db")
    svc = ServiceProcess("src.naive_service", naive_db, os.path.join(out_dir, "naive_service.log"))
    svc.start()
    client = Client("127.0.0.1", svc.port)

    phase_competing(client, "n-conc", WALLETS, per_wallet=10)
    rows = fetch(client, "n-conc")
    per_wallet = {}
    for r in rows:
        per_wallet.setdefault(r["wallet"], []).append(r)
    duplicates = {w: len(v) for w, v in per_wallet.items() if len(v) > 1}

    bounty, wallet = "n-review", "w-nreview"
    do_create(client, "naive_review", bounty, wallet, "n-review:create", 1, "v1")
    do_review(client, "naive_review", bounty, wallet, "n-review:review", "accepted")
    before = fetch(client, bounty, wallet)[0]
    fp_before = submission_fingerprint(before)
    r_upd = do_update(client, "naive_review", bounty, wallet, "n-review:update", 2, "v2-illegal")
    after = fetch(client, bounty, wallet)[0]
    fp_after = submission_fingerprint(after)
    reviewed_overwritten = fp_before != fp_after
    db_rows = client.call("GET", "/debug/submissions")[1]["submissions"]
    svc.stop()

    violations = []
    if duplicates:
        violations.append("duplicate_active_submissions")
    if reviewed_overwritten:
        violations.append("overwritten_reviewed_submission")

    return {
        "duplicates": duplicates,
        "duplicate_wallets": len(duplicates),
        "rows_for_bounty_n-conc": len(rows),
        "reviewed_update_status": r_upd["status"],
        "reviewed_overwritten": reviewed_overwritten,
        "reviewed_fp_before": fp_before,
        "reviewed_fp_after": fp_after,
        "violations": violations,
        "db_rows": db_rows,
    }


# --- driver -----------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="results")
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()
    out_dir = os.path.join(_REPO_ROOT, args.out)
    os.makedirs(out_dir, exist_ok=True)
    random.seed(args.seed)

    mock_db = os.path.join(out_dir, "mock.db")
    for base in (mock_db, os.path.join(out_dir, "naive.db")):
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(base + suffix):
                os.remove(base + suffix)

    evidence = {"config": {"seed": args.seed, "wallets": WALLETS}, "phases": {}}

    svc = ServiceProcess("src.mock_service", mock_db, os.path.join(out_dir, "mock_service.log"))
    svc.start()
    client = Client("127.0.0.1", svc.port)
    evidence["phases"]["health"] = {"status": client.call("GET", "/health")[0]}

    # 1) concurrency wave A, then a genuine mid-run process restart
    wave_a, wave_b = WALLETS[:5], WALLETS[5:]
    phase_retry_storm(client, "b-conc", wave_a)
    pre = fetch(client, "b-conc")
    pre_by_wallet = {r["wallet"]: r for r in pre}
    replay_wallet = wave_a[0]
    replay_key = "b-conc:create:%s" % replay_wallet
    replay_pre_id = pre_by_wallet[replay_wallet]["id"]
    port_before = svc.port

    new_port = svc.restart()
    client = Client("127.0.0.1", svc.port)
    health_after = client.call("GET", "/health")[0]
    post = fetch(client, "b-conc")
    post_ids = {r["wallet"]: r["id"] for r in post}
    persisted = len(post) == len(pre) and all(
        post_ids.get(w) == pre_by_wallet[w]["id"] for w in pre_by_wallet)
    rep = do_create(client, "restart_replay", "b-conc", replay_wallet, replay_key, 1,
                    "payload:%s" % replay_wallet)
    evidence["phases"]["restart"] = {
        "starts": svc.starts, "health_after": health_after,
        "port_before": port_before, "port_after": new_port,
        "rows_before": len(pre), "rows_after": len(post), "persisted": persisted,
        "replay_status": rep["status"], "replay_id": rep["submission_id"],
        "replay_pre_id": replay_pre_id, "replay_same_id": rep["submission_id"] == replay_pre_id,
    }

    # 2) concurrency wave B after the restart (same invariant, new wallets)
    phase_retry_storm(client, "b-conc", wave_b)

    # 3) competing distinct-key creates
    phase_competing(client, "b-dup", WALLETS, per_wallet=10)

    # 4) response loss for create and for update
    evidence["phases"]["response_loss_create"] = phase_response_loss_create(client)
    evidence["phases"]["response_loss_update"] = phase_response_loss_update(client)

    # 5) stale versions, 6) review immutability, 7) idempotency-key reuse
    evidence["phases"]["stale"] = phase_stale(client)
    evidence["phases"]["review"] = phase_review(client)
    evidence["phases"]["idem_conflict"] = phase_idem_conflict(client)

    # 8) snapshot while the service is still up, then stop and test the schema
    evidence["mock_db"] = client.call("GET", "/debug/submissions")[1]["submissions"]
    svc.stop()
    evidence["phases"]["schema_constraint"] = raw_duplicate_insert_test(mock_db)

    # 9) run the naive service and capture its violations
    evidence["naive"] = run_naive(out_dir)

    # 10) metrics + artifacts
    mock_traces = [t for t in TRACES if t.get("service") == "mock"]
    conc = [t for t in mock_traces if t.get("phase") in ("retry_storm", "competing")]
    evidence["metrics"] = {
        "total_traces": len(TRACES),
        "mock_requests": len(mock_traces),
        "concurrent_requests": len(conc),
        "concurrent_wallets": len(sorted({t.get("wallet") for t in conc if t.get("wallet")})),
        "mock_service_starts": svc.starts,
    }
    with open(os.path.join(out_dir, "traces.jsonl"), "w") as f:
        for t in TRACES:
            f.write(json.dumps(t, sort_keys=True) + "\n")
    with open(os.path.join(out_dir, "evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2, sort_keys=True)

    print("[client] %d mock requests, %d concurrent, %d wallet identities"
          % (evidence["metrics"]["mock_requests"], evidence["metrics"]["concurrent_requests"],
             evidence["metrics"]["concurrent_wallets"]))
    print("[client] evidence -> %s" % os.path.join(out_dir, "evidence.json"))
    print("[client] traces   -> %s" % os.path.join(out_dir, "traces.jsonl"))
    return 0


if __name__ == "__main__":
    sys.exit(main())

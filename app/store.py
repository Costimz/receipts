"""SQLite store for runs and their event logs, so every receipt has a permanent link."""
import json
import os
import sqlite3
import threading
import time

DB_PATH = os.environ.get("RECEIPTS_DB", "/var/lib/receipts/receipts.db")
_lock = threading.Lock()
_conn = None


def conn():
    global _conn
    if _conn is None:
        os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.executescript("""
            CREATE TABLE IF NOT EXISTS runs(
              id TEXT PRIMARY KEY, kind TEXT, question TEXT, status TEXT,
              created REAL, finished REAL, result TEXT, error TEXT);
            CREATE TABLE IF NOT EXISTS events(
              run_id TEXT, seq INTEGER, ts REAL, type TEXT, data TEXT,
              PRIMARY KEY(run_id, seq));
        """)
        # A run that was in flight when the app stopped is never coming back.
        _conn.execute("UPDATE runs SET status='failed', error='the server restarted during this run' WHERE status='running'")
        _conn.commit()
    return _conn


def create_run(run_id, kind, question):
    with _lock:
        conn().execute("INSERT INTO runs(id,kind,question,status,created) VALUES(?,?,?,?,?)",
                       (run_id, kind, question, "running", time.time()))
        conn().commit()


def add_event(run_id, kind, data):
    with _lock:
        c = conn()
        seq = c.execute("SELECT COALESCE(MAX(seq),0)+1 FROM events WHERE run_id=?", (run_id,)).fetchone()[0]
        c.execute("INSERT INTO events VALUES(?,?,?,?,?)", (run_id, seq, time.time(), kind, json.dumps(data)))
        c.commit()


def finish_run(run_id, result=None, error=None):
    with _lock:
        conn().execute("UPDATE runs SET status=?, finished=?, result=?, error=? WHERE id=?",
                       ("failed" if error else "done", time.time(), json.dumps(result) if result is not None else None,
                        error, run_id))
        conn().commit()


def get_run(run_id, after=0):
    with _lock:
        c = conn()
        row = c.execute("SELECT id,kind,question,status,created,finished,result,error FROM runs WHERE id=?",
                        (run_id,)).fetchone()
        if not row:
            return None
        events = c.execute("SELECT seq,ts,type,data FROM events WHERE run_id=? AND seq>? ORDER BY seq",
                           (run_id, after)).fetchall()
    return {
        "id": row[0], "kind": row[1], "question": row[2], "status": row[3], "created": row[4], "finished": row[5],
        "result": json.loads(row[6]) if row[6] else None, "error": row[7],
        "events": [{"seq": e[0], "ts": e[1], "type": e[2], "data": json.loads(e[3])} for e in events],
    }


def stats():
    with _lock:
        c = conn()
        done = c.execute("SELECT COUNT(*) FROM runs WHERE status='done'").fetchone()[0]
        sandboxes = c.execute("SELECT COUNT(*) FROM events WHERE type='execution'").fetchone()[0]
        attacks = c.execute("SELECT COUNT(*) FROM events WHERE type='probe'").fetchone()[0]
        escaped = c.execute("SELECT COUNT(*) FROM events WHERE type='probe' AND json_extract(data,'$.escaped')=1").fetchone()[0]
    return {"runs": done, "sandboxes": sandboxes, "attacks": attacks, "escaped": escaped}

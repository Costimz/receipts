#!/usr/bin/env python3
"""Receipts web app and API. Stdlib only. Binds to localhost, with Caddy in front."""
import json
import mimetypes
import os
import secrets
import shutil
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import agent  # noqa: E402
import attacks  # noqa: E402
import llm  # noqa: E402
import store  # noqa: E402

STATIC = Path(__file__).parent.parent / "static"
PORT = int(os.environ.get("PORT", "8100"))
RATE_PER_HOUR = int(os.environ.get("PUBLIC_RATE_PER_HOUR", "8"))
MAX_QUESTION = 500
MAX_ACTIVE = 3

_hits = {}
_hits_lock = threading.Lock()
_active = threading.BoundedSemaphore(MAX_ACTIVE)


def allowed(ip):
    """A small per-IP budget, held in memory only, because inference costs money and IPs aren't worth keeping."""
    now = time.time()
    with _hits_lock:
        recent = [t for t in _hits.get(ip, []) if now - t < 3600]
        if len(recent) >= RATE_PER_HOUR:
            _hits[ip] = recent
            return False
        recent.append(now)
        _hits[ip] = recent
    return True


def start_run(kind, question, work):
    run_id = secrets.token_urlsafe(9)
    store.create_run(run_id, kind, question)

    def emit(event_type, data):
        store.add_event(run_id, event_type, data)

    def worker():
        try:
            store.finish_run(run_id, result=work(emit))
        except Exception as e:  # noqa: BLE001 - shown to the user as a failed run
            store.finish_run(run_id, error=f"{type(e).__name__}: {str(e)[:300]}")
        finally:
            _active.release()

    threading.Thread(target=worker, daemon=True).start()
    return run_id


def status():
    return {
        "inference": llm.configured(),
        "model": os.environ.get("MODEL_CODE", "glm-5.3"),
        "provider": "Vultr Serverless Inference" if "vultr" in os.environ.get("INFERENCE_BASE_URL", "vultr") else "custom",
        "runtime": os.environ.get("SANDBOX_RUNTIME") or "runc",
        "docker": bool(shutil.which("docker")),
        **store.stats(),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "receipts"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass

    def client_ip(self):
        return (self.headers.get("X-Forwarded-For") or self.client_address[0]).split(",")[0].strip()

    def send_json(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_file(self, path):
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mimetypes.guess_type(path.name)[0] or "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                         "font-src https://fonts.gstatic.com; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/healthz":
            return self.send_json({"ok": True})
        if path == "/api/status":
            return self.send_json(status())
        if path.startswith("/api/runs/"):
            after = 0
            if "after=" in self.path:
                try:
                    after = int(self.path.split("after=")[1].split("&")[0])
                except ValueError:
                    pass
            run = store.get_run(path.rsplit("/", 1)[1], after)
            return self.send_json(run) if run else self.send_json({"error": "not found"}, 404)
        if path == "/" or path.startswith("/r/"):
            return self.send_file(STATIC / "index.html")
        target = (STATIC / path.lstrip("/")).resolve()
        if target.is_file() and STATIC.resolve() in target.parents:
            return self.send_file(target)
        self.send_json({"error": "not found"}, 404)

    def read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > 4096:
            return None
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return None

    def do_POST(self):
        path = self.path.split("?")[0]
        if path not in ("/api/investigate", "/api/attack"):
            return self.send_json({"error": "not found"}, 404)
        body = self.read_json()
        if body is None:
            return self.send_json({"error": "bad request"}, 400)
        if path == "/api/investigate":
            question = str(body.get("question", "")).strip()
            if len(question) < 5 or len(question) > MAX_QUESTION:
                return self.send_json({"error": f"ask a question of 5 to {MAX_QUESTION} characters"}, 400)
            if not llm.configured():
                return self.send_json({"error": "inference is not configured yet"}, 503)
        if not allowed(self.client_ip()):
            return self.send_json({"error": "you've hit the hourly limit for this demo, try again later"}, 429)
        if not _active.acquire(blocking=False):
            return self.send_json({"error": "the sandbox queue is full, try again in a minute"}, 503)
        if path == "/api/investigate":
            run_id = start_run("investigate", question, lambda emit: agent.investigate(question, emit))
        else:
            run_id = start_run("attack", "Try to break out", lambda emit: attacks.run_attack(emit))
        self.send_json({"id": run_id}, 202)


def main():
    store.conn()
    if not os.environ.get(attacks.CANARY_ENV):
        os.environ[attacks.CANARY_ENV] = "canary-" + secrets.token_hex(16)
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()

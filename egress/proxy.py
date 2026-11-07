#!/usr/bin/env python3
"""Allowlist egress proxy. The sandbox network has no route out, so this is the only exit.

Only CONNECT to an allowlisted host on port 443 is tunnelled. Every attempt, allowed
or refused, is appended to a JSONL log that the app reads back into each receipt.
"""
import base64
import ipaddress
import json
import os
import select
import socket
import socketserver
import time

ALLOWLIST_PATH = os.environ.get("ALLOWLIST", "/etc/receipts/allowlist.txt")
LOG_PATH = os.environ.get("EGRESS_LOG", "/log/egress.jsonl")
PORT = int(os.environ.get("PORT", "3128"))
MAX_BYTES = int(os.environ.get("MAX_TUNNEL_BYTES", str(20 * 1024 * 1024)))
IDLE_SECONDS = 30


def load_allowlist(path=ALLOWLIST_PATH):
    with open(path) as f:
        return {ln.strip().lower() for ln in f if ln.strip() and not ln.startswith("#")}


def is_public(ip):
    addr = ipaddress.ip_address(ip)
    return addr.is_global and not addr.is_multicast


def decide(method, target, allowlist):
    """Return (host, port, allowed, reason) for a proxy request line."""
    if method != "CONNECT":
        host = target.split("/")[2] if "://" in target else target
        return host.split(":")[0].lower(), 80, False, "plain_http_refused"
    host, _, port = target.rpartition(":")
    host = host.strip("[]").lower()
    port = int(port) if port.isdigit() else 0
    if port != 443:
        return host, port, False, "port_refused"
    if host not in allowlist:
        return host, port, False, "host_not_allowlisted"
    return host, port, True, "allowlisted"


def run_token(headers):
    """The app labels each sandbox with a run token in the proxy credentials, for attribution."""
    raw = headers.get("proxy-authorization", "")
    if raw.lower().startswith("basic "):
        try:
            return base64.b64decode(raw[6:]).decode().split(":")[0]
        except Exception:
            pass
    return "unknown"


class Handler(socketserver.StreamRequestHandler):
    def log_event(self, **event):
        event["ts"] = round(time.time(), 3)
        with open(self.server.log_path, "a") as f:
            f.write(json.dumps(event) + "\n")

    def reply(self, status):
        self.wfile.write(f"HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".encode())

    def handle(self):
        self.request.settimeout(15)
        try:
            line = self.rfile.readline(4096).decode("latin1").strip()
            headers = {}
            while True:
                h = self.rfile.readline(4096).decode("latin1").strip()
                if not h:
                    break
                k, _, v = h.partition(":")
                headers[k.strip().lower()] = v.strip()
            method, target, _ = line.split(" ", 2)
        except Exception:
            return
        host, port, allowed, reason = decide(method, target, self.server.allowlist)
        run = run_token(headers)
        upstream = None
        if allowed:
            try:
                # Resolve here and refuse private answers, so a poisoned record can't reach the VM's neighbours.
                ip = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0][4][0]
                if not is_public(ip) and not self.server.allow_private:
                    allowed, reason = False, "resolved_private_ip"
                else:
                    upstream = socket.create_connection((ip, port), timeout=15)
            except OSError:
                allowed, reason = False, "upstream_unreachable"
        self.log_event(run=run, host=host, port=port, allowed=allowed, reason=reason)
        if not allowed:
            self.reply("403 Forbidden")
            return
        self.reply("200 Connection Established")
        self.tunnel(upstream)

    def tunnel(self, upstream):
        client = self.request
        total = 0
        try:
            while total < MAX_BYTES:
                ready, _, _ = select.select([client, upstream], [], [], IDLE_SECONDS)
                if not ready:
                    return
                for sock in ready:
                    data = sock.recv(65536)
                    if not data:
                        return
                    total += len(data)
                    (upstream if sock is client else client).sendall(data)
        except OSError:
            pass
        finally:
            upstream.close()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def make_server(port=PORT, allowlist=None, log_path=LOG_PATH, allow_private=False):
    srv = Server(("0.0.0.0", port), Handler)
    srv.allowlist = load_allowlist() if allowlist is None else allowlist
    srv.log_path = log_path
    srv.allow_private = allow_private
    return srv


if __name__ == "__main__":
    make_server().serve_forever()

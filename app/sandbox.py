"""Runs untrusted Python in a fresh, locked-down, single-use container and proves it is gone."""
import hashlib
import json
import os
import secrets
import subprocess
import threading
import time

IMAGE = os.environ.get("SANDBOX_IMAGE", "receipts-sandbox:latest")
NETWORK = os.environ.get("SANDBOX_NETWORK", "receipts-sbx")
# A fixed IP, because gVisor bypasses Docker's embedded DNS, and that is one less thing a sandbox can use.
PROXY_HOST = os.environ.get("EGRESS_HOST", "172.30.0.2")
EGRESS_LOG = os.environ.get("EGRESS_LOG", "/var/lib/receipts/egress/egress.jsonl")
OUTPUT_CAP = 64 * 1024
DEFAULTS = {"timeout": 45, "memory_mb": 256, "cpus": "0.5", "pids": 64, "tmpfs_mb": 16}

# One sandbox at a time, so there is never a sibling for a hostile script to reach.
_slot = threading.Semaphore(int(os.environ.get("SANDBOX_CONCURRENCY", "1")))


def sha256(text):
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def docker_args(name, token, limits, runtime):
    args = [
        "docker", "run", "-i", "--name", name, "--hostname", "sandbox",
        "--network", NETWORK,
        "--log-driver", "none",  # otherwise an output flood fills the VM's disk with container logs
        "--read-only",
        "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={limits['tmpfs_mb']}m",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", str(limits["pids"]),
        "--memory", f"{limits['memory_mb']}m",
        "--memory-swap", f"{limits['memory_mb']}m",
        "--cpus", limits["cpus"],
        "--user", "65534:65534",
        "--env", f"HTTPS_PROXY=http://{token}:x@{PROXY_HOST}:3128",
        "--env", f"HTTP_PROXY=http://{token}:x@{PROXY_HOST}:3128",
        "--env", "HOME=/tmp",
        "--env", "PYTHONDONTWRITEBYTECODE=1",
    ]
    if runtime:
        args += ["--runtime", runtime]
    return args + [IMAGE, "python", "-I", "-u", "-"]


def read_egress(token, path=None):
    """The proxy's own record of what this sandbox tried to reach."""
    out = []
    try:
        with open(path or EGRESS_LOG) as f:
            for line in f:
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if e.get("run") == token:
                    out.append({k: e.get(k) for k in ("host", "port", "allowed", "reason")})
    except FileNotFoundError:
        pass
    return out


def _docker_quiet(*args):
    """Run a docker command, returning a failed result rather than raising if Docker is slow."""
    try:
        return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, 124, "", "docker timed out")


def run(code, **overrides):
    limits = {**DEFAULTS, **overrides}
    runtime = os.environ.get("SANDBOX_RUNTIME", "")
    token = secrets.token_hex(8)
    name = f"sbx-{token}"
    with _slot:
        return _run_locked(code, name, token, limits, runtime)


def _run_locked(code, name, token, limits, runtime):
    started = time.time()
    proc = subprocess.Popen(docker_args(name, token, limits, runtime), stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    killed = {"reason": None}

    def kill(reason):
        # On its own thread, so the readers keep draining: a blocked pipe would stop the container exiting.
        if not killed["reason"]:
            killed["reason"] = reason
            threading.Thread(target=_docker_quiet, args=("kill", name), daemon=True).start()

    buffers = {"out": bytearray(), "err": bytearray()}

    def reader(stream, key):
        size = 0
        while True:
            chunk = stream.read(8192)
            if not chunk:
                return
            size += len(chunk)
            room = OUTPUT_CAP - len(buffers[key])
            if room > 0:
                buffers[key] += chunk[:room]
            # A flood gets the container killed rather than filling the VM's memory.
            if size > OUTPUT_CAP * 4:
                kill("output_cap")

    threads = [threading.Thread(target=reader, args=(proc.stdout, "out"), daemon=True),
               threading.Thread(target=reader, args=(proc.stderr, "err"), daemon=True)]
    for t in threads:
        t.start()
    try:
        proc.stdin.write(code.encode())
        proc.stdin.close()
    except (BrokenPipeError, OSError):
        pass
    try:
        proc.wait(timeout=limits["timeout"])
    except subprocess.TimeoutExpired:
        kill("timeout")
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            _docker_quiet("rm", "-f", name)
            proc.kill()
    for t in threads:
        t.join(timeout=5)

    state = _docker_quiet("inspect", "--format", "{{.Id}} {{.State.OOMKilled}}", name).stdout.split()
    container_id = state[0][:12] if state else ""
    if len(state) > 1 and state[1] == "true" and not killed["reason"]:
        killed["reason"] = "out_of_memory"
    _docker_quiet("rm", "-f", name)
    # Ask Docker again, so "destroyed" is an observation and not an assumption.
    destroyed = _docker_quiet("inspect", name).returncode != 0

    stdout = buffers["out"].decode("utf-8", "replace")
    stderr = buffers["err"].decode("utf-8", "replace")
    return {
        "exit_code": proc.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "duration_ms": int((time.time() - started) * 1000),
        "container": container_id,
        "image": IMAGE,
        "runtime": runtime or "runc",
        "limits": {k: limits[k] for k in ("timeout", "memory_mb", "cpus", "pids", "tmpfs_mb")},
        "killed": killed["reason"],
        "destroyed": destroyed,
        "code_sha256": sha256(code),
        "stdout_sha256": sha256(stdout),
        "egress": read_egress(token),
    }

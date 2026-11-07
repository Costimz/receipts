#!/usr/bin/env bash
# Run on the VM. Stores the inference key without it appearing on screen or in shell history.
set -euo pipefail
read -rsp "Paste your Vultr Serverless Inference API key (nothing will show): " KEY; echo
[ -n "$KEY" ] || { echo "No key entered, nothing changed."; exit 1; }
python3 -I - "$KEY" <<'PY'
import sys
path = "/etc/receipts/app.env"
lines = [l for l in open(path).read().splitlines() if not l.startswith("INFERENCE_API_KEY=")]
lines.insert(0, "INFERENCE_API_KEY=" + sys.argv[1])
open(path, "w").write("\n".join(lines) + "\n")
PY
chmod 600 /etc/receipts/app.env
systemctl restart receipts
echo "Saved. The app restarted with the new key."

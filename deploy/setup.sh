#!/usr/bin/env bash
# Run once on a fresh Ubuntu 24.04 Vultr VM, as root, from the repo folder.
#   DOMAIN=1-2-3-4.sslip.io bash deploy/setup.sh
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
cd "$(dirname "$0")/.."
ROOT=/opt/receipts
DOMAIN="${DOMAIN:?set DOMAIN, e.g. DOMAIN=\$(curl -s ifconfig.me | tr . -).sslip.io}"

apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg python3 ufw rsync debian-keyring debian-archive-keyring apt-transport-https

# Docker
if ! command -v docker >/dev/null; then
  curl -fsSL https://get.docker.com | sh
fi

# gVisor gives each sandbox its own user-space kernel, on top of the container limits.
if ! command -v runsc >/dev/null; then
  curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" > /etc/apt/sources.list.d/gvisor.list
  apt-get update -qq && apt-get install -y -qq runsc
fi
runsc install
systemctl restart docker

# Caddy for HTTPS
if ! command -v caddy >/dev/null; then
  curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -qq && apt-get install -y -qq caddy
fi

# App files and an unprivileged service user. It needs Docker to start sandboxes.
id receipts >/dev/null 2>&1 || useradd --system --home "$ROOT" --shell /usr/sbin/nologin receipts
usermod -aG docker receipts
mkdir -p "$ROOT" /etc/receipts /var/lib/receipts/egress
rsync -a --delete --exclude .git --exclude .env ./ "$ROOT/"
cp egress/allowlist.txt /etc/receipts/allowlist.txt
[ -f /etc/receipts/app.env ] || { cp .env.example /etc/receipts/app.env; echo "EDIT /etc/receipts/app.env to add INFERENCE_API_KEY"; }
chmod 600 /etc/receipts/app.env
chown -R receipts:receipts /var/lib/receipts
chmod 750 /var/lib/receipts

docker build -q -t receipts-sandbox:latest sandbox

# The sandbox network has no route out. The proxy is the only other thing on it.
docker network inspect receipts-sbx >/dev/null 2>&1 || \
  docker network create --internal --subnet 172.30.0.0/24 -o com.docker.network.bridge.name=sbx0 receipts-sbx
docker rm -f receipts-egress >/dev/null 2>&1 || true
docker run -d --name receipts-egress --restart unless-stopped --read-only --cap-drop ALL \
  --security-opt no-new-privileges --memory 128m --pids-limit 128 \
  -v "$ROOT/egress/proxy.py:/proxy.py:ro" -v /etc/receipts/allowlist.txt:/etc/receipts/allowlist.txt:ro \
  -v /var/lib/receipts/egress:/log --user "$(id -u receipts):$(id -g receipts)" \
  python:3.12-slim python -I -u /proxy.py >/dev/null
docker network connect --ip 172.30.0.2 receipts-sbx receipts-egress

# Nothing on the sandbox bridge may talk to the host itself. Docker's isolation rules don't cover this path.
iptables -C INPUT -i sbx0 -j DROP 2>/dev/null || iptables -I INPUT -i sbx0 -j DROP
ip6tables -C INPUT -i sbx0 -j DROP 2>/dev/null || ip6tables -I INPUT -i sbx0 -j DROP
# Docker's own rules can't be trusted to survive a reboot in this order, so this unit restores ours.
cat > /etc/systemd/system/receipts-firewall.service <<'UNIT'
[Unit]
Description=Block the sandbox bridge from the host
After=docker.service
Requires=docker.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'iptables -C INPUT -i sbx0 -j DROP 2>/dev/null || iptables -I INPUT -i sbx0 -j DROP'
[Install]
WantedBy=multi-user.target
UNIT

cp deploy/receipts.service /etc/systemd/system/receipts.service
sed "s/__DOMAIN__/$DOMAIN/" deploy/Caddyfile > /etc/caddy/Caddyfile
ufw allow 22/tcp >/dev/null; ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null; ufw --force enable >/dev/null
systemctl daemon-reload
systemctl enable --now receipts-firewall receipts >/dev/null
systemctl restart receipts caddy
sleep 2
curl -s localhost:8100/healthz && echo
echo "Live at https://$DOMAIN"

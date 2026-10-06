#!/usr/bin/env bash
# install.sh — stand up the Cybernet genesis node on the public host (artificer-labs).
#
# Run as root from the repo checkout (which on HQ lives at ~/cybernet/node):
#   sudo ./deploy/install.sh <public-hostname>
#
# What it does:
#   1. Creates the venv + installs requirements (if missing).
#   2. Installs deploy/cybernet-node.service as /etc/systemd/system/cybernet-node.service
#      and enables + starts it (node listens on 127.0.0.1:8471 only).
#   3. Installs deploy/Caddyfile as /etc/caddy/Caddyfile with PUBLIC_HOSTNAME set,
#      and enables + starts caddy (TLS termination, reverse proxy to the node).
#
# No secrets, no identities — the node is public by design. Re-run to update.

set -euo pipefail

HOSTNAME_ARG="${1:-}"
if [[ -z "$HOSTNAME_ARG" ]]; then
    echo "usage: sudo ./deploy/install.sh <public-hostname>" >&2
    exit 1
fi
if [[ "$EUID" -ne 0 ]]; then
    echo "must run as root (sudo)" >&2
    exit 1
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE_DIR="${NODE_DIR:-/home/villhaze/cybernet/node}"
SERVICE_USER="${SERVICE_USER:-villhaze}"

echo "[1/3] node runtime"
if [[ ! -x "$NODE_DIR/venv/bin/uvicorn" ]]; then
    echo "  creating venv and installing requirements in $NODE_DIR"
    mkdir -p "$NODE_DIR"
    python3 -m venv "$NODE_DIR/venv"
    "$NODE_DIR/venv/bin/pip" install -q -r "$REPO_DIR/requirements.txt"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$NODE_DIR"
else
    echo "  venv present, refreshing requirements"
    "$NODE_DIR/venv/bin/pip" install -q -r "$REPO_DIR/requirements.txt"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$NODE_DIR"
fi

echo "[2/3] systemd unit"
install -m 0644 "$REPO_DIR/deploy/cybernet-node.service" /etc/systemd/system/cybernet-node.service
systemctl daemon-reload
systemctl enable cybernet-node.service
# Restart (not just --now) so a re-run picks up new code AND the new unit file.
systemctl restart cybernet-node.service
sleep 2
systemctl is-active --quiet cybernet-node.service \
    && echo "  cybernet-node.service active" \
    || { echo "  ERROR: cybernet-node.service failed to start"; systemctl status cybernet-node.service --no-pager | tail -5; exit 1; }

echo "[3/3] caddy reverse proxy"
if ! command -v caddy >/dev/null 2>&1; then
    echo "  caddy not installed — install it first (https://caddyserver.com/docs/install)"
    exit 1
fi
mkdir -p /etc/caddy
sed "s/{\\\$PUBLIC_HOSTNAME}/$HOSTNAME_ARG/" "$REPO_DIR/deploy/Caddyfile" > /etc/caddy/Caddyfile
systemctl enable --now caddy
# Reload so a re-run picks up the new Caddyfile without dropping connections.
systemctl reload caddy
echo "  caddy active; genesis node should answer at https://$HOSTNAME_ARG/api/v1/node"

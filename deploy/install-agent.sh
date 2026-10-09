#!/usr/bin/env bash
# install-agent.sh — one-command per-agent .cyberspace stand-up.
#
# Run as root on the agent's machine from the repo checkout:
#   sudo ./deploy/install-agent.sh [--user NAME] [--mirror URL] [--hostd-env PATH]
#
# What it does:
#   1. Creates the venv + installs requirements (if missing) at
#      /home/<user>/cybernet/node (override: NODE_DIR env).
#   2. Installs deploy/resolverd.service as /etc/systemd/system/resolverd.service
#      (EDIT lines rewritten from --user/--mirror/NODE_DIR), enables + starts it:
#      the per-agent .cyberspace resolver daemon on 127.0.0.1:5353.
#   3. Smoke-tests the daemon through the shipped client CLI:
#      a junk name must come back NXDOMAIN (exit 1 = the daemon answers,
#      exit 2 = dead).
#   4. If --hostd-env points at a mint_name.py env file (or exactly one
#      ~/.cyberspace/hostd/*.env exists), installs it as
#      /etc/cybernet-hostd/hostd.env (0600) and starts deploy/hostd.service —
#      the per-agent hosting daemon (primitive 3 + primitive 6).
#      Otherwise prints the mint_name.py line and stops at resolution.
#
# The daemon holds no keys. The name key lives only in the 0600 hostd env
# file. Re-run to update.

set -euo pipefail

AGENT_USER="${SERVICE_USER:-villhaze}"
NODE_DIR="${NODE_DIR:-/home/$AGENT_USER/cybernet/node}"
MIRROR_URL="http://127.0.0.1:8471"
HOSTD_ENV=""

usage() {
    echo "usage: sudo ./deploy/install-agent.sh [--user NAME] [--mirror URL] [--hostd-env PATH]" >&2
    exit 2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --user)       AGENT_USER="$2"; NODE_DIR="/home/$AGENT_USER/cybernet/node"; shift 2 ;;
        --mirror)     MIRROR_URL="$2"; shift 2 ;;
        --hostd-env)  HOSTD_ENV="$2"; shift 2 ;;
        -h|--help)    usage ;;
        *)            echo "unknown option: $1" >&2; usage ;;
    esac
done

if [[ "$EUID" -ne 0 ]]; then
    echo "must run as root (sudo)" >&2
    exit 1
fi
if [[ -n "$HOSTD_ENV" && ! -f "$HOSTD_ENV" ]]; then
    echo "hostd env not found: $HOSTD_ENV" >&2
    exit 1
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PY="$NODE_DIR/venv/bin/python"

echo "[1/4] agent runtime"
if [[ ! -x "$VENV_PY" ]]; then
    echo "  creating venv and installing requirements in $NODE_DIR"
    mkdir -p "$NODE_DIR"
    python3 -m venv "$NODE_DIR/venv"
    "$NODE_DIR/venv/bin/pip" install -q -r "$REPO_DIR/requirements.txt"
    chown -R "$AGENT_USER:$AGENT_USER" "$NODE_DIR"
else
    echo "  venv present, refreshing requirements"
    "$NODE_DIR/venv/bin/pip" install -q -r "$REPO_DIR/requirements.txt"
    chown -R "$AGENT_USER:$AGENT_USER" "$NODE_DIR"
fi

# Rewrite the EDIT lines of a shipped unit for this machine.
stamp_unit() { # $1=source $2=dest
    sed -e "s|^User=villhaze$|User=$AGENT_USER|" \
        -e "s|^WorkingDirectory=/home/villhaze/cybernet/node$|WorkingDirectory=$NODE_DIR|" \
        -e "s|^Environment=\"PATH=/home/villhaze/cybernet/node/venv/bin:/usr/bin:/bin\"$|Environment=\"PATH=$NODE_DIR/venv/bin:/usr/bin:/bin\"|" \
        -e "s|^ExecStart=/home/villhaze/cybernet/node/venv/bin/python|ExecStart=$VENV_PY|" \
        "$1" > "$2"
}

echo "[2/4] resolverd unit"
stamp_unit "$REPO_DIR/deploy/resolverd.service" /etc/systemd/system/resolverd.service
sed -i "s|^Environment=\"CYBERNET_MIRROR_URL=.*\"$|Environment=\"CYBERNET_MIRROR_URL=$MIRROR_URL\"|" \
    /etc/systemd/system/resolverd.service
systemctl daemon-reload
systemctl enable resolverd.service
systemctl restart resolverd.service
sleep 2
systemctl is-active --quiet resolverd.service \
    || { echo "  ERROR: resolverd.service failed to start"; systemctl status resolverd.service --no-pager | tail -5; exit 1; }

echo "[3/4] resolver smoke (junk name must be NXDOMAIN)"
rc=0
"$VENV_PY" -m resolver.client "definitely-not-a-name.cyberspace" --tcp-only >/dev/null 2>&1 || rc=$?
case "$rc" in
    1) echo "  resolverd answers on 127.0.0.1:5353 (NXDOMAIN as expected)" ;;
    0) echo "  WARNING: junk name resolved — mirror is answering with a live binding; check before trusting" ;;
    *) echo "  ERROR: resolverd not answering (client exit $rc)"; exit 1 ;;
esac

echo "[4/4] hostd (hosting daemon)"
if [[ -z "$HOSTD_ENV" ]]; then
    CANDIDATES=(/home/"$AGENT_USER"/.cyberspace/hostd/*.env)
    if [[ ${#CANDIDATES[@]} -eq 1 && -f "${CANDIDATES[0]}" ]]; then
        HOSTD_ENV="${CANDIDATES[0]}"
        echo "  found mint_name.py env: $HOSTD_ENV"
    fi
fi
if [[ -z "$HOSTD_ENV" ]]; then
    echo "  no hostd env — resolution only. To host a name:"
    echo "    $VENV_PY $REPO_DIR/mint_name.py <label> $MIRROR_URL"
    echo "  then re-run with --hostd-env ~/.cyberspace/hostd/<label>.env"
else
    install -d -m 0700 /etc/cybernet-hostd
    install -m 0600 "$HOSTD_ENV" /etc/cybernet-hostd/hostd.env
    stamp_unit "$REPO_DIR/deploy/hostd.service" /etc/systemd/system/hostd.service
    systemctl daemon-reload
    systemctl enable hostd.service
    systemctl restart hostd.service
    sleep 2
    systemctl is-active --quiet hostd.service \
        || { echo "  ERROR: hostd.service failed to start"; systemctl status hostd.service --no-pager | tail -5; exit 1; }
    HOSTED="$(grep -E '^CYBERNET_HOSTED_NAME=' /etc/cybernet-hostd/hostd.env | cut -d= -f2)"
    echo "  hostd active; $HOSTED.cyberspace is live on this machine"
fi

echo "done — resolve with: $VENV_PY -m resolver.client <name>.cyberspace"

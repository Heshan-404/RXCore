#!/bin/bash
set -euo pipefail

VPS_HOST="${1:-root@172.236.153.131}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "========================================="
echo "      Ruve VPN One-Click Deployment      "
echo "========================================="
echo "Target VPS: $VPS_HOST"

BINARY_PATH="$SCRIPT_DIR/target_core/target/release/target_core"

if [ ! -f "$BINARY_PATH" ]; then
    echo "[1/4] Building target_core binary..."
    cd "$SCRIPT_DIR/target_core"
    cargo build --release
fi

SSH_OPTS="-o ConnectTimeout=10 -o ServerAliveInterval=10 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=accept-new"

echo "[2/4] Uploading files to VPS..."
scp $SSH_OPTS "$BINARY_PATH" "$VPS_HOST:target_core.tmp"
scp $SSH_OPTS "$SCRIPT_DIR/config.json" "$VPS_HOST:"
scp $SSH_OPTS "$SCRIPT_DIR/install.sh" "$VPS_HOST:"
scp $SSH_OPTS "$SCRIPT_DIR/warp_autoshield.sh" "$VPS_HOST:"

echo "[3/4] Installing and configuring VPS..."
ssh $SSH_OPTS "$VPS_HOST" "sudo mv -f target_core.tmp /root/target_core && sudo chmod +x /root/target_core /root/install.sh /root/warp_autoshield.sh && sudo bash /root/install.sh"

echo "[4/4] Verifying services..."
ssh $SSH_OPTS "$VPS_HOST" "systemctl is-active target_core.service warp_autoshield.service"

HOST_IP=$(echo "$VPS_HOST" | sed 's/.*@//')
echo ""
echo "========================================="
echo "   Deployment Completed Successfully!    "
echo "========================================="
echo "Admin Portal : http://${HOST_IP}:9091/"
echo "Default Pass : RuveAdmin@2026!"

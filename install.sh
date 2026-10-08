#!/bin/bash
set -euo pipefail

echo "========================================="
echo "   Ruve VPN Server Automated Installer   "
echo "========================================="

# 1. System Limits & File Descriptors (Fix for 'Too many open files')
echo "[1/6] Applying 1M File Descriptor Limits..."
cat << 'EOF' > /etc/security/limits.d/99-target-core.conf
* soft nofile 1048576
* hard nofile 1048576
* soft nproc 512000
* hard nproc 512000
root soft nofile 1048576
root hard nofile 1048576
root soft nproc 512000
root hard nproc 512000
EOF

sed -i 's/^#DefaultLimitNOFILE=.*/DefaultLimitNOFILE=1048576/' /etc/systemd/system.conf 2>/dev/null || true
sed -i 's/^#DefaultLimitNPROC=.*/DefaultLimitNPROC=512000/' /etc/systemd/system.conf 2>/dev/null || true

# 2. Kernel & TCP BBR Optimization
echo "[2/6] Configuring TCP BBR & Network Buffers..."
cat << 'EOF' > /etc/sysctl.d/99-vless-optimizations.conf
fs.file-max = 2097152
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
EOF
sysctl --system > /dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-vless-optimizations.conf 2>/dev/null || true

# 3. Firewall Configuration (Allow 443, 9091, 9100, 22)
echo "[3/6] Configuring Firewall Rules..."
iptables -I INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || true
iptables -I INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
iptables -I INPUT -p udp --dport 443 -j ACCEPT 2>/dev/null || true
iptables -I INPUT -p tcp --dport 9091 -j ACCEPT 2>/dev/null || true
iptables -I INPUT -p tcp --dport 9100 -j ACCEPT 2>/dev/null || true

if command -v ufw >/dev/null 2>&1; then
    ufw allow 22/tcp 2>/dev/null || true
    ufw allow 443/tcp 2>/dev/null || true
    ufw allow 443/udp 2>/dev/null || true
    ufw allow 9091/tcp 2>/dev/null || true
    ufw allow 9100/tcp 2>/dev/null || true
fi

# Anti-Torrent Protection Rules
iptables -A OUTPUT -p tcp -m string --string "BitTorrent" --algo bm -j DROP 2>/dev/null || true
iptables -A OUTPUT -p udp -m string --string "BitTorrent" --algo bm -j DROP 2>/dev/null || true
iptables -A OUTPUT -p tcp -m string --string "peer_id=" --algo bm -j DROP 2>/dev/null || true
iptables -A OUTPUT -p tcp -m string --string "info_hash=" --algo bm -j DROP 2>/dev/null || true

# 4. Cloudflare WARP Setup
echo "[4/6] Setting up Cloudflare WARP Outbound..."
if ! command -v warp-cli >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq curl gnupg lsb-release > /dev/null
    curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/cloudflare-client.list > /dev/null
    apt-get update -qq && apt-get install -y -qq --no-install-recommends cloudflare-warp > /dev/null
fi

warp-cli --accept-tos registration new 2>/dev/null || true
warp-cli --accept-tos mode proxy 2>/dev/null || true
warp-cli --accept-tos proxy port 40000 2>/dev/null || true
warp-cli --accept-tos connect 2>/dev/null || true

# 5. Admin Credentials Auto-Initialization
echo "[5/6] Checking Admin Credentials..."
mkdir -p /root/data
if [ ! -f /root/data/admin_credentials.json ] && [ -x /root/target_core ]; then
    DEFAULT_PASS="${ADMIN_PASSWORD:-RuveAdmin@2026!}"
    echo -n "$DEFAULT_PASS" > /root/admin_pass.txt
    chmod 600 /root/admin_pass.txt
    cd /root && /root/target_core admin init --password-file /root/admin_pass.txt > /dev/null 2>&1 || true
    rm -f /root/admin_pass.txt
    echo " -> Admin credentials initialized (Default Password: $DEFAULT_PASS)"
else
    echo " -> Existing admin credentials preserved."
fi

# 6. Systemd Services
echo "[6/6] Configuring and Starting System Services..."
cat << 'EOF' > /etc/systemd/system/warp_autoshield.service
[Unit]
Description=Cloudflare WARP AutoShield IP Rotator
After=network.target warp-svc.service

[Service]
Type=simple
ExecStart=/bin/bash /root/warp_autoshield.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

cat << 'EOF' > /etc/systemd/system/target_core.service
[Unit]
Description=Target Core Service
After=network.target warp-svc.service

[Service]
Type=simple
WorkingDirectory=/root
ExecStart=/root/target_core
Restart=always
RestartSec=5
LimitNOFILE=1048576
LimitNPROC=512000

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable warp_autoshield.service target_core.service > /dev/null 2>&1
systemctl restart warp_autoshield.service target_core.service

echo "========================================="
echo "   Installation & Start Successful!     "
echo "========================================="

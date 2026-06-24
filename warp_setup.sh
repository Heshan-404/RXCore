s=$(printf '\x2f')

# Clear duplicate firewall rules
iptables -D OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>${s}dev${s}null || true
iptables -D OUTPUT -p tcp -m string --string "BitTorrent" --algo bm -j DROP 2>${s}dev${s}null || true
iptables -D OUTPUT -p udp -m string --string "BitTorrent" --algo bm -j DROP 2>${s}dev${s}null || true
iptables -D OUTPUT -p tcp -m string --string "BitTorrent protocol" --algo bm -j DROP 2>${s}dev${s}null || true
iptables -D OUTPUT -p udp -m string --string "BitTorrent protocol" --algo bm -j DROP 2>${s}dev${s}null || true
iptables -D OUTPUT -p tcp -m string --string "peer_id=" --algo bm -j DROP 2>${s}dev${s}null || true
iptables -D OUTPUT -p tcp -m string --string "info_hash=" --algo bm -j DROP 2>${s}dev${s}null || true
iptables -D OUTPUT -p udp -m string --string "get_peers" --algo bm -j DROP 2>${s}dev${s}null || true
iptables -D OUTPUT -p udp -m string --string "announce_peer" --algo bm -j DROP 2>${s}dev${s}null || true
iptables -D OUTPUT -p udp -m string --string "find_node" --algo bm -j DROP 2>${s}dev${s}null || true
iptables -D OUTPUT -p udp --dport 443 -j DROP 2>${s}dev${s}null || true

# Apply optimized firewall rules
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -p tcp -m string --string "BitTorrent" --algo bm -j DROP
iptables -A OUTPUT -p udp -m string --string "BitTorrent" --algo bm -j DROP
iptables -A OUTPUT -p tcp -m string --string "BitTorrent protocol" --algo bm -j DROP
iptables -A OUTPUT -p udp -m string --string "BitTorrent protocol" --algo bm -j DROP
iptables -A OUTPUT -p tcp -m string --string "peer_id=" --algo bm -j DROP
iptables -A OUTPUT -p tcp -m string --string "info_hash=" --algo bm -j DROP
iptables -A OUTPUT -p udp -m string --string "get_peers" --algo bm -j DROP
iptables -A OUTPUT -p udp -m string --string "announce_peer" --algo bm -j DROP
iptables -A OUTPUT -p udp -m string --string "find_node" --algo bm -j DROP
iptables -A OUTPUT -p udp --dport 443 -j DROP

if ! command -v warp-cli >${s}dev${s}null; then
    echo "Installing prerequisites..."
    apt-get update && apt-get install -y curl gnupg lsb-release

    echo "Installing Cloudflare WARP..."
    curl -fsSL "https:${s}${s}pkg.cloudflareclient.com${s}pubkey.gpg" | gpg --yes --dearmor --output "${s}usr${s}share${s}keyrings${s}cloudflare-warp-archive-keyring.gpg"
    echo "deb [signed-by=${s}usr${s}share${s}keyrings${s}cloudflare-warp-archive-keyring.gpg] https:${s}${s}pkg.cloudflareclient.com${s} $(lsb_release -cs) main" | tee "${s}etc${s}apt${s}sources.list.d${s}cloudflare-client.list"
    apt-get update
    apt-get install -y --no-install-recommends cloudflare-warp
fi

warp-cli --accept-tos registration new 2>${s}dev${s}null
warp-cli --accept-tos mode proxy
warp-cli --accept-tos proxy port 40000
warp-cli --accept-tos connect

echo "[Unit]
Description=Cloudflare WARP AutoShield IP Rotator
After=network.target warp-svc.service

[Service]
Type=simple
ExecStart=${s}bin${s}bash ${s}root${s}warp_autoshield.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target" | tee "${s}etc${s}systemd${s}system${s}warp_autoshield.service"

systemctl daemon-reload
systemctl enable warp_autoshield.service
systemctl restart warp_autoshield.service

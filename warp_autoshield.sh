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

last_rotation=0
while true; do
    current_time=$SECONDS
    elapsed=$((current_time - last_rotation))
    if [ $elapsed -ge 1800 ]; then
        echo "Periodic rotation triggered. Resetting registration..."
        warp-cli --accept-tos registration delete
        warp-cli --accept-tos registration new
        warp-cli --accept-tos mode proxy
        warp-cli --accept-tos proxy port 40000
        warp-cli --accept-tos connect
        last_rotation=$SECONDS
    else
        status_code=$(curl -s -I -o ${s}dev${s}null -w "%{http_code}" --socks5-hostname 127.0.0.1:40000 "https:${s}${s}online-fix.me")
        if [ "$status_code" = "403" ] || [ "$status_code" = "1015" ] || [ "$status_code" = "503" ] || [ "$status_code" = "000" ]; then
            echo "Access issue detected (Status: $status_code). Resetting registration to rotate IP..."
            warp-cli --accept-tos registration delete
            warp-cli --accept-tos registration new
            warp-cli --accept-tos mode proxy
            warp-cli --accept-tos proxy port 40000
            warp-cli --accept-tos connect
            last_rotation=$SECONDS
        fi
    fi
    sleep 30
done

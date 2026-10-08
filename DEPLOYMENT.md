# Ruve VPN Deployment & System Configuration Guide

## Architecture Overview
- **Protocol**: VLESS Reality with SNI masking (`aka.ms`, `speedtest.net`)
- **Outbound Tunnel**: Cloudflare WARP proxy (`127.0.0.1:40000`) with auto-rotation for geo-unblocking
- **Admin Dashboard**: Web UI on port `9091` (`http://<SERVER_IP>:9091/`)
- **Subscription Server**: Automated client subscription links on port `9100`

---

## One-Click Deployment

All system optimizations, limits, firewall rules, services, and credentials initialization are automated. No manual post-CLI commands required.

### From Windows (PowerShell)
```powershell
.\deploy.ps1 -VpsHost root@<YOUR_VPS_IP>
```

### From Linux / macOS / WSL
```bash
bash deploy.sh root@<YOUR_VPS_IP>
```

---

## Automated Configurations Included in `install.sh`

1. **System & File Descriptor Limits** (`os error 24` prevention):
   - Sets `LimitNOFILE=1048576` and `LimitNPROC=512000` in `/etc/systemd/system/target_core.service`.
   - Sets `DefaultLimitNOFILE=1048576` in `/etc/systemd/system.conf`.
   - Applies limits to `/etc/security/limits.d/99-target-core.conf`.
2. **Network Performance**:
   - Enables TCP BBR Congestion Control.
   - Sets high-throughput network buffer sizes.
   - Raises `fs.file-max` and `net.core.somaxconn`.
3. **Firewall & Security**:
   - Opens port `443` (VLESS Reality TCP/UDP).
   - Opens port `9091` (Admin Dashboard Web UI).
   - Opens port `9100` (Subscription Server).
   - Blocks BitTorrent protocol via IPTables string matching.
4. **Cloudflare WARP**:
   - Installs and connects WARP in SOCKS5 proxy mode on `127.0.0.1:40000`.
   - Starts `warp_autoshield.service` (`Restart=always`) for automatic IP rotation.
5. **Crash Recovery & Auto-Restart**:
   - `target_core.service` configured with `Restart=always` and `RestartSec=5`.
6. **Admin Credentials**:
   - Automatically initializes admin credentials if not already present (`RuveAdmin@2026!`).
   - Uses `SameSite=Lax` cookies for stable dashboard access over HTTP.

---

## Admin Portal Access
- **URL**: `http://<YOUR_VPS_IP>:9091/`
- **Default Password**: `RuveAdmin@2026!`

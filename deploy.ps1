$s = [char]47
$vps = "root@162.243.68.194"
$ErrorActionPreference = "Stop"

Write-Host "1. Building target_core in WSL..." -ForegroundColor Cyan
wsl bash -i -c "cd ${s}mnt${s}c${s}Users${s}Heshan${s}Desktop${s}Ruve${s}target_core && cargo build --release"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed" -ForegroundColor Red
    exit 1
}

$ssh_opts = @("-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3")

Write-Host "2. Stopping target_core and autoshield on VPS..." -ForegroundColor Cyan
ssh $ssh_opts $vps "sudo systemctl stop target_core.service || true"
ssh $ssh_opts $vps "sudo systemctl stop warp_autoshield.service || true"
ssh $ssh_opts $vps "sudo pkill -9 target_core || true"

Write-Host "2.5. Cleaning up old VPN files, logs, and server storage..." -ForegroundColor Cyan
ssh $ssh_opts $vps "sudo systemctl stop warp-svc.service || true"
ssh $ssh_opts $vps "sudo pkill -9 -f apt || true"
ssh $ssh_opts $vps "sudo pkill -9 -f dpkg || true"
ssh $ssh_opts $vps "sudo rm -f ${s}var${s}lib${s}dpkg${s}lock-frontend ${s}var${s}lib${s}dpkg${s}lock ${s}var${s}cache${s}apt${s}archives${s}lock || true"
ssh $ssh_opts $vps "sudo dpkg --configure -a || true"
ssh $ssh_opts $vps "sudo apt-get purge -y cloudflare-warp || true"
ssh $ssh_opts $vps "sudo apt-get autoremove -y || true"
ssh $ssh_opts $vps "sudo rm -rf ${s}var${s}log${s}cloudflare-warp ${s}var${s}lib${s}cloudflare-warp ${s}etc${s}apt${s}sources.list.d${s}cloudflare-client.list ${s}usr${s}share${s}keyrings${s}cloudflare-warp-archive-keyring.gpg ${s}root${s}target_core ${s}root${s}config.json ${s}root${s}warp_setup.sh ${s}root${s}warp_autoshield.sh ${s}root${s}target_core.tmp"
ssh $ssh_opts $vps "sudo journalctl --vacuum-size=10M || true"
ssh $ssh_opts $vps "sudo find ${s}var${s}log -type f -name '*.log' -exec truncate -s 0 {} + || true"
ssh $ssh_opts $vps "sudo sed -i 's|#SystemMaxUse=|SystemMaxUse=50M|' ${s}etc${s}systemd${s}journald.conf || true"
ssh $ssh_opts $vps "sudo sed -i 's|SystemMaxUse=.*|SystemMaxUse=50M|' ${s}etc${s}systemd${s}journald.conf || true"
ssh $ssh_opts $vps "sudo systemctl restart systemd-journald || true"

Write-Host "3. Uploading files to VPS..." -ForegroundColor Cyan
scp $ssh_opts target_core\target\release\target_core ${vps}:target_core.tmp
if ($LASTEXITCODE -ne 0) {
    Write-Host "Upload binary failed" -ForegroundColor Red
    exit 1
}
scp $ssh_opts config.json ${vps}:
scp $ssh_opts warp_setup.sh ${vps}:
scp $ssh_opts warp_autoshield.sh ${vps}:

Write-Host "4. Replacing binary and setting execute permissions..." -ForegroundColor Cyan
ssh $ssh_opts $vps "sudo mv target_core.tmp ${s}root${s}target_core && (sudo cp config.json ${s}root${s} 2>${s}dev${s}null || true) && (sudo cp warp_setup.sh ${s}root${s} 2>${s}dev${s}null || true) && (sudo cp warp_autoshield.sh ${s}root${s} 2>${s}dev${s}null || true) && sudo chmod +x ${s}root${s}target_core ${s}root${s}warp_setup.sh ${s}root${s}warp_autoshield.sh"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Replacing binary and setting permissions failed" -ForegroundColor Red
    exit 1
}

Write-Host "5. Running warp setup on VPS..." -ForegroundColor Cyan
ssh $ssh_opts $vps "sudo bash ${s}root${s}warp_setup.sh"
if ($LASTEXITCODE -ne 0) {
    Write-Host "WARP setup failed" -ForegroundColor Red
    exit 1
}

Write-Host "6. Ensuring warp_autoshield service is running on VPS..." -ForegroundColor Cyan
ssh $ssh_opts $vps "sudo systemctl restart warp_autoshield.service || true"

Write-Host "7. Starting target_core on VPS..." -ForegroundColor Cyan
ssh $ssh_opts $vps "sudo systemctl restart target_core.service"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to start target_core on VPS" -ForegroundColor Red
    exit 1
}

Write-Host "Deployment completed successfully!" -ForegroundColor Green

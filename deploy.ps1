$s = [char]47
$vps = "root@68.183.191.244"
$ErrorActionPreference = "Stop"

Write-Host "1. Building target_core in WSL..." -ForegroundColor Cyan
wsl bash -i -c "cd ${s}mnt${s}c${s}Users${s}Heshan${s}Desktop${s}Ruve${s}target_core && cargo build --release"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed" -ForegroundColor Red
    exit 1
}

Write-Host "2. Stopping target_core and autoshield on VPS..." -ForegroundColor Cyan
ssh $vps "pkill target_core"
ssh $vps "systemctl stop warp_autoshield.service || true"

Write-Host "3. Uploading files to VPS..." -ForegroundColor Cyan
scp target_core\target\release\target_core ${vps}:
if ($LASTEXITCODE -ne 0) {
    Write-Host "Upload binary failed" -ForegroundColor Red
    exit 1
}
scp config.json ${vps}:
scp warp_setup.sh ${vps}:
scp warp_autoshield.sh ${vps}:

Write-Host "4. Setting execute permissions..." -ForegroundColor Cyan
ssh $vps "chmod +x target_core warp_setup.sh warp_autoshield.sh"

Write-Host "5. Running warp setup on VPS..." -ForegroundColor Cyan
ssh $vps "bash warp_setup.sh"
if ($LASTEXITCODE -ne 0) {
    Write-Host "WARP setup failed" -ForegroundColor Red
    exit 1
}

Write-Host "6. Ensuring warp_autoshield service is running on VPS..." -ForegroundColor Cyan
ssh $vps "systemctl restart warp_autoshield.service"

Write-Host "7. Starting target_core on VPS..." -ForegroundColor Cyan
ssh $vps "nohup .${s}target_core > target_core.log 2>&1 &"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to start target_core on VPS" -ForegroundColor Red
    exit 1
}

Write-Host "Deployment completed successfully!" -ForegroundColor Green

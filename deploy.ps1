$ErrorActionPreference = "Stop"

Write-Host "1. Building target_core in WSL (with interactive shell environment)..." -ForegroundColor Cyan
wsl bash -i -c "cd /mnt/c/Users/Heshan/Desktop/Ruve/target_core && cargo build --release"

Write-Host "2. Stopping target_core on VPS..." -ForegroundColor Cyan
ssh root@139.59.104.63 "pkill target_core"

Write-Host "3. Uploading binary to VPS..." -ForegroundColor Cyan
scp target_core/target/release/target_core root@139.59.104.63:/root/

Write-Host "4. Starting target_core on VPS..." -ForegroundColor Cyan
ssh root@139.59.104.63 "nohup /root/target_core > /root/target_core.log 2>&1 &"

Write-Host "Deployment completed successfully!" -ForegroundColor Green

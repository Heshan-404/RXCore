$ErrorActionPreference = "Stop"

Write-Host "1. Building target_core in WSL (with interactive shell environment)..." -ForegroundColor Cyan
wsl bash -i -c "cd /mnt/c/Users/Heshan/Desktop/Ruve/target_core && cargo build --release"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed" -ForegroundColor Red
    exit 1
}

Write-Host "2. Stopping target_core on VPS..." -ForegroundColor Cyan
ssh root@159.89.206.233 "pkill target_core"

Write-Host "3. Uploading binary to VPS..." -ForegroundColor Cyan
scp target_core/target/release/target_core root@159.89.206.233:/root/
if ($LASTEXITCODE -ne 0) {
    Write-Host "Upload failed" -ForegroundColor Red
    exit 1
}

Write-Host "3b. Setting execute permissions..." -ForegroundColor Cyan
ssh root@159.89.206.233 "chmod +x /root/target_core"

Write-Host "4. Starting target_core on VPS..." -ForegroundColor Cyan
ssh root@159.89.206.233 "nohup /root/target_core > /root/target_core.log 2>&1 &"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to start on VPS" -ForegroundColor Red
    exit 1
}

Write-Host "Deployment completed successfully!" -ForegroundColor Green

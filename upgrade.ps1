$s = [char]47
$vps = "root@172.236.150.147"
$ErrorActionPreference = "Stop"

Write-Host "1. Building target_core in WSL..." -ForegroundColor Cyan
wsl bash -i -c "cd ${s}mnt${s}c${s}Users${s}Heshan${s}Desktop${s}Ruve${s}target_core && CARGO_HOME=${s}mnt${s}c${s}Users${s}Heshan${s}.cargo cargo build --release --offline"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed" -ForegroundColor Red
    exit 1
}

$local_path = "target_core\target\release\target_core"
$local_hash = (Get-FileHash $local_path -Algorithm SHA256).Hash
Write-Host "Local SHA256 Checksum: $local_hash" -ForegroundColor Yellow

$ssh_opts = @("-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3")

Write-Host "2. Uploading binary under temporary name target_core.tmp..." -ForegroundColor Cyan
scp $ssh_opts $local_path "${vps}:target_core.tmp"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Upload failed" -ForegroundColor Red
    exit 1
}

Write-Host "2.5 Verifying remote checksum..." -ForegroundColor Cyan
$remote_hash_out = ssh $ssh_opts $vps "sha256sum ${s}root${s}target_core.tmp"
$remote_hash = ($remote_hash_out -split "\s+")[0].Trim().ToUpper()
if ($remote_hash -ne $local_hash.ToUpper()) {
    Write-Host "Verification failed! Remote checksum ($remote_hash) does not match local checksum ($local_hash)!" -ForegroundColor Red
    exit 1
}
Write-Host "Remote checksum verification succeeded: $remote_hash" -ForegroundColor Green

Write-Host "3. Backing up active binary, credentials, and configuration on server..." -ForegroundColor Cyan
ssh $ssh_opts $vps "sudo cp ${s}root${s}target_core ${s}root${s}target_core.bak 2>${s}dev${s}null || true"
ssh $ssh_opts $vps "sudo cp ${s}root${s}config.json ${s}root${s}config.json.bak 2>${s}dev${s}null || true"
ssh $ssh_opts $vps "sudo cp -p ${s}root${s}data${s}admin_credentials.json ${s}root${s}data${s}admin_credentials.json.bak 2>${s}dev${s}null || true"

Write-Host "4. Replacing active binary atomically..." -ForegroundColor Cyan
ssh $ssh_opts $vps "sudo systemctl stop target_core.service"
ssh $ssh_opts $vps "sudo mv ${s}root${s}target_core.tmp ${s}root${s}target_core"
ssh $ssh_opts $vps "sudo chmod +x ${s}root${s}target_core"

Write-Host "5. Starting target_core service..." -ForegroundColor Cyan
ssh $ssh_opts $vps "sudo systemctl start target_core.service"

Write-Host "6. Verifying startup health..." -ForegroundColor Cyan
Start-Sleep -Seconds 3

# Check if systemd service is active
$status = ssh $ssh_opts $vps "systemctl is-active target_core.service"
$status = $status.Trim()
if ($status -ne "active") {
    Write-Host "Service failed to start! Status: $status" -ForegroundColor Red
    Write-Host "Rolling back to previous backup..." -ForegroundColor Yellow
    ssh $ssh_opts $vps "sudo mv ${s}root${s}target_core.bak ${s}root${s}target_core && sudo cp ${s}root${s}config.json.bak ${s}root${s}config.json 2>${s}dev${s}null || true && sudo cp -p ${s}root${s}data${s}admin_credentials.json.bak ${s}root${s}data${s}admin_credentials.json 2>${s}dev${s}null || true && sudo systemctl start target_core.service"
    exit 1
}

# Verify system API health check
$health = ssh $ssh_opts $vps "curl -s -o ${s}dev${s}null -w '%{http_code}' http:${s}${s}127.0.0.1:9091${s}health"
$health = $health.Trim()
if ($health -ne "200") {
    Write-Host "Health check failed with HTTP code: $health" -ForegroundColor Red
    Write-Host "Rolling back to previous backup..." -ForegroundColor Yellow
    ssh $ssh_opts $vps "sudo mv ${s}root${s}target_core.bak ${s}root${s}target_core && sudo cp ${s}root${s}config.json.bak ${s}root${s}config.json 2>${s}dev${s}null || true && sudo cp -p ${s}root${s}data${s}admin_credentials.json.bak ${s}root${s}data${s}admin_credentials.json 2>${s}dev${s}null || true && sudo systemctl start target_core.service"
    exit 1
}

Write-Host "Upgrade completed successfully and health verified!" -ForegroundColor Green

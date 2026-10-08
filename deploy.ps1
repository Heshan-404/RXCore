param(
    [string]$VpsHost = "root@172.236.153.131",
    [switch]$Rebuild
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "      Ruve VPN One-Click Deployment      " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Target VPS: $VpsHost" -ForegroundColor Yellow

$binaryPath = Join-Path $ScriptDir "target_core\target\release\target_core"

# Check if binary exists or needs building
if ($Rebuild -or -not (Test-Path $binaryPath)) {
    Write-Host "[1/4] Building target_core binary..." -ForegroundColor Cyan
    if (Get-Command wsl -ErrorAction SilentlyContinue) {
        $wslPath = $ScriptDir.Replace("\", "/").Replace("C:", "/mnt/c")
        wsl bash -i -c "cd '$wslPath/target_core' && cargo build --release"
    } else {
        Write-Host "WSL not found locally. Using pre-existing binary or building on VPS." -ForegroundColor Yellow
    }
} else {
    Write-Host "[1/4] Using pre-compiled release binary..." -ForegroundColor Green
}

$ssh_opts = @("-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3", "-o", "StrictHostKeyChecking=accept-new")

# Step 2: Upload files
Write-Host "[2/4] Uploading files to VPS..." -ForegroundColor Cyan
scp $ssh_opts "$binaryPath" "${VpsHost}:target_core.tmp"
scp $ssh_opts (Join-Path $ScriptDir "config.json") "${VpsHost}:"
scp $ssh_opts (Join-Path $ScriptDir "install.sh") "${VpsHost}:"
scp $ssh_opts (Join-Path $ScriptDir "warp_autoshield.sh") "${VpsHost}:"

# Step 3: Run installer & apply configurations
Write-Host "[3/4] Installing and applying system configurations on VPS..." -ForegroundColor Cyan
ssh $ssh_opts $VpsHost "sudo mv -f target_core.tmp /root/target_core && sudo chmod +x /root/target_core /root/install.sh /root/warp_autoshield.sh && sudo bash /root/install.sh"

# Step 4: Verification
Write-Host "[4/4] Verifying services..." -ForegroundColor Cyan
ssh $ssh_opts $VpsHost "systemctl is-active target_core.service warp_autoshield.service"

Write-Host "`n=========================================" -ForegroundColor Green
Write-Host "   Deployment Completed Successfully!    " -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
Write-Host "Admin Portal : http://$($VpsHost.Replace('root@','')):9091/" -ForegroundColor Yellow
Write-Host "Default Pass : RuveAdmin@2026!" -ForegroundColor Yellow

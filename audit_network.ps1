# audit_network.ps1
param(
    [string]$Target = "8.8.8.8",
    [int]$Count = 50
)

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "      VPN Network Performance Audit      " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Target Host: $Target"
Write-Host "Ping Count: $Count"
Write-Host "Auditing ICMP (Ping) RTT, Jitter, and Packet Loss..." -ForegroundColor Yellow

$rtts = @()
$lost = 0

for ($i = 1; $i -le $Count; $i++) {
    $ping = Test-Connection -ComputerName $Target -Count 1 -ErrorAction SilentlyContinue
    if ($ping) {
        $rtt = $ping.ResponseTime
        $rtts += $rtt
        Write-Host "Ping $($i): RTT = $($rtt) ms" -ForegroundColor Green
    } else {
        $lost++
        Write-Host "Ping $($i): Request Timed Out / Lost" -ForegroundColor Red
    }
    Start-Sleep -Milliseconds 200
}

Write-Host ""
Write-Host "--- ICMP Statistics ---" -ForegroundColor Cyan
if ($rtts.Count -gt 0) {
    $min = ($rtts | Measure-Object -Minimum).Minimum
    $max = ($rtts | Measure-Object -Maximum).Maximum
    $avg = ($rtts | Measure-Object -Average).Average
    $lossPct = [math]::Round(($lost / $Count) * 100, 2)
    
    # Calculate jitter (RFC 3550: absolute difference between consecutive RTTs)
    $jitterSum = 0
    for ($j = 0; $j -lt ($rtts.Count - 1); $j++) {
        $diff = [math]::Abs($rtts[$j] - $rtts[$j+1])
        $jitterSum += $diff
    }
    $jitter = 0
    if ($rtts.Count -gt 1) {
        $jitter = [math]::Round($jitterSum / ($rtts.Count - 1), 2)
    }

    Write-Host "Packets: Sent = $Count, Received = $($rtts.Count), Lost = $lost ($lossPct% Loss)"
    Write-Host "Round-Trip Time (RTT): Min = $min ms, Max = $max ms, Avg = $([math]::Round($avg, 2)) ms" -ForegroundColor Green
    Write-Host "Estimated Jitter: $jitter ms" -ForegroundColor Yellow
} else {
    Write-Host "All pings lost ($lost lost, 100% Loss)" -ForegroundColor Red
}

Write-Host ""
Write-Host "Auditing TCP Port Latency (Handshake RTT)..." -ForegroundColor Yellow
$tcpTarget = "google.com"
$tcpPort = 443
$tcpRtts = @()
$tcpLost = 0

for ($i = 1; $i -le 10; $i++) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connect = $tcpClient.BeginConnect($tcpTarget, $tcpPort, $null, $null)
        $wait = $connect.AsyncWaitHandle.WaitOne(2000, $true)
        if ($wait) {
            $tcpClient.EndConnect($connect)
            $sw.Stop()
            $tcpRtt = $sw.Elapsed.TotalMilliseconds
            $tcpRtts += $tcpRtt
            Write-Host "TCP Connect $($i) to $($tcpTarget):$($tcpPort) = $([math]::Round($tcpRtt, 2)) ms" -ForegroundColor Green
        } else {
            $tcpLost++
            Write-Host "TCP Connect $($i) to $($tcpTarget):$($tcpPort) = Timed Out" -ForegroundColor Red
        }
        $tcpClient.Close()
    } catch {
        $tcpLost++
        Write-Host "TCP Connect $($i) to $($tcpTarget):$($tcpPort) = Failed" -ForegroundColor Red
    }
    Start-Sleep -Milliseconds 200
}

Write-Host ""
Write-Host "--- TCP Connection Statistics ---" -ForegroundColor Cyan
if ($tcpRtts.Count -gt 0) {
    $tcpMin = ($tcpRtts | Measure-Object -Minimum).Minimum
    $tcpMax = ($tcpRtts | Measure-Object -Maximum).Maximum
    $tcpAvg = ($tcpRtts | Measure-Object -Average).Average
    $tcpLossPct = [math]::Round(($tcpLost / 10) * 100, 2)
    Write-Host "TCP Connects: Sent = 10, Success = $($tcpRtts.Count), Failed = $tcpLost ($tcpLossPct% Loss)"
    Write-Host "TCP Handshake RTT: Min = $([math]::Round($tcpMin, 2)) ms, Max = $([math]::Round($tcpMax, 2)) ms, Avg = $([math]::Round($tcpAvg, 2)) ms" -ForegroundColor Green
} else {
    Write-Host "All TCP connections failed" -ForegroundColor Red
}
Write-Host "=========================================" -ForegroundColor Cyan

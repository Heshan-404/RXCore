# benchmark.ps1
# Latency & Packet Loss benchmarking tool for Ruve VPN Server

param(
    [string]$TargetIP = "157.230.42.209",
    [int]$Samples = 500
)

function Get-Stats {
    param([array]$latencies, [int]$lost)
    
    if ($latencies.Count -eq 0) {
        return @{
            Min = 0
            P50 = 0
            P95 = 0
            P99 = 0
            Max = 0
            Loss = 100
        }
    }
    
    $sorted = $latencies | Sort-Object
    $min = $sorted[0]
    $max = $sorted[-1]
    
    $p50_idx = [math]::Max(0, [math]::Ceiling($sorted.Count * 0.50) - 1)
    $p95_idx = [math]::Max(0, [math]::Ceiling($sorted.Count * 0.95) - 1)
    $p99_idx = [math]::Max(0, [math]::Ceiling($sorted.Count * 0.99) - 1)
    
    $p50 = $sorted[$p50_idx]
    $p95 = $sorted[$p95_idx]
    $p99 = $sorted[$p99_idx]
    
    $loss = ($lost * 100.0) / ($latencies.Count + $lost)
    
    return @{
        Min = $min
        P50 = $p50
        P95 = $p95
        P99 = $p99
        Max = $max
        Loss = $loss
    }
}

Write-Host "Starting isolated latency benchmark targeting $TargetIP ($Samples samples)..." -ForegroundColor Cyan

$icmp_latencies = @()
$icmp_lost = 0

$tcp_latencies = @()
$tcp_lost = 0

$stopwatch = New-Object System.Diagnostics.Stopwatch

for ($i = 1; $i -le $Samples; $i++) {
    # 1. Measure ICMP Ping (Baseline)
    try {
        $ping = Test-Connection -ComputerName $TargetIP -Count 1 -TimeoutMilliSeconds 1000 -ErrorAction SilentlyContinue
        if ($ping -and $ping.ResponseTime -ne $null) {
            $icmp_latencies += $ping.ResponseTime
        } else {
            $icmp_lost++
        }
    } catch {
        $icmp_lost++
    }

    # 2. Measure TCP Connection to Port 443 (Reality Listening)
    $stopwatch.Restart()
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $connect = $client.BeginConnect($TargetIP, 443, $null, $null)
        $success = $connect.AsyncWaitHandle.WaitOne(1000, $true)
        $stopwatch.Stop()
        
        if ($success) {
            $client.EndConnect($connect)
            $tcp_latencies += $stopwatch.Elapsed.TotalMilliseconds
        } else {
            $tcp_lost++
        }
    } catch {
        $tcp_lost++
    } finally {
        $client.Close()
    }
    
    if ($i % 50 -eq 0) {
        Write-Host "Completed $i / $Samples samples..."
    }
    Start-Sleep -Milliseconds 100
}

$icmp_stats = Get-Stats $icmp_latencies $icmp_lost
$tcp_stats = Get-Stats $tcp_latencies $tcp_lost

Write-Host "`n================ BENCHMARK RESULTS ================" -ForegroundColor Green
Write-Host "1. ICMP Baseline Ping Stats:" -ForegroundColor Yellow
Write-Host "   Minimum Latency:     $([math]::Round($icmp_stats.Min, 2)) ms"
Write-Host "   Median (p50):        $([math]::Round($icmp_stats.P50, 2)) ms"
Write-Host "   p95 Latency:         $([math]::Round($icmp_stats.P95, 2)) ms"
Write-Host "   p99 Latency:         $([math]::Round($icmp_stats.P99, 2)) ms"
Write-Host "   Maximum Latency:     $([math]::Round($icmp_stats.Max, 2)) ms"
Write-Host "   Packet Loss:         $([math]::Round($icmp_stats.Loss, 2))%"

Write-Host "`n2. TCP Port 443 (Reality) Handshake Stats:" -ForegroundColor Yellow
Write-Host "   Minimum Latency:     $([math]::Round($tcp_stats.Min, 2)) ms"
Write-Host "   Median (p50):        $([math]::Round($tcp_stats.P50, 2)) ms"
Write-Host "   p95 Latency:         $([math]::Round($tcp_stats.P95, 2)) ms"
Write-Host "   p99 Latency:         $([math]::Round($tcp_stats.P99, 2)) ms"
Write-Host "   Maximum Latency:     $([math]::Round($tcp_stats.Max, 2)) ms"
Write-Host "   Packet Loss:         $([math]::Round($tcp_stats.Loss, 2))%"
Write-Host "===================================================" -ForegroundColor Green

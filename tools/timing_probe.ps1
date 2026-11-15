# 临时诊断：量搜索请求的 TTFB 与缓存命中头。
# 用法：powershell -NoProfile -File tools\timing_probe.ps1 <查询词>
param([string]$Query = "zzprobe8")

$url0 = "https://github.com/search?q=$Query&type=repositories"
$url1 = "https://github.com/search?q=$Query&type=repositories&p=1"

function Probe([string]$label, [string]$url) {
    $t = [Diagnostics.Stopwatch]::StartNew()
    $resp = curl.exe --ssl-no-revoke -x http://127.0.0.1:7810 -s -o NUL -D - --max-time 30 $url
    $t.Stop()
    $hit = ($resp | Select-String -Pattern 'x-gitport-cache').Line
    $status = ($resp | Select-String -Pattern '^HTTP/1.1 \d+').Line | Select-Object -Last 1
    Write-Host ("{0,-14} TTFB={1,7:N0}ms  {2}  {3}" -f $label, $t.ElapsedMilliseconds, $status, $hit)
}

Probe "fresh(miss)" $url0
Probe "again(hit?)" $url0
Probe "p=1(hit?)" $url1

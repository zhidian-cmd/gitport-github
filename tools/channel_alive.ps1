# 会话域通道存活实验(诊断脚本, 不改应用代码):
# 对目标 GitHub 域名的 IP:443 建一条 TLS 通道(无 SNI, 与代理会话通道同形态),
# 每 30s 发一个 HEAD 请求探活, 记录通道能活多久。提前断开立即退出并报时长。
# 用法: powershell -File tools\channel_alive.ps1 -Name github.com [-IP 140.82.121.3] [-Minutes 10]
param(
    [string]$Name = 'github.com',
    [string]$IP = '',
    [int]$Minutes = 10,
    [int]$EverySec = 30,
    [int]$FirstDelaySec = 30,
    [switch]$Sni
)
$ErrorActionPreference = 'Continue'

function Log($m) {
    Write-Output ("[{0:HH:mm:ss}] {1}" -f (Get-Date), $m)
}

# 默认 IP 取自代理实测日志里当前活着的边缘(代理用 IP 表不走 DNS); 可用 -IP 覆盖。
$defaults = @{
    'github.com'     = '140.82.121.3'
    'api.github.com' = '140.82.112.5'
}
if (-not $IP) { $IP = $defaults[$Name] }
if (-not $IP) { Log "[$Name] 解析不到 IP, 实验中止"; exit 1 }

Log "[$Name] 目标 ${IP}:443, 每 ${EverySec}s 一发, 计划 ${Minutes} 分钟"

$start = Get-Date
$deadline = $start.AddMinutes($Minutes)
$tcp = $null; $ssl = $null; $i = 0

try {
    $tcp = New-Object Net.Sockets.TcpClient
    $ar = $tcp.BeginConnect($IP, 443, $null, $null)
    if (-not $ar.AsyncWaitHandle.WaitOne(10000)) { throw "TCP 连接超时(10s)" }
    $tcp.EndConnect($ar)
    $ms = [int]((Get-Date) - $start).TotalMilliseconds
    Log "[$Name] TCP 已建立(${ms}ms)"

    $ssl = [Net.Security.SslStream]::new($tcp.GetStream(), $false, { $true })
    if ($Sni) { $ssl.AuthenticateAsClient($Name) } else { $ssl.AuthenticateAsClient('') }  # 默认无 SNI(与代理会话通道同形态); -Sni 为对照
    $next = $start.AddSeconds($FirstDelaySec)
    Log "[$Name] TLS 握手完成, 通道建立, 开始探活"
} catch {
    Log "[$Name] 建连失败: $($_.Exception.GetBaseException().Message) → 存活 0s"
    exit 1
}

while ((Get-Date) -lt $deadline) {
    if ((Get-Date) -ge $next) {
        $i++
        $t = (Get-Date) - $start
        try {
            $req = [Text.Encoding]::ASCII.GetBytes("HEAD / HTTP/1.1`r`nHost: $Name`r`nUser-Agent: gitport-alive-probe`r`nConnection: keep-alive`r`n`r`n")
            $ssl.Write($req, 0, $req.Length)
            $ssl.ReadTimeout = 15000
            $buf = New-Object byte[] 4096
            $n = $ssl.Read($buf, 0, $buf.Length)
            if ($n -le 0) {
                Log "[$Name] 第 $i 发收到 0 字节(对端关闭) → 通道已死, 存活 $([int]$t.TotalSeconds)s"
                exit 1
            }
            Log "[$Name] 第 $i 发成功(${n}B), 已存活 $([int]$t.TotalSeconds)s"
        } catch {
            $msg = $_.Exception.GetBaseException().Message
            Log "[$Name] 第 $i 发失败($msg) → 通道已死, 存活 $([int]$t.TotalSeconds)s"
            exit 1
        }
        $next = (Get-Date).AddSeconds($EverySec)
    }
    Start-Sleep -Milliseconds 250
}
Log "[$Name] 实验结束——通道存活满 ${Minutes} 分钟, 共 $i 发全部成功, 通道仍然健康"
exit 0

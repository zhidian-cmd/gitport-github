# temp diagnostic: compare stored variants for one query.
param([string]$Filter = "zzprobe8")

$dir = Join-Path $PSScriptRoot "..\dist\.cache\pages"
Get-ChildItem $dir | ForEach-Object {
    $raw = [IO.File]::ReadAllBytes($_.FullName)
    if ($raw.Length -lt 8) { return }
    $hlen = ([int]$raw[0] -shl 24) -bor ([int]$raw[1] -shl 16) -bor ([int]$raw[2] -shl 8) -bor [int]$raw[3]
    if ($hlen -le 0 -or ($hlen + 4) -gt $raw.Length) { return }
    $j = [Text.Encoding]::UTF8.GetString($raw, 4, $hlen)
    if ($j -match '"key":"([^"]*)"') {
        $k = $Matches[1]
        if (-not $k.Contains($Filter)) { return }
        $ct = if ($j -match '"content-type","([^"]*)"') { $Matches[1] } else { "?" }
        $body = $raw[(4 + $hlen)..($raw.Length - 1)]
        $head = [Text.Encoding]::UTF8.GetString($body, 0, [Math]::Min(120, $body.Length)) -replace '[\r\n]', ' '
        Write-Host ("KEY: " + $k)
        Write-Host ("  ct=" + $ct + "  bodylen=" + $body.Length)
        Write-Host ("  head=" + $head)
        Write-Host ""
    }
}

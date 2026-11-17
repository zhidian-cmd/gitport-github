# temp diagnostic: list cache entries with timestamps (CreationTime vs LastWriteTime).
param([string]$Filter = "search")

$dir = Join-Path $PSScriptRoot "..\dist\.cache\pages"
$rows = @()
Get-ChildItem $dir | ForEach-Object {
    $raw = [IO.File]::ReadAllBytes($_.FullName)
    if ($raw.Length -lt 8) { return }
    $hlen = ([int]$raw[0] -shl 24) -bor ([int]$raw[1] -shl 16) -bor ([int]$raw[2] -shl 8) -bor [int]$raw[3]
    if ($hlen -le 0 -or ($hlen + 4) -gt $raw.Length) { return }
    $j = [Text.Encoding]::UTF8.GetString($raw, 4, [Math]::Min($hlen, 40000))
    if ($j -match '"key":"([^"]*)"') {
        $k = $Matches[1]
        if ($k.Contains($Filter)) {
            $rows += [PSCustomObject]@{
                Created = $_.CreationTime.ToString("MM-dd HH:mm:ss")
                Written = $_.LastWriteTime.ToString("MM-dd HH:mm:ss")
                Key     = $k
            }
        }
    }
}
$rows = $rows | Sort-Object Written
Write-Host ("total " + $rows.Count)
$rows | ForEach-Object { Write-Host ("create=" + $_.Created + "  write=" + $_.Written + "  " + $_.Key) }

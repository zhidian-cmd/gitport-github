# temp diagnostic: compare GitHub's response for the same search URL with html vs json Accept.
$q = "zzprobe8"
$u = "https://github.com/search?q=$q&type=repositories"
$px = "http://127.0.0.1:7810"

$h = curl.exe --ssl-no-revoke -x $px -s -D - -o "$env:TEMP\srch_html.bin" --max-time 30 -H "Accept: text/html,application/xhtml+xml" $u
$j = curl.exe --ssl-no-revoke -x $px -s -D - -o "$env:TEMP\srch_json.bin" --max-time 30 -H "Accept: application/json" $u

Write-Host "=== HTML request ==="
$h | Select-String -Pattern '^HTTP/1.1 |^content-type|^x-gitport-cache' | ForEach-Object { Write-Host $_.Line }
$hb = [IO.File]::ReadAllBytes("$env:TEMP\srch_html.bin")
Write-Host ("html body bytes: " + $hb.Length)
$hs = [Text.Encoding]::UTF8.GetString($hb, 0, [Math]::Min(300, $hb.Length))
Write-Host ("html body head: " + $hs)

Write-Host "=== JSON request ==="
$j | Select-String -Pattern '^HTTP/1.1 |^content-type|^x-gitport-cache' | ForEach-Object { Write-Host $_.Line }
$jb = [IO.File]::ReadAllBytes("$env:TEMP\srch_json.bin")
Write-Host ("json body bytes: " + $jb.Length)
$js = [Text.Encoding]::UTF8.GetString($jb, 0, [Math]::Min(300, $jb.Length))
Write-Host ("json body head: " + $js)

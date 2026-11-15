# temp diagnostic: does the html's embeddedData payload match the json endpoint's payload?
# One fetch feeding both consumers is only possible if these two are the same shape.
$q = "DNS"
$u = "https://github.com/search?q=$q&type=repositories&p=1"
$px = "http://127.0.0.1:7810"

curl.exe --ssl-no-revoke -x $px -s -o "$env:TEMP\emb_html.bin" --max-time 30 -H "Accept: text/html" -H "Accept-Encoding: identity" $u
curl.exe --ssl-no-revoke -x $px -s -o "$env:TEMP\emb_json.bin" --max-time 30 -H "Accept: application/json" -H "Accept-Encoding: identity" $u

$hb = [IO.File]::ReadAllBytes("$env:TEMP\emb_html.bin")
$hs = [Text.Encoding]::UTF8.GetString($hb)
Write-Host ("html bytes: " + $hb.Length)

# extract embeddedData script: <script type="application/json" data-target="react-app.embeddedData">...</script>
$m = [regex]::Match($hs, 'data-target="react-app\.embeddedData"[^>]*>(.*?)</script>', [System.Text.RegularExpressions.RegexOptions]::Singleline)
if (-not $m.Success) {
    Write-Host "VERDICT: no embeddedData script found in html - extraction path does not exist"
    $jl = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes("$env:TEMP\emb_json.bin"))
    Write-Host ("json endpoint head: " + $jl.Substring(0, [Math]::Min(300, $jl.Length)))
    exit
}
$emb = $m.Groups[1].Value
Write-Host ("embeddedData bytes: " + $emb.Length)

$jb = [IO.File]::ReadAllBytes("$env:TEMP\emb_json.bin")
$js = [Text.Encoding]::UTF8.GetString($jb)
Write-Host ("json endpoint bytes: " + $jb.Length)

try { $E = $emb | ConvertFrom-Json } catch { Write-Host ("embeddedData not valid json: " + $_.Exception.Message); exit }
try { $J = $js | ConvertFrom-Json } catch { Write-Host ("json endpoint not valid json: " + $_.Exception.Message); exit }

Write-Host "--- top-level keys ---"
Write-Host ("embeddedData: " + (($E.PSObject.Properties.Name) -join ", "))
Write-Host ("json endpoint: " + (($J.PSObject.Properties.Name) -join ", "))

if ($E.payload -and $J.payload) {
    Write-Host "--- payload keys diff ---"
    $ek = ($E.payload.PSObject.Properties.Name) | Sort-Object
    $jk = ($J.payload.PSObject.Properties.Name) | Sort-Object
    Write-Host ("embedded payload: " + ($ek -join ", "))
    Write-Host ("json payload:     " + ($jk -join ", "))
    $onlyE = $ek | Where-Object { $jk -notcontains $_ }
    $onlyJ = $jk | Where-Object { $ek -notcontains $_ }
    Write-Host ("keys only in embedded: " + (($onlyE -join ", ") -replace '^$', '(none)'))
    Write-Host ("keys only in json endpoint: " + (($onlyJ -join ", ") -replace '^$', '(none)'))
    Write-Host ("embedded results count: " + @($E.payload.results).Count + "   json results count: " + @($J.payload.results).Count)
}

# volatile fields that would never match byte-for-byte anyway
Write-Host "--- volatile fields (expected to differ) ---"
foreach ($f in @("elapsed_millis", "query_id")) {
    $ev = $E.payload.$f; $jv = $J.payload.$f
    Write-Host ("$f embedded=" + $ev + "  json=" + $jv)
}

# the real question: byte-identical after removing known-volatile fields?
Write-Host "--- byte equality of the two payloads (ignoring nothing) ---"
Write-Host ("payload bytes equal: " + ($emb -eq $js))

#requires -Version 5.1
<#
.SYNOPSIS
  Secure Vault - demo skripta sigurnosne posture (Faza 12).

.DESCRIPTION
  Proverava zive servise (gateway + backend, opciono Redis) bez klijentske kriptografije:
    1. Health lanac (gateway + proxy ka backendu).
    2. Sigurnosna HTTP zaglavlja na proxy odgovoru (CSP, X-Frame-Options, ...).
    3. Striktan CORS (dozvoljen frontend origin; stran origin odbijen).
    4. Zastita privatnih endpointa (bez sesije -> 401).
    5. Rate limiting na login toku (-> 429).

  End-to-end FUNKCIONALNI tok (registracija -> deljenje -> honeypot -> audit) je
  browser-zasnovan (zero-knowledge, klijentska kripto) i opisan je u TESTIRANJE.md.

.EXAMPLE
  ./demo.ps1
  ./demo.ps1 -Gateway http://localhost:8080 -FrontendOrigin http://localhost:5173
#>
[CmdletBinding()]
param(
    [string]$Gateway = "http://localhost:8080",
    [string]$FrontendOrigin = "http://localhost:5173"
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$script:Pass = 0
$script:Fail = 0

function Write-Result {
    param([bool]$Ok, [string]$Name, [string]$Detail)
    if ($Ok) { $script:Pass++; Write-Host "[PASS] $Name" -ForegroundColor Green }
    else     { $script:Fail++; Write-Host "[FAIL] $Name" -ForegroundColor Red }
    if ($Detail) { Write-Host "       $Detail" -ForegroundColor DarkGray }
}

# HTTP poziv otporan na 4xx/5xx (PS 5.1 nema -SkipHttpErrorCheck). Vraca status + zaglavlja.
function Invoke-Http {
    param([string]$Method = 'GET', [string]$Url, [hashtable]$Headers, [string]$Body, [string]$ContentType)
    $p = @{ Method = $Method; Uri = $Url; UseBasicParsing = $true; TimeoutSec = 10; ErrorAction = 'Stop' }
    if ($Headers)     { $p.Headers = $Headers }
    if ($Body)        { $p.Body = $Body }
    if ($ContentType) { $p.ContentType = $ContentType }
    try {
        $r = Invoke-WebRequest @p
        $h = @{}; foreach ($k in $r.Headers.Keys) { $h[$k] = ($r.Headers[$k] -join ', ') }
        return [pscustomobject]@{ Status = [int]$r.StatusCode; Headers = $h; Body = $r.Content; Reached = $true }
    } catch [System.Net.WebException] {
        $resp = $_.Exception.Response
        if ($null -ne $resp) {
            $h = @{}
            try { foreach ($k in $resp.Headers.AllKeys) { $h[$k] = $resp.Headers[$k] } } catch {}
            return [pscustomobject]@{ Status = [int]$resp.StatusCode; Headers = $h; Body = $null; Reached = $true }
        }
        return [pscustomobject]@{ Status = 0; Headers = @{}; Body = $null; Reached = $false; Error = $_.Exception.Message }
    } catch {
        return [pscustomobject]@{ Status = 0; Headers = @{}; Body = $null; Reached = $false; Error = $_.Exception.Message }
    }
}

# Case-insensitivno citanje zaglavlja iz normalizovane hashtable.
function Get-Header {
    param($Headers, [string]$Name)
    foreach ($k in $Headers.Keys) { if ($k -ieq $Name) { return $Headers[$k] } }
    return $null
}

Write-Host ""
Write-Host "=== Secure Vault - demo sigurnosne posture ===" -ForegroundColor Cyan
Write-Host "Gateway: $Gateway   Frontend origin: $FrontendOrigin"
Write-Host ""

# --- 0. Dostupnost gateway-a ---
$health = Invoke-Http -Url "$Gateway/health"
if (-not $health.Reached) {
    Write-Host "[GRESKA] Gateway nije dostupan na $Gateway." -ForegroundColor Red
    Write-Host "         Pokreni: mvn -f gateway/pom.xml spring-boot:run  (uz backend i Redis)." -ForegroundColor DarkGray
    exit 2
}

# --- 1. Health lanac ---
Write-Result (($health.Status -eq 200) -and ($health.Body -match '"status"\s*:\s*"ok"')) `
    "1a. Gateway /health = 200 {status:ok}" "status=$($health.Status)"

$apiHealth = Invoke-Http -Url "$Gateway/api/health"
Write-Result (($apiHealth.Status -eq 200) -and ($apiHealth.Body -match '"status"\s*:\s*"ok"')) `
    "1b. Proxy /api/health -> backend = 200 {status:ok}" "status=$($apiHealth.Status)"

# --- 2. Sigurnosna zaglavlja (backend, prosledjena kroz gateway) ---
$xcto = Get-Header $apiHealth.Headers 'X-Content-Type-Options'
$xfo  = Get-Header $apiHealth.Headers 'X-Frame-Options'
$csp  = Get-Header $apiHealth.Headers 'Content-Security-Policy'
$ref  = Get-Header $apiHealth.Headers 'Referrer-Policy'
$pp   = Get-Header $apiHealth.Headers 'Permissions-Policy'
Write-Result ($xcto -ieq 'nosniff')                 "2a. X-Content-Type-Options: nosniff" "vrednost=$xcto"
Write-Result ($xfo  -ieq 'DENY')                    "2b. X-Frame-Options: DENY"          "vrednost=$xfo"
Write-Result ($csp -and $csp.Contains("default-src 'none'")) "2c. Content-Security-Policy: default-src 'none'" "vrednost=$csp"
Write-Result ($ref -ieq 'no-referrer')              "2d. Referrer-Policy: no-referrer"   "vrednost=$ref"
Write-Result (-not [string]::IsNullOrEmpty($pp))    "2e. Permissions-Policy prisutan"    "vrednost=$pp"

# --- 3. Striktan CORS ---
$allowPre = Invoke-Http -Method 'OPTIONS' -Url "$Gateway/api/health" -Headers @{
    'Origin'                        = $FrontendOrigin
    'Access-Control-Request-Method' = 'POST'
}
$acaoAllow = Get-Header $allowPre.Headers 'Access-Control-Allow-Origin'
Write-Result ($acaoAllow -eq $FrontendOrigin) `
    "3a. CORS preflight dozvoljava frontend origin" "Access-Control-Allow-Origin=$acaoAllow"

$rogue = 'http://evil.example'
$roguePre = Invoke-Http -Method 'OPTIONS' -Url "$Gateway/api/health" -Headers @{
    'Origin'                        = $rogue
    'Access-Control-Request-Method' = 'POST'
}
$acaoRogue = Get-Header $roguePre.Headers 'Access-Control-Allow-Origin'
Write-Result ($acaoRogue -ne $rogue) `
    "3b. CORS odbija stran origin" "status=$($roguePre.Status), Access-Control-Allow-Origin=$acaoRogue"

# --- 4. Zastita privatnih endpointa (bez sesije -> 401) ---
foreach ($ep in @('/api/auth/me', '/api/admin/audit/verify', '/api/honeypot/search?label=x')) {
    $r = Invoke-Http -Url "$Gateway$ep"
    Write-Result ($r.Status -eq 401) "4. $ep bez sesije -> 401" "status=$($r.Status)"
}

# --- 5. Rate limiting na login toku (-> 429) ---
$body = '{"username":"demo-nobody"}'
$got429 = $false
$statuses = @()
for ($i = 0; $i -lt 25; $i++) {
    $r = Invoke-Http -Method 'POST' -Url "$Gateway/api/auth/login/params" -Body $body -ContentType 'application/json'
    $statuses += $r.Status
    if ($r.Status -eq 429) { $got429 = $true; break }
}
Write-Result $got429 "5. Brzi niz login zahteva -> 429 (rate limit)" `
    "statusi=$($statuses -join ','); ako nema 429, proveri da je Redis pokrenut"

# --- Rezime ---
Write-Host ""
Write-Host "=== Rezime: $script:Pass PASS / $script:Fail FAIL ===" -ForegroundColor Cyan
Write-Host "Funkcionalni end-to-end tok (registracija->share->honeypot->audit) je u TESTIRANJE.md." -ForegroundColor DarkGray
if ($script:Fail -gt 0) { exit 1 } else { exit 0 }

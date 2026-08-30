$ErrorActionPreference = 'Stop'

$ScriptDir  = $PSScriptRoot
$Helper     = Join-Path $ScriptDir 'tuntop/tunnel/helper.py'
$Tui        = Join-Path $ScriptDir 'tuntop/ui/dashboard.py'
$Tun2socks  = Join-Path $ScriptDir 'tun2socks-windows-amd64-v3.exe'

$VlessEndpointPort = '443'
$SocksPort         = '10808'
$VpnInterface      = ''        # set to your exact VPN connection name to override auto-detect
$DnsServer         = '8.8.8.8'

# VLESS server address(es) - IP or hostname, as many as you like.
$Servers           = @('188.114.97.6')

# geoip.dat bypass (route-level "bypass a country").
# The script looks for geoip.dat inside a 'geofil' sub-folder next to this script.
# If it is missing you will be prompted to download it automatically.
$GeoIpDir          = Join-Path $ScriptDir 'geofil'
$GeoIpFile         = Join-Path $GeoIpDir 'geoip.dat'
$GeoIpCode         = ''

function Find-Python {
    <#
      A 'python'/'python3' on PATH can resolve to a BROKEN Windows Store
      app-execution-alias stub (AppData\Local\Microsoft\WindowsApps\python*.exe)
      that prints "Python was not found" and exits 9009 instead of running
      (it happens when this script is elevated). So we test-run every
      candidate with -c and only accept one that actually starts a Python 3
      interpreter. The 'py' launcher is also tried.
    #>
    function Test-Py ([string]$Src) {
        # Quote-free probe: PowerShell strips embedded double-quotes from the
        # -c string when spawning a native process, so the simpler
        # sys.version_info[0] form (no nested quotes) is required.
        try {
            $v = & $Src -c 'import sys;print(sys.version_info[0])' 2>$null
            return ($LASTEXITCODE -eq 0 -and ($v -match '^3'))
        } catch { return $false }
    }
    foreach ($c in 'python', 'python3', 'py') {
        $hits = @(Get-Command $c -All -ErrorAction SilentlyContinue |
                  Where-Object { $_.CommandType -eq 'Application' } |
                  Select-Object -ExpandProperty Source -Unique)
        foreach ($src in $hits) {
            if (Test-Py $src) { return $src }
        }
    }
    # Last resort: sweep PATH for any python*.exe that actually runs.
    foreach ($dir in ($env:PATH -split ';')) {
        if (-not $dir) { continue }
        try {
            $exes = @(Get-ChildItem -LiteralPath $dir -Filter 'python*.exe' -ErrorAction SilentlyContinue |
                      Select-Object -ExpandProperty FullName)
        } catch { continue }
        foreach ($src in $exes) {
            if (Test-Py $src) { return $src }
        }
    }
    return $null
}

function Get-Dependency {
    <#
      One-click dependency fetch. Downloads anything missing:
        - tun2socks-windows-amd64-v3.exe  (GitHub releases)
        - wintun.dll                      (wintun.net bundle)
      Existing files are NEVER overwritten, so re-running stays
      offline-friendly and idempotent.
    #>
    param(
        [string]$Destination,
        [string]$Url,
        [string]$ZipMember,     # path of the file inside the zip ('' = exe zip root scan)
        [string]$FriendlyName,
        [string]$ManualHint
    )
    if (Test-Path $Destination) { return $true }

    $safe = $FriendlyName -replace '\W', '_'
    Write-Host "[*] Downloading $FriendlyName (first run only)..." -ForegroundColor Cyan
    $zip  = Join-Path $env:TEMP "$safe.zip"
    $temp = Join-Path $env:TEMP "$safe-x"
    try {
        # curl.exe ships with Windows 10 1803+; Invoke-WebRequest as fallback.
        $curl = Join-Path $env:SystemRoot 'System32\curl.exe'
        $downloaded = $false
        if (Test-Path $curl) {
            & $curl -L --fail --silent --show-error --ssl-no-revoke --output $zip $Url
            if ($LASTEXITCODE -eq 0) { $downloaded = $true }
        }
        if (-not $downloaded) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $Url -OutFile $zip -UseBasicParsing
        }
        if (Test-Path $temp) { Remove-Item $temp -Recurse -Force }
        Expand-Archive -LiteralPath $zip -DestinationPath $temp -Force

        $src = $null
        if ($ZipMember) {
            $candidate = Join-Path $temp $ZipMember
            if (Test-Path $candidate) { $src = $candidate }
        }
        else {
            $src = Get-ChildItem $temp -Recurse -Filter 'tun2socks*.exe' |
                   Select-Object -First 1 -ExpandProperty FullName
        }
        if (-not $src) { throw "$FriendlyName not found inside the downloaded zip" }

        Copy-Item $src $Destination -Force
        Write-Host "[+] $FriendlyName ready." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[!] Could not fetch $FriendlyName : $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "    Do it manually: $ManualHint"
        return $false
    }
    finally {
        if ($zip -and (Test-Path $zip)) { Remove-Item $zip -Force -ErrorAction SilentlyContinue }
    }
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Set-Location $ScriptDir

# --- Python ---------------------------------------------------------------
$py = Find-Python
if (-not $py) {
    Write-Host ''
    Write-Host 'ERROR: No Python interpreter found (tried python, python3, py).' -ForegroundColor Red
    Write-Host ''
    Write-Host 'Install it with ONE of these:'
    Write-Host '  winget install -e --id Python.Python.3.12'
    Write-Host '  or download: https://www.python.org/downloads/'
    if (-not $isAdmin) {
        Write-Host ''
        Write-Host 'Then run this script again.'
    }
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    exit 1
}

# --- Companion scripts ----------------------------------------------------
foreach ($f in @($Helper, $Tui)) {
    if (-not (Test-Path $f)) {
        Write-Error "Missing file next to this script: $f"
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        exit 1
    }
}

# --- One-click dependencies (no admin needed to download) ------------------
$okTun2socks = Get-Dependency `
    -Destination $Tun2socks `
    -Url 'https://github.com/xjasonlyu/tun2socks/releases/download/v2.7.0/tun2socks-windows-amd64-v3.zip' `
    -ZipMember '' `
    -FriendlyName 'tun2socks' `
    -ManualHint 'https://github.com/xjasonlyu/tun2socks/releases -> place tun2socks-windows-amd64-v3.exe next to this script'

$WintunDll   = Join-Path $ScriptDir 'wintun.dll'
$okWintun    = Get-Dependency `
    -Destination $WintunDll `
    -Url 'https://www.wintun.net/builds/wintun-0.14.1.zip' `
    -ZipMember 'wintun/bin/amd64/wintun.dll' `
    -FriendlyName 'wintun.dll' `
    -ManualHint 'https://www.wintun.net/ -> copy bin\amd64\wintun.dll next to this script'

if (-not ($okTun2socks -and $okWintun)) {
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    exit 1
}

# --- geoip.dat (geo bypass) ------------------------------------------------
if (-not (Test-Path $GeoIpDir)) {
    New-Item -ItemType Directory -Path $GeoIpDir -Force | Out-Null
}

if (-not (Test-Path $GeoIpFile)) {
    Write-Host ''
    Write-Host '[*] geoip.dat not found in geofil folder.' -ForegroundColor Yellow
    $yn = Read-Host 'Download geoip.dat now? (Y/n)'
    if ($yn.Trim() -ne 'n') {
        $geoUrl = 'https://github.com/v2fly/geoip/releases/latest/download/geoip.dat'
        Write-Host "[*] Downloading geoip.dat from $geoUrl ..." -ForegroundColor Cyan
        $curl = Join-Path $env:SystemRoot 'System32\curl.exe'
        $downloaded = $false
        if (Test-Path $curl) {
            & $curl -L --fail --silent --show-error --ssl-no-revoke --output $GeoIpFile $geoUrl
            if ($LASTEXITCODE -eq 0) { $downloaded = $true }
        }
        if (-not $downloaded) {
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Invoke-WebRequest -Uri $geoUrl -OutFile $GeoIpFile -UseBasicParsing
                $downloaded = $true
            } catch {
                Write-Host "[!] Download failed: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        if ($downloaded -and (Test-Path $GeoIpFile)) {
            Write-Host '[+] geoip.dat downloaded successfully.' -ForegroundColor Green
        } else {
            Write-Host '[!] Could not download geoip.dat. Geo bypass will be unavailable.' -ForegroundColor Yellow
            $GeoIpFile = ''
        }
    } else {
        Write-Host '[*] Skipping geoip.dat download. Geo bypass will be unavailable.' -ForegroundColor Yellow
        $GeoIpFile = ''
    }
}

# --- Elevate AFTER everything is fetched, so download errors are visible ---
if (-not $isAdmin) {
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding  = [System.Text.Encoding]::UTF8
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
chcp 65001 > $null 2>&1

Write-Host ''
Write-Host 'Choose Windows VPN mode:'
Write-Host '  [1] Bypass VPN endpoint  - keeps a connected PPTP/Windows VPN alive'
Write-Host '  [2] Do not bypass VPN    - sends VPN endpoint traffic into the TUN'
Write-Host '  [3] VLESS through VPN    - use Windows VPN for VLESS transport; keep its endpoint bypassed'
$mode = Read-Host 'Select mode (1/2/3)'
switch ($mode.Trim()) {
    '3'      { $VpnMode = '--vless-over-vpn'; $VpnModeLabel = 'VLESS transport through Windows VPN' }
    '2'      { $VpnMode = '--no-vpn-bypass';  $VpnModeLabel = 'VPN bypass disabled' }
    default  { $VpnMode = '';                 $VpnModeLabel = 'VPN endpoint bypass enabled' }
}

# Glyph mode: Auto (let the dashboard probe the terminal), force Unicode
# box/block glyphs, or force plain ASCII (+ - #) for a weak/old console.
Write-Host ''
Write-Host 'Choose glyph mode:'
Write-Host '  [1] Auto    - use Unicode box/block glyphs if the terminal supports them'
Write-Host '  [2] Unicode - force box/block glyphs (needs a Unicode-capable font)'
Write-Host '  [3] ASCII   - plain + - # (safe for old cmd.exe / Raster font)'
$gmode = Read-Host 'Select glyph mode (1/2/3)'
switch ($gmode.Trim()) {
    '2'      { $GlyphArg = '--unicode'; $GlyphLabel = 'Unicode (forced)' }
    '3'      { $GlyphArg = '--ascii';   $GlyphLabel = 'ASCII (forced)' }
    default  { $GlyphArg = '';          $GlyphLabel = 'Auto' }
}

# geoip.dat bypass (route-level bypass of a country). The file lives inside
# the 'geofil' folder next to this script. This menu picks whether to actually
# enable it, and - if enabled - which egress the geoip country traffic should
# use. This choice applies in ALL three VPN modes (1/2/3) selected above.
$hasGeoIp = $GeoIpFile -and (Test-Path $GeoIpFile)
Write-Host ''
Write-Host 'Choose geo bypass (route-level bypass of a country):'
Write-Host '  [1] None'
if ($hasGeoIp) {
    Write-Host '  [2] geoip.dat only   - IP ranges from --geoip-code'
} else {
    Write-Host '  [2] geoip.dat only   - (not available - file missing)'
}
$geo = Read-Host 'Select geo bypass (1/2)'
$GeoIpArg   = @()
$GeoEgressArg = @()
switch ($geo.Trim()) {
    '2' {
        if (-not $hasGeoIp) {
            Write-Host '[!] geoip.dat not found in geofil folder; skipping' -ForegroundColor Yellow
        }
        else {
            Write-Host ''
            Write-Host 'Select region to bypass:'
            Write-Host '  [1] ir - Iran'
            Write-Host '  [2] cn - China'
            Write-Host '  [3] ru - Russia'
            Write-Host '  [4] pk - Pakistan'
            Write-Host '  [5] other - enter manually'
            $region = Read-Host 'Select region (1-5)'
            switch ($region.Trim()) {
                '1' { $GeoIpCode = 'ir' }
                '2' { $GeoIpCode = 'cn' }
                '3' { $GeoIpCode = 'ru' }
                '4' { $GeoIpCode = 'pk' }
                '5' { $GeoIpCode = Read-Host 'Enter country code (e.g. sy, iq, af)' }
                default { $GeoIpCode = 'ir' }
            }
            $GeoIpArg = '--geoip', $GeoIpFile, '--geoip-code', $GeoIpCode
            # Geo bypass egress: wifi (physical adapter) or a connected Windows VPN.
            Write-Host ''
            Write-Host 'Route geoip country traffic via:'
            Write-Host '  [1] Wi-Fi / physical adapter (default)'
            Write-Host '  [2] Connected Windows VPN        (--geoip-via-win-vpn)'
            $geoEgress = Read-Host 'Select geo egress (1/2)'
            if ($geoEgress.Trim() -eq '2') {
                $GeoEgressArg = '--geoip-via-win-vpn'
            }
        }
    }
    default { }
}

$VpnIfaceArg = ''
if ($VpnInterface) {
    $VpnIfaceArg = "--vpn-interface", $VpnInterface
}

Write-Host '============================================================'
Write-Host '  v2ray TUN setup + Monitor - running as Administrator'
Write-Host " Python : $py"
Write-Host " Folder : $ScriptDir"
Write-Host " Mode   : $VpnModeLabel"
Write-Host " Glyphs : $GlyphLabel"
$GeoParts = @()
if ($GeoIpArg)   { $GeoParts += "geoip:$GeoIpCode" }
if ($GeoEgressArg) { $GeoParts += "via Windows VPN" } else { $GeoParts += "via wifi" }
$GeoLabel = if ($GeoIpArg) { "enabled ($($GeoParts -join ', '))" } else { 'None' }
Write-Host " Geo    : $GeoLabel"
Write-Host '  The dashboard builds and owns the tunnel (incl. IPv6) and shows it.'
Write-Host '============================================================'

# The dashboard (tuntop/ui/dashboard.py) launches and OWNS tuntop/tunnel/helper.py
# itself (main() -> app.launch()), capturing its output into the on-screen log
# panel. Do NOT start a second helper here. Running one with -NoNewWindow
# shares this console's stdout, so its setup/teardown text interleaves with
# the dashboard's cursor-positioned redraws and garbles the screen; and two
# helpers fight over tun2socks + the routes, which tears the tunnel down (or
# duplicates it) a few seconds in. Let the dashboard own the tunnel setup.

# Launch as a module (-m tuntop.ui.dashboard) instead of by file path.
# Running "py tuntop/ui/dashboard.py" puts tuntop/ui/ on sys.path, so the
# dashboard's "from tuntop.routing import ..." fails with
# ModuleNotFoundError: No module named 'tuntop'. Running it as a module keeps
# the repo root (this script's folder) on sys.path, so the package resolves.
$pyArgs = @(
    '-m', 'tuntop.ui.dashboard',
    '--server', $Servers,
    '--endpoint-port', $VlessEndpointPort,
    '--port', $SocksPort,
    '--tun2socks', $Tun2socks,
    '--dns4', $DnsServer
)
if ($VpnMode)     { $pyArgs += $VpnMode }
if ($VpnIfaceArg) { $pyArgs += $VpnIfaceArg }
if ($GlyphArg)    { $pyArgs += $GlyphArg }
if ($GeoIpArg)    { $pyArgs += $GeoIpArg }
if ($GeoEgressArg) { $pyArgs += $GeoEgressArg }

& $py @pyArgs
$rc = $LASTEXITCODE

Write-Host ''
if ($rc -eq 0) { Write-Host 'Helper finished normally.' }
else           { Write-Host "Helper exited with code $rc." }
Write-Host ''
Write-Host 'Press any key to close this window...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
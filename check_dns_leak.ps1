# TunTop DNS-leak diagnostic - run in an ELEVATED PowerShell while a tunnel is UP.
# Answers two things: does the catch-all NRPT rule exist, and is Windows
# actually USING it? (A rule in the registry that Windows ignores protects
# nothing - that is the case this script is built to distinguish.)
$ErrorActionPreference = 'Continue'
$root = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig'

Write-Host "`n=== 1. TunTop NRPT keys in the registry ===" -ForegroundColor Cyan
$keys = @(Get-ChildItem -Path $root -ErrorAction SilentlyContinue |
          Where-Object { $_.PSChildName -like 'TunTop-*' })
if ($keys.Count -eq 0) {
    Write-Host "  NONE - the catch-all rule is NOT installed (this is the leak)" -ForegroundColor Red
} else {
    foreach ($k in $keys) {
        $p = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
        Write-Host ("  {0}  Name={1}  Servers={2}  ConfigOptions={3}" -f `
            $k.PSChildName, ($p.Name -join ','), $p.GenericDNSServers, $p.ConfigOptions)
    }
}

Write-Host "`n=== 2. Windows' EFFECTIVE NRPT policy (what the resolver obeys) ===" -ForegroundColor Cyan
$pol = @(Get-DnsClientNrptPolicy -Effective -ErrorAction SilentlyContinue)
if ($pol.Count -eq 0) {
    Write-Host "  (empty - no catch-all namespace, so every adapter's resolver is queried in parallel)" -ForegroundColor Red
} else {
    $pol | ForEach-Object {
        Write-Host ("  Namespace='{0}'  NameServers={1}" -f ($_.Namespace -join ','), ($_.NameServers -join ','))
    }
    if (@($pol | Where-Object { $_.Namespace -contains '.' }).Count -gt 0) {
        Write-Host "  OK - the root namespace is pinned; the ISP resolver cannot be asked" -ForegroundColor Green
    } else {
        Write-Host "  NOT pinned - no rule claims '.'" -ForegroundColor Red
    }
}

Write-Host "`n=== 3. Adapters Windows may still query in parallel ===" -ForegroundColor Cyan
$up = @(Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq 'Up' } | ForEach-Object { $_.Name })
$loops = @('127.0.0.1', '::1', 'fec0:0:0:ffff::1', 'fec0:0:0:ffff::2', 'fec0:0:0:ffff::3')
Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
    Where-Object { $up -contains $_.InterfaceAlias -and $_.InterfaceAlias -ne 'wintun' } |
    ForEach-Object {
        $a = @($_.ServerAddresses | Where-Object { $_ -and $loops -notcontains $_ })
        if ($a.Count -gt 0) { Write-Host ("  {0} = {1}" -f $_.InterfaceAlias, ($a -join ',')) -ForegroundColor Yellow }
    }

Write-Host "`n=== 4. Installed TunTop instances (more than one = the guard is being fought over) ===" -ForegroundColor Cyan
$p = @(Get-Process -Name 'TunTop*' -ErrorAction SilentlyContinue)
Write-Host ("  {0} running" -f $p.Count)
$p | ForEach-Object { Write-Host ("    pid {0}  started {1}" -f $_.Id, $_.StartTime) }

Write-Host "`n=== 5. Verdict ===" -ForegroundColor Cyan
$hasKey = $keys.Count -gt 0
$hasEff = @($pol | Where-Object { $_.Namespace -contains '.' }).Count -gt 0
if ($hasKey -and $hasEff) {
    Write-Host "  The guard IS in force. If a leak test still shows an ISP resolver, the" -ForegroundColor Green
    Write-Host "  query is coming from something OTHER than the OS resolver - see 6." -ForegroundColor Green
} elseif ($hasKey -and -not $hasEff) {
    Write-Host "  The rule is in the registry but Windows is NOT enforcing it" -ForegroundColor Red
    Write-Host "  (malformed rule, or a Group Policy NRPT overriding it). Check GPO:" -ForegroundColor Red
    Write-Host "    HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\NrptRules" -ForegroundColor Red
} else {
    Write-Host "  No rule installed while the tunnel is up = the leak." -ForegroundColor Red
    Write-Host "  Look for the helper's line:  [*] DNS leak guard: Windows DNS pinned to ..." -ForegroundColor Red
    Write-Host "  or                            [!] DNS leak guard NOT active: <reason>" -ForegroundColor Red
}

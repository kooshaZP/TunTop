# Run_Monitor.ps1 - relaunches the window-diagnostic elevated (UAC prompt),
# then runs monitor_windows2.py which writes monitor_out.log in this folder.
$ErrorActionPreference = 'Stop'
$dir = $PSScriptRoot
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
      ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell -Verb RunAs -Wait -WindowStyle Hidden -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', "`"$PSCommandPath`""
    )
    exit
}
& py -3 (Join-Path $dir 'monitor_windows2.py')
exit $LASTEXITCODE

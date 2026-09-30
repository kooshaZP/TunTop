# Run_Monitor.ps1 - relaunches the window-diagnostic elevated (UAC prompt),
# then runs monitor_windows2.py which writes monitor_out.log in this folder.
$ErrorActionPreference = 'Stop'
$dir = $PSScriptRoot
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
      ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Deliberately NOT -WindowStyle Hidden: this script exists to SHOW diagnostics,
    # and a hidden relaunch swallows a declined UAC prompt, a launch failure and
    # every traceback into a window that closes before it can be read.
    $child = Start-Process powershell -Verb RunAs -Wait -PassThru -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', "`"$PSCommandPath`""
    )
    # Carry the elevated run's status out instead of a bare exit: a crash, or a
    # cancelled UAC prompt, in the child would otherwise be reported as success.
    exit $child.ExitCode
}

# Resolve the interpreter the way Run_Helper.ps1's Find-Python does. 'py' is
# often absent outright, and an elevated session can see only a broken Windows
# Store app-execution-alias stub that prints "Python was not found" and exits
# 9009 - so every candidate is test-run with -c, and only one that actually
# starts a Python 3 interpreter is accepted. That probe is also why -3 is no
# longer passed on: a launcher defaulting to Python 2 fails the version check
# and is skipped, instead of being handed the script and failing obscurely.
$py = $null
foreach ($c in 'py', 'python', 'python3') {
    $hits = @(Get-Command $c -All -ErrorAction SilentlyContinue |
              Where-Object { $_.CommandType -eq 'Application' } |
              Select-Object -ExpandProperty Source -Unique)
    foreach ($src in $hits) {
        # Quote-free probe: PowerShell strips embedded double-quotes from the -c
        # string when spawning a native process, so the simpler
        # sys.version_info[0] form (no nested quotes) is the one that survives.
        # The try/catch catches a stub that fails to launch at all, which throws
        # under $ErrorActionPreference = 'Stop'.
        try {
            $v = & $src -c 'import sys;print(sys.version_info[0])' 2>$null
        } catch { continue }
        if ($LASTEXITCODE -eq 0 -and ($v -match '^3')) { $py = $src; break }
    }
    if ($py) { break }
}
if (-not $py) {
    # A missing interpreter is the most common reason this monitor produces no
    # log at all; name it instead of leaving the reader to decode a bare 9009.
    Write-Host '[!] No working Python 3 interpreter found (tried: py, python, python3).' -ForegroundColor Red
    Write-Host '    Install Python 3 and re-run, or start this script from a terminal' -ForegroundColor Red
    Write-Host '    where "py -3 -c pass" succeeds.' -ForegroundColor Red
    exit 3
}
& $py (Join-Path $dir 'monitor_windows2.py')
exit $LASTEXITCODE

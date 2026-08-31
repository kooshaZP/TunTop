@echo off
REM ============================================================================
REM  TunTop launcher  -  double-click THIS file to start TunTop.
REM
REM  Why this exists: files downloaded from GitHub (or copied out of a ZIP)
REM  carry Windows' "Mark of the Web". When you then right-click
REM  Run_Helper.ps1 -> "Run with PowerShell", PowerShell may refuse with
REM     "running scripts is disabled on this system"          (execution policy)
REM     "Windows protected your PC" / script is not digitally signed
REM  This launcher fixes BOTH automatically:
REM    1. Unblock-File strips the Mark of the Web from every TunTop file.
REM    2. -ExecutionPolicy Bypass runs the script regardless of machine policy
REM       (nothing is installed system-wide; the bypass applies to this run only).
REM
REM  Style: the console is set to a 120x36 window, UTF-8, and the classic
REM  blue TunTop colour scheme. Font: the console host uses the font chosen in
REM  "Properties" of its window (defaults to Consolas / Cascadia Mono); a
REM  raster font would mangle the dashboard's box glyphs, so a TrueType font is
REM  preselected in the registry for this console title.
REM ============================================================================

title TunTop
color 1F
chcp 65001 >nul
mode con: cols=120 lines=36 >nul
cd /d "%~dp0"

REM ── Find a working PowerShell (Windows PowerShell or PowerShell 7+) ─────────
set "PS=powershell"
where pwsh >nul 2>&1 && set "PS=pwsh"

REM ── TrueType font for this console (raster fonts break the box glyphs) ──────
REM HKCU\Console\TunTop matches consoles whose title is "TunTop" (set above).
REM FaceName: Consolas (0x0 = auto). FontSize: 0x00120000 = 18px. DWORD values
REM only touch THIS named-console profile, never the global console defaults.
reg add "HKCU\Console\TunTop" /v FaceName   /t REG_SZ    /d Consolas /f >nul 2>&1
reg add "HKCU\Console\TunTop" /v FontFamily /t REG_DWORD /d 54       /f >nul 2>&1
reg add "HKCU\Console\TunTop" /v FontSize   /t REG_DWORD /d 0x120000 /f >nul 2>&1
reg add "HKCU\Console\TunTop" /v FontWeight /t REG_DWORD /d 400      /f >nul 2>&1
REM A console already open (this one) picks the font up on its next relaunch;
REM for the current window the PowerShell layer below sizes it explicitly.

REM ── Run the PowerShell launcher with the download-safe settings ─────────────
%PS% -NoProfile -ExecutionPolicy Bypass -Command ^
  "& { Get-ChildItem -LiteralPath '%~dp0' -Recurse -Include *.ps1,*.py,*.bat,*.psm1 -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue; & '%~dp0Run_Helper.ps1' }"

set "RC=%ERRORLEVEL%"

echo.
if not "%RC%"=="0" (
    color 4F
    echo  [!] TunTop exited with code %RC%.
    echo      If you saw "running scripts is disabled", right-click this .BAT and
    echo      choose "Run as administrator", then run it again.
) else (
    echo  [+] TunTop finished.
)
echo.
pause

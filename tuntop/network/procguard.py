"""PID-safe tun2socks process control - kill ONLY what TunTop owns.

tun2socks is a generic, widely-used open-source proxy tool
(xjasonlyu/tun2socks). Other software on the same machine can legitimately
run its own tun2socks.exe. Every cleanup path in TunTop used to kill BY
PROCESS NAME (`Get-Process | ? ProcessName -like 'tun2socks*'`), which
means TunTop's preflight, watchdog and startup recovery could terminate a
FOREIGN tun2socks it never started. This module is the single shared
implementation that replaces all of those name-based kills.

Ownership rules - a tun2socks* process belongs to TunTop iff ANY holds:

  1. its PID was recorded from TunTop's own Popen handles this session
     (the caller passes them in; PID reuse is inherently guarded because
     the enumeration only sees processes whose image name is tun2socks*);
  2. its ExecutablePath equals the tun2socks path TunTop was configured
     to run (--tun2socks), compared case/separator-insensitively;
  3. its executable's file name is the distinctive vendored name
     (``TUN2SOCKS_BINARY``). This covers crash recovery after a frozen
     (PyInstaller onefile) run: the child ran from a throwaway per-run
     extraction dir whose exact path differs between runs, so rule 2
     cannot match - but that file name is specific enough to TunTop that
     a generic ``tun2socks.exe`` shipped by another tool never hits it.

A generic ``tun2socks.exe`` from another tool matches NONE of the rules:
it is never killed and never counted, even when TunTop's sweep runs.

Pure stdlib; the PowerShell plumbing comes from tuntop.network.routing
(imported lazily inside the call, so this module stays import-safe from
both the helper and the watchdog bootstrap paths).
"""
from __future__ import annotations

import json
import os
import subprocess

#: The vendored tun2socks file name (mirrors build_release.BINARIES and
#: dashboard.py's default --tun2socks). Distinctive: another tool shipping
#: its own tun2socks almost always names it plain ``tun2socks.exe``.
TUN2SOCKS_BINARY = "tun2socks-windows-amd64-v3.exe"

#: One probe returns everything we need to decide ownership: PID, image
#: name, executable path and command line. WQL 'LIKE' uses '%' wildcards.
_PS_ENUM = (
    "Get-CimInstance Win32_Process "
    "-Filter \"Name LIKE 'tun2socks%'\" -ErrorAction SilentlyContinue | "
    "Select-Object ProcessId,Name,ExecutablePath,CommandLine | "
    "ConvertTo-Json -Compress -Depth 2"
)


def _ps(script, timeout=8):
    """Delegate to routing._ps (lazy: keeps import order simple)."""
    from tuntop.network.routing import _ps as _run
    return _run(script, timeout)


def enumerate_tun2socks() -> list:
    """Every running process whose image name starts with 'tun2socks', as
    dicts with pid / name / exe / cmd. [] on any failure (never raises:
    a broken probe must not crash a cleanup path)."""
    ok, out = _ps(_PS_ENUM)
    if not ok or not out or out.strip() in ("", "No result"):
        return []
    try:
        data = json.loads(out)
    except Exception:
        return []
    if isinstance(data, dict):
        data = [data]
    rows = []
    for d in data if isinstance(data, list) else []:
        if not isinstance(d, dict):
            continue
        try:
            pid = int(d.get("ProcessId") or 0)
        except Exception:
            continue
        if pid <= 0:
            continue
        rows.append({
            "pid": pid,
            "name": str(d.get("Name") or ""),
            "exe": str(d.get("ExecutablePath") or ""),
            "cmd": str(d.get("CommandLine") or ""),
        })
    return rows
def _norm(path: str) -> str:
    """Case/separator-insensitive absolute form (Windows-safe; identity on
    other platforms, which only makes matching stricter there)."""
    try:
        return os.path.normcase(os.path.abspath(path)) if path else ""
    except Exception:
        return ""


def select_own(rows: list, tun2socks_path=None, recorded=()) -> list:
    """PURE ownership filter - the heart of this module, unit-testable on
    any OS (tests/unit/test_procguard.py). Returns the subset of `rows`
    (as produced by enumerate_tun2socks) that belong to TunTop."""
    recorded_ids = set()
    for p in (recorded or ()):
        try:
            recorded_ids.add(int(p))
        except Exception:
            continue
    want_path = _norm(tun2socks_path) if tun2socks_path else ""
    own = []
    for r in rows or []:
        if not str(r.get("name", "")).lower().startswith("tun2socks"):
            continue
        exe = str(r.get("exe") or "")
        exe_norm = _norm(exe)
        # No path available (can happen for protected processes): fall back
        # to the image name itself.
        base = (os.path.basename(exe_norm) if exe_norm
                else str(r.get("name") or "").lower())
        if (r.get("pid") in recorded_ids
                or (want_path and exe_norm == want_path)
                or base == os.path.normcase(TUN2SOCKS_BINARY)):
            own.append(r)
    return own


def count_own(tun2socks_path=None, recorded=()) -> int:
    """How many TunTop-owned tun2socks processes are running."""
    return len(select_own(enumerate_tun2socks(), tun2socks_path, recorded))


def kill_own(tun2socks_path=None, recorded=(), log=None) -> int:
    """Force-stop ONLY the tun2socks processes TunTop owns. taskkill /T
    takes any children too; raw TerminateProcess is the fallback (same
    pattern as the watchdog's helper-tree kill). Best-effort; returns how
    many victims were identified and targeted."""
    log = log or (lambda msg: None)
    victims = select_own(enumerate_tun2socks(), tun2socks_path, recorded)
    for v in victims:
        pid = v["pid"]
        where = v["exe"] or v["name"]
        try:
            rc = subprocess.call(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL)
            if rc == 0:
                log(f"stopped owned tun2socks PID {pid} ({where})")
                continue
        except Exception:
            pass
        try:
            import ctypes
            k32 = ctypes.windll.kernel32
            h = k32.OpenProcess(0x0001, False, int(pid))   # PROCESS_TERMINATE
            if h:
                try:
                    if k32.TerminateProcess(h, 1):
                        log(f"stopped owned tun2socks PID {pid} ({where})")
                finally:
                    k32.CloseHandle(h)
        except Exception:
            pass
    return len(victims)


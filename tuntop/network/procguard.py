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
     (the caller passes them in as `recorded`). NOTE this rule only ever
     fires for a caller that actually passes PIDs: the helper holds
     tun2socks's Popen handle, but the dashboard and the watchdog only ever
     observe the helper, so they rely on rules 2 and 3. Every caller MUST
     pass `recorded` whenever it has the handle - a bare `kill_own()` gets
     rule 3 alone.
  2. its ExecutablePath equals the tun2socks path TunTop was configured
     to run (--tun2socks), compared case/separator-insensitively;
  3. its executable's file name is the distinctive vendored name
     (``TUN2SOCKS_BINARY``) AND it lives somewhere TunTop put it: next to
     TunTop.exe, or in a PyInstaller ``_MEI*`` extraction dir. This covers
     crash recovery after a frozen (PyInstaller onefile) run: the child ran
     from a throwaway per-run extraction dir whose exact path differs
     between runs, so rule 2 cannot match.

Rule 3's LOCATION half is load-bearing, not decoration. The vendored name
is ``tun2socks-windows-amd64-v3.exe`` - which is the UPSTREAM
xjasonlyu/tun2socks v2.7.0 release asset name (see Run_Helper.ps1 and
.github/workflows/release.yml, which download exactly that file). Any user
who installed tun2socks from its own upstream release - or any tool that
vendors the same build (v2rayN, xray, nekoray) - has a process whose
basename matches EXACTLY. Matching on the bare name therefore made
``taskkill /F /T`` terminate a foreign proxy on every TunTop teardown,
startup recovery and watchdog sweep. The name alone is not TunTop's; the
name plus a TunTop-controlled directory is.

A generic ``tun2socks.exe`` from another tool matches NONE of the rules:
it is never killed and never counted, even when TunTop's sweep runs. Neither
does an upstream-named binary installed somewhere else.

Pure stdlib; the PowerShell plumbing comes from tuntop.network.routing
(imported lazily inside the call, so this module stays import-safe from
both the helper and the watchdog bootstrap paths).
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys

#: The vendored tun2socks file name (mirrors build_release.BINARIES and
#: dashboard.py's default --tun2socks). NOTE: this is also the upstream
#: release asset name, so it is only ever matched together with a
#: TunTop-controlled location - see the module docstring and rule 3.
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
    """Platform-independent case/separator-insensitive absolute form.

    Unlike ``os.path.normcase(os.path.abspath(path))`` - which lowercases ONLY
    on Windows and treats ``\\`` as a literal character on POSIX (so a Windows
    ``C:\\Tools\\TUN2SOCKS.EXE`` is left upper-case and split on the wrong
    char there, making the ownership test broken rather than "stricter") -
    this lowercases and treats BOTH ``/`` and ``\\`` as separators on EVERY
    platform.

    The separator and case handling really is host-independent, and that is
    what makes the ownership test RUNNABLE on Linux: a Windows path can be
    fed in and compared without a Windows box. So is the absolute-path step,
    because a DRIVE-LETTER path is recognised as already-absolute and
    returned unchanged - which is what Windows' own abspath() does with it.
    Without that, a Windows ``C:/Tools/x.exe`` normalized to
    ``<cwd>/C:/Tools/x.exe`` on POSIX, so the same input produced a different
    string per host and the location test could not be exercised off
    Windows at all (it silently depended on the test's own working
    directory). Anything without a drive letter is a POSIX path or a
    genuinely relative one, and is resolved as before.

    A bare filename (no separator) has no directory component to resolve, so
    its canonical form is the lowercased name itself - this keeps the
    vendored-name compare against a basename a true no-op.
    """
    try:
        if not path:
            return ""
        p = str(path).replace("\\", "/").lower()
        if "/" not in p:
            return p
        if _DRIVE_RE.match(p):
            return p          # already absolute, on every host
        return os.path.abspath(p).replace("\\", "/").lower()
    except Exception:
        return ""


#: A Windows drive-qualified path (``c:/tools/x.exe``). ``os.path.abspath``
#: leaves these untouched on Windows, so skipping it elsewhere is what makes
#: the normalized form identical on every host.
_DRIVE_RE = re.compile(r"^[a-z]:/")


#: A PyInstaller onefile extraction dir: %TEMP%\_MEIxxxxxx. The frozen
#: helper's tun2socks child is spawned from there, and the exact name
#: changes every run - which is the only reason rule 3 exists at all.
_MEI_RE = re.compile(r"(^|/)_mei[0-9a-z]+(/|$)", re.IGNORECASE)


def _norm_dir(path: str) -> str:
    """Normalize a DIRECTORY into the same form _norm() produces for a file
    path (lower-cased, forward slashes), so the two can be compared."""
    try:
        if not path:
            return ""
        return str(path).replace("\\", "/").rstrip("/").lower()
    except Exception:
        return ""


def _tuntop_owned_locations():
    """Directories TunTop itself puts binaries in: next to TunTop.exe (frozen),
    or next to the application root derived from this package (source run).

    Every entry is derived from EITHER the frozen executable's location or
    this module's own location on disk. That is the whole point: ownership
    must follow from something TunTop controls, never from ambient state.

    Two entries that used to be here are deliberately GONE:

    ``os.getcwd()`` - the directory the user happened to launch from. It is
    user-controlled, not TunTop-controlled: every installer, ``cd``-then-run
    habit and "open Terminal here" makes it different. Worse, it is the
    *most* common place to drop a downloaded tool, so a foreign upstream
    tun2socks.exe sitting in the folder TunTop was started from was treated
    as TunTop's and killed on every teardown. The coverage it was added for
    is now provided structurally by the APP_ROOT entry below, which is the
    real root rather than whatever the shell happened to be sitting in.

    ``%TEMP%`` / ``%TMP%`` - shared with every other application and user on
    the machine. Anything can unpack a binary there; v2rayN/xray/nekoray
    unpack their vendored copies into temp dirs by design. The PyInstaller
    case that entry was presumably added for is already covered by _MEI_RE
    (a frozen run's child really does live in ``%TEMP%\\_MEIxxxxxx``), which
    is an exact pattern match instead of a blanket directory.
    """
    locs = []
    exe = getattr(sys, "executable", "") or ""
    if exe and getattr(sys, "frozen", False):
        locs.append(os.path.dirname(os.path.abspath(exe)))
    # Source run. The naming trap worth stating: __file__ is tuntop/network/
    # procguard.py, so pkg_dir below is ``tuntop/network``, its parent is
    # ``tuntop/`` (the PACKAGE dir - the release zip writes binaries there),
    # and APP_ROOT is one level further up (a git checkout, whose binaries sit
    # beside the package rather than inside it). Deriving the root from
    # __file__ instead of os.getcwd() covers both layouts on every host with
    # no reliance on the launcher's working directory.
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    pkg_root = os.path.dirname(pkg_dir)
    locs.append(pkg_dir)
    locs.append(pkg_root)
    app_root = os.path.dirname(pkg_root)
    if app_root:
        locs.append(app_root)
    return {_norm_dir(p) for p in locs if p}


def _is_tuntop_location(exe_norm: str) -> bool:
    """True when `exe_norm` (a normalized absolute path) sits somewhere
    TunTop put a binary, or in a PyInstaller extraction dir."""
    if not exe_norm:
        return False
    if _MEI_RE.search(exe_norm):
        return True
    if "/" not in exe_norm:
        return False            # a bare name proves nothing about location
    parent = os.path.dirname(exe_norm)
    return parent in _tuntop_owned_locations()


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
    if want_path and "/" not in want_path:
        # A bare configured name can never equal CIM's absolute
        # ExecutablePath, so rule 2 was silently inert. Resolve it against
        # the locations TunTop actually uses.
        for _loc in sorted(_tuntop_owned_locations()):
            _cand = os.path.join(_loc, want_path)
            if os.path.exists(_cand):
                want_path = _norm(_cand)
                break
    own = []
    for r in rows or []:
        if not str(r.get("name", "")).lower().startswith("tun2socks"):
            continue
        exe = str(r.get("exe") or "")
        exe_norm = _norm(exe)
        # A row with no readable path still has an image name, and the name
        # is what rule 3's first half compares. The location half is then
        # what decides it - and with no path, _is_tuntop_location("") is
        # False, so a pathless row can only ever be ours via a recorded PID.
        base = (os.path.basename(exe_norm) if exe_norm
                else str(r.get("name") or "").lower())
        if r.get("pid") in recorded_ids:
            own.append(r)
            continue
        if want_path and exe_norm == want_path:
            own.append(r)
            continue
        # Rule 3: the vendored NAME, but only from a directory TunTop put
        # it in. The name alone is the upstream release asset name, so
        # matching it anywhere would kill another application's proxy.
        #
        # The LOCATION half is not optional and cannot be softened. The
        # previous version also accepted `or not exe_norm` ("no path at
        # all") - but CIM reports an EMPTY ExecutablePath precisely when it
        # cannot open the process, i.e. for the elevated/other-user case,
        # so that clause selected exactly the processes whose identity
        # could not be established: any upstream-named proxy running
        # elevated got taskkill /F /T on every teardown. The inline comment
        # said "recorded PIDs only", but rule 1 above has already claimed
        # and `continue`d on every recorded PID, so nothing reaching this
        # line is a recorded PID. With no path there is no proof of
        # location, and no proof means NOT OURS.
        if base == _norm(TUN2SOCKS_BINARY) and _is_tuntop_location(exe_norm):
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
    _NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    victims = select_own(enumerate_tun2socks(), tun2socks_path, recorded)
    for v in victims:
        pid = v["pid"]
        where = v["exe"] or v["name"]
        try:
            rc = subprocess.call(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL, creationflags=_NO_WINDOW)
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


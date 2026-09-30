"""Detached cleanup watchdog - the safety net under EVERY exit path.

Normal teardown ([Q], Ctrl+C, a window close that finishes within its
5-second slot, atexit) removes the Wintun adapter, its routes and every
bypass route. But when the dashboard dies WITHOUT its cleanup running -
Alt+F4's close timeout expiring mid-teardown, Task Manager's
TerminateProcess, a crash, a power flicker - whatever the helper had
installed stays on the system: the default route keeps pointing into a
TUN adapter nothing serves anymore, and the machine loses its internet
until the next TunTop run fixes it at startup.

The dashboard spawns THIS module as a detached process (it deliberately
outlives the dashboard) and hands it the dashboard's PID, the origin
hosts and (once known) the tunnel helper's PID. The watchdog then:

    1. waits for the dashboard process to exit (any reason),
    2. waits out a short grace period so a clean teardown can finish,
    3. checks the crash marker (`.last_run.json`): gone -> the run exited
       cleanly, do nothing; owned by a NEWER session -> do nothing (that
       session's own watchdog covers it); still OURS -> the exit was
       unclean,
    4. kills the tunnel helper first (a live helper could restart
       tun2socks or re-assert routes mid-sweep), then runs the SAME
       probe-based sweep a next launch would have done
       (startup_recovery: kill orphan tun2socks, remove the Wintun
       adapter + its routes, sweep stale per-host bypass routes),
    5. clears the marker so the next launch starts on a clean slate.

Pure stdlib, zero pip dependencies. The sweep itself is the already
battle-tested startup_recovery code (scan + recover with injectable
probes), so there is exactly ONE implementation of route cleanup - the
watchdog only decides WHEN to run it. The decision logic is fully unit
tested without Windows (tests/recovery/test_cleanup_watchdog.py).
"""
from __future__ import annotations

import argparse
import ipaddress         # CIDR-vs-CIDR comparison in the geo sweep
import json
import os
import subprocess
import sys
import tempfile          # sweep batch files - eager, see _MEI note
import time
import traceback         # sweep failure diagnosis (full stack in the log)

from tuntop import procidentity   # PID identity, not just liveness

# When executed as a script (`python cleanup_watchdog.py --pid N`), the
# package root is NOT on sys.path (sys.path[0] is this file's directory).
# Fix that before importing anything from the tuntop package.
_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))   # file is tuntop/core/x.py -> repo root
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from tuntop.startup_recovery import (  # noqa: E402
    MARKER_FILE, clear_marker, read_marker, recover_ex, scan,
)

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# Windows access rights / wait codes (ctypes only; absent on other OSes).
_SYNCHRONIZE = 0x00100000
_PROCESS_TERMINATE = 0x0001
_ERROR_INVALID_PARAMETER = 87

#: How long a dead parent's cleanup gets to finish before we look around.
DEFAULT_GRACE_SECONDS = 3.0

#: Watchdog diagnostics land next to the crash marker (best-effort).
#: Frozen exe: __file__ sits in a throwaway per-run extraction dir, so the
#: diary is parked next to TunTop.exe instead (same rule as MARKER_FILE /
#: STATE_FILE) - otherwise every sweep runs INVISIBLY and a leftover-routes
#: report can never be diagnosed.
if getattr(sys, "frozen", False):
    LOG_FILE = os.path.join(
        os.path.dirname(os.path.abspath(sys.executable)),
        ".cleanup_watchdog.log")
else:
    LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            ".cleanup_watchdog.log")

#: Live-session state sidecar (written by the dashboard whenever bypass /
#: geo state changes, deleted on clean teardown). Read at sweep time so
#: bypasses the user added LIVE (dashboard [A]/[F] dialogs, after the
#: watchdog was spawned with the startup args) are cleaned too.
if getattr(sys, "frozen", False):
    # Frozen exe: the dashboard parks the sidecar next to TunTop.exe (its
    # own __file__ lives in a throwaway extraction dir, and so does ours -
    # this file's directory is NOT where the dashboard wrote it).
    STATE_FILE = os.path.join(
        os.path.dirname(os.path.abspath(sys.executable)),
        ".cleanup_watchdog_state.json")
else:
    STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              ".cleanup_watchdog_state.json")


_LOG_SEEN: set = set()


def _state_path(marker_path: str) -> str:
    """The live-session state sidecar that goes with `marker_path`.

    The sidecar lives NEXT TO the crash marker - the dashboard writes both to
    the same directory, and that directory is where the exe is when frozen.
    It was derived twice by hand (a str.replace in one place, an
    os.path.join in the other) and the fallback branch read the module-level
    STATE_FILE, which is derived from sys.executable / __file__ instead: with
    a `--marker` pointing somewhere else, the merge silently read a file from
    the WRONG DIRECTORY and the live bypass/geo state was lost - the routes
    the sweep was supposed to know about. One derivation, one answer."""
    return os.path.join(os.path.dirname(os.path.abspath(marker_path)),
                        os.path.basename(STATE_FILE))


def read_live_state(path: str = STATE_FILE) -> dict:
    """Best-effort read of the dashboard's live-session state sidecar.
    Missing/corrupt -> {} (the sweep then relies on the startup args)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _log(msg: str, log=None) -> None:
    """Report to the caller's sink AND append to the on-disk diary (the
    watchdog has no console - without the file, a sweep that ran or failed
    silently would be undiagnosable). The sink may itself be _log (main()
    wires it that way) - a _sentinel de-dupes that chain so every message
    lands in the diary exactly once."""
    if log is not None and msg not in _LOG_SEEN:
        _LOG_SEEN.add(msg)
        try:
            log(msg)
        except Exception:
            pass
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
    except Exception:
        pass


def _kernel32():
    """A kernel32 handle that actually REPORTS GetLastError, with the 64-bit
    prototypes declared.

    Both details are load-bearing:
      * ctypes.windll does NOT set use_last_error, so ctypes.GetLastError()
        on its functions is meaningless - the watchdog could not tell
        "access denied (process alive)" from "no such process" and treated a
        LIVE dashboard as dead, then tore its tunnel down.
      * Without an explicit restype, OpenProcess's 64-bit HANDLE is
        sign-extended into a 32-bit int: a handle above 4 GiB becomes a
        different (or negative) value, so WaitForSingleObject is handed a
        bogus handle and the wait never completes.
    """
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k32.WaitForSingleObject.restype = wintypes.DWORD
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL
    k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    k32.TerminateProcess.restype = wintypes.BOOL
    return k32


def wait_for_exit(pid: int, timeout_s: float = None) -> bool:
    """Block until the process `pid` is gone. Returns True when it is gone.
    Best-effort by design, but NEVER optimistic: "I could not tell" keeps
    polling until the deadline rather than reporting the process as gone -
    reporting a live dashboard as dead tears down a working tunnel."""
    if not sys.platform.startswith("win") or int(pid) <= 0:
        return True
    try:
        import ctypes
        k32 = _kernel32()
        deadline = None if timeout_s is None else time.time() + timeout_s
        while True:
            h = k32.OpenProcess(_SYNCHRONIZE, False, int(pid))
            if h:
                try:
                    # 1s wait slices so a timeout can still be honoured.
                    rc = k32.WaitForSingleObject(h, 1000)
                    if rc == 0:            # WAIT_OBJECT_0: exited
                        return True
                finally:
                    k32.CloseHandle(h)
            else:
                err = ctypes.get_last_error()
                if err == _ERROR_INVALID_PARAMETER:
                    return True            # no such process: already gone
                if err == 5:               # 5 = access denied: still alive
                    _log(f"watchdog: cannot open PID {pid} (access denied) "
                         "- assuming it is still running", None)
                # any other error: cannot observe - keep polling until the
                # deadline instead of declaring a possibly-live process gone.
            if deadline is not None and time.time() >= deadline:
                return False
            time.sleep(0.5)
    except Exception:
        return False


def _helper_start(marker_path, helper_pid):
    """The creation time the marker recorded for `helper_pid`, or None.

    Two ways to get None, and both are deliberately permissive (see
    kill_pid): the marker may predate identity tracking, or the PID being
    killed did not come from the marker at all (it arrived on the command
    line). A key that is ABSENT cannot contradict anything; a key that is
    PRESENT for a DIFFERENT pid could, so that case is treated as absent
    rather than trusted.
    """
    try:
        marker = read_marker(marker_path) or {}
        if int(marker.get("helper_pid", 0) or 0) != int(helper_pid):
            return None
        recorded = marker.get("helper_started")
        return int(recorded) if recorded else None
    except Exception:
        return None


def kill_pid(pid: int, log=None, recorded_start=None) -> bool:
    """Forcefully stop the helper process tree (helper + its tun2socks
    children). taskkill /T is tried first because it takes the whole tree
    in one shot; raw TerminateProcess is the fallback. Best-effort.

    IDENTITY GATE. `taskkill /F /T` on a bare PID is the single most
    destructive thing this watchdog can do, and the PID came off disk from a
    crash marker that may be from a previous boot - after which the number
    plausibly belongs to something else entirely (a browser, another VPN
    client), and /T would take its whole tree with it. So a `recorded_start`
    creation time must be supplied and must match before anything is
    killed. Refusing is always the right answer here: the helper dying is
    harmless, an unrelated process tree being force-terminated is not.

    An older marker with no `helper_started` still kills, or a crash whose
    helper genuinely died would be left running - so absence of the key is
    allowed, while a key that is present and DISAGREES is fatal to the kill.
    """
    if not pid or int(pid) <= 0:
        return False
    if not sys.platform.startswith("win"):
        return False
    if recorded_start is not None and \
            not procidentity.same_process(pid, recorded_start):
        _log(f"watchdog: PID {pid} is no longer the helper this marker "
             f"recorded (creation time differs) - refusing to kill it",
             log)
        return False
    try:
        rc = subprocess.run(["taskkill", "/F", "/T", "/PID", str(int(pid))],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            stdin=subprocess.DEVNULL,
                            creationflags=_NO_WINDOW,
                            timeout=30).returncode
        if rc == 0:
            _log(f"watchdog: helper tree (PID {pid}) terminated", log)
            return True
    except subprocess.TimeoutExpired:
        _log(f"watchdog: taskkill for PID {pid} timed out - falling back to "
             "TerminateProcess", log)
    except Exception:
        pass
    try:
        k32 = _kernel32()
        h = k32.OpenProcess(_PROCESS_TERMINATE, False, int(pid))
        if h:
            try:
                ok = bool(k32.TerminateProcess(h, 1))
            finally:
                k32.CloseHandle(h)
            if ok:
                _log(f"watchdog: helper (PID {pid}) terminated", log)
            return ok
    except Exception:
        pass
    _log(f"watchdog: could not terminate helper (PID {pid})", log)
    return False


#: LAN bypass prefixes TunTop's helper installs EVERY run: imported from
#: tuntop.config.defaults (LAN_BYPASS_PREFIXES) - the single copy shared with
#: the helper and the dashboard's sweep.
from tuntop.config.defaults import LAN_BYPASS_PREFIXES  # noqa: E402


def _lan_victims(rows, iface, gw):
    """Victim selection for sweep_lan_routes - DELEGATES to the shared rule
    in tuntop.network.routeops.sweeps (one implementation for the dashboard,
    the helper and this watchdog). Thin alias kept for the unit tests."""
    from tuntop.network.routeops.sweeps import lan_victims
    return lan_victims(rows, iface, gw, prefixes=LAN_BYPASS_PREFIXES)


#: Total wall-clock budget for the geo sweep's chunked netsh deletes. It used
#: to be per-chunk (180 s EACH), so 4096 leftover routes was 16 chunks and up
#: to 48 minutes of a half-cleaned table - while default traffic still pointed
#: into a dead tunnel. Past the budget the sweep gives up and RETAINS the
#: marker, which is the fail-safe direction: the next launch retries from
#: scratch instead of inheriting a sweep that never finished.
_GEO_SWEEP_BUDGET_SECONDS = 300.0


def _live_rows(timeout=90):
    """The live routing table as row dicts, via the FAST text dump.

    Both sweeps used to read the table with
    `Get-NetRoute ... | ConvertTo-Json`, and that was wrong twice over:

      * TIMEOUT. The call went through `routing._ps` with no `timeout`, so it
        inherited _ps's default of EIGHT seconds - while the `netsh` deletes in
        the very same functions were allowed 120 s and 180 s. Over a table
        with thousands of leftover geo routes, i.e. exactly the crash this
        watchdog exists to clean up, ConvertTo-Json exceeds 8 s, raises
        TimeoutExpired, and the outer `except Exception` turned the whole
        sweep into a None. None means "the marker is RETAINED", so the safety
        net reported a failure, removed nothing, and left every route
        installed - the one situation it exists for.
      * COST. routing._dump_route_table_ps() was written for the dashboard
        precisely because ConvertTo-Json is the bottleneck on large tables
        (PowerShell 5.1 serialises big object arrays slowly), and it defaults
        to a 90 s timeout.

    Returns [] for a genuinely empty table and **None** when the table could
    not be read at all. The difference is load-bearing: "found nothing" lets
    the caller retire the crash marker, "could not look" must not.
    """
    try:
        import tuntop.network.routing as routing
        ok, out = routing._dump_route_table_ps(timeout=timeout)
    except Exception:
        return None
    if not ok:
        return None
    try:
        return routing._parse_route_rows(out)
    except Exception:
        return None


def sweep_lan_routes(log=None) -> int:
    """Remove leftover LAN bypass routes from the PHYSICAL adapter. They are
    benign on the network where they were installed (they point at the same
    gateway Windows uses anyway) but stale after a network change, so a
    crash followed by switching Wi-Fi would otherwise keep routing RFC1918
    traffic at the old gateway. Returns how many were removed, or None when
    the sweep could not be trusted."""
    log = log or (lambda m: None)
    try:
        import tuntop.network.routing as routing
        def_gw = routing._get_ipv4_default()
        if not def_gw:
            return 0
        iface, gw = def_gw[0], def_gw[1]
        rows = _live_rows()
        if rows is None:
            _log("watchdog: could not read the routing table for the LAN "
                 "sweep - marker retained", log)
            return None
        victims = _lan_victims(rows, iface, gw)
        if not victims:
            return 0
        lines = [f'interface ipv4 delete route {dp} "{alias}"'
                 f'{"" if nh in ("0.0.0.0", "On-link") else (" " + nh if nh else "")}'
                 for dp, alias, nh in victims]
        fd, tmp = tempfile.mkstemp(suffix=".txt", prefix="wd_lan_")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            try:
                proc = subprocess.run(["netsh", "-f", tmp],
                                      capture_output=True, timeout=120,
                                      creationflags=_NO_WINDOW)
            except subprocess.TimeoutExpired:
                _log(f"watchdog: LAN sweep timed out - {len(victims)} "
                     f"route(s) may remain, marker retained", log)
                return None
        finally:
            try:
                os.unlink(tmp)
            except Exception:
                pass
        # netsh -f reports per-line failures in its OUTPUT and still exits 0,
        # while a non-zero code (or no output at all, which means the file was
        # never read) means the batch did NOT go through. The geo sweep above
        # already treats that verdict as load-bearing precisely because
        # counting an undelivered batch cleared the crash marker while the
        # routes were still installed; the LAN sweep discarded the return
        # value entirely and returned len(victims) either way, so a
        # half-failed sweep was indistinguishable from a successful one and
        # the marker was retired over routes that were still live. Same rule,
        # same reason.
        out_txt = ((proc.stdout or b"").decode("utf-8", "replace")
                   + (proc.stderr or b"").decode("utf-8", "replace"))
        if proc.returncode != 0:
            _log(f"watchdog: LAN sweep failed (netsh rc={proc.returncode}) - "
                 f"{len(victims)} route(s) kept, marker retained", log)
            return None
        if not out_txt.strip():
            _log(f"watchdog: LAN sweep produced no netsh output - "
                 f"{len(victims)} route(s) unconfirmed, marker retained", log)
            return None
        # Count what netsh CONFIRMED, not what we asked for: it reports
        # per-line failures in the same output it just checked above, and
        # still exits 0.
        return sum(1 for ln in out_txt.splitlines() if ln.strip() == "Ok.")
    except Exception as e:
        _log(f"watchdog: LAN sweep failed: {e}\n"
             f"{traceback.format_exc()}".rstrip(), log)
        # None (not 0): the caller must NOT treat this as "sweep ran and
        # found nothing" - a failed sweep leaves the crash marker in place
        # so the next launch re-runs the whole recovery. (Field evidence:
        # the frozen watchdog's lazy imports died with Errno 2 on
        # base_library.zip after the parent's _MEI dir was deleted, the
        # sweeps no-op'd - and the marker was STILL cleared, so the log
        # said "system is clean" while routes stayed.)
        return None


def sweep_geo_routes(geoip: str, geoip_code: str, log=None) -> int:
    """Remove every live route whose DestinationPrefix is one of the geoip
    country's CIDRs. Geo bypass routes live on the PHYSICAL adapter, so the
    Wintun teardown above never sees them - after a hard kill they keep
    routing that country's traffic around the (now dead) tunnel, which both
    breaks connectivity for those prefixes and leaves the bypass intent
    armed for the next session. Batch netsh -f deletes, same fast path the
    dashboard's own sweep uses. Returns how many were removed (VERIFIED from
    netsh's own per-line answers), or None when the sweep could not be
    trusted."""
    log = log or (lambda m: None)
    try:
        if not geoip or not os.path.isfile(geoip):
            return 0
        # A geoip file without a country code means geo bypass was never
        # active this session - nothing to sweep, and NOT an error (the
        # empty code used to reach parse_geoip and be logged as a scary
        # "no CIDR entries found for geoip code ''" failure).
        if not geoip_code:
            return 0
        from tuntop.geoip import parse_geoip          # repo root on sys.path
        cidrs = set(parse_geoip(geoip, geoip_code))
        if not cidrs:
            return 0
        # Compare CIDRs as NETWORKS, not strings. parse_geoip renders IPv6 in
        # the uncompressed eight-group form ("2001:db8:0:0:0:0:0:0/32")
        # while Get-NetRoute returns Windows' canonical compressed form
        # ("2001:db8::/32") - a string compare misses EVERY IPv6 geo route,
        # so they survived every sweep and kept routing that country's
        # traffic around a dead tunnel. Same for a CIDR with host bits set.
        wanted = set()
        for c in cidrs:
            try:
                wanted.add(str(ipaddress.ip_network(str(c), strict=False)))
            except ValueError:
                continue
        # Victim selection is the SHARED rule (routeops.sweeps), the same copy
        # the dashboard uses - this sweep had its own hand-rolled inline loop.
        from tuntop.network.routeops.sweeps import geo_victims
        rows = _live_rows()
        if rows is None:
            _log("watchdog: could not read the routing table for the geo "
                 "sweep - marker retained", log)
            return None
        victims = geo_victims(rows, wanted)
        if not victims:
            return 0
        # Batch netsh -f deletes: hundreds of lines per process, disjoint
        # prefixes cannot collide.
        chunks = [victims[i:i + 256] for i in range(0, len(victims), 256)]
        deadline = time.time() + _GEO_SWEEP_BUDGET_SECONDS
        removed = 0
        for chunk in chunks:
            if time.time() >= deadline:
                _log(f"watchdog: geo sweep ran out of time after {removed} "
                     f"route(s) - {len(victims) - removed} may remain, "
                     "marker retained", log)
                return None
            lines = []
            for dp, alias, nh in chunk:
                verb = "ipv6" if ":" in dp else "ipv4"
                nh_tok = ""
                if nh and nh not in ("0.0.0.0", "::"):
                    nh_tok = f" {nh}"
                lines.append(f'interface {verb} delete route {dp} "{alias}"{nh_tok}')
            try:
                fd, tmp = tempfile.mkstemp(suffix=".txt", prefix="wd_geo_")
                try:
                    with os.fdopen(fd, "w", encoding="utf-8") as f:
                        f.write("\n".join(lines))
                    proc = subprocess.run(["netsh", "-f", tmp],
                                          capture_output=True, timeout=180,
                                          creationflags=_NO_WINDOW)
                    # netsh -f reports per-line failures in its OUTPUT and
                    # still exits 0, so a non-zero code (or no output at all,
                    # which means the file was not read) means the chunk did
                    # NOT go through. Counting the chunk anyway cleared the
                    # crash marker while the routes were still installed.
                    out_txt = (proc.stdout or b"").decode(
                        "utf-8", "replace") + (proc.stderr or b"").decode(
                        "utf-8", "replace")
                finally:
                    try:
                        os.unlink(tmp)
                    except Exception:
                        pass
                if proc.returncode != 0:
                    _log(f"watchdog: geo sweep chunk failed (netsh rc="
                         f"{proc.returncode}) - {len(chunk)} route(s) kept, "
                         "marker retained", log)
                    return None
                if not out_txt.strip():
                    _log(f"watchdog: geo sweep chunk produced no netsh output "
                         f"- {len(chunk)} route(s) unconfirmed, marker "
                         "retained", log)
                    return None
                # VERIFIED count. netsh answers each successful line with
                # "Ok." and reports per-line failures in the SAME output, while
                # still exiting 0 - so len(chunk) was never a removal count,
                # and the "removed N routes" line above was fiction whenever a
                # line was refused.
                removed += sum(1 for ln in out_txt.splitlines()
                               if ln.strip() == "Ok.")
            except subprocess.TimeoutExpired:
                _log(f"watchdog: geo sweep chunk timed out - {len(chunk)} "
                     "route(s) may remain, marker retained", log)
                return None
            except Exception as e:
                _log(f"watchdog: geo sweep chunk error ({e}) - marker "
                     "retained", log)
                return None
        return removed
    except Exception as e:
        _log(f"watchdog: geo sweep failed: {e}\n"
             f"{traceback.format_exc()}".rstrip(), log)
        # None (not 0): the caller must NOT treat this as "sweep ran and
        # found nothing" - a failed sweep leaves the crash marker in place
        # so the next launch re-runs the whole recovery.
        return None


def sweep_after_unclean_exit(pid: int, hosts=(), helper_pid=None,
                             marker_path: str = MARKER_FILE, log=None,
                             probes=None, geoip: str = None,
                             geoip_code: str = "",
                             marker_live=None) -> bool:
    """The watchdog's whole decision, in one testable function.

    Returns True when an unclean exit of session `pid` was detected and
    the recovery sweep ran. Every other case (no marker, marker owned by
    a newer session) returns False and touches nothing.

    `probes` is passed straight through to startup_recovery's scan/recover
    so tests can run the whole path with fakes and no Windows. When
    `geoip`/`geoip_code` are given, geo-bypass routes on the PHYSICAL
    adapter are swept too (the Wintun teardown can't see them).

    `marker_live` is passed straight through to scan as well, so a caller
    can STATE whether the marker's dashboard PID is still running instead of
    leaving that verdict to the machine's process table. That verdict is a
    property of the HOST, not of this decision: a marker PID that happens to
    be alive (CI runners reuse low PIDs) IS a live session by definition, and
    the sweep then correctly refuses to touch anything - which is what made
    the crash-path tests fail on CI while passing locally. Tests that
    simulate a crashed run pin it to False.
    """
    log = log or (lambda m: None)
    try:
        marker = read_marker(marker_path)
    except Exception as e:
        _log(f"watchdog: marker unreadable ({e}) - not sweeping", log)
        return False
    if not marker:
        _log("watchdog: marker gone - previous run exited cleanly", log)
        return False
    try:
        marker_pid = int(marker.get("pid", -1) or -1)
    except Exception:
        marker_pid = -1
    if marker_pid != int(pid):
        _log(f"watchdog: marker belongs to session {marker_pid}, not "
             f"{pid} - a newer session owns it, leaving it alone", log)
        return False

    # Re-read the marker IMMEDIATELY before the first destructive step. The
    # 3 s grace period is exactly the window in which a user relaunches
    # TunTop; a newer session writes its own marker and starts its own
    # tunnel. The pid check below only guarded the marker CLEAR, so this
    # watchdog used to kill the new session's helper and rip the Wintun
    # adapter out from under a live, working tunnel.
    try:
        current = read_marker(marker_path)
        current_pid = int((current or {}).get("pid", -1) or -1)
    except Exception as e:
        _log(f"watchdog: marker became unreadable before the sweep ({e}) - "
             "aborting, leaving the system untouched", log)
        return False
    if current_pid != int(pid):
        _log(f"watchdog: marker now belongs to session {current_pid} - a "
             "newer session started during the grace period, leaving it "
             "alone", log)
        return False

    # Unclean exit confirmed. The helper dies FIRST: with its tun2socks
    # child gone it must not auto-restart one (or re-assert routes) while
    # the sweep is tearing the adapter down. `helper_started` is the
    # identity proof from the marker - without it a recycled PID would get
    # an unrelated process tree force-killed.
    if helper_pid:
        kill_pid(helper_pid, log,
                 recorded_start=_helper_start(marker_path, helper_pid))

    findings = scan(hosts=list(hosts or []), probes=probes,
                    marker_path=marker_path, marker_live=marker_live)
    actions, recovery_ok = recover_ex(findings, probes=probes,
                                      log=lambda m: _log(m, log))
    if not actions:
        _log("watchdog: sweep found nothing left to clean", log)

    # Geo bypass routes sit on the PHYSICAL adapter - invisible to the
    # Wintun teardown. Sweep them by CIDR match if a geoip file is known.
    # All three of these return None on failure - a half-failed sweep must
    # NOT retire the crash marker, or the log lies ("clean") while routes
    # stay and the next launch skips its startup recovery. `recovery_ok`
    # is the same veto from the OTHER half of the sweep: a refused adapter
    # teardown or an unremovable DNS guard used to be reported as "the next
    # launch retries" and then immediately followed by a cleared marker, so
    # the next launch never retried anything.
    sweeps_ok = bool(recovery_ok)
    n_geo = sweep_geo_routes(geoip, geoip_code, log=log)
    if n_geo is None:
        sweeps_ok = False
    elif n_geo:
        _log(f"watchdog: removed {n_geo} leftover geoip route(s)", log)

    # LAN bypass routes (helper installs them every run, physical adapter).
    n_lan = sweep_lan_routes(log=log)
    if n_lan is None:
        sweeps_ok = False
    elif n_lan:
        _log(f"watchdog: removed {n_lan} leftover LAN bypass route(s)", log)

    # Clear the marker ONLY if it is still ours AND the sweeps ran clean - a session started while
    # we swept has written its own by now and owns the system.
    try:
        marker = read_marker(marker_path)
        if marker and int(marker.get("pid", -1) or -1) == int(pid):
            if sweeps_ok:
                clear_marker(marker_path)
                _log("watchdog: crash marker cleared - system is clean", log)
            else:
                _log("watchdog: sweep PARTIALLY FAILED - crash marker LEFT "
                     "in place so the next launch re-runs the recovery", log)
    except Exception as e:
        _log(f"watchdog: could not clear the crash marker: {e}", log)
    return True


def main(argv=None) -> int:
    """Detached entry point: wait for the dashboard, then sweep on an
    unclean exit. Every failure is contained - the watchdog must never be
    the thing that breaks the system it is guarding."""
    ap = argparse.ArgumentParser(
        description="TunTop cleanup watchdog (spawned by the dashboard).")
    ap.add_argument("--pid", type=int, required=True,
                    help="dashboard process to wait for")
    ap.add_argument("--hosts", default="",
                    help="comma-separated origin hosts for the route sweep")
    ap.add_argument("--geoip", default=None, metavar="PATH",
                    help="geoip .dat path - after an unclean exit, every live "
                         "route whose prefix matches --geoip-code's CIDRs is "
                         "swept too (they live on the PHYSICAL adapter, which "
                         "the Wintun teardown never touches)")
    ap.add_argument("--geoip-code", default="", metavar="CC",
                    help="country code inside --geoip to sweep (required with --geoip)")
    ap.add_argument("--helper-pid", type=int, default=None,
                    help="tunnel helper PID (from the session marker)")
    ap.add_argument("--marker", default=MARKER_FILE)
    ap.add_argument("--grace", type=float, default=DEFAULT_GRACE_SECONDS)
    args = ap.parse_args(argv)

    # Eager-import EVERYTHING the sweeps need BEFORE waiting. The sweeps
    # used to import tuntop.network.routing lazily (inside the sweep
    # functions) and the frozen exe paid for it: the routing import chain
    # (base64/json/tempfile -> base_library.zip) ran AFTER the parent died,
    # and if the child's _MEI extraction dir had been wiped in between the
    # whole sweep died with Errno 2 on base_library.zip (observed in the
    # field: geo+LAN sweeps no-op'd, marker still cleared -> looked like
    # "cleanup works" while routes stayed). Loading everything now means
    # the sweep only needs RAM, not the filesystem.
    try:
        import tuntop.network.routing as _routing  # noqa: F401
        import tuntop.network.dns as _dns  # noqa: F401  (socket/threading)
        # The DNS leak guard (1.0.40) imports routing lazily inside its
        # runner; preload the module itself so the post-death sweep cannot
        # die on a zipimport of base_library.zip.
        import tuntop.network.dns_guard as _dns_guard  # noqa: F401
        from tuntop.geoip import parse_geoip as _pg  # noqa: F401
        from tuntop.startup_recovery import scan as _scan  # noqa: F401
        from tuntop.startup_recovery import recover as _recover  # noqa: F401
        # Codec warm-up (belt & braces for the _MEI class): encoding to
        # 'utf-16-le' inside routing._ps is a LAZY codec import - it reads
        # base_library.zip from the extraction dir on FIRST use. Do it now,
        # while the dir is guaranteed alive, not during the sweep later.
        for _codec in ("utf-8", "utf-16-le", "utf-16-be", "utf-16",
                       "cp1252", "latin-1"):
            try:
                "".encode(_codec)
            except Exception:
                pass
    except Exception:
        _log(f"watchdog: eager import failed: {traceback.format_exc()}"
             .rstrip() + " - sweeps may fail; continuing so startup "
             "recovery can still clean up")

    try:
        # Wait for the dashboard to die - for as long as it lives.
        #
        # This used to be bounded at 15 minutes, and the log on the reporting
        # machine showed exactly what that costs:
        #     "watchdog: dashboard still alive after 15m - abandoning the
        #      sweep (refusing to tear down a running session)"
        # A watchdog whose only job is to survive its parent was giving up on
        # every session longer than a quarter of an hour - i.e. most of them.
        # After that the catch-all NRPT DNS pin, the wintun adapter and every
        # route stayed exactly as they were when the user closed the console
        # with Alt+F4, and DNS stayed hijacked machine-wide until the next
        # launch happened to run startup recovery. Refusing to tear down a
        # RUNNING session is right; giving up on a LONG one is not - a session
        # that is still up has not failed yet, and when it does die this
        # process is still here to clean up.
        #
        # It is a hidden, console-less process with a 1 s wait slice, so
        # waiting costs nothing. A heartbeat keeps the state visible in
        # .cleanup_watchdog.log rather than silent.
        _heartbeat = 0.0
        while True:
            if wait_for_exit(args.pid, timeout_s=60.0):
                break
            if time.time() - _heartbeat > 600.0:
                _heartbeat = time.time()
                _log(f"watchdog: dashboard pid {args.pid} still running - "
                     "still watching for its exit (nothing to sweep yet)", None)
        # Grace: a clean exit may still be tearing routes down right now
        # (atexit runs inside the parent, but the OS can report the exit a
        # moment before the last route delete lands).
        time.sleep(max(0.0, args.grace))
        marker = read_marker(args.marker) or {}
        helper_pid = args.helper_pid
        if not helper_pid:
            try:
                helper_pid = int(marker.get("helper_pid", 0) or 0) or None
            except Exception:
                helper_pid = None
        hosts = [h.strip() for h in (args.hosts or "").split(",") if h.strip()]
        # Merge the dashboard's live-session state: bypasses/geo chosen
        # AFTER this watchdog was spawned (dashboard [A]/[F]/geo dialogs)
        # are only present here - never in the startup args.
        state = read_live_state(_state_path(args.marker))
        hosts = list(dict.fromkeys(
            hosts + [h for h in (state.get("hosts") or []) if h]))
        geoip = state.get("geoip") or args.geoip
        geoip_code = state.get("geoip_code") or args.geoip_code or ""
        sweep_after_unclean_exit(args.pid, hosts=hosts,
                                 helper_pid=helper_pid,
                                 marker_path=args.marker,
                                 geoip=geoip,
                                 geoip_code=geoip_code)
    except Exception as e:
        _log(f"watchdog: unexpected failure: {e}")
        return 1
    # Consume the sidecar: it described THIS session's live state and the
    # session is over. Only delete when it still names the swept pid - a
    # session started while we swept has rewritten it and owns the file.
    # 1.0.33: a PARTIALLY FAILED sweep leaves the crash marker in place
    # (the next launch must re-run the recovery) - keep the sidecar too in
    # that case, since it describes the routes that still need sweeping.
    try:
        _sc_path = _state_path(args.marker)
        _marker_now = read_marker(args.marker)
        _marker_ours = (_marker_now
                        and int(_marker_now.get("pid", -1) or -1) == int(args.pid))
        if _marker_ours:
            _log("watchdog: sidecar kept with the marker - sweep incomplete")
        elif os.path.isfile(_sc_path):
            with open(_sc_path, "r", encoding="utf-8") as _f:
                _sc = json.load(_f)
            if int(_sc.get("pid", -1) or -1) == int(args.pid):
                os.unlink(_sc_path)
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())

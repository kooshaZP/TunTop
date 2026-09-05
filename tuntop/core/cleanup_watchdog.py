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
import os
import subprocess
import sys
import time

# When executed as a script (`python cleanup_watchdog.py --pid N`), the
# package root is NOT on sys.path (sys.path[0] is this file's directory).
# Fix that before importing anything from the tuntop package.
_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from tuntop.startup_recovery import (  # noqa: E402
    MARKER_FILE, clear_marker, read_marker, recover, scan,
)

# Windows access rights / wait codes (ctypes only; absent on other OSes).
_SYNCHRONIZE = 0x00100000
_PROCESS_TERMINATE = 0x0001
_INFINITE = 0xFFFFFFFF
_ERROR_INVALID_PARAMETER = 87

#: How long a dead parent's cleanup gets to finish before we look around.
DEFAULT_GRACE_SECONDS = 3.0

#: Watchdog diagnostics land next to the crash marker (best-effort).
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        ".cleanup_watchdog.log")


def _log(msg: str, log=None) -> None:
    """Report to the caller's sink AND append to the on-disk diary (the
    watchdog has no console - without the file, a sweep that ran or failed
    silently would be undiagnosable)."""
    if log is not None:
        try:
            log(msg)
        except Exception:
            pass
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
    except Exception:
        pass


def wait_for_exit(pid: int, timeout_s: float = None) -> bool:
    """Block until the process `pid` is gone. Returns True when it is gone
    (or was never there / the OS refuses to tell us - the sweep then runs
    against a system where nothing of the session should be left anyway).
    Best-effort by design: the watchdog must never hang forever on a
    missing handle."""
    if not sys.platform.startswith("win") or int(pid) <= 0:
        return True
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
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
                err = ctypes.GetLastError()
                if err == _ERROR_INVALID_PARAMETER:
                    return True            # no such process: already gone
                if err != 5:               # 5 = access denied: still alive
                    return True            # can't observe - assume gone
            if deadline is not None and time.time() >= deadline:
                return False
            time.sleep(0.5)
    except Exception:
        return True


def kill_pid(pid: int, log=None) -> bool:
    """Forcefully stop the helper process tree (helper + its tun2socks
    children). taskkill /T is tried first because it takes the whole tree
    in one shot; raw TerminateProcess is the fallback. Best-effort."""
    if not pid or int(pid) <= 0:
        return False
    if not sys.platform.startswith("win"):
        return False
    try:
        rc = subprocess.call(["taskkill", "/F", "/T", "/PID", str(int(pid))],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL)
        if rc == 0:
            _log(f"watchdog: helper tree (PID {pid}) terminated", log)
            return True
    except Exception:
        pass
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
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


def sweep_after_unclean_exit(pid: int, hosts=(), helper_pid=None,
                             marker_path: str = MARKER_FILE, log=None,
                             probes=None) -> bool:
    """The watchdog's whole decision, in one testable function.

    Returns True when an unclean exit of session `pid` was detected and
    the recovery sweep ran. Every other case (no marker, marker owned by
    a newer session) returns False and touches nothing.

    `probes` is passed straight through to startup_recovery's scan/recover
    so tests can run the whole path with fakes and no Windows.
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

    # Unclean exit confirmed. The helper dies FIRST: with its tun2socks
    # child gone it must not auto-restart one (or re-assert routes) while
    # the sweep is tearing the adapter down.
    if helper_pid:
        kill_pid(helper_pid, log)

    findings = scan(hosts=list(hosts or []), probes=probes,
                    marker_path=marker_path)
    actions = recover(findings, probes=probes, log=log)
    for a in actions:
        _log(f"watchdog: {a}", log)
    if not actions:
        _log("watchdog: sweep found nothing left to clean", log)

    # Clear the marker ONLY if it is still ours - a session started while
    # we swept has written its own by now and owns the system.
    try:
        marker = read_marker(marker_path)
        if marker and int(marker.get("pid", -1) or -1) == int(pid):
            clear_marker(marker_path)
            _log("watchdog: crash marker cleared - system is clean", log)
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
    ap.add_argument("--helper-pid", type=int, default=None,
                    help="tunnel helper PID (from the session marker)")
    ap.add_argument("--marker", default=MARKER_FILE)
    ap.add_argument("--grace", type=float, default=DEFAULT_GRACE_SECONDS)
    args = ap.parse_args(argv)

    try:
        wait_for_exit(args.pid)
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
        sweep_after_unclean_exit(args.pid, hosts=hosts,
                                 helper_pid=helper_pid,
                                 marker_path=args.marker,
                                 log=lambda m: None)
    except Exception as e:
        _log(f"watchdog: unexpected failure: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

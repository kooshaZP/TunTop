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
import base64            # routing._ps dependency - eager, see _MEI note
import json
import os
import socket            # tuntop.network.dns chain - eager, see _MEI note
import subprocess
import sys
import tempfile          # sweep batch files - eager, see _MEI note
import threading         # tuntop.network.dns chain - eager, see _MEI note
import time
import traceback         # sweep failure diagnosis (full stack in the log)

# When executed as a script (`python cleanup_watchdog.py --pid N`), the
# package root is NOT on sys.path (sys.path[0] is this file's directory).
# Fix that before importing anything from the tuntop package.
_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))   # file is tuntop/core/x.py -> repo root
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


#: LAN bypass prefixes TunTop's helper installs EVERY run
#: (mirror of tuntop/tunnel/helper.py:_add_lan_bypass - keep in sync).
#: Swept after an unclean exit only when the live route's next-hop matches
#: the CURRENT default gateway (or is on-link) on that same interface, so
#: a foreign static route to one of these ranges (corporate VPN split
#: routes, admin-configured) via a different gateway is never touched.
LAN_BYPASS_PREFIXES = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "224.0.0.0/4",
    "255.255.255.255/32",
]


def sweep_lan_routes(log=None) -> int:
    """Remove leftover LAN bypass routes from the PHYSICAL adapter. They are
    benign on the network where they were installed (they point at the same
    gateway Windows uses anyway) but stale after a network change, so a
    crash followed by switching Wi-Fi would otherwise keep routing RFC1918
    traffic at the old gateway. Returns how many were removed."""
    log = log or (lambda m: None)
    try:
        import tuntop.network.routing as routing
        def_gw = routing._get_ipv4_default()
        if not def_gw:
            return 0
        iface, gw = def_gw[0], def_gw[1]
        ok, out = routing._ps(
            "Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
            "Select-Object DestinationPrefix,InterfaceAlias,NextHop | "
            "ConvertTo-Json -Compress -Depth 2")
        rows = []
        if ok and out.strip():
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            rows = data
        victims = []
        for r in rows:
            dp = str(r.get("DestinationPrefix", ""))
            if dp not in LAN_BYPASS_PREFIXES:
                continue
            alias = str(r.get("InterfaceAlias", "") or "")
            nh = str(r.get("NextHop", "") or "")
            # Gateway/iface match keeps foreign static routes alive.
            if alias != str(iface):
                continue
            if nh and nh not in (str(gw), "0.0.0.0", "On-link"):
                continue
            victims.append((dp, alias, nh))
        if not victims:
            return 0
        lines = [f'interface ipv4 delete route {dp} "{alias}"'
                 f'{"" if nh in ("0.0.0.0", "On-link") else (" " + nh if nh else "")}'
                 for dp, alias, nh in victims]
        fd, tmp = tempfile.mkstemp(suffix=".txt", prefix="wd_lan_")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            subprocess.run(["netsh", "-f", tmp],
                           capture_output=True, timeout=120)
        finally:
            try:
                os.unlink(tmp)
            except Exception:
                pass
        return len(victims)
    except Exception as e:
        _log(f"watchdog: LAN sweep failed: {e}\n"
             f"{traceback.format_exc()}".rstrip(), log)
        return 0


def sweep_geo_routes(geoip: str, geoip_code: str, log=None) -> int:
    """Remove every live route whose DestinationPrefix is one of the geoip
    country's CIDRs. Geo bypass routes live on the PHYSICAL adapter, so the
    Wintun teardown above never sees them - after a hard kill they keep
    routing that country's traffic around the (now dead) tunnel, which both
    breaks connectivity for those prefixes and leaves the bypass intent
    armed for the next session. Batch netsh -f deletes, same fast path the
    dashboard's own sweep uses. Returns how many were removed."""
    log = log or (lambda m: None)
    try:
        if not geoip or not os.path.isfile(geoip):
            return 0
        from tuntop.geoip import parse_geoip          # repo root on sys.path
        import tuntop.network.routing as routing
        cidrs = set(parse_geoip(geoip, geoip_code))
        if not cidrs:
            return 0
        ok, out = routing._ps(
            "Get-NetRoute -AddressFamily IPv4,IPv6 -ErrorAction SilentlyContinue | "
            "Select-Object DestinationPrefix,InterfaceAlias,NextHop | "
            "ConvertTo-Json -Compress -Depth 2")
        rows = []
        if ok and out.strip():
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            rows = data
        victims = []
        for r in rows:
            dp = str(r.get("DestinationPrefix", ""))
            if dp not in cidrs:
                continue
            alias = str(r.get("InterfaceAlias", "") or "").replace("'", "")
            nh = str(r.get("NextHop", "") or "")
            victims.append((dp, alias, nh))
        if not victims:
            return 0
        # Batch netsh -f deletes: hundreds of lines per process, disjoint
        # prefixes cannot collide.
        chunks = [victims[i:i + 256] for i in range(0, len(victims), 256)]
        removed = 0
        for chunk in chunks:
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
                    subprocess.run(["netsh", "-f", tmp],
                                   capture_output=True, timeout=180)
                finally:
                    try:
                        os.unlink(tmp)
                    except Exception:
                        pass
                removed += len(chunk)
            except Exception:
                pass
        return removed
    except Exception as e:
        _log(f"watchdog: geo sweep failed: {e}\n"
             f"{traceback.format_exc()}".rstrip(), log)
        return 0


def sweep_after_unclean_exit(pid: int, hosts=(), helper_pid=None,
                             marker_path: str = MARKER_FILE, log=None,
                             probes=None, geoip: str = None,
                             geoip_code: str = "") -> bool:
    """The watchdog's whole decision, in one testable function.

    Returns True when an unclean exit of session `pid` was detected and
    the recovery sweep ran. Every other case (no marker, marker owned by
    a newer session) returns False and touches nothing.

    `probes` is passed straight through to startup_recovery's scan/recover
    so tests can run the whole path with fakes and no Windows. When
    `geoip`/`geoip_code` are given, geo-bypass routes on the PHYSICAL
    adapter are swept too (the Wintun teardown can't see them).
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
    actions = recover(findings, probes=probes,
                      log=lambda m: _log(m, log))
    if not actions:
        _log("watchdog: sweep found nothing left to clean", log)

    # Geo bypass routes sit on the PHYSICAL adapter - invisible to the
    # Wintun teardown. Sweep them by CIDR match if a geoip file is known.
    n_geo = sweep_geo_routes(geoip, geoip_code, log=log)
    if n_geo:
        _log(f"watchdog: removed {n_geo} leftover geoip route(s)", log)

    # LAN bypass routes (helper installs them every run, physical adapter).
    n_lan = sweep_lan_routes(log=log)
    if n_lan:
        _log(f"watchdog: removed {n_lan} leftover LAN bypass route(s)", log)

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
        from tuntop.geoip import parse_geoip as _pg  # noqa: F401
        from tuntop.startup_recovery import scan as _scan  # noqa: F401
        from tuntop.startup_recovery import recover as _recover  # noqa: F401
    except Exception as _e:
        _log(f"watchdog: eager import failed: {traceback.format_exc()}"
             .rstrip() + " - sweeps may fail; continuing so startup "
             "recovery can still clean up")

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
        # Merge the dashboard's live-session state: bypasses/geo chosen
        # AFTER this watchdog was spawned (dashboard [A]/[F]/geo dialogs)
        # are only present here - never in the startup args.
        state = read_live_state(args.marker.replace(
            os.path.basename(args.marker),
            os.path.basename(STATE_FILE))) if os.path.isfile(
                os.path.join(os.path.dirname(args.marker),
                             os.path.basename(STATE_FILE))) else read_live_state()
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
    try:
        _sc_path = os.path.join(os.path.dirname(os.path.abspath(args.marker)),
                                os.path.basename(STATE_FILE))
        if os.path.isfile(_sc_path):
            with open(_sc_path, "r", encoding="utf-8") as _f:
                _sc = json.load(_f)
            if int(_sc.get("pid", -1) or -1) == int(args.pid):
                os.unlink(_sc_path)
    except Exception:
        pass

    # Also retire a state file that outlived its session WITHOUT a sweep
    # (clean exit / newer session): a stale sidecar would feed an old
    # session's geo config to a future sweep. startup_recovery's marker
    # protocol already decides whether a sweep runs - the sidecar must
    # never be the stale half of that decision.
    return 0


if __name__ == "__main__":
    sys.exit(main())

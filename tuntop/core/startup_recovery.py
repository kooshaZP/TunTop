"""Startup crash recovery - never launch a new tunnel on top of old state.

If TunTop is killed hard (Task Manager, power loss, a frozen helper), its
cleanup never runs: the Wintun adapter and its routes stay installed,
orphaned tun2socks processes keep running, and per-host bypass routes
linger. The next launch then starts on top of that mess - and the "next
launch fails or hangs" class of bugs is born.

This module makes startup self-repairing:

    launch -> was there an unclean exit?  (crash-marker file still there)
          -> is there stale tunnel state? (orphan tun2socks, Wintun
             routes/adapter, leftover host /32 - /128 routes)
          -> if yes: report it, clean it, THEN start the new tunnel

The crash marker is the lynchpin: it is written when the dashboard starts
and only deleted after a verified clean teardown. A hard kill leaves it
behind, so "marker present at startup" literally means "the previous run
never finished cleaning up".

Like the rest of the package: the Windows probes are injected (defaulting
to the same battle-tested helpers the dashboard uses), so the detection
and decision logic is fully unit-testable on any OS
(see tests/test_startup_recovery.py). Pure stdlib, zero pip dependencies.
"""
from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from tuntop.network import routing
from tuntop.network.dns import _resolve_cached

#: Crash marker lives next to the package (survives reinstalls of the
#: CWD; deleted only after a verified clean teardown).
MARKER_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           ".last_run.json")
if getattr(sys, "frozen", False):
    # Frozen exe: __file__ sits in a THROWAWAY per-run extraction dir
    # (PyInstaller onefile), so a marker written there can never be found by
    # the next run - nor by the watchdog child, which gets its own extraction
    # dir. Park the marker next to TunTop.exe instead: stable across runs and
    # identical for every process launched from the same exe.
    MARKER_FILE = os.path.join(
        os.path.dirname(os.path.abspath(sys.executable)), ".last_run.json")


# ── Crash marker ────────────────────────────────────────────────────────

def _atomic_write_json(path: str, payload: dict) -> None:
    """Write JSON so a concurrent reader NEVER observes a partial file.

    open(path, "w") truncates to zero before the first write lands, and
    record_helper is a read-modify-write on the same file. The watchdog polls
    this file on its own schedule, so a plain truncate-then-dump let it read
    "" or a half-written object, get a decode error, and conclude "the
    previous run exited cleanly" - skipping the entire recovery sweep while
    routes stayed installed. Same class of bug for the helper PID update.
    """
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)        # atomic on Windows, same volume
    finally:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except Exception:
            pass


def write_marker(pid: int, path: str = MARKER_FILE) -> None:
    """Mark 'a tunnel is running' (best-effort; never blocks the launch)."""
    try:
        _atomic_write_json(path, {"pid": int(pid), "started": time.time()})
    except Exception:
        pass


def clear_marker(path: str = MARKER_FILE) -> None:
    """Mark 'clean exit' - called only after verified teardown."""
    try:
        if os.path.exists(path):
            os.unlink(path)
    except Exception:
        pass


def record_helper(helper_pid: int, path: str = MARKER_FILE) -> None:
    """Attach the tunnel helper's PID to the session marker (best-effort).

    The cleanup watchdog reads this after an unclean dashboard exit so it
    can stop the helper - and through `taskkill /T` its whole process tree,
    tun2socks included - BEFORE sweeping the routes. Without this, a still
    running helper could restart tun2socks or re-assert routes while the
    watchdog is mid-sweep."""
    try:
        data = read_marker(path) or {}
        if int(data.get("pid", 0) or 0) <= 0:
            return                      # no live session marker: nothing to do
        data["helper_pid"] = int(helper_pid)
        _atomic_write_json(path, data)
    except Exception:
        pass


def read_marker(path: str = MARKER_FILE) -> Optional[dict]:
    """The previous run's marker, if it never got to clean up. None means
    either a clean exit or a first run."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def marker_is_live(path: str = MARKER_FILE) -> Optional[bool]:
    """Is the session that wrote this marker STILL RUNNING?

    True  - the recorded dashboard PID is alive, so its tunnel is live and
            must not be torn down
    False - the PID is gone (a genuine unclean exit)
    None  - cannot tell (no marker, no PID, or the probe failed)

    This is what stops one launch from destroying another launch's working
    tunnel: there is no single-instance guard, so a user double-clicking the
    exe twice used to have the second instance kill the first instance's
    tun2socks, remove its Wintun adapter and sweep its routes on the way
    past. Callers must treat None as LIVE (do not touch) - the cost of
    skipping a needed cleanup is far lower than killing a running tunnel.
    """
    marker = read_marker(path)
    if not marker:
        return None
    try:
        pid = int(marker.get("pid", -1) or -1)
    except (TypeError, ValueError):
        return None
    if pid <= 0:
        return None
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL,
                                        wintypes.DWORD]
            k32.OpenProcess.restype = wintypes.HANDLE
            h = k32.OpenProcess(0x100000, False, pid)   # SYNCHRONIZE
            if not h:
                err = ctypes.get_last_error()
                if err == 5:
                    return True         # access denied: it exists, not ours
                return None              # cannot tell
            try:
                return k32.WaitForSingleObject(h, 0) == 0x102   # WAIT_TIMEOUT
            finally:
                k32.CloseHandle(h)
        except Exception:
            return None
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except Exception:
        return None
    return True


# ── Probes (Windows defaults, injectable for tests) ─────────────────────

@dataclass
class Probes:
    """Everything system-specific, in six callables.

    tun2socks_count()           -> number of running tun2socks processes
    wintun_route_count()        -> routes installed on the wintun adapter
    host_routes(hosts)          -> stale per-host routes as (family, dest)
    kill_tun2socks()            -> kill orphans, return how many
    teardown_adapter()          -> remove wintun adapter + its routes
    sweep_host_routes(routes)   -> remove the given routes, return count
    """

    tun2socks_count: Callable[[], int]
    wintun_route_count: Callable[[], int]
    host_routes: Callable[[list], list]
    kill_tun2socks: Callable[[], int]
    teardown_adapter: Callable[[], bool]
    sweep_host_routes: Callable[[list], int]
    #: DNS leak guard (tuntop/network/dns_guard.py). Optional - a caller that
    #: does not provide them simply never reports a leftover guard. They are
    #: kept optional (rather than required) so existing probe fakes/tests keep
    #: working unchanged. `dns_guard_present` must return exactly True to be
    #: acted on: a leftover NRPT rule rewrites name resolution system-wide,
    #: and guessing "probably installed" is not a good enough reason to touch
    #: the registry.
    dns_guard_present: Optional[Callable[[], bool]] = None
    remove_dns_guard: Optional[Callable[[], bool]] = None


def _wintun_route_count() -> int:
    """Routes currently installed on the tunnel adapters (0 = clean). Counts
    BOTH the primary 'wintun' and the optional second pipe's 'wintun2' (left
    behind when a crash hit while --proxy2-port was active)."""
    total = 0
    for adapter in ("wintun", "wintun2"):
        ok, out = routing._ps(
            f"Get-NetRoute -InterfaceAlias '{adapter}' -ErrorAction SilentlyContinue | "
            "Measure-Object | Select-Object -ExpandProperty Count")
        if ok:
            try:
                total += int(out.strip())
            except Exception:
                pass
    return total


def _tun2socks_owned_count(tun2socks_path=None) -> int:
    """TunTop-owned tun2socks processes currently running (0 on any probe
    failure). Ownership-scoped: a generic tun2socks.exe another tool runs is
    NEVER counted (tuntop.network.procguard decides by identity, not name)."""
    try:
        from tuntop.network.procguard import count_own
        return count_own(tun2socks_path)
    except Exception:
        return 0



def default_probes() -> Probes:
    """The real Windows probes (PowerShell/netsh via tuntop.routing)."""

    def host_routes(hosts):
        found = []
        for h in hosts or []:
            v4, v6 = _resolve_cached(h)
            if not v4 and not v6:
                # Fresh process (the watchdog) has an empty DNS cache and
                # _resolve_cached does zero I/O by design - do a real
                # resolve here, best effort, so hostname bypass entries are
                # still matched against the live table. An IP literal or a
                # dead host just yields [] and is skipped.
                try:
                    from tuntop.network.dns import _resolve_detail
                    v4, v6, _err, _src = _resolve_detail(
                        h, use_cache=False, fallback=False)
                except Exception:
                    v4, v6 = [], []
            for ip in v4:
                dest = f"{ip}/32"
                if routing._route_exists_v4(dest):
                    found.append(("v4", dest))
            for ip in v6:
                dest = f"{ip}/128"
                if routing._route_exists_v6(dest):
                    found.append(("v6", dest))
        return found

    def kill_tun2socks():
        # Ownership-scoped (tuntop.network.procguard): only processes that
        # are provably TunTop's - recorded PIDs, the exact configured
        # binary, or the distinctive vendored file name. A generic
        # tun2socks.exe run by another tool is never touched.
        from tuntop.network.procguard import kill_own
        return kill_own()

    def teardown_adapter():
        routing._teardown_wintun()          # routes + owned tun2socks, best-effort
        return True

    def sweep_host_routes(routes):
        n = 0
        for fam, dest in routes or []:
            if fam == "v4":
                iface_gw = routing._get_ipv4_default()
            else:
                iface_gw = routing._get_ipv6_default()
            iface = iface_gw[0] if iface_gw else None
            if iface is None:
                continue
            if fam == "v4":
                ok, _foreign = routing._del_route_v4(dest, iface, iface_gw[1])
            else:
                ok, _foreign = routing._del_route_v6(dest, iface, iface_gw[1])
            if ok:
                n += 1
        return n

    def dns_guard_present():
        """True when a TunTop DNS-guard NRPT rule (or its install record)
        survived a previous run. Never raises: an unreadable registry is
        reported as "nothing found" so recovery never guesses."""
        try:
            from tuntop.network import dns_guard
        except Exception:
            return False
        try:
            if dns_guard.load_state() is not None:
                return True
        except Exception:
            pass
        try:
            ok, state = dns_guard.detect()
            return bool(ok and state.get("keys"))
        except Exception:
            return False

    def remove_dns_guard():
        """Delete every TunTop-* NRPT rule + the install record.

        force=True: this is the RECOVERY owner. It runs at launch, when no
        live instance should still be relying on the rule - a leftover from a
        crash is exactly what it exists to clear, and the ownership guard
        would otherwise keep a dead instance's pin alive on the machine."""
        try:
            from tuntop.network import dns_guard
        except Exception:
            return False
        try:
            ok, _msg = dns_guard.ensure_removed(force=True)
            return bool(ok)
        except Exception:
            return False

    return Probes(
        tun2socks_count=_tun2socks_owned_count,
        wintun_route_count=_wintun_route_count,
        host_routes=host_routes,
        kill_tun2socks=kill_tun2socks,
        teardown_adapter=teardown_adapter,
        sweep_host_routes=sweep_host_routes,
        dns_guard_present=dns_guard_present,
        remove_dns_guard=remove_dns_guard,
    )


# ── Detection & recovery ────────────────────────────────────────────────

@dataclass
class StartupFindings:
    """What the last run left behind. Everything here is stale by
    definition: the scan runs BEFORE any tunnel of this session exists."""

    marker: Optional[dict] = None       # unclean-exit marker (None = clean)
    orphan_tun2socks: int = 0           # running tun2socks processes
    wintun_routes: int = 0              # routes on the wintun adapter
    host_routes: list = field(default_factory=list)  # [("v4", "1.2.3.4/32")]
    #: A TunTop DNS-guard NRPT rule is still installed (the previous run
    #: never removed it): system-wide name resolution is still pinned to a
    #: tunnel that no longer exists - remove it before anything else.
    dns_guard: bool = False
    #: The marker's dashboard PID is STILL ALIVE: a second TunTop window is
    #: running with a working tunnel. Nothing that marker points at may be
    #: torn down - this launch must not kill another instance's session.
    live_session: Optional[int] = None

    @property
    def dirty(self) -> bool:
        if self.live_session:
            return False                # a live session owns this state
        return bool(self.marker or self.orphan_tun2socks
                    or self.wintun_routes or self.host_routes
                    or self.dns_guard)

    def summary_lines(self) -> list:
        """Human-readable 'what we found' lines for the startup log."""
        lines = []
        if self.live_session:
            lines.append(f"another TunTop session (PID {self.live_session}) "
                         "is still running - its tunnel was left untouched; "
                         "close that window before starting a second one")
            return lines
        if self.marker:
            pid = self.marker.get("pid")
            lines.append(f"previous run (PID {pid}) did not exit cleanly")
        if self.orphan_tun2socks:
            lines.append(f"{self.orphan_tun2socks} orphaned tun2socks "
                         "process(es) still running")
        if self.wintun_routes:
            lines.append(f"{self.wintun_routes} stale route(s) on the "
                         "Wintun adapter")
        if self.host_routes:
            lines.append(f"{len(self.host_routes)} stale per-host bypass "
                         "route(s)")
        if self.dns_guard:
            lines.append("a leftover DNS leak-guard rule (system name "
                         "resolution is still pinned to the dead tunnel)")
        return lines


def scan(hosts=None, probes: Optional[Probes] = None,
         marker_path: str = MARKER_FILE,
         marker_live: Optional[Callable[[str], Optional[bool]]] = None
         ) -> StartupFindings:
    """Look for leftovers of a previous run. Cheap PowerShell probes, run
    once at startup - never in a loop.

    A marker whose dashboard PID is STILL ALIVE belongs to a running session,
    not to a crashed one. There is no single-instance guard, so without this
    check a second launch found the first launch's marker and - believing it
    was a crash - killed that instance's tun2socks, removed its Wintun
    adapter and swept its routes, leaving the user's live tunnel dead.
    `marker_live` is injectable for tests; defaults to the real probe.
    """
    p = probes or default_probes()
    findings = StartupFindings(marker=read_marker(marker_path))
    if findings.marker:
        live = marker_live(marker_path) if marker_live else \
            globals()["marker_is_live"](marker_path)
        if live:
            findings.live_session = int(
                findings.marker.get("pid", -1) or -1)
            # Nothing this marker points at may be touched.
            findings.marker = None
            findings.orphan_tun2socks = 0
            findings.wintun_routes = 0
            findings.host_routes = []
            findings.dns_guard = False
            return findings
    # Never let one broken probe hide the others (each returns a safe
    # default on failure, but a hard raise here must not crash startup).
    try:
        findings.orphan_tun2socks = p.tun2socks_count() or 0
    except Exception:
        findings.orphan_tun2socks = 0
    try:
        findings.wintun_routes = p.wintun_route_count() or 0
    except Exception:
        findings.wintun_routes = 0
    # DNS leak-guard probe: a leftover NRPT rule keeps rewriting name
    # resolution for EVERY process, so it is reported even when the routing
    # state looks clean. Only an exact True counts (see Probes.dns_guard_present).
    _guard_probe = getattr(p, "dns_guard_present", None)
    if callable(_guard_probe):
        try:
            findings.dns_guard = _guard_probe() is True
        except Exception:
            findings.dns_guard = False
    if hosts:
        try:
            findings.host_routes = list(p.host_routes(hosts) or [])
        except Exception:
            findings.host_routes = []
    return findings


def recover(findings: StartupFindings,
            probes: Optional[Probes] = None,
            log: Optional[Callable[[str], None]] = None,
            progress: Optional[Callable[[int, int, str], None]] = None
            ) -> list:
    """Clean everything `scan` found. Order matters: kill the orphans
    FIRST (a live tun2socks would re-assert its routes), then tear down
    the adapter, then sweep lingering host routes. Returns the list of
    actions performed (each one also passed to `log`)."""
    p = probes or default_probes()
    log = log or (lambda msg: None)
    actions = []

    if findings.live_session:
        # A live session owns everything we would have swept. Say so and
        # touch nothing - this is the "launched TunTop twice" case.
        msg = (f"another TunTop session (PID {findings.live_session}) is "
               "still running - its tunnel, routes and DNS guard were left "
               "alone; close that window first if you meant to replace it")
        log(f"[*] Recovery: {msg}")
        return [msg]

    tasks = []
    if findings.dns_guard:
        # FIRST: a leftover NRPT rule pins every process's name resolution to
        # a tunnel that is being torn down - remove it before touching routes,
        # otherwise DNS keeps failing (or, worse, keeps being answered by the
        # wrong resolver) all through the sweep.
        tasks.append(("remove leftover DNS guard", _do_dns_guard))
    if findings.orphan_tun2socks:
        tasks.append(("kill orphaned tun2socks", _do_kill))
    if findings.wintun_routes or findings.marker or findings.orphan_tun2socks:
        tasks.append(("tear down stale Wintun adapter", _do_teardown))
    if findings.host_routes:
        tasks.append(("sweep stale per-host routes", _do_sweep))

    for i, (label, fn) in enumerate(tasks):
        if progress is not None:
            try:
                progress(i, len(tasks), label)
            except Exception:
                pass
        try:
            detail = fn(p, findings)
        except (Exception, SystemExit) as e:
            # SystemExit matters: the platform probes legitimately call
            # sys.exit() on failure, and a BaseException here would abort
            # every remaining cleanup step AND the caller's startup.
            log(f"[!] Recovery step '{label}' failed: {e}")
            detail = f"failed: {e}"
        msg = f"{label}" + (f" - {detail}" if detail else "")
        actions.append(msg)
        log(f"[*] Recovery: {msg}")
    return actions


def _do_kill(p: Probes, f: StartupFindings) -> str:
    n = p.kill_tun2socks()
    return f"stopped {n} process(es)"


def _do_dns_guard(p: Probes, f: StartupFindings) -> str:
    """Remove a leftover catch-all NRPT rule. A missing probe (a caller that
    did not supply one) is reported instead of silently passing."""
    fn = getattr(p, "remove_dns_guard", None)
    if not callable(fn):
        return "no DNS-guard probe available"
    removed = fn()
    if removed is True:
        return "NRPT rule removed (name resolution is unpinned again)"
    return "removal reported failure - the next launch retries"


def _do_teardown(p: Probes, f: StartupFindings) -> str:
    # Report what the probe actually said. Discarding its verdict made a
    # teardown that returned False log "routes and adapter cleared" - the
    # log claimed a clean slate while the adapter and its routes stayed.
    ok = p.teardown_adapter()
    if ok is False:
        return "removal reported a failure - the next launch retries"
    return "routes and adapter cleared"


def _do_sweep(p: Probes, f: StartupFindings) -> str:
    n = p.sweep_host_routes(f.host_routes)
    return f"removed {n} route(s)"


def startup_recover(hosts=None, log=None, marker_path: str = MARKER_FILE,
                    probes: Optional[Probes] = None,
                    marker_live: Optional[Callable[[str], Optional[bool]]] = None
                    ) -> list:
    """One-call convenience for the dashboard: scan + recover + write the
    fresh marker. Returns the recovery actions (empty list on a clean
    system).

    `marker_live` is forwarded to `scan` (see the note there): a caller can
    state the previous session's liveness instead of inheriting the verdict
    from the host's process table, which is what makes "a crashed run is
    recovered" testable on a machine whose PID table is unknown.
    """
    p = probes
    findings = scan(hosts=hosts, probes=p, marker_path=marker_path,
                    marker_live=marker_live)
    if findings.live_session:
        # Deliberately do NOT write our own marker: that would steal
        # ownership from the session that is still running, so its watchdog
        # would no longer recognise the marker as its own.
        for _line in findings.summary_lines():
            log(_line) if log else None
        return [f"skipped recovery - a live session (PID "
                f"{findings.live_session}) owns this system"]
    if not findings.dirty:
        write_marker(os.getpid(), marker_path)
        return []
    actions = recover(findings, probes=p, log=log)
    write_marker(os.getpid(), marker_path)
    return actions


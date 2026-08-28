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
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from tunmood import routing
from tunmood.netdns import _resolve_cached

#: Crash marker lives next to the package (survives reinstalls of the
#: CWD; deleted only after a verified clean teardown).
MARKER_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           ".last_run.json")


# ── Crash marker ────────────────────────────────────────────────────────

def write_marker(pid: int, path: str = MARKER_FILE) -> None:
    """Mark 'a tunnel is running' (best-effort; never blocks the launch)."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"pid": int(pid), "started": time.time()}, f)
    except Exception:
        pass


def clear_marker(path: str = MARKER_FILE) -> None:
    """Mark 'clean exit' - called only after verified teardown."""
    try:
        if os.path.exists(path):
            os.unlink(path)
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


def _count_processes_like(name: str) -> int:
    ok, out = routing._ps(
        f"Get-Process -ErrorAction SilentlyContinue | "
        f"Where-Object {{$_.ProcessName -like '{name}*'}} | "
        f"Measure-Object | Select-Object -ExpandProperty Count")
    if ok:
        try:
            return int(out.strip())
        except Exception:
            return 0
    return 0


def _wintun_route_count() -> int:
    """Routes currently installed on the wintun adapter (0 = clean)."""
    ok, out = routing._ps(
        "Get-NetRoute -InterfaceAlias 'wintun' -ErrorAction SilentlyContinue | "
        "Measure-Object | Select-Object -ExpandProperty Count")
    if ok:
        try:
            return int(out.strip())
        except Exception:
            return 0
    return 0


def default_probes() -> Probes:
    """The real Windows probes (PowerShell/netsh via tunmood.routing)."""

    def host_routes(hosts):
        found = []
        for h in hosts or []:
            v4, v6 = _resolve_cached(h)
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
        before = _count_processes_like("tun2socks")
        if before:
            routing._ps(
                "Get-Process -ErrorAction SilentlyContinue | "
                "Where-Object {$_.ProcessName -like 'tun2socks*'} | "
                "ForEach-Object { Stop-Process -Force -Id $_.Id "
                "-ErrorAction SilentlyContinue }")
        return before

    def teardown_adapter():
        routing._teardown_wintun()          # routes + tun2socks, best-effort
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
                ok = routing._del_route_v4(dest, iface, iface_gw[1])
            else:
                ok = routing._del_route_v6(dest, iface, iface_gw[1])
            if ok:
                n += 1
        return n

    return Probes(
        tun2socks_count=lambda: _count_processes_like("tun2socks"),
        wintun_route_count=_wintun_route_count,
        host_routes=host_routes,
        kill_tun2socks=kill_tun2socks,
        teardown_adapter=teardown_adapter,
        sweep_host_routes=sweep_host_routes,
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

    @property
    def dirty(self) -> bool:
        return bool(self.marker or self.orphan_tun2socks
                    or self.wintun_routes or self.host_routes)

    def summary_lines(self) -> list:
        """Human-readable 'what we found' lines for the startup log."""
        lines = []
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
        return lines


def scan(hosts=None, probes: Optional[Probes] = None,
         marker_path: str = MARKER_FILE) -> StartupFindings:
    """Look for leftovers of a previous run. Cheap PowerShell probes, run
    once at startup - never in a loop."""
    p = probes or default_probes()
    findings = StartupFindings(marker=read_marker(marker_path))
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

    tasks = []
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
        except Exception as e:
            log(f"[!] Recovery step '{label}' failed: {e}")
            detail = f"failed: {e}"
        msg = f"{label}" + (f" - {detail}" if detail else "")
        actions.append(msg)
        log(f"[*] Recovery: {msg}")
    return actions


def _do_kill(p: Probes, f: StartupFindings) -> str:
    n = p.kill_tun2socks()
    return f"stopped {n} process(es)"


def _do_teardown(p: Probes, f: StartupFindings) -> str:
    p.teardown_adapter()
    return "routes and adapter cleared"


def _do_sweep(p: Probes, f: StartupFindings) -> str:
    n = p.sweep_host_routes(f.host_routes)
    return f"removed {n} route(s)"


def startup_recover(hosts=None, log=None, marker_path: str = MARKER_FILE,
                    probes: Optional[Probes] = None) -> list:
    """One-call convenience for the dashboard: scan + recover + write the
    fresh marker. Returns the recovery actions (empty list on a clean
    system)."""
    p = probes
    findings = scan(hosts=hosts, probes=p, marker_path=marker_path)
    if not findings.dirty:
        write_marker(os.getpid(), marker_path)
        return []
    actions = recover(findings, probes=p, log=log)
    write_marker(os.getpid(), marker_path)
    return actions


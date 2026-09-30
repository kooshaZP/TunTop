"""Regression tests for the ownership / lifetime / cleanup fixes.

Each test here pins a specific defect: the OLD behaviour is what made the
bug reachable, so asserting the new behaviour is what stops it coming back.
The defects are grouped by the promise they broke:

  * a foreign binary is never killed  (procguard rule 3, and the helper's
    preflight, which had its own duplicate ownership filter that matched the
    vendored name ANYWHERE on disk)
  * a released identity is not a live one  (dns_guard's install record, the
    crash marker's PIDs - a bare PID is a recycled slot)
  * "unknown" never means "still there"  (the DNS guard's liveness probe,
    startup recovery's marker probe, a failed route-table read)
  * one owner per teardown  (the dashboard publishing STOPPED while its own
    sweep was still running, and a start slipping in behind that sweep)

Run:  python -m pytest tests/unit/test_lifetime_and_ownership_fixes.py -v
"""
import os
import unittest
from unittest import mock

from tuntop import procidentity
from tuntop.config import updates
from tuntop.core import cleanup_watchdog, startup_recovery
from tuntop.network import dns_guard, procguard, routing


# ── The updater must not accept a downgrade to plaintext ────────────────────

class TestRedirectSchemeIsEnforced(unittest.TestCase):
    """A 30x to an ALLOWED host over http was accepted.

    The handler checked the host but not the scheme, while its own docstring
    said it refused "ANY host and ANY scheme". checksums.txt arrives from the
    same release, so the SHA-256 only proves the bytes were not corrupted in
    transit - an attacker who can answer for the release answers for both
    files and the checksum agrees. That is what makes the scheme half of the
    allow-list load-bearing rather than cosmetic.
    """

    def _redirect(self, newurl):
        h = updates._SameHostRedirectHandler()
        req = updates.urllib.request.Request("https://github.com/a/b")
        return h.redirect_request(req, None, 302, "Found", {}, newurl)

    def test_https_to_an_allowed_host_is_followed(self):
        # The GitHub asset CDN leg is legitimate and must keep working.
        out = self._redirect("https://release-assets.githubusercontent.com/x")
        self.assertIsNotNone(out)

    def test_http_downgrade_on_an_allowed_host_is_refused(self):
        with self.assertRaises(updates.urllib.error.HTTPError) as cm:
            self._redirect("http://github.com/kooshaZP/TunTop/releases/x.exe")
        self.assertIn("https", str(cm.exception).lower())

    def test_https_to_an_unknown_host_is_refused(self):
        with self.assertRaises(updates.urllib.error.HTTPError):
            self._redirect("https://github.com.evil.test/x.exe")

    def test_non_http_scheme_is_refused(self):
        for url in ("ftp://github.com/x", "file:///C:/x.exe"):
            with self.subTest(url=url):
                with self.assertRaises(updates.urllib.error.HTTPError):
                    self._redirect(url)


# ── procguard: an unreadable path is not proof of ownership ─────────────────

class TestPathlessProcessIsNotOurs(unittest.TestCase):
    """CIM returns an empty ExecutablePath exactly when it cannot open the
    process - another user, or elevated. The old rule-3 clause
    `or not exe_norm` therefore selected precisely the processes whose
    identity could not be established, and `taskkill /F /T` on every
    teardown took out a foreign upstream proxy."""

    def _row(self, pid=13, name=procguard.TUN2SOCKS_BINARY, exe=""):
        return {"pid": pid, "name": name, "exe": exe, "cmd": ""}

    def test_pathless_vendored_name_is_not_selected(self):
        self.assertEqual(procguard.select_own([self._row()]), [])

    def test_pathless_is_still_ours_when_the_pid_was_recorded(self):
        rows = [self._row()]
        self.assertEqual([r["pid"] for r in
                          procguard.select_own(rows, recorded=[13])], [13])


# ── The helper must not reimplement ownership ──────────────────────────────

class TestPreflightDelegatesOwnership(unittest.TestCase):
    """`preflight_cleanup` used to run its OWN PowerShell filter, matching
    `-like '*tun2socks-windows-amd64-v3.exe'` - the vendored name, anywhere
    on disk, with no location half. The vendored name is also the upstream
    xjasonlyu release asset name, so a user's own upstream install (or
    v2rayN's vendored copy) in ANY directory was force-killed at every
    helper start, while the docstring promised it never would be."""

    def test_preflight_uses_procguard_and_not_an_inline_name_match(self):
        """Behavioural, not textual: no PowerShell script it runs may filter
        on the vendored name, and the kill must go through procguard."""
        from tuntop.tunnel import helper
        with mock.patch.object(helper, "run_ps") as run_ps, \
             mock.patch.object(helper, "remove_stale_wintun_devices"), \
             mock.patch.object(helper.time, "sleep"), \
             mock.patch("tuntop.network.procguard.kill_own",
                        return_value=0) as kill_own:
            helper.preflight_cleanup(tun2socks_path=r"C:\TunTop\t2s.exe")
        kill_own.assert_called_once()
        self.assertEqual(
            kill_own.call_args.kwargs.get("tun2socks_path"),
            r"C:\TunTop\t2s.exe")
        for call in run_ps.call_args_list:
            self.assertNotIn("tun2socks-windows-amd64-v3.exe", call.args[0],
                             "preflight must not filter on the vendored name")


# ── dns_guard: a released PID is not a live owner ──────────────────────────

class TestOwnerIdentity(unittest.TestCase):
    def test_record_carries_a_creation_time(self):
        rec = {}
        path = os.path.join(self._tmp(), "state.json")
        self.assertTrue(dns_guard.save_state(["8.8.8.8"], path=path))
        # Nothing to read here on a non-Windows box, so assert the KEY is
        # present (present-but-null is legitimate: "could not be determined").
        with open(path, encoding="utf-8") as f:
            import json
            rec = json.load(f)
        self.assertIn("owner_started", rec)
        self.assertIn("owner_pid", rec)

    def _tmp(self):
        import tempfile
        return tempfile.mkdtemp()

    def test_a_reused_pid_is_not_a_live_owner(self):
        """A record whose creation time disagrees with the live process is a
        DIFFERENT process that inherited the number, so the leftover rule
        must be clearable rather than protected forever."""
        rec = {"owner_pid": os.getppid(), "owner_started": 1}
        with mock.patch.object(procidentity, "same_process",
                               return_value=False):
            self.assertFalse(dns_guard.record_owner_alive(rec))

    def test_an_unreadable_creation_time_is_not_proof_of_ownership(self):
        rec = {"owner_pid": os.getppid(), "owner_started": 12345}
        with mock.patch.object(procidentity, "process_start_time",
                               return_value=None):
            self.assertFalse(procguard.select_own([]) or
                             dns_guard.record_owner_alive(rec))

    def test_a_matching_creation_time_still_protects_a_live_owner(self):
        rec = {"owner_pid": os.getppid(), "owner_started": 1}
        with mock.patch.object(procidentity, "same_process",
                               return_value=True), \
             mock.patch.object(dns_guard, "_pid_alive", return_value=True):
            self.assertTrue(dns_guard.record_owner_alive(rec))

    def test_our_own_record_is_never_foreign(self):
        self.assertFalse(dns_guard.record_owner_alive(
            {"owner_pid": os.getpid(), "owner_started": 1}))

    def test_pid_liveness_fails_closed(self):
        """The docstring promises "unknown means dead"; the body returned
        True on an access-denied OpenProcess and on a failed
        GetExitCodeProcess - the one direction that strands a machine-wide
        DNS pin. Now asserted on the shared leaf."""
        self.assertFalse(procidentity.process_alive(0))
        self.assertFalse(procidentity.process_alive(-1))
        self.assertFalse(procidentity.process_alive("nonsense"))
        self.assertTrue(procidentity.process_alive(os.getpid()))

    def test_same_process_fails_closed(self):
        self.assertFalse(procidentity.same_process(os.getpid(), None))
        self.assertFalse(procidentity.same_process(os.getpid(), "bad"))
        with mock.patch.object(procidentity, "process_start_time",
                               return_value=None):
            self.assertFalse(procidentity.same_process(os.getpid(), 5))


# ── startup_recovery: UNKNOWN marker liveness must not sweep ───────────────

class TestUnknownMarkerLivenessIsTreatedAsLive(unittest.TestCase):
    """`scan` tested `if live:`, so None ("cannot tell") fell through to the
    full destructive sweep - exactly what `marker_is_live`'s docstring says
    callers must never do. A second launch then killed the first launch's
    tun2socks and ripped out its adapter."""

    def _probes(self):
        p = mock.MagicMock()
        p.tun2socks_count.return_value = 3
        p.wintun_route_count.return_value = 9
        p.host_routes.return_value = [("v4", "1.2.3.4/32")]
        p.dns_guard_present.return_value = True
        return p

    def _scan(self, live):
        import tempfile
        path = os.path.join(tempfile.mkdtemp(), ".last_run.json")
        startup_recovery.write_marker(4242, path)
        return startup_recovery.scan(hosts=["example.com"],
                                     probes=self._probes(),
                                     marker_path=path,
                                     marker_live=lambda _p: live)

    def test_none_does_not_sweep(self):
        f = self._scan(None)
        self.assertTrue(f.live_session)
        self.assertIsNone(f.marker)
        self.assertEqual(f.orphan_tun2socks, 0)
        self.assertEqual(f.wintun_routes, 0)
        self.assertEqual(f.host_routes, [])
        self.assertFalse(f.dns_guard)
        self.assertFalse(f.dirty)

    def test_true_does_not_sweep(self):
        self.assertTrue(self._scan(True).live_session)

    def test_false_sweeps(self):
        f = self._scan(False)
        self.assertFalse(f.live_session)
        self.assertTrue(f.marker)
        self.assertTrue(f.dirty)


# ── A crash marker must not authorise killing a recycled PID ───────────────

class TestWatchdogKillIdentity(unittest.TestCase):
    def test_a_mismatched_creation_time_refuses_the_kill(self):
        with mock.patch.object(procidentity, "same_process",
                               return_value=False), \
             mock.patch.object(cleanup_watchdog.subprocess, "run") as run:
            self.assertFalse(cleanup_watchdog.kill_pid(
                5555, recorded_start=999999))
        run.assert_not_called()

    def test_a_matching_creation_time_allows_the_kill(self):
        with mock.patch.object(procidentity, "same_process",
                               return_value=True), \
             mock.patch.object(cleanup_watchdog.subprocess, "run") as run:
            run.return_value = mock.Mock(returncode=0)
            self.assertTrue(cleanup_watchdog.kill_pid(
                5555, recorded_start=999999))
        run.assert_called_once()


# ── A failed route-table read is not a successful removal ──────────────────

class TestScopedDeleteFailsClosed(unittest.TestCase):
    """`_del_route_scoped` built its leftover list only from a SUCCESSFUL
    `Get-NetRoute`, so a timeout / access-denied left it empty and the
    function returned (removed=True, foreign=False) - the exact success
    verdict its docstring forbids without evidence."""

    def test_a_failed_probe_is_not_removed(self):
        with mock.patch.object(routing, "_ps", return_value=(False, "")):
            removed, foreign = routing._del_route_scoped(
                "1.2.3.4/32", "v4", ["wintun"])
        self.assertFalse(removed)
        self.assertFalse(foreign)

    def test_a_clean_table_is_removed(self):
        with mock.patch.object(routing, "_ps", return_value=(True, "none")):
            removed, foreign = routing._del_route_scoped(
                "1.2.3.4/32", "v4", ["wintun"])
        self.assertTrue(removed)
        self.assertFalse(foreign)

    def test_a_leftover_on_our_own_interface_is_ours_not_foreign(self):
        with mock.patch.object(routing, "_ps", return_value=(True, "wintun")):
            removed, foreign = routing._del_route_scoped(
                "1.2.3.4/32", "v4", ["wintun"])
        self.assertFalse(removed)
        self.assertFalse(foreign)


# ── recover() must be able to report failure to the watchdog ───────────────

class TestRecoveryReportsItsOwnFailures(unittest.TestCase):
    def _findings(self):
        return startup_recovery.StartupFindings(
            marker={"pid": 1}, orphan_tun2socks=1, wintun_routes=2,
            host_routes=[("v4", "1.2.3.4/32")], dns_guard=True)

    def _probes(self, dns_ok=True, adapter_ok=True):
        p = mock.MagicMock()
        p.kill_tun2socks.return_value = 1
        p.sweep_host_routes.return_value = 1
        p.teardown_adapter.return_value = adapter_ok
        p.remove_dns_guard.return_value = dns_ok
        return p

    def test_all_success_is_ok(self):
        _actions, ok = startup_recovery.recover_ex(
            self._findings(), probes=self._probes())
        self.assertTrue(ok)

    def test_a_refused_dns_removal_vetoes_success(self):
        # Its own detail text says "the next launch retries" - which the
        # watchdog used to follow with a cleared marker, so nothing retried.
        _actions, ok = startup_recovery.recover_ex(
            self._findings(), probes=self._probes(dns_ok=False))
        self.assertFalse(ok)

    def test_a_failed_adapter_teardown_vetoes_success(self):
        _actions, ok = startup_recovery.recover_ex(
            self._findings(), probes=self._probes(adapter_ok=False))
        self.assertFalse(ok)

    def test_a_raising_step_vetoes_success(self):
        p = self._probes()
        p.teardown_adapter.side_effect = RuntimeError("boom")
        _actions, ok = startup_recovery.recover_ex(self._findings(), probes=p)
        self.assertFalse(ok)

    def test_recover_keeps_its_list_returning_contract(self):
        actions = startup_recovery.recover(
            self._findings(), probes=self._probes())
        self.assertIsInstance(actions, list)
        self.assertTrue(actions)


# ── The LAN sweep must honour the netsh verdict ────────────────────────────

class TestLanSweepHonoursNetsh(unittest.TestCase):
    """The geo sweep already refused to count a batch netsh did not accept
    (it reports per-line failures in its OUTPUT while still exiting 0, and a
    non-zero code means the file was never read). The LAN sweep discarded
    the return value entirely and returned len(victims) either way, so a
    half-failed sweep retired the crash marker over live routes.

    The table is fed in the `|-delimited` text form that
    routing._dump_route_table_ps produces, which is what the sweep reads now.
    It used to be `ConvertTo-Json` - and that came with the two defects this
    test's siblings cover: a 8-second inherited timeout that voided the whole
    sweep on a large table, and JSON serialisation cost on exactly the
    thousands-of-routes case the watchdog exists for."""

    def _run(self, returncode, stdout):
        import tuntop.network.routing as rt
        from tuntop.config.defaults import LAN_BYPASS_PREFIXES
        prefix = LAN_BYPASS_PREFIXES[0]
        table = f"{prefix}|Wi-Fi|192.168.1.1\n"
        with mock.patch.object(rt, "_get_ipv4_default",
                               return_value=("Wi-Fi", "192.168.1.1")), \
             mock.patch.object(rt, "_ps", return_value=(True, table)), \
             mock.patch.object(cleanup_watchdog.subprocess, "run") as run:
            run.return_value = mock.Mock(returncode=returncode,
                                         stdout=stdout, stderr=b"")
            return cleanup_watchdog.sweep_lan_routes(log=lambda m: None)

    def test_a_failed_netsh_is_reported_as_a_failure(self):
        self.assertIsNone(self._run(1, b"some error"))

    def test_silence_is_reported_as_a_failure(self):
        self.assertIsNone(self._run(0, b""))

    def test_a_real_batch_reports_its_count(self):
        self.assertEqual(self._run(0, b"Ok.\n"), 1)

    def test_the_table_read_is_not_capped_at_eight_seconds(self):
        """The sweep read the table through `routing._ps` with no timeout, so
        it inherited _ps's 8-second default while the netsh deletes in the
        same function were allowed 120. Over a table with thousands of
        leftover geo routes - precisely the crash this watchdog exists to
        clean up - the read raised TimeoutExpired, the sweep returned None,
        and the marker was retained over routes that were never touched."""
        import tuntop.network.routing as rt
        from tuntop.config.defaults import LAN_BYPASS_PREFIXES
        prefix = LAN_BYPASS_PREFIXES[0]
        seen = {}

        def _ps(_script, timeout=8):
            seen["timeout"] = timeout
            return True, f"{prefix}|Wi-Fi|192.168.1.1\n"

        with mock.patch.object(rt, "_get_ipv4_default",
                               return_value=("Wi-Fi", "192.168.1.1")), \
             mock.patch.object(rt, "_ps", _ps), \
             mock.patch.object(cleanup_watchdog.subprocess, "run") as run:
            run.return_value = mock.Mock(returncode=0, stdout=b"Ok.\n",
                                         stderr=b"")
            cleanup_watchdog.sweep_lan_routes(log=lambda m: None)
        self.assertGreaterEqual(seen.get("timeout", 0), 90)


# ── One owner per teardown ─────────────────────────────────────────────────

def _app():
    """A BTopTui with only the attributes these tests touch."""
    import threading
    from tuntop.core.state import TunnelStateMachine
    from tuntop.ui import dashboard
    app = dashboard.BTopTui.__new__(dashboard.BTopTui)
    app.tunnel = TunnelStateMachine()
    app.proc = None
    app._stopping = threading.Event()
    app._teardown_lock = threading.RLock()
    app._shutting_down = False
    app._cleanup_done = False
    app._helper_exit_reason = ""
    app.manager = mock.MagicMock()
    app.logs = mock.MagicMock()
    app.event_log = mock.MagicMock()   # _blog mirrors into it
    app.log_lines = []
    return app


def _force(app, state):
    """Put the machine in `state` for test setup.

    The graph forbids STOPPED -> STOPPING (only a real tunnel can be torn
    down), so a test that needs to stand in for a teardown has to force the
    state rather than walk there honestly.
    """
    app.tunnel.transition(state, "test setup", force=True)


class TestStartDoesNotSlipInBehindATeardown(unittest.TestCase):
    """The teardown gate was checked only AFTER request_start failed.

    During a teardown the reader used to publish STOPPED, and STOPPED ->
    STARTING is a legal edge, so request_start SUCCEEDED and the guard was
    skipped: a [S], a recovery restart or a bypass restart could launch a new
    helper while the previous session's sweep was still deleting routes and
    re-creating the pre-session snapshot over the new ones.
    """

    def test_a_teardown_in_progress_refuses_the_start(self):
        app = _app()
        app.manager.request_start.return_value = True   # it WOULD have worked
        app._stopping.set()                             # ...but a sweep is live
        self.assertFalse(app._managed_start())
        app.manager.request_start.assert_not_called()

    def test_the_stopping_state_alone_also_refuses(self):
        from tuntop.core.state import TunnelState
        app = _app()
        _force(app, TunnelState.STOPPING)
        self.assertFalse(app._managed_start())
        app.manager.request_start.assert_not_called()

    def test_a_quiet_machine_still_starts(self):
        app = _app()
        app.manager.request_start.return_value = True
        self.assertTrue(app._managed_start())
        app.manager.request_start.assert_called_once()


class TestOnlyTheTeardownOwnerPublishesStopped(unittest.TestCase):
    """_stop_locked sets STOPPING and then spends seconds in the live-route
    cleanup, the wintun teardown, the exit sweep and the snapshot restore.
    The stdout reader's EOF path fired in the middle of all of it and, since
    STOPPING -> STOPPED is a legal edge, published "STOPPED = system clean"
    for a teardown that had not finished."""

    def test_the_reader_owns_the_transition_when_nothing_else_does(self):
        from tuntop.core.state import TunnelState
        app = _app()
        app._stopping.set()
        app._stopping.clear()
        # Emulate the EOF branch's decision, not the whole reader thread.
        teardown_owns = (app._stopping.is_set() or app._shutting_down
                         or app._cleanup_done)
        self.assertFalse(teardown_owns)
        app.tunnel.try_transition(TunnelState.STOPPING, "helper exited")
        app.tunnel.try_transition(TunnelState.STOPPED, "helper exited")
        self.assertIs(app.tunnel.current, TunnelState.STOPPED)

    def test_a_live_teardown_keeps_the_machine_out_of_stopped(self):
        from tuntop.core.state import TunnelState
        app = _app()
        _force(app, TunnelState.STOPPING)
        app._stopping.set()
        teardown_owns = (app._stopping.is_set() or app._shutting_down
                         or app._cleanup_done)
        self.assertTrue(teardown_owns)
        # The reader must not have moved the machine on...
        self.assertIs(app.tunnel.current, TunnelState.STOPPING)
        # ...until the owner itself finishes.
        app.tunnel.try_transition(TunnelState.STOPPED, "teardown complete")
        self.assertIs(app.tunnel.current, TunnelState.STOPPED)


class TestHelperLifetimeIsBoundToADeadHelper(unittest.TestCase):
    """Nothing tied tun2socks to the helper's lifetime, so killing the helper
    left tun2socks running - still holding the Wintun adapter, its routes and
    the traffic path - while the UI said STOPPED. A kill-on-close Job Object
    makes the OS reap the tree when the dashboard dies, for any reason."""

    def test_a_job_is_never_handed_out_on_a_non_windows_box(self):
        from tuntop.ui import dashboard
        with mock.patch.object(dashboard.sys, "platform", "linux"):
            self.assertIsNone(dashboard._create_kill_on_close_job())

    def test_job_creation_failure_is_soft(self):
        """Refusing to start the tunnel because a lifetime guard could not be
        installed would be a far worse outcome than running without one."""
        from tuntop.ui import dashboard
        with mock.patch.object(dashboard.sys, "platform", "win32"), \
             mock.patch.object(dashboard.ctypes, "windll",
                               mock.Mock()) as windll:
            windll.kernel32.CreateJobObjectW.return_value = 0
            self.assertIsNone(dashboard._create_kill_on_close_job())

    def test_assignment_needs_a_live_handle(self):
        from tuntop.ui import dashboard
        self.assertFalse(dashboard._assign_to_job(None, None))
        self.assertFalse(dashboard._assign_to_job(1234, None))
        self.assertFalse(dashboard._assign_to_job(1234, object()))


class TestPostExitCleanupOwnsTheSystem(unittest.TestCase):
    """A dead helper could leave orphaned routes, the adapter and the DNS
    pin. Only the recovery engine's restart ever cleaned that, because it
    calls stop() first - so with --no-auto-recover, once recovery gave up, or
    on a markerless exit, nothing ran and the UI said STOPPED."""

    def test_the_cleanup_runs_the_sweeps_without_pausing_recovery(self):
        app = _app()
        app.recovery = mock.MagicMock()
        calls = []
        app._run_teardown_sweeps = lambda: calls.append("sweeps")
        app._cleanup_after_helper_exit()
        self.assertEqual(calls, ["sweeps"])
        # Pausing recovery here would CANCEL the restart that is already
        # queued, turning a self-healing crash into a stopped tunnel - the
        # reason this is not simply stop().
        app.recovery.pause.assert_not_called()
        # And the quiesce is released, so a later start is not blocked.
        self.assertFalse(app._stopping.is_set())

    def test_a_second_cleanup_joins_the_first_instead_of_racing_it(self):
        app = _app()
        calls = []
        app._run_teardown_sweeps = lambda: calls.append("sweeps")
        app._stopping.set()            # somebody else owns the teardown
        app._cleanup_after_helper_exit()
        self.assertEqual(calls, [])    # waited, then deferred to the owner


if __name__ == "__main__":
    unittest.main()

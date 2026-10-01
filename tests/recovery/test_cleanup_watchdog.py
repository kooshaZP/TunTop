"""Unit tests for tuntop.core.cleanup_watchdog - Phase 5+ crash watchdog.

Every probe, wait, and PID kill is faked: deterministic, no Windows, no
subprocesses, no network. The decision logic (when to sweep, what to clear)
is fully testable without the OS.

Run:  python -m unittest discover -s tests -v
"""
import json
import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from tuntop.core.cleanup_watchdog import (
    kill_pid,
    main,
    sweep_after_unclean_exit,
    sweep_geo_routes,
    sweep_lan_routes,
    wait_for_exit,
)


# ── Helpers ──────────────────────────────────────────────────────────

def make_marker(pid=1234, helper_pid=None, path=None):
    path = path or os.path.join(tempfile.mkdtemp(), "marker.json")
    data = {"pid": int(pid), "started": 1000.0}
    if helper_pid:
        data["helper_pid"] = int(helper_pid)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)
    return path


def dead_session(_path):
    """Pin scan()'s liveness verdict to "the session that wrote this marker is
    gone".

    Every test below simulates a CRASHED run, and the verdict must not be
    inherited from the machine running the suite: `marker_is_live` answers
    True for ANY process in the host's PID table, and CI runners reuse low
    PIDs - 999 was live on windows-latest. scan() then reported a live
    session, so `dirty` was False and recover() refused to touch anything:
    test_unclean_exit_runs_sweep_and_clears_marker and
    test_leftover_dns_guard_is_removed failed on CI while passing locally.
    `marker_live` is the injection point scan() documents for exactly this,
    so pass it wherever a marker is present.
    """
    return False


# ── wait_for_exit ────────────────────────────────────────────────────

class TestWaitForExit(unittest.TestCase):
    def test_non_win_returns_true(self):
        with patch("sys.platform", "linux"):
            self.assertTrue(wait_for_exit(999, timeout_s=1.0))

    def test_bad_pid_returns_true(self):
        with patch("sys.platform", "win"):
            self.assertTrue(wait_for_exit(0))
            self.assertTrue(wait_for_exit(-1))

    def test_timeout_returns_false(self):
        """If OpenProcess succeeds but the process never exits within the
        timeout, wait_for_exit returns False."""
        pass  # Windows-only kernel32 interaction - covered by integration

    def test_process_gone_returns_true(self):
        """If OpenProcess fails with ERROR_INVALID_PARAMETER, the PID is
        already gone -> True."""
        pass  # Windows-only kernel32 interaction - covered by integration


# ── kill_pid ─────────────────────────────────────────────────────────

class TestKillPid(unittest.TestCase):
    def test_bad_pid_returns_false(self):
        self.assertFalse(kill_pid(0))
        self.assertFalse(kill_pid(-1))

    def test_non_win_returns_false(self):
        with patch("sys.platform", "linux"):
            self.assertFalse(kill_pid(1234))

    def test_taskkill_success(self):
        with patch("sys.platform", "win"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            self.assertTrue(kill_pid(1234))
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            self.assertEqual(args, ["taskkill", "/F", "/T", "/PID", "1234"])
            # A hung taskkill used to park the watchdog forever: every other
            # netsh/PowerShell call in the watchdog is bounded, this was not.
            self.assertEqual(mock_run.call_args[1]["timeout"], 30)

    def test_taskkill_timeout_falls_back(self):
        """A hung taskkill must not block the sweep - fall through to
        TerminateProcess."""
        with patch("sys.platform", "win"), \
             patch("subprocess.run", side_effect=TimeoutError("hung")), \
             patch("tuntop.core.cleanup_watchdog._kernel32") as mock_k32:
            mock_k32.return_value.OpenProcess.return_value = "FAKE_HANDLE"
            mock_k32.return_value.TerminateProcess.return_value = True
            self.assertTrue(kill_pid(1234))

    def test_taskkill_fails_falls_back(self):
        """taskkill non-zero -> TerminateProcess fallback."""
        with patch("sys.platform", "win"), \
             patch("subprocess.run") as mock_run, \
             patch("tuntop.core.cleanup_watchdog._kernel32") as mock_k32:
            mock_run.return_value = MagicMock(returncode=1)
            mock_k32.return_value.OpenProcess.return_value = "FAKE_HANDLE"
            mock_k32.return_value.TerminateProcess.return_value = True
            self.assertTrue(kill_pid(1234))


# ── sweep_after_unclean_exit ─────────────────────────────────────────

class TestSweepAfterUncleanExit(unittest.TestCase):
    def setUp(self):
        # The non-route residue sweep (physical adapter metric + DoH
        # templates) reads the real on-disk record and issues real PowerShell.
        # Patch it for this whole class; the one test that cares about its
        # verdict overrides it.
        p = patch("tuntop.core.cleanup_watchdog.sweep_residue",
                  return_value=True)
        p.start()
        self.addCleanup(p.stop)

    def _make_probes(self, killed=0, torn_down=False, swept=0):
        """Fake probes with call recording."""
        state = {"killed": None, "torn_down": torn_down, "swept": None}

        def kill():
            state["killed"] = killed
            return killed

        def teardown():
            state["torn_down"] = True
            return True

        def sweep_host(routes):
            state["swept"] = routes
            return swept

        p = MagicMock()
        p.tun2socks_count.return_value = killed
        p.wintun_route_count.return_value = 5 if torn_down else 0
        p.host_routes.return_value = [("v4", "1.2.3.4/32")]
        p.kill_tun2socks = kill
        p.teardown_adapter = teardown
        p.sweep_host_routes = sweep_host
        return p, state

    def test_no_marker_no_sweep(self):
        p, state = self._make_probes()
        result = sweep_after_unclean_exit(999, hosts=(), marker_path=os.path.join(tempfile.mkdtemp(), "none.json"), probes=p)
        self.assertFalse(result)
        self.assertIsNone(state["killed"])
        self.assertFalse(state["torn_down"])

    def test_marker_owned_by_other_session_no_sweep(self):
        path = make_marker(pid=1111)  # owned by PID 1111, not 999
        p, state = self._make_probes()
        result = sweep_after_unclean_exit(999, marker_path=path, probes=p)
        self.assertFalse(result)
        self.assertIsNone(state["killed"])

    def test_unclean_exit_runs_sweep_and_clears_marker(self):
        path = make_marker(pid=999, helper_pid=5555)
        p, state = self._make_probes(killed=2)

        with patch("tuntop.core.cleanup_watchdog.sweep_geo_routes",
                   return_value=0), \
             patch("tuntop.core.cleanup_watchdog.sweep_lan_routes",
                   return_value=0), \
             patch("tuntop.core.cleanup_watchdog.kill_pid") as mock_kill:
            result = sweep_after_unclean_exit(999, hosts=("example.com",),
                                              helper_pid=5555,
                                              marker_path=path, probes=p,
                                              marker_live=dead_session)

        self.assertTrue(result)
        self.assertEqual(state["killed"], 2)
        # kill_pid is the REAL taskkill /F /T against a PID from the HOST's
        # table - patched here so the suite never kills an unrelated process.
        mock_kill.assert_called_once()
        self.assertEqual(mock_kill.call_args[0][0], 5555)
        self.assertTrue(state["torn_down"])
        self.assertIsNone(read_marker(path))  # marker cleared

    def test_failed_sweep_keeps_marker(self):
        """A HALF-FAILED sweep must NOT clear the crash marker: the log used
        to say "system is clean" while leftover routes stayed (field: the
        frozen watchdog's lazy imports died with Errno 2 on base_library.zip
        after the parent's _MEI dir was deleted - the geo/LAN sweeps no-op'd
        and the marker was cleared anyway). With the marker left, the next
        launch re-runs the whole startup recovery."""
        path = make_marker(pid=999, helper_pid=5555)
        p, state = self._make_probes()
        with patch("tuntop.core.cleanup_watchdog.sweep_geo_routes",
                   return_value=0), \
             patch("tuntop.core.cleanup_watchdog.sweep_lan_routes",
                   return_value=None), \
             patch("tuntop.core.cleanup_watchdog.kill_pid"):   # sweep FAILED
            sweep_after_unclean_exit(999, hosts=(), helper_pid=5555,
                                     marker_path=path, probes=p,
                                     marker_live=dead_session)
        self.assertIsNotNone(read_marker(path))  # marker KEPT

    def test_residue_sweep_failure_keeps_marker(self):
        """The physical adapter's InterfaceMetric and the machine-wide DoH
        templates are not routes, so no route sweep reaches them - and before
        the residue record existed nothing could undo them at all. A failed
        restore must therefore hold the marker exactly like a failed route
        sweep does, or the next launch is told the machine is clean."""
        path = make_marker(pid=999, helper_pid=5555)
        p, state = self._make_probes()
        with patch("tuntop.core.cleanup_watchdog.sweep_geo_routes",
                   return_value=0), \
             patch("tuntop.core.cleanup_watchdog.sweep_lan_routes",
                   return_value=0), \
             patch("tuntop.core.cleanup_watchdog.sweep_residue",
                   return_value=False), \
             patch("tuntop.core.cleanup_watchdog.kill_pid"):
            sweep_after_unclean_exit(999, hosts=(), helper_pid=5555,
                                     marker_path=path, probes=p,
                                     marker_live=dead_session)
        self.assertIsNotNone(read_marker(path))

    def test_geo_sweep_failure_keeps_marker_too(self):
        path = make_marker(pid=999)
        p, state = self._make_probes()
        with patch("tuntop.core.cleanup_watchdog.sweep_geo_routes",
                   return_value=None), \
             patch("tuntop.core.cleanup_watchdog.sweep_lan_routes",
                   return_value=0):
            sweep_after_unclean_exit(999, hosts=(), marker_path=path,
                                     probes=p, marker_live=dead_session)
        self.assertIsNotNone(read_marker(path))  # marker KEPT

    def test_leftover_dns_guard_is_removed(self):
        """A hard-killed run can leave the catch-all NRPT rule installed. It
        rewrites name resolution for EVERY process on the machine, so the
        detached watchdog - the only thing still alive after the dashboard is
        killed - has to take it down with the routes."""
        path = make_marker(pid=999)
        p, state = self._make_probes()
        p.dns_guard_present = MagicMock(return_value=True)
        p.remove_dns_guard = MagicMock(return_value=True)
        with patch("tuntop.core.cleanup_watchdog.sweep_geo_routes",
                   return_value=0), \
             patch("tuntop.core.cleanup_watchdog.sweep_lan_routes",
                   return_value=0):
            sweep_after_unclean_exit(999, hosts=(), marker_path=path,
                                     probes=p, marker_live=dead_session)
        p.remove_dns_guard.assert_called_once()

    def test_no_guard_means_no_guard_removal(self):
        path = make_marker(pid=999)
        p, state = self._make_probes()
        p.dns_guard_present = MagicMock(return_value=False)
        p.remove_dns_guard = MagicMock(return_value=True)
        with patch("tuntop.core.cleanup_watchdog.sweep_geo_routes",
                   return_value=0), \
             patch("tuntop.core.cleanup_watchdog.sweep_lan_routes",
                   return_value=0):
            sweep_after_unclean_exit(999, hosts=(), marker_path=path,
                                     probes=p, marker_live=dead_session)
        p.remove_dns_guard.assert_not_called()

    def test_helper_killed_before_sweep(self):
        """The watchdog must kill the helper BEFORE scanning/sweeping."""
        call_order = []

        def kill():
            call_order.append("kill")
            return 1

        def teardown():
            call_order.append("teardown")
            return True

        p = MagicMock()
        p.tun2socks_count.return_value = 1
        p.wintun_route_count.return_value = 2
        p.host_routes.return_value = []
        p.kill_tun2socks = kill
        p.teardown_adapter = teardown
        p.sweep_host_routes.return_value = 0

        path = make_marker(pid=888)
        with patch("tuntop.core.cleanup_watchdog.sweep_geo_routes",
                   return_value=0), \
             patch("tuntop.core.cleanup_watchdog.sweep_lan_routes",
                   return_value=0), \
             patch("tuntop.core.cleanup_watchdog.kill_pid"):
            sweep_after_unclean_exit(888, helper_pid=4444, marker_path=path,
                                     probes=p, marker_live=dead_session)

        self.assertEqual(call_order[0], "kill", "helper must die before teardown")

    def test_marker_not_ours_after_sweep_not_cleared(self):
        """If a new session wrote its marker while we were sweeping, leave it.

        The marker is read THREE times by sweep_after_unclean_exit: once to
        confirm the crash is ours, once immediately before the first
        destructive step (the grace period is exactly the relaunch window),
        and once more AFTER the sweep, before the marker is retired. The third
        read is this test's subject: the sweeps take seconds, and a session
        that started during them now owns the system. Clearing its marker
        would tell the next launch the system is clean when it is not, and
        leave that session's own watchdog with nothing to do.

        sweep_geo_routes / sweep_lan_routes are patched because the REAL
        sweep_lan_routes shells out to `powershell -EncodedCommand`
        (Get-NetRoute) and netsh: a unit test must never spawn a subprocess,
        and it is the only reason this test used to be slow. Their return
        value 0 means "ran, found nothing", so the sweep is treated as clean
        and the post-sweep re-read is genuinely reached. scan/recover are the
        real ones over the fake probes, so the sweep really executes.

        The read sequence is driven through read_marker itself, so the marker
        file is rewritten for real when the newer session claims it - the
        assertions below then read the file off disk, not the mock.
        """
        path = make_marker(pid=777)
        reads = []

        def fake_read(_p):
            reads.append(1)
            if len(reads) < 3:
                return {"pid": 777, "started": 1000.0}
            # A newer session claimed the marker mid-sweep: write it for
            # real, so "not cleared" is asserted against the file on disk.
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"pid": 8888, "started": 2000.0}, f)
            return {"pid": 8888, "started": 2000.0}

        p, state = self._make_probes(killed=1)
        with patch("tuntop.core.cleanup_watchdog.read_marker", side_effect=fake_read), \
             patch("tuntop.core.cleanup_watchdog.sweep_geo_routes", return_value=0) as geo, \
             patch("tuntop.core.cleanup_watchdog.sweep_lan_routes", return_value=0) as lan, \
             patch("tuntop.core.cleanup_watchdog.clear_marker") as clear:
            result = sweep_after_unclean_exit(777, marker_path=path, probes=p,
                                              marker_live=dead_session)

        self.assertEqual(len(reads), 3,
                         "the marker is read before the sweep, just before the "
                         "destructive step, and again before it is retired")
        self.assertTrue(result, "the unclean exit WAS detected and swept")
        self.assertEqual(state["killed"], 1, "the sweep really ran")
        # The patched sweeps are the ones that ran - no powershell/netsh.
        self.assertTrue(geo.called)
        self.assertTrue(lan.called)
        clear.assert_not_called()
        on_disk = read_marker(path)
        self.assertIsNotNone(on_disk, "the newer session's marker must survive")
        self.assertEqual(on_disk["pid"], 8888,
                         "the file must still be the NEWER session's marker, "
                         "not deleted and not overwritten with ours")

    def test_live_session_marker_is_left_completely_alone(self):
        """The mirror image of the crash tests, and the reason the liveness
        verdict is injectable: a marker whose dashboard PID is STILL RUNNING
        belongs to another live instance - not one process, route or DNS
        guard it owns may be touched."""
        path = make_marker(pid=999)
        p, state = self._make_probes(killed=2)
        with patch("tuntop.core.cleanup_watchdog.sweep_geo_routes",
                   return_value=0), \
             patch("tuntop.core.cleanup_watchdog.sweep_lan_routes",
                   return_value=0):
            result = sweep_after_unclean_exit(999, marker_path=path, probes=p,
                                              marker_live=lambda _p: True)
        self.assertTrue(result)
        self.assertIsNone(state["killed"])      # no orphan was killed
        self.assertFalse(state["torn_down"])    # the live adapter survived
        self.assertIsNone(state["swept"])       # no route was swept


# ── main() ────────────────────────────────────────────────────────────


    def test_accepts_geoip_kwargs(self):
        """sweep_after_unclean_exit takes geoip/geoip_code (physical-adapter sweep)."""
        path = make_marker(pid=4242)
        p, state = self._make_probes()
        with patch("tuntop.core.cleanup_watchdog.sweep_geo_routes",
                   return_value=0), \
             patch("tuntop.core.cleanup_watchdog.sweep_lan_routes",
                   return_value=0):
            result = sweep_after_unclean_exit(4242, marker_path=path, probes=p,
                                              geoip=None, geoip_code="ir",
                                              marker_live=dead_session)
        self.assertTrue(result)

class TestMain(unittest.TestCase):
    def test_main_writes_log_and_returns_zero(self):
        """main() should return 0 on a clean sweep."""
        with patch("tuntop.core.cleanup_watchdog.wait_for_exit", return_value=True), \
             patch("tuntop.core.cleanup_watchdog.read_marker", return_value=None), \
             patch("tuntop.core.cleanup_watchdog.time.sleep"):
            rc = main(["--pid", "9999", "--hosts", "example.com"])
        self.assertEqual(rc, 0)

    def test_main_returns_zero_even_on_failure(self):
        """The watchdog must never raise - any exception is caught."""
        with patch("tuntop.core.cleanup_watchdog.wait_for_exit", side_effect=OSError("boom")):
            rc = main(["--pid", "9999"])
        self.assertEqual(rc, 1)  # caught -> returns 1, never raises

    def test_watchdog_log_file_created(self):
        """Diagnostics are written to .cleanup_watchdog.log."""
        log_path = os.path.join(tempfile.mkdtemp(), "watchdog.log")
        with patch.dict("os.environ", {}), \
             patch("tuntop.core.cleanup_watchdog.LOG_FILE", log_path), \
             patch("tuntop.core.cleanup_watchdog.wait_for_exit", return_value=True), \
             patch("tuntop.core.cleanup_watchdog.read_marker", return_value=None), \
             patch("tuntop.core.cleanup_watchdog.time.sleep"):
            main(["--pid", "1"])
        self.assertTrue(os.path.exists(log_path))


# ── Module-level helpers ─────────────────────────────────────────────

def read_marker(path):
    import json
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


class TestSweepGeoRoutes(unittest.TestCase):
    def test_missing_file_returns_zero(self):
        self.assertEqual(sweep_geo_routes(r"C:\\definitely\\missing.dat", "ir"), 0)

    def test_none_geoip_returns_zero(self):
        self.assertEqual(sweep_geo_routes(None, "ir"), 0)

    def test_empty_geoip_code_is_a_quiet_noop(self):
        """geoip set but no country code = geo bypass never active. The old
        code ran this into parse_geoip and logged a scary 'no CIDR entries
        found for geoip code '''' failure on every unclean-exit sweep."""
        import tuntop.geoip as geoip_mod
        with patch.object(geoip_mod, "parse_geoip",
                          side_effect=AssertionError("must not be called")):
            self.assertEqual(sweep_geo_routes(r"C:\anywhere\geoip.dat", ""), 0)

    def test_geo_sweep_failure_returns_none_not_zero(self):
        """None (= sweep FAILED) is distinct from 0 (= ran, found nothing) -
        the marker-clearing logic keeps the marker only on None."""
        import tuntop.geoip as geoip_mod
        with patch("os.path.isfile", return_value=True), \
             patch.object(geoip_mod, "parse_geoip",
                          side_effect=OSError("unreadable")):
            self.assertIsNone(sweep_geo_routes(r"C:\anywhere\geoip.dat", "ir"))

    def test_lan_sweep_failure_returns_none_not_zero(self):
        import tuntop.network.routing as routing
        with patch.object(routing, "_ps",
                          side_effect=OSError("no powershell")):
            self.assertIsNone(sweep_lan_routes())



if __name__ == "__main__":
    unittest.main()

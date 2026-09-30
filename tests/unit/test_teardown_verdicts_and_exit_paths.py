"""Every teardown path can now REPORT failure, and the crash/gateway paths
that used to hang, wedge or drop work.

The bugs these pin, all found by reading the four exit-related paths end to
end:

  * `_atexit_all` assigned `cleanup_ok = True` unconditionally, because every
    function it called swallowed its own exceptions. The crash marker was
    retired on EVERY exit - including a total cleanup failure - which told the
    detached watchdog and the next launch's startup recovery that the system
    was clean. That bypasses the entire `sweeps_ok` veto chain.
  * No sweep could express failure at all: `_batch_delete_routes` threw away
    netsh's return code and output and returned `len(chunk)`; netsh exits 0
    even when an individual line fails, so a half-failed sweep and a clean one
    were the same value.
  * `_final_host_route_sweep` promised to clear leftover server /32s
    "regardless of which interface/gateway they were installed through" while
    scoping to `[TUN, TUN2]` - and the helper installs them on the RESOLVED
    EGRESS, so it could not remove the leftovers it exists for.
  * `_ctrl` latched `_shutting_down = True` and never cleared it. A Ctrl+C the
    app survives left every interactive path ([Q] [S] [A] [T] [F]) a silent
    no-op: the dashboard could only be killed from Task Manager, which is
    exactly the "crash" the watchdog then has to clean up.
  * The crash handler called `app.stop()`, which re-acquires a NON-REENTRANT
    `_teardown_lock` the crashing thread usually already holds - an instant
    self-deadlock in the one handler whose whole job is to clean up.
  * No `threading.excepthook`: a dead daemon thread vanished silently, and
    main()'s `except BaseException` can never see it (main thread only).
  * A second `[GATEWAY]` change arriving during an in-flight geo re-point was
    DISCARDED, leaving that country's routes pinned to a dead gateway.

Everything is mocked: no Windows, no subprocesses, no network.
"""
import os
import sys
import threading
import time
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))

from tuntop.network.routeops import SweepResult          # noqa: E402
from tuntop.ui import dashboard                          # noqa: E402


def _app(**attrs):
    """A BTopTui with only the attributes these tests touch.

    __init__ is never run (no console, no TUI), which is why the production
    code reads optional state through getattr - several tests do the same.
    """
    app = dashboard.BTopTui.__new__(dashboard.BTopTui)
    app.proc = None
    app._live_geo_added = []
    app._live_bypass_added = []
    app._iface_cache = None
    app._gw_geo_repoint_active = False
    app._gw_geo_pending = None
    app._shutting_down = False
    app._cleanup_done = False
    app._teardown_lock = threading.Lock()
    app._in_teardown = None
    app._stopping = threading.Event()
    app._running = True
    app._route_snapshot = None
    app._blog = mock.Mock()
    for k, v in attrs.items():
        setattr(app, k, v)
    return app


# ── SweepResult: three different questions, and a trap in __bool__ ──────────

class TestSweepResult(unittest.TestCase):
    def test_found_and_removed_are_different_questions(self):
        r = SweepResult(found=400, removed=0, ok=False, err="batch never ran")
        self.assertEqual(r.found, 400)
        self.assertEqual(r.removed, 0)
        self.assertFalse(r.ok)
        self.assertIn("never ran", r.err)

    def test_bool_is_removed_not_ok(self):
        """Every historical call site is `if n:` meaning "did we remove
        anything". Flipping __bool__ to `ok` would make a sweep that found 400
        rows and removed all 400 falsy at every one of them."""
        self.assertTrue(SweepResult(400, 400, ok=True))
        self.assertFalse(SweepResult(400, 0, ok=False))
        # ...and `int()` keeps it usable where a count was interpolated.
        self.assertEqual(int(SweepResult(400, 400, ok=True)), 400)

    def test_a_bare_count_is_still_acceptable_to_callers(self):
        """A collaborator that predates the type (an older caller, a test
        double) may return a plain int, and no aggregation may crash on it."""
        for v in (0, 1, 5):
            self.assertFalse(isinstance(v, SweepResult))


# ── The exit sweep reports a verdict ────────────────────────────────────────

class TestExitRouteSweepVerdict(unittest.TestCase):
    """_exit_route_sweep returned NOTHING while every sweep inside it
    swallowed its own exceptions, so its caller's `cleanup_ok = True` was
    unreachable-by-failure. It now verifies the table instead of trusting the
    sweeps' own summaries."""

    def _patch(self, app, *, geo=None, lan=None, host=True, verify=(True, "ok")):
        geo = geo if geo is not None else SweepResult.clean(0, 0)
        lan = lan if lan is not None else SweepResult.clean(0, 0)
        return (
            mock.patch.object(app, "_cleanup_live_routes",
                              return_value=SweepResult.clean(0, 0)),
            mock.patch.object(app, "_sweep_geo_leftovers", return_value=geo),
            mock.patch.object(app, "_sweep_lan_leftovers", return_value=lan),
            mock.patch.object(app, "_final_host_route_sweep",
                              return_value=host),
            mock.patch.object(app, "_dump_route_table", return_value=[]),
            mock.patch.object(app, "_verify_routes_clear", return_value=verify),
        )

    def _run(self, app, patches):
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        return app._exit_route_sweep()

    def test_all_clean_and_table_empty_is_clean(self):
        app = _app()
        self.assertTrue(self._run(app, self._patch(app)))

    def test_a_failed_sweep_is_evidence_but_the_table_wins(self):
        """A sweep reporting not-ok is EVIDENCE, not proof: netsh refuses
        individual lines while still exiting 0, and a route that was already
        gone never answers "Ok." either. If the verification read says the
        table is clear, it is clear - the route sweeps are not a second veto,
        or every already-absent route would fail every teardown."""
        app = _app()
        self.assertTrue(self._run(app, self._patch(
            app, lan=SweepResult.failed(3, "netsh confirmed only 0 of 3"),
            verify=(True, "clear"))))
        # ...but the reason is still surfaced, not swallowed.
        self.assertTrue(any("confirmed only 0" in str(c)
                            for c in app._blog.call_args_list))

    def test_a_failed_host_sweep_is_a_hard_veto(self):
        """The one step the verification cannot see: it counts wintun, geo and
        LAN rows, never the per-host /32s."""
        app = _app()
        self.assertFalse(self._run(app, self._patch(
            app, host=False, verify=(True, "clear"))))

    def test_a_raising_sweep_vetoes_the_verdict(self):
        app = _app()
        patches = list(self._patch(app))
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        with mock.patch.object(app, "_sweep_geo_leftovers",
                               side_effect=RuntimeError("boom")):
            self.assertFalse(app._exit_route_sweep())

    def test_routes_still_present_vetoes_it_even_when_every_sweep_said_ok(self):
        """The authoritative check looks at the TABLE. netsh reports
        per-line failures in its output and still exits 0, so "every sweep
        reported clean" is not evidence."""
        app = _app()
        self.assertFalse(self._run(app, self._patch(
            app, verify=(False, "3 wintun route(s) left"))))
        self.assertTrue(any("3 wintun" in str(c)
                            for c in app._blog.call_args_list))

    def test_an_unreadable_table_is_not_a_clean_exit(self):
        app = _app()
        patches = list(self._patch(app))
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        with mock.patch.object(app, "_verify_routes_clear",
                               side_effect=OSError("no powershell")):
            self.assertFalse(app._exit_route_sweep())

    def test_one_shared_table_read_serves_both_victim_selections(self):
        """The geo and LAN sweeps used to each dump the whole table. They take
        a `rows=` argument now, so a teardown pays for ONE read - safe because
        their victim sets are disjoint (public country CIDRs vs RFC1918), so a
        geo delete cannot hide a row from the LAN match."""
        app = _app()
        dump = mock.patch.object(app, "_dump_route_table", return_value=[])
        geo_p = mock.patch.object(app, "_sweep_geo_leftovers")
        lan_p = mock.patch.object(app, "_sweep_lan_leftovers")
        with dump as d, geo_p as g, lan_p as ln:
            d.return_value = []
            g.return_value = SweepResult.clean(0, 0)
            ln.return_value = SweepResult.clean(0, 0)
            app._exit_route_sweep()
        self.assertIsNotNone(g.call_args[1].get("rows"))
        self.assertIsNotNone(ln.call_args[1].get("rows"))
        self.assertIs(g.call_args[1]["rows"], ln.call_args[1]["rows"])


class TestVerifyRoutesClear(unittest.TestCase):
    def _app(self, rows, **extra):
        app = _app()
        app._geo_sweep_cidrs = mock.Mock(return_value={"5.0.0.0/8"})
        return app

    def test_counts_wintun_geo_and_lan_from_one_read(self):
        app = _app()
        app._geo_sweep_cidrs = mock.Mock(return_value={"5.0.0.0/8"})
        rows = [
            {"DestinationPrefix": "0.0.0.0/0", "InterfaceAlias": "wintun",
             "NextHop": "192.168.123.1"},
            {"DestinationPrefix": "5.0.0.0/8", "InterfaceAlias": "Wi-Fi",
             "NextHop": "192.168.1.1"},
            {"DestinationPrefix": "10.0.0.0/8", "InterfaceAlias": "Wi-Fi",
             "NextHop": "192.168.1.1"},
        ]
        with mock.patch("tuntop.ui.dashboard._get_ipv4_default",
                        return_value=("Wi-Fi", "192.168.1.1")):
            clear, detail = app._verify_routes_clear(rows=rows)
        self.assertFalse(clear)
        self.assertIn("1 wintun", detail)
        self.assertIn("1 geoip", detail)
        self.assertIn("1 LAN", detail)

    def test_an_empty_table_is_clear(self):
        app = _app()
        app._geo_sweep_cidrs = mock.Mock(return_value=set())
        with mock.patch("tuntop.ui.dashboard._get_ipv4_default",
                        return_value=("Wi-Fi", "192.168.1.1")):
            clear, _detail = app._verify_routes_clear(rows=[])
        self.assertTrue(clear)

    def test_count_wintun_routes_uses_a_given_table(self):
        """The old _count_wintun_routes spawned two PowerShell processes (one
        per tunnel adapter) per call, and the [Q] verify loop called it up to
        six times - a dozen process spawns to count two numbers."""
        rows = [{"DestinationPrefix": "a", "InterfaceAlias": "wintun",
                 "NextHop": ""},
                {"DestinationPrefix": "b", "InterfaceAlias": "wintun2",
                 "NextHop": ""},
                {"DestinationPrefix": "c", "InterfaceAlias": "Wi-Fi",
                 "NextHop": ""}]
        with mock.patch("tuntop.ui.dashboard._ps") as ps:
            self.assertEqual(dashboard.BTopTui._count_wintun_routes(rows), 2)
        ps.assert_not_called()


# ── The host-route sweep can actually reach what it must ───────────────────

class TestHostSweepScope(unittest.TestCase):
    """It was scoped to [TUN, TUN2], but the helper installs the server and
    bypass /32s on the RESOLVED EGRESS - so the sweep added to fix "my servers
    stay in the routing table after Alt+F4" could not remove them. The fix must
    stay scoped, though: an UNSCOPED Remove-NetRoute deletes the prefix on
    every interface, which is how a corporate VPN client's /32 got removed."""

    def test_scope_includes_the_tunnel_adapters(self):
        app = _app()
        with mock.patch("tuntop.ui.dashboard._get_ipv4_default",
                        return_value=None), \
             mock.patch("tuntop.ui.dashboard._get_ipv6_default",
                        return_value=None):
            scope = app._host_sweep_scope()
        self.assertIn("wintun", scope)
        self.assertIn("wintun2", scope)

    def test_scope_includes_the_current_physical_egress(self):
        app = _app()
        with mock.patch("tuntop.ui.dashboard._get_ipv4_default",
                        return_value=("Wi-Fi", "192.168.1.1")), \
             mock.patch("tuntop.ui.dashboard._get_ipv6_default",
                        return_value=("Wi-Fi", "fe80::1")):
            scope = app._host_sweep_scope()
        self.assertIn("Wi-Fi", scope)

    def test_scope_includes_interfaces_from_our_own_ledgers(self):
        app = _app()
        app._live_bypass_added = [("v4", "1.2.3.4/32", "Ethernet", "10.0.0.1")]
        app._live_geo_added = [("v4", "5.0.0.0/8", "USB-Ethernet", "10.1.0.1")]
        with mock.patch("tuntop.ui.dashboard._get_ipv4_default",
                        return_value=("Wi-Fi", "192.168.1.1")), \
             mock.patch("tuntop.ui.dashboard._get_ipv6_default",
                        return_value=None):
            scope = app._host_sweep_scope()
        self.assertIn("Ethernet", scope)
        self.assertIn("USB-Ethernet", scope)

    def test_an_unrelated_vpn_adapter_is_never_in_scope(self):
        """A corporate VPN client is a DIFFERENT alias, and scoping is the
        only thing standing between this sweep and someone else's /32."""
        app = _app()
        with mock.patch("tuntop.ui.dashboard._get_ipv4_default",
                        return_value=("Wi-Fi", "192.168.1.1")), \
             mock.patch("tuntop.ui.dashboard._get_ipv6_default",
                        return_value=None):
            scope = app._host_sweep_scope()
        self.assertNotIn("Corp-VPN01", scope)

    def test_the_generated_statements_are_scoped(self):
        app = _app()
        app.ns = types.SimpleNamespace(bypass_ip=[], server=[],
                                       proxy2_bypass_ip=[], vpn_server=[],
                                       vpn_bypass_ip=[])
        app.endpoint_v4 = ["1.2.3.4"]
        app.endpoint_v6 = []
        captured = {}

        def _ps(script, timeout=8):
            captured["script"] = script
            return True, ""

        with mock.patch("tuntop.ui.dashboard._resolve_cached",
                        return_value=(["1.2.3.4"], [])), \
             mock.patch("tuntop.ui.dashboard._ps", _ps), \
             mock.patch("tuntop.ui.dashboard._get_ipv4_default",
                        return_value=("Wi-Fi", "192.168.1.1")), \
             mock.patch("tuntop.ui.dashboard._get_ipv6_default",
                        return_value=None):
            self.assertTrue(app._final_host_route_sweep())
        script = captured["script"]
        self.assertIn("Where-Object", script)
        self.assertIn("Wi-Fi", script)
        self.assertNotIn("Corp-VPN01", script)
        # The scoped form pipes through Get-NetRoute | Where-Object | Remove;
        # a bare unscoped Remove-NetRoute is what deletes other adapters' rows.
        self.assertNotIn("Remove-NetRoute -DestinationPrefix '1.2.3.4/32' "
                         "-AddressFamily IPv4 -Confirm:$false "
                         "-ErrorAction SilentlyContinue | Out-Null", script)

    def test_it_reports_a_failed_powershell_call(self):
        app = _app()
        app.ns = types.SimpleNamespace(bypass_ip=[], server=[],
                                       proxy2_bypass_ip=[], vpn_server=[],
                                       vpn_bypass_ip=[])
        app.endpoint_v4 = ["1.2.3.4"]
        app.endpoint_v6 = []
        with mock.patch("tuntop.ui.dashboard._resolve_cached",
                        return_value=(["1.2.3.4"], [])), \
             mock.patch("tuntop.ui.dashboard._ps",
                        return_value=(False, "no powershell")), \
             mock.patch("tuntop.ui.dashboard._get_ipv4_default",
                        return_value=("Wi-Fi", "192.168.1.1")), \
             mock.patch("tuntop.ui.dashboard._get_ipv6_default",
                        return_value=None):
            self.assertFalse(app._final_host_route_sweep())

    def test_nothing_to_remove_is_not_a_failure(self):
        app = _app()
        app.ns = types.SimpleNamespace(bypass_ip=[], server=[],
                                       proxy2_bypass_ip=[], vpn_server=[],
                                       vpn_bypass_ip=[])
        app.endpoint_v4 = []
        app.endpoint_v6 = []
        with mock.patch("tuntop.ui.dashboard._ps") as ps:
            self.assertTrue(app._final_host_route_sweep())
        ps.assert_not_called()


# ── the batch helpers report what netsh confirmed ───────────────────────────

class TestNetshBatchResult(unittest.TestCase):
    def _run(self, returncode, stdout, add=False):
        with mock.patch("tuntop.ui.dashboard.subprocess.run") as run:
            run.return_value = mock.Mock(returncode=returncode,
                                        stdout=stdout, stderr=b"")
            return dashboard._netsh_batch_result(["x"], add=add)

    def test_a_failed_batch_never_ran(self):
        self.assertEqual(self._run(1, b"error"), (0, False))

    def test_silence_means_the_script_file_was_never_read(self):
        self.assertEqual(self._run(0, b""), (0, False))

    def test_ok_lines_are_counted(self):
        self.assertEqual(self._run(0, b"Ok.\nOk.\nOk.\n"), (3, True))

    def test_per_line_failures_are_not_counted(self):
        """netsh exits 0 and reports the failure in its OUTPUT. The old delete
        path returned len(chunk) regardless, so a half-failed sweep was
        indistinguishable from a clean one - and the crash marker was retired
        over routes that were still installed."""
        out = b"Ok.\nThe following command cannot be run: nope\nOk.\n"
        self.assertEqual(self._run(0, out), (2, True))

    def test_already_exists_counts_for_adds_only(self):
        out = b"already exists\n"
        self.assertEqual(self._run(0, out, add=True), (1, True))
        self.assertEqual(self._run(0, out, add=False), (0, True))

    def test_a_timeout_is_a_batch_that_never_ran(self):
        import subprocess
        with mock.patch("tuntop.ui.dashboard.subprocess.run",
                        side_effect=subprocess.TimeoutExpired("netsh", 180)):
            self.assertEqual(dashboard._netsh_batch_result(["x"]), (0, False))


class TestBatchDeleteReportsFailure(unittest.TestCase):
    def _app(self):
        app = _app()
        app._SWEEP_CHUNK = 250
        app._SWEEP_WORKERS = 6
        return app

    def test_a_short_confirmed_count_is_not_ok(self):
        """netsh answered 0 of the 1 line it was given with "Ok." - it ran, and
        it refused. The route is still installed, so the sweep is not clean."""
        app = self._app()
        with mock.patch("tuntop.ui.dashboard._netsh_batch_result",
                        return_value=(0, True)):
            res = app._batch_delete_routes([("1.0.0.0/8", "Wi-Fi", "")])
        self.assertFalse(res.ok)
        self.assertEqual(res.found, 1)
        self.assertEqual(res.removed, 0)
        self.assertIn("0 of 1", res.err)

    def test_a_fully_confirmed_batch_is_clean(self):
        app = self._app()
        with mock.patch("tuntop.ui.dashboard._netsh_batch_result",
                        return_value=(1, True)):
            res = app._batch_delete_routes([("1.0.0.0/8", "Wi-Fi", "")])
        self.assertTrue(res.ok)
        self.assertEqual(res.removed, 1)

    def test_a_batch_that_never_ran_is_not_ok(self):
        app = self._app()
        with mock.patch("tuntop.ui.dashboard._netsh_batch_result",
                        return_value=(0, False)):
            res = app._batch_delete_routes([("1.0.0.0/8", "Wi-Fi", "")])
        self.assertFalse(res.ok)

    def test_nothing_to_delete_is_clean(self):
        res = self._app()._batch_delete_routes([])
        self.assertTrue(res.ok)
        self.assertEqual(res.found, 0)

    def test_cleanup_live_routes_reports_a_batch_that_never_ran(self):
        """_cleanup_live_routes returned nothing at all, so "deleted
        everything" and "netsh never ran" were the same outcome."""
        app = self._app()
        app._live_bypass_added = [("v4", "1.2.3.4/32", "Wi-Fi", "192.168.1.1")]
        with mock.patch("tuntop.ui.dashboard._netsh_batch_result",
                        return_value=(0, False)):
            res = app._cleanup_live_routes()
        self.assertFalse(res.ok)
        # the ledger is still cleared (the sweep is idempotent on a re-run)
        self.assertEqual(app._live_bypass_added, [])

    def test_progress_reaches_the_total_even_on_a_partial_failure(self):
        """The bar reports ROUTES COVERED, not confirmed removed, so a partial
        failure cannot leave the shutdown screen looking wedged at 97%."""
        app = self._app()
        seen = []
        with mock.patch("tuntop.ui.dashboard._netsh_batch_result",
                        return_value=(0, True)):
            app._batch_delete_routes(
                [("1.0.0.0/8", "Wi-Fi", ""), ("2.0.0.0/8", "Wi-Fi", "")],
                progress=lambda d, t: seen.append((d, t)))
        self.assertEqual(seen[0], (0, 2))
        self.assertEqual(seen[-1], (2, 2))


# ── [Q] does not sleep on a verified-clean exit ─────────────────────────────

class TestShutdownNoDeadSleep(unittest.TestCase):
    def _app(self):
        app = _app()
        app._shutting_down = False
        app._stopping = threading.Event()
        app.recovery = mock.MagicMock()
        app.tunnel = mock.MagicMock()
        app._sweep_progress_cb = mock.MagicMock()
        app._draw_shutdown = mock.MagicMock()
        app.running = True
        return app

    def _run(self, *, clear):
        app = self._app()
        slept = []
        with mock.patch("tuntop.ui.dashboard.time.sleep", slept.append), \
             mock.patch.object(dashboard.BTopTui, "_count_wintun_routes",
                               return_value=0), \
             mock.patch.object(dashboard.BTopTui, "_tun2socks_running",
                               return_value=False), \
             mock.patch.object(app, "_dump_route_table", return_value=[]), \
             mock.patch.object(app, "_geo_victim_rows",
                               return_value=clear), \
             mock.patch.object(app, "_cleanup_live_routes",
                               return_value=SweepResult.clean(0, 0)), \
             mock.patch.object(app, "_sweep_geo_leftovers",
                               return_value=SweepResult.clean(0, 0)), \
             mock.patch.object(app, "_sweep_lan_leftovers",
                               return_value=SweepResult.clean(0, 0)), \
             mock.patch.object(app, "_final_host_route_sweep",
                               return_value=True), \
             mock.patch.object(app, "_shutdown_teardown_wintun",
                               lambda: None), \
             mock.patch.object(app, "_sweep_dns_guard", return_value=True), \
             mock.patch.object(app, "_restore_route_snapshot",
                               return_value=(0, 0)), \
             mock.patch("tuntop.ui.dashboard._teardown_wintun"), \
             mock.patch.object(app, "_batch_delete_routes",
                               return_value=SweepResult.clean(0, 0)):
            app._shutdown_with_progress()
        return app, slept

    def test_a_verified_clean_quit_does_not_pause(self):
        """The 600ms beat existed only so the "safe to quit" screen could be
        read. On a clean exit there is nothing to read and nothing to act on."""
        _app_, slept = self._run(clear=[])
        self.assertNotIn(0.6, slept)

    def test_a_failed_verification_still_pauses_so_the_warning_can_be_read(self):
        _app_, slept = self._run(clear=[("5.0.0.0/8", "Wi-Fi", "")])
        self.assertIn(0.6, slept)


# ── the console-close handler must not wedge the app ─────────────────────────

class TestCtrlEventLiveness(unittest.TestCase):
    def test_a_window_close_is_fatal(self):
        self.assertTrue(dashboard._ctrl_event_is_fatal(
            dashboard.CTRL_CLOSE_EVENT))

    def test_logoff_and_shutdown_are_fatal(self):
        self.assertTrue(dashboard._ctrl_event_is_fatal(
            dashboard.CTRL_LOGOFF_EVENT))
        self.assertTrue(dashboard._ctrl_event_is_fatal(
            dashboard.CTRL_SHUTDOWN_EVENT))

    def test_ctrl_c_is_not_fatal(self):
        """Ctrl+C raises KeyboardInterrupt on the main thread and the process
        CARRIES ON, so the handler has to give `_shutting_down` back. It did
        not, and `_shutting_down` is only ever cleared in __init__ - so one
        Ctrl+C turned [Q] [S] [A] [T] [F] into silent no-ops and the dashboard
        could only be killed from Task Manager."""
        self.assertFalse(dashboard._ctrl_event_is_fatal(0))
        self.assertFalse(dashboard._ctrl_event_is_fatal(1))

    def test_an_unknown_code_does_not_wedge_the_app(self):
        # Fail towards leaving the app usable: a latched claim is unrecoverable,
        # a released one is re-taken by whichever teardown is next.
        self.assertFalse(dashboard._ctrl_event_is_fatal(None))
        self.assertFalse(dashboard._ctrl_event_is_fatal("nonsense"))

    def test_the_handler_releases_the_claim_on_a_survivable_event(self):
        """The finally block must clear it. (Source-level, because `_ctrl` is
        a closure inside main() and cannot be called directly.)"""
        import inspect
        src = inspect.getsource(dashboard.main)
        self.assertIn("app._stopping.clear()", src)
        # the reset is guarded by the liveness test, not unconditional
        self.assertIn("if not fatal:", src)
        self.assertIn("app._shutting_down = False", src)


# ── the crash handler must not deadlock on its own lock ──────────────────────

class TestCrashHandlerTeardownOwnership(unittest.TestCase):
    def test_the_owning_thread_is_recognised(self):
        app = _app()
        with app._teardown_guard():
            self.assertTrue(dashboard._crash_owns_teardown(app))
        self.assertFalse(dashboard._crash_owns_teardown(app))

    def test_another_thread_is_not_the_owner(self):
        app = _app()
        seen = []
        with app._teardown_guard():
            t = threading.Thread(target=lambda: seen.append(
                dashboard._crash_owns_teardown(app)))
            t.start()
            t.join(5)
        self.assertEqual(seen, [False],
                         "a DIFFERENT thread must take the normal stop() path")

    def test_reacquiring_from_the_owning_thread_would_deadlock(self):
        """The premise of the whole fix. `_teardown_lock` is a plain Lock, so
        this genuinely hangs - proven with a timeout rather than asserted."""
        app = _app()
        done = []

        def _reenter():
            with app._teardown_lock:
                done.append(1)

        with app._teardown_guard():
            t = threading.Thread(target=_reenter, daemon=True)
            t.start()
            t.join(0.5)
        self.assertEqual(done, [], "the plain Lock did NOT block - premise gone")
        # ...which is why the crash handler must not go through stop() here.
        self.assertTrue(dashboard._crash_owns_teardown(app) is False)

    def test_the_guard_clears_ownership_even_when_the_body_raises(self):
        app = _app()
        with self.assertRaises(RuntimeError):
            with app._teardown_guard():
                raise RuntimeError("crash inside the teardown")
        self.assertFalse(dashboard._crash_owns_teardown(app))
        # ...and the lock is genuinely free again.
        acquired = []
        t = threading.Thread(target=lambda: acquired.append(
            app._teardown_lock.acquire(timeout=2)))
        t.start()
        t.join(5)
        self.assertEqual(acquired, [True])

    def test_the_crash_handler_branches_on_ownership(self):
        import inspect
        src = inspect.getsource(dashboard.main)
        self.assertIn("_crash_owns_teardown(app)", src)
        self.assertIn("app.stop()", src)


# ── a dead daemon thread is no longer invisible ─────────────────────────────

class TestThreadCrashIsRecorded(unittest.TestCase):
    def _args(self, name="gw-geo-repoint"):
        try:
            raise ValueError("worker exploded")
        except ValueError:
            exc = sys.exc_info()
        t = threading.Thread(target=lambda: None, name=name)
        return types.SimpleNamespace(thread=t, exc_type=exc[0],
                                     exc_value=exc[1], exc_traceback=exc[2])

    def test_it_writes_the_traceback_to_the_crash_log(self):
        import tempfile
        log = os.path.join(tempfile.mkdtemp(), "crash.log")
        blog = mock.Mock()
        dashboard._record_thread_crash(self._args(), blog=blog, crash_log=log)
        with open(log, encoding="utf-8") as f:
            body = f.read()
        self.assertIn("gw-geo-repoint", body)
        self.assertIn("ValueError", body)
        self.assertIn("worker exploded", body)

    def test_it_also_reaches_the_ui(self):
        import tempfile
        blog = mock.Mock()
        dashboard._record_thread_crash(
            self._args("telemetry"), blog=blog,
            crash_log=os.path.join(tempfile.mkdtemp(), "c.log"))
        self.assertTrue(blog.called)
        self.assertIn("telemetry", str(blog.call_args))

    def test_it_falls_back_to_the_panel_when_blog_swallows_its_failure(self):
        """BTopTui._blog() swallows its own exceptions ON PURPOSE - it must never
        break the UI frame - so a crash inside it is indistinguishable from
        success. A caller that only wrapped `blog(...)` in try/except believes
        it notified the panel every time it did not. `log_lines` is the direct
        path that cannot fail that way."""
        import tempfile
        lines = []

        def _broken_blog(_msg):
            raise AttributeError("no such attribute: 'log_lines'")

        dashboard._record_thread_crash(
            self._args("telemetry"), blog=_broken_blog, log_lines=lines,
            crash_log=os.path.join(tempfile.mkdtemp(), "c.log"))
        self.assertEqual(len(lines), 1)
        self.assertIn("telemetry", lines[0])

    def test_an_unwritable_log_does_not_raise_into_the_interpreter(self):
        blog = mock.Mock()
        dashboard._record_thread_crash(self._args(), blog=blog,
                                       crash_log=r"\\?\NUL\bad\path.log")
        self.assertTrue(blog.called)      # still reached the UI

    def test_a_thread_with_no_name_still_records(self):
        import tempfile
        log = os.path.join(tempfile.mkdtemp(), "c.log")
        args = self._args()
        args.thread = threading.Thread(target=lambda: None)
        dashboard._record_thread_crash(args, crash_log=log)
        with open(log, encoding="utf-8") as f:
            self.assertIn("ValueError", f.read())

    def test_main_installs_the_hook(self):
        import inspect
        self.assertIn("threading.excepthook = _thread_crashed",
                      inspect.getsource(dashboard.main))


# ── a gateway change is coalesced, not dropped ──────────────────────────────

class TestGeoRePointCoalescing(unittest.TestCase):
    MARKER_A = ("[GATEWAY] Physical egress changed: "
                "Wi-Fi (192.168.1.1) -> Ethernet (10.0.0.1)")
    MARKER_B = ("[GATEWAY] Physical egress changed: "
                "Ethernet (10.0.0.1) -> Wi-Fi (192.168.2.1)")

    def _running(self):
        app = _app()
        app.proc = mock.Mock()
        app.proc.poll.return_value = None
        app._tel_lock = None
        app.baseline_bytes = [1]
        app._last_raw_rx = 1
        app._last_raw_tx = 1
        app.speed_hist = [1.0]
        app.rx_hist = [1.0]
        app.tx_hist = [1.0]
        return app

    def _wait(self, pred, timeout=5.0):
        deadline = time.time() + timeout
        while not pred() and time.time() < deadline:
            time.sleep(0.01)
        return pred()

    def test_a_second_change_is_drained_not_discarded(self):
        """The handler used to `return` when a re-point was already running,
        throwing away the new target - so the in-flight worker finished moving
        the routes to a now-superseded gateway and nothing moved them onto the
        one that replaced it. That country's traffic then stayed pinned to a
        dead gateway for the rest of the session."""
        app = self._running()
        started = threading.Event()
        release = threading.Event()
        calls = []

        def _slow(old, new, gw):
            calls.append((old, new, gw))
            started.set()
            release.wait(5)
            return 0

        with mock.patch.object(app, "_reroute_own_bypass_live"), \
             mock.patch.object(app, "_reroute_live_geo_rows", _slow):
            app._on_gateway_changed(self.MARKER_A)
            self.assertTrue(started.wait(5))
            # the second change lands WHILE the first is still running
            app._on_gateway_changed(self.MARKER_B)
            self.assertEqual(app._gw_geo_pending,
                             ("Ethernet", "Wi-Fi", "192.168.2.1"))
            release.set()
            self.assertTrue(self._wait(
                lambda: not app._gw_geo_repoint_active))
        self.assertEqual(calls, [
            ("Wi-Fi", "Ethernet", "10.0.0.1"),
            ("Ethernet", "Wi-Fi", "192.168.2.1"),
        ], "the queued target must be drained after the in-flight one")

    def test_repeated_changes_collapse_to_one_extra_pass(self):
        app = self._running()
        started = threading.Event()
        release = threading.Event()
        calls = []

        def _slow(old, new, gw):
            calls.append((old, new, gw))
            started.set()
            release.wait(5)
            return 0

        with mock.patch.object(app, "_reroute_own_bypass_live"), \
             mock.patch.object(app, "_reroute_live_geo_rows", _slow):
            app._on_gateway_changed(self.MARKER_A)
            self.assertTrue(started.wait(5))
            for _ in range(5):
                app._on_gateway_changed(self.MARKER_B)
            release.set()
            self.assertTrue(self._wait(
                lambda: not app._gw_geo_repoint_active))
        self.assertEqual(len(calls), 2,
                         "the newest target wins; the rest collapse away")

    def test_the_pending_slot_is_emptied_after_a_drain(self):
        app = self._running()
        with mock.patch.object(app, "_reroute_own_bypass_live"), \
             mock.patch.object(app, "_reroute_live_geo_rows", return_value=1):
            app._on_gateway_changed(self.MARKER_A)
            self.assertTrue(self._wait(
                lambda: not app._gw_geo_repoint_active))
        self.assertIsNone(app._gw_geo_pending)

    def test_a_raising_worker_releases_the_claim(self):
        app = self._running()
        with mock.patch.object(app, "_reroute_own_bypass_live"), \
             mock.patch.object(app, "_reroute_live_geo_rows",
                               side_effect=RuntimeError("boom")):
            app._on_gateway_changed(self.MARKER_A)
            self.assertTrue(self._wait(
                lambda: not app._gw_geo_repoint_active))
        self.assertTrue(app._blog.called)


class TestBypassRePointIsBatched(unittest.TestCase):
    """It looped per route: a scoped delete, a transaction add, the
    transaction's verify probe and - these are /32 host routes - its shadow()
    table probe. Four PowerShell process spawns PER ENTRY, on every live
    [A]/[N]/[V] apply and on every gateway change."""

    def _app(self, rows):
        app = _app()
        app.ns = types.SimpleNamespace(vless_over_vpn=False,
                                       vpn_interface=None)
        app._vpn_res_state = {}
        app._live_bypass_added = list(rows)
        app._SWEEP_CHUNK = 250
        app._SWEEP_WORKERS = 6
        return app

    def _run(self, app):
        with mock.patch("tuntop.ui.dashboard._get_ipv4_default",
                        return_value=("Ethernet", "10.0.0.1")), \
             mock.patch("tuntop.ui.dashboard._get_ipv6_default",
                        return_value=None), \
             mock.patch("tuntop.ui.dashboard._netsh_batch_result",
                        return_value=(250, True)) as batch, \
             mock.patch("tuntop.ui.dashboard._del_route_scoped") as per_route, \
             mock.patch.object(dashboard, "RouteTransaction") as txn:
            app._reroute_own_bypass_live()
            deadline = time.time() + 5
            while (app._live_bypass_added
                   and app._live_bypass_added[0][2] == "Wi-Fi"
                   and time.time() < deadline):
                time.sleep(0.01)
        txn.assert_not_called()
        per_route.assert_not_called()
        return batch.call_count

    def test_150_rows_cost_two_batches_not_600_processes(self):
        rows = [("v4", f"1.2.3.{i}/32", "Wi-Fi", "192.168.1.1")
                for i in range(150)]
        calls = self._run(self._app(rows))
        # 150 adds + 150 deletes = 2 chunks of 250 => at most 2 netsh batches
        self.assertLessEqual(calls, 2)

    def test_tracking_follows_the_table(self):
        app = self._app([("v4", "1.2.3.4/32", "Wi-Fi", "192.168.1.1")])
        with mock.patch("tuntop.ui.dashboard._get_ipv4_default",
                        return_value=("Ethernet", "10.0.0.1")), \
             mock.patch("tuntop.ui.dashboard._get_ipv6_default",
                        return_value=None), \
             mock.patch("tuntop.ui.dashboard._netsh_batch_result",
                        return_value=(1, True)):
            app._reroute_own_bypass_live()
            deadline = time.time() + 5
            while (app._live_bypass_added
                   and app._live_bypass_added[0][2] == "Wi-Fi"
                   and time.time() < deadline):
                time.sleep(0.01)
        self.assertEqual(app._live_bypass_added,
                         [("v4", "1.2.3.4/32", "Ethernet", "10.0.0.1")])

    def test_a_short_add_count_claims_nothing_and_keeps_the_old_rows(self):
        app = self._app([("v4", "1.2.3.4/32", "Wi-Fi", "192.168.1.1")])
        deleted = []
        with mock.patch("tuntop.ui.dashboard._get_ipv4_default",
                        return_value=("Ethernet", "10.0.0.1")), \
             mock.patch("tuntop.ui.dashboard._get_ipv6_default",
                        return_value=None), \
             mock.patch("tuntop.ui.dashboard._netsh_batch_result",
                        return_value=(0, True)), \
             mock.patch.object(app, "_batch_delete_routes",
                               side_effect=lambda r: deleted.extend(r)
                               or SweepResult.clean(len(r), len(r))):
            app._reroute_own_bypass_live()
            time.sleep(0.2)
        self.assertEqual(deleted, [], "nothing may be deleted on a short add")
        self.assertEqual(app._live_bypass_added,
                         [("v4", "1.2.3.4/32", "Wi-Fi", "192.168.1.1")],
                         "the old rows stay tracked, so [Q] still clears them")
        self.assertTrue(any("Re-pointed 0/1" in str(c)
                            for c in app._blog.call_args_list))


if __name__ == "__main__":
    unittest.main()

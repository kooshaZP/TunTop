"""Offline tests for the route-table snapshot/restore (no Windows calls).

The contract: after ANY exit the routing table looks exactly like it did
before the tunnel started. `_compute_route_diff` is the pure heart of that
guarantee - these tests pin its behaviour: missing snapshot entries are
re-added with their original metric/store, modified/foreign copies of
snapshot prefixes are deleted first, and Windows-managed noise (defaults,
multicast, wintun) never participates.
"""
import os
import sys
import threading
import unittest
from contextlib import ExitStack
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from tuntop.ui import dashboard


def _row(dest, alias, nh, metric=0, store="ActiveStore"):
    return {"DestinationPrefix": dest, "InterfaceAlias": alias,
            "NextHop": nh, "RouteMetric": metric, "Store": store}


class TestSnapshotRowFilter(unittest.TestCase):
    def test_normal_route_participates(self):
        self.assertTrue(dashboard.BTopTui._snapshot_row(
            _row("192.0.2.0/24", "Wi-Fi", "192.168.1.1")))

    def test_wintun_routes_never_participate(self):
        self.assertFalse(dashboard.BTopTui._snapshot_row(
            _row("0.0.0.0/1", "wintun", "192.168.123.1")))

    def test_defaults_and_windows_noise_never_participate(self):
        for dp in ("0.0.0.0/0", "::/0", "224.0.0.0/4",
                   "255.255.255.255/32", "127.0.0.0/8"):
            self.assertFalse(dashboard.BTopTui._snapshot_row(
                _row(dp, "Wi-Fi", "192.168.1.1")), dp)

    def test_malformed_rows_never_participate(self):
        self.assertFalse(dashboard.BTopTui._snapshot_row({"DestinationPrefix":
                                                          ""}))
        self.assertFalse(dashboard.BTopTui._snapshot_row(
            {"DestinationPrefix": "192.0.2.0/24", "InterfaceAlias": ""}))


class TestSnapshotKey(unittest.TestCase):
    def test_on_link_tokens_normalize(self):
        k1 = dashboard.BTopTui._snapshot_key("192.0.2.0/24", "Wi-Fi", "")
        self.assertEqual(
            k1, dashboard.BTopTui._snapshot_key("192.0.2.0/24", "Wi-Fi",
                                                "0.0.0.0"))
        self.assertEqual(
            k1, dashboard.BTopTui._snapshot_key("192.0.2.0/24", "wi-fi",
                                                "On-link"))


class TestComputeRouteDiff(unittest.TestCase):
    snap = [_row("192.0.2.0/24", "Wi-Fi", "192.168.1.1", metric=25),
            _row("198.51.100.0/24", "Ethernet", "10.0.0.1", metric=5,
                 store="PersistentStore")]

    def test_identical_tables_produce_no_diff(self):
        cur = [_row("192.0.2.0/24", "Wi-Fi", "192.168.1.1", metric=25),
               _row("198.51.100.0/24", "Ethernet", "10.0.0.1", metric=5,
                    store="PersistentStore")]
        to_del, to_add = dashboard.BTopTui._compute_route_diff(self.snap, cur)
        self.assertEqual((to_del, to_add), ([], []))

    def test_missing_snapshot_row_is_readded_with_metric_and_store(self):
        cur = [_row("192.0.2.0/24", "Wi-Fi", "192.168.1.1")]
        to_del, to_add = dashboard.BTopTui._compute_route_diff(self.snap, cur)
        self.assertEqual(to_del, [])
        self.assertEqual(to_add, [{"dest": "198.51.100.0/24",
                                   "iface": "Ethernet", "nh": "10.0.0.1",
                                   "metric": 5, "persistent": True}])

    def test_modified_copy_is_deleted_then_original_restored(self):
        # the session replaced the user's route via a different gateway
        cur = [_row("192.0.2.0/24", "Wi-Fi", "192.168.9.9", metric=1),
               _row("198.51.100.0/24", "Ethernet", "10.0.0.1")]
        to_del, to_add = dashboard.BTopTui._compute_route_diff(self.snap, cur)
        self.assertEqual(to_del, [("192.0.2.0/24", "Wi-Fi", "192.168.9.9")])
        self.assertEqual(to_add, [{"dest": "192.0.2.0/24", "iface": "Wi-Fi",
                                   "nh": "192.168.1.1", "metric": 25,
                                   "persistent": False}])

    def test_session_only_routes_are_ignored(self):
        # routes for prefixes the snapshot does not know are our own installs
        # (or mid-session user adds) - the sweeps own them, not the restore.
        cur = self.snap + [_row("203.0.113.0/24", "Wi-Fi", "192.168.1.1")]
        to_del, to_add = dashboard.BTopTui._compute_route_diff(self.snap, cur)
        self.assertEqual((to_del, to_add), ([], []))

    def test_wintun_noise_in_current_table_is_ignored(self):
        cur = self.snap + [_row("0.0.0.0/1", "wintun", "192.168.123.1")]
        to_del, to_add = dashboard.BTopTui._compute_route_diff(self.snap, cur)
        self.assertEqual((to_del, to_add), ([], []))


class TestFastDumpIntegration(unittest.TestCase):
    """Verify the |-delimited fast dump feeds _dump_route_table[_full]
    correctly (mock _ps — no Windows)."""

    def _app(self):
        return dashboard.BTopTui.__new__(dashboard.BTopTui)

    def test_base_dump_returns_three_key_dicts(self):
        text = ("192.0.2.0/24|Wi-Fi|192.168.1.1\n"
                "2001:db8::/64|Ethernet|2001:db8::1")
        with mock.patch("tuntop.network.routing._ps",
                        return_value=(True, text)):
            rows = self._app()._dump_route_table()
        self.assertEqual(len(rows), 2)
        for r in rows:
            self.assertIn("DestinationPrefix", r)
            self.assertIn("InterfaceAlias", r)
            self.assertIn("NextHop", r)
            self.assertNotIn("RouteMetric", r)
            self.assertNotIn("Store", r)

    def test_full_dump_returns_five_key_dicts(self):
        text = ("192.0.2.0/24|Wi-Fi|192.168.1.1|25|ActiveStore\n"
                "2001:db8::/64|Ethernet|2001:db8::1|0|PersistentStore")
        with mock.patch("tuntop.network.routing._ps",
                        return_value=(True, text)):
            rows = self._app()._dump_route_table_full()
        self.assertEqual(len(rows), 2)
        for r in rows:
            self.assertIn("DestinationPrefix", r)
            self.assertIn("InterfaceAlias", r)
            self.assertIn("NextHop", r)
            self.assertIn("RouteMetric", r)
            self.assertIn("Store", r)
        self.assertEqual(rows[0]["RouteMetric"], 25)
        self.assertEqual(rows[1]["Store"], "PersistentStore")

    def test_full_dump_empty_on_ps_failure(self):
        with mock.patch("tuntop.network.routing._ps",
                        return_value=(False, "No result")):
            rows = self._app()._dump_route_table_full()
        self.assertEqual(rows, [])


class TestShutdownVerifyDedupe(unittest.TestCase):
    """Verify _shutdown_with_progress's verify loop doesn't redundantly dump
    the routing table (mock _ps / high-level methods — no Windows)."""

    def _app(self):
        app = dashboard.BTopTui.__new__(dashboard.BTopTui)
        app._shutting_down = False
        app._stopping = threading.Event()
        app.recovery = mock.MagicMock()
        app.tunnel = mock.MagicMock()
        app.proc = None
        app._live_geo_added = []
        app._live_bypass_added = []
        app._sweep_progress_cb = mock.MagicMock()
        app._draw_shutdown = mock.MagicMock()
        app._cleanup_done = False
        app.running = True
        return app

    def _patch_all(self, app, *, count_wintun=0, tun2socks=False):
        """Enter all patches needed for _shutdown_with_progress and return
        a dict of the important mock objects."""
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.object(
            dashboard.BTopTui, "_count_wintun_routes", return_value=count_wintun))
        if isinstance(tun2socks, list):
            # Pad with the last value so every call (loop break check + final
            # post-loop check) gets a value without StopIteration.
            side = list(tun2socks) + [tun2socks[-1]] * 3
            stack.enter_context(mock.patch.object(
                dashboard.BTopTui, "_tun2socks_running", side_effect=side))
        else:
            stack.enter_context(mock.patch.object(
                dashboard.BTopTui, "_tun2socks_running",
                return_value=tun2socks))
        dump = stack.enter_context(mock.patch.object(
            app, "_dump_route_table", return_value=[]))
        stack.enter_context(mock.patch.object(
            app, "_geo_sweep_cidrs", return_value=set()))
        sweep = stack.enter_context(mock.patch.object(
            app, "_sweep_geo_leftovers", return_value=0))
        stack.enter_context(mock.patch.object(
            app, "_shutdown_teardown_wintun", lambda: None))
        stack.enter_context(mock.patch.object(
            app, "_sweep_lan_leftovers", return_value=0))
        stack.enter_context(mock.patch.object(
            app, "_final_host_route_sweep", return_value=None))
        stack.enter_context(mock.patch.object(
            app, "_restore_route_snapshot", return_value=(0, 0)))
        stack.enter_context(mock.patch(
            "tuntop.ui.dashboard._teardown_wintun"))
        stack.enter_context(mock.patch(
            "tuntop.ui.dashboard.time.sleep"))
        return {"dump": dump, "sweep": sweep}

    def test_clean_table_dumps_at_most_once(self):
        """Clean table (0 wintun, 0 geo, no tun2socks) → loop breaks on
        attempt 0. _dump_route_table is called once (by _leftover_geo_routes);
        _sweep_geo_leftovers is called once (task list, NOT verify retry)."""
        app = self._app()
        m = self._patch_all(app)
        app._shutdown_with_progress()
        self.assertLessEqual(m["dump"].call_count, 1)
        self.assertEqual(m["sweep"].call_count, 1)

    def test_clean_table_with_tun2socks_dumps_at_most_once(self):
        """Clean table but tun2socks alive — loop goes to attempt 1 to kill
        it, yet the dedup prevents a SECOND full-table dump (old code re-dumped
        via _sweep_geo_leftovers on attempt 1)."""
        app = self._app()
        m = self._patch_all(app, tun2socks=[True, False])
        app._shutdown_with_progress()
        self.assertLessEqual(m["dump"].call_count, 1)
        self.assertEqual(m["sweep"].call_count, 1)

    def test_geo_leftovers_triggers_re_sweep(self):
        """When geo leftovers exist, the verify loop MUST re-sweep on
        retry (dedup only skips re-sweeping a clean table)."""
        app = self._app()
        geo_row = [{"DestinationPrefix": "1.2.0.0/16",
                    "InterfaceAlias": "Wi-Fi", "NextHop": ""}]
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.object(
            dashboard.BTopTui, "_count_wintun_routes", return_value=0))
        stack.enter_context(mock.patch.object(
            dashboard.BTopTui, "_tun2socks_running", return_value=False))
        dump = stack.enter_context(mock.patch.object(
            app, "_dump_route_table", side_effect=[geo_row, geo_row, []]))
        stack.enter_context(mock.patch.object(
            app, "_geo_sweep_cidrs", return_value={"1.2.0.0/16"}))
        stack.enter_context(mock.patch.object(
            app, "_batch_delete_routes", return_value=1))
        sweep = stack.enter_context(mock.patch.object(
            app, "_sweep_geo_leftovers", wraps=app._sweep_geo_leftovers))
        stack.enter_context(mock.patch.object(
            app, "_shutdown_teardown_wintun", lambda: None))
        stack.enter_context(mock.patch.object(
            app, "_sweep_lan_leftovers", return_value=0))
        stack.enter_context(mock.patch.object(
            app, "_final_host_route_sweep", return_value=None))
        stack.enter_context(mock.patch.object(
            app, "_restore_route_snapshot", return_value=(0, 0)))
        stack.enter_context(mock.patch(
            "tuntop.ui.dashboard._teardown_wintun"))
        stack.enter_context(mock.patch(
            "tuntop.ui.dashboard.time.sleep"))
        app._shutdown_with_progress()
        # Attempt 0 dumps to find geo leftovers; attempt 1 re-sweeps after
        # the count pass. Each retry dumps at least once.
        self.assertGreaterEqual(dump.call_count, 2)
        # _sweep_geo_leftovers called from the task list + at least one retry.
        self.assertGreaterEqual(sweep.call_count, 2)


class TestRestoreRouteSnapshot(unittest.TestCase):
    def _app(self):
        # Build the object without running __init__ (no console/TUI setup).
        return dashboard.BTopTui.__new__(dashboard.BTopTui)

    def test_restore_without_snapshot_is_a_noop(self):
        app = self._app()
        app._route_snapshot = None
        self.assertEqual(app._restore_route_snapshot(), (0, 0))

    def test_restore_deletes_modified_and_readds_missing(self):
        app = self._app()
        app._route_snapshot = [
            _row("192.0.2.0/24", "Wi-Fi", "192.168.1.1", metric=25),
            _row("198.51.100.0/24", "Ethernet", "10.0.0.1", metric=5,
                 store="PersistentStore"),
        ]
        cur = [_row("192.0.2.0/24", "Wi-Fi", "192.168.9.9", metric=1)]
        deleted_rows = []
        added_rows = []
        with mock.patch.object(app, "_dump_route_table_full",
                               return_value=cur), \
             mock.patch.object(app, "_batch_delete_routes",
                               side_effect=lambda rows:
                               deleted_rows.extend(rows) or len(rows)), \
             mock.patch.object(app, "_batch_add_routes",
                               side_effect=lambda rows:
                               added_rows.extend(rows) or len(rows)):
            deleted, added = app._restore_route_snapshot()
        self.assertEqual((deleted, added), (1, 2))
        self.assertEqual(deleted_rows, [("192.0.2.0/24", "Wi-Fi",
                                         "192.168.9.9")])
        self.assertIn(("198.51.100.0/24", "Ethernet", "10.0.0.1", 5, True),
                      added_rows)
        self.assertIn(("192.0.2.0/24", "Wi-Fi", "192.168.1.1", 25, False),
                      added_rows)


class TestVpnPersistentRouteSurvival(unittest.TestCase):
    """Verify that shadowing a VPN route via _raw_add_route (non-destructive)
    means the persistent route survives in the table and the dashboard's
    _compute_route_diff does NOT flag it for re-creation at restore time."""

    snap = [_row("217.26.222.255/32", "VPN01", "10.8.0.1", metric=35,
                 store="PersistentStore")]

    def test_persistent_vpn_route_survives_shadow_and_needs_no_restore(self):
        # Current table after override_vpn_routes (using _raw_add_route):
        # the VPN's persistent route is untouched, alongside a Wintun shadow
        # at a lower metric.  Wintun rows are filtered out of the diff.
        cur = [
            _row("217.26.222.255/32", "VPN01", "10.8.0.1", metric=35,
                 store="PersistentStore"),
            _row("217.26.222.255/32", "wintun", "192.168.123.1", metric=1),
        ]
        to_del, to_add = dashboard.BTopTui._compute_route_diff(self.snap, cur)
        # No deletion needed — the VPN route is exactly as snapshotted.
        self.assertEqual(to_del, [])
        # No re-add needed — it was never deleted, so the restore is a no-op.
        self.assertEqual(to_add, [])


if __name__ == "__main__":
    unittest.main()

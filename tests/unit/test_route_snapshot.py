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
import unittest
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


if __name__ == "__main__":
    unittest.main()

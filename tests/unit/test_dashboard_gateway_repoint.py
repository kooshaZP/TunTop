"""Offline tests for the dashboard side of the gateway-change re-point.

The helper re-points ITS routes on a Wi-Fi/LAN change and prints a
[GATEWAY] marker; the routes the DASHBOARD installed live ([A] bypass
entries, live geo re-apply) are tracked dashboard-side and must follow.
These tests pin the marker handling and the batched geo re-point without
touching Windows (all route primitives mocked).
"""
import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from tuntop.ui import dashboard


def _app():
    app = dashboard.BTopTui.__new__(dashboard.BTopTui)
    app._blog = mock.Mock()
    app._live_geo_added = []
    app._iface_cache = ("Wi-Fi", "192.168.1.1")
    app._gw_geo_repoint_active = False
    return app


class TestRerouteLiveGeoRows(unittest.TestCase):
    def test_only_old_physical_v4_rows_move(self):
        app = _app()
        app._live_geo_added.extend([
            ("v4", "5.0.0.0/8", "Wi-Fi", "192.168.1.1"),      # moves
            ("v4", "31.13.0.0/16", "Wi-Fi", "192.168.1.1"),   # moves
            ("v4", "2.16.0.0/20", "Ethernet", "10.0.0.1"),    # other egress
            ("v4", "8.8.8.8/32", "wintun", "192.168.123.1"),  # tunneled geo
            ("v6", "2606:4700::/32", "Wi-Fi", "fe80::1"),     # v6 stays
        ])
        deleted = []
        added = []
        with mock.patch.object(app, "_batch_delete_routes",
                               side_effect=lambda rows:
                               deleted.extend(rows) or len(rows)), \
             mock.patch.object(app, "_batch_add_routes",
                               side_effect=lambda rows:
                               added.extend(rows) or len(rows)):
            n = app._reroute_live_geo_rows("Wi-Fi", "Ethernet", "10.0.0.1")
        self.assertEqual(n, 2)
        self.assertEqual(sorted(deleted),
                         [("31.13.0.0/16", "Wi-Fi", "192.168.1.1"),
                          ("5.0.0.0/8", "Wi-Fi", "192.168.1.1")])
        self.assertEqual(sorted(added),
                         [("31.13.0.0/16", "Ethernet", "10.0.0.1", 1, False),
                          ("5.0.0.0/8", "Ethernet", "10.0.0.1", 1, False)])
        # tracking follows the table so [Q] cleanup stays exact
        self.assertIn(("v4", "5.0.0.0/8", "Ethernet", "10.0.0.1"),
                      app._live_geo_added)
        self.assertNotIn(("v4", "5.0.0.0/8", "Wi-Fi", "192.168.1.1"),
                         app._live_geo_added)
        self.assertIn(("v6", "2606:4700::/32", "Wi-Fi", "fe80::1"),
                      app._live_geo_added)

    def test_no_matching_rows_is_a_noop(self):
        app = _app()
        with mock.patch.object(app, "_batch_delete_routes") as bd, \
             mock.patch.object(app, "_batch_add_routes") as ba:
            n = app._reroute_live_geo_rows("Wi-Fi", "Ethernet", "10.0.0.1")
        self.assertEqual(n, 0)
        bd.assert_not_called()
        ba.assert_not_called()


class TestOnGatewayChanged(unittest.TestCase):
    MARKER = ("[GATEWAY] Physical egress changed: "
              "Wi-Fi (192.168.1.1) -> Ethernet (10.0.0.1)")

    def _running_app(self):
        app = _app()
        app.proc = mock.Mock()
        app.proc.poll.return_value = None
        return app

    def test_marker_moves_bypass_and_geo(self):
        app = self._running_app()
        with mock.patch.object(app, "_reroute_own_bypass_live") as rb, \
             mock.patch.object(app, "_reroute_live_geo_rows",
                               return_value=3) as rg:
            app._on_gateway_changed(self.MARKER)
            rb.assert_called_once()
            deadline = time.time() + 5
            while rg.call_count == 0 and time.time() < deadline:
                time.sleep(0.02)
        rg.assert_called_once_with("Wi-Fi", "Ethernet", "10.0.0.1")
        self.assertIsNone(app._iface_cache)   # future [A] adds re-resolve
        # worker finished -> guard released
        deadline = time.time() + 5
        while app._gw_geo_repoint_active and time.time() < deadline:
            time.sleep(0.02)
        self.assertFalse(app._gw_geo_repoint_active)

    def test_stopped_tunnel_is_ignored(self):
        app = _app()
        app.proc = mock.Mock()
        app.proc.poll.return_value = 1     # exited
        with mock.patch.object(app, "_reroute_own_bypass_live") as rb:
            app._on_gateway_changed(self.MARKER)
        rb.assert_not_called()
        self.assertEqual(app._iface_cache, ("Wi-Fi", "192.168.1.1"))

    def test_unparseable_marker_still_repoints_bypass_only(self):
        app = self._running_app()
        with mock.patch.object(app, "_reroute_own_bypass_live") as rb, \
             mock.patch.object(app, "_reroute_live_geo_rows") as rg:
            app._on_gateway_changed("[GATEWAY] ???")
        rb.assert_called_once()
        rg.assert_not_called()


if __name__ == "__main__":
    unittest.main()

"""Offline tests for the WiFi/gateway-change auto re-route and the cleanup
ORDER fix (no network, no admin, no Windows calls).

Two regressions covered here:
  * a network change under a running tunnel used to leave every route pinned
    to the dead gateway - the helper now re-points them at the new one;
  * cleanup() used to run the slow bulk geo delete FIRST, so an Alt+F4 kill
    mid-cleanup skipped the endpoint /32+/128 removals - "the servers I
    added stay in the routing table". The order is now asserted.
"""
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from tuntop.tunnel import helper as H


class _HelperStateCase(unittest.TestCase):
    """Save/restore every helper global the code under test touches.

    The ledgers are restored IN PLACE (clear + extend): rebinding the module
    attribute to a plain list would break the next test in the class."""

    def setUp(self):
        self._saved = (
            list(H.added_routes), list(H.geoip_added),
            list(H.vpn_override_routes), list(H.vpn_saved_routes),
            H.wintun_saved_metric, H.cleaned, H.tun_proc, H.tun2_proc,
            H.phys_bypass_metric_saved, H.phys_bypass_iface,
            dict(H._live_mode), H._gw_pending, H._gw_pending_since,
        )

    def tearDown(self):
        def _restore_ledger(ledger, saved):
            ledger.clear()
            ledger.extend(saved)
        _restore_ledger(H.added_routes, self._saved[0])
        _restore_ledger(H.geoip_added, self._saved[1])
        _restore_ledger(H.vpn_override_routes, self._saved[2])
        H.vpn_saved_routes[:] = self._saved[3]
        (H.wintun_saved_metric, H.cleaned, H.tun_proc, H.tun2_proc) = \
            (self._saved[4], self._saved[5], self._saved[6], self._saved[7])
        (H.phys_bypass_metric_saved, H.phys_bypass_iface) = (self._saved[8],
                                                             self._saved[9])
        H._live_mode.clear()
        H._live_mode.update(self._saved[10])
        (H._gw_pending, H._gw_pending_since) = (self._saved[11],
                                                self._saved[12])


class TestRepointPinnedRoutes(_HelperStateCase):
    def test_v4_rows_on_old_egress_move_to_new_gateway(self):
        H.added_routes.extend([
            ("v4", "1.2.3.4/32", "Wi-Fi", "192.168.1.1"),   # pinned -> moves
            ("v4", "0.0.0.0/1", "wintun", "192.168.123.1"),  # TUN -> untouched
            ("v4", "5.6.7.8/32", "Ethernet", "10.0.0.1"),    # other egress
        ])
        adds = []
        with mock.patch.object(H, "add_v4",
                               side_effect=lambda d, i, g, metric=1:
                               adds.append((d, i, g, metric)) or True):
            moved = H._repoint_pinned_routes(
                "Wi-Fi", "192.168.1.1", "Wi-Fi", "192.168.2.1")
        self.assertEqual(moved, 1)
        self.assertEqual(adds, [("1.2.3.4/32", "Wi-Fi", "192.168.2.1", 1)])
        # the moved row left the tracking list - cleanup stays exact
        self.assertNotIn(("v4", "1.2.3.4/32", "Wi-Fi", "192.168.1.1"),
                         H.added_routes)

    def test_lan_bypass_repoints_at_its_own_metric(self):
        # seeded with the metric it was installed with (LAN bypass = 10):
        # the ledger keeps that fidelity and the re-point reproduces it.
        H.added_routes.append(("v4", "192.168.0.0/16", "Wi-Fi", "192.168.1.1"),
                              metric=10)
        adds = []
        with mock.patch.object(H, "add_v4",
                               side_effect=lambda d, i, g, metric=1:
                               adds.append((d, i, g, metric)) or True):
            H._repoint_pinned_routes(
                "Wi-Fi", "192.168.1.1", "Wi-Fi", "192.168.2.1")
        self.assertEqual(adds,
                         [("192.168.0.0/16", "Wi-Fi", "192.168.2.1", 10)])

    def test_v6_rows_move_only_with_a_new_v6_egress(self):
        H.added_routes.extend([
            ("v6", "2606:4700::1111/128", "Wi-Fi", "fe80::1"),
        ])
        v6adds = []
        with mock.patch.object(H, "get_ipv6_default", return_value=None), \
             mock.patch.object(H, "add_v6",
                               side_effect=lambda d, i, g, m=1:
                               v6adds.append(d) or True):
            moved = H._repoint_pinned_routes(
                "Wi-Fi", "192.168.1.1", "Wi-Fi", "192.168.2.1",
                old6=("Wi-Fi", "fe80::1"), new6=None)
        self.assertEqual(moved, 0)          # no new v6 egress -> nothing dies
        self.assertIn(("v6", "2606:4700::1111/128", "Wi-Fi", "fe80::1"),
                      H.added_routes)       # still tracked

        H.added_routes[:] = [("v6", "2606:4700::1111/128", "Wi-Fi", "fe80::1")]
        with mock.patch.object(H, "get_ipv6_default", return_value=None), \
             mock.patch.object(
                 H, "add_v6",
                 side_effect=lambda d, i, g, m=1: v6adds.append(d) or True):
            moved = H._repoint_pinned_routes(
                "Wi-Fi", "192.168.1.1", "Wi-Fi", "192.168.2.1",
                old6=("Wi-Fi", "fe80::1"), new6=("Wi-Fi", "fe80::2"))
        self.assertEqual(moved, 1)
        self.assertEqual(v6adds, ["2606:4700::1111/128"])


class TestRepointGeoRoutes(_HelperStateCase):
    def test_rows_on_old_iface_are_moved_and_rewritten(self):
        H.geoip_added.extend([
            ("v4", "5.0.0.0/8", "Wi-Fi", "192.168.1.1"),
            ("v4", "31.13.0.0/16", "Wi-Fi", "192.168.1.1"),
            ("v4", "2.16.0.0/20", "Ethernet", "10.0.0.1"),   # other egress
            ("v6", "2606:4700::/32", "Wi-Fi", "fe80::1"),
        ])
        order = []
        with mock.patch.object(H, "_remove_routes_bulk",
                               side_effect=lambda rows: order.append("delete")), \
             mock.patch.object(H, "_repoint_geo_batch",
                               side_effect=lambda rows: order.append("add") or len(rows)), \
             mock.patch.object(H, "get_ipv6_default",
                               return_value={"InterfaceAlias": "Wi-Fi",
                                             "NextHop": "fe80::9"}):
            n = H._repoint_geo_routes("Wi-Fi", "Wi-Fi", "192.168.2.1")
        self.assertEqual(n, 3)
        self.assertEqual(order, ["add", "delete"])
        # tracking rewritten: old rows gone, new rows in, foreign row kept
        self.assertNotIn(("v4", "5.0.0.0/8", "Wi-Fi", "192.168.1.1"),
                         H.geoip_added)
        self.assertIn(("v4", "5.0.0.0/8", "Wi-Fi", "192.168.2.1"),
                      H.geoip_added)
        self.assertIn(("v4", "2.16.0.0/20", "Ethernet", "10.0.0.1"),
                      H.geoip_added)

    def test_v6_rows_dropped_when_no_v6_default(self):
        H.geoip_added[:] = [("v6", "2606:4700::/32", "Wi-Fi", "fe80::1")]
        with mock.patch.object(H, "_remove_routes_bulk") as rm, \
             mock.patch.object(H, "_repoint_geo_batch") as batch, \
             mock.patch.object(H, "get_ipv6_default", return_value=None):
            n = H._repoint_geo_routes("Wi-Fi", "Wi-Fi", "192.168.2.1")
        self.assertEqual(n, 0)
        batch.assert_not_called()
        rm.assert_not_called()  # old route remains as the safe fallback


class TestCheckGatewayChange(_HelperStateCase):
    def _arm(self):
        H._live_mode.update({"phys": ("Wi-Fi", "192.168.1.1"),
                             "phys6": ("Wi-Fi", "fe80::1")})

    def test_same_gateway_is_a_noop(self):
        self._arm()
        with mock.patch.object(H, "get_ipv4_default",
                               return_value=("Wi-Fi", "192.168.1.1", 7)), \
             mock.patch.object(H, "_repoint_pinned_routes") as rep:
            H._check_gateway_change()
        rep.assert_not_called()

    def test_no_default_route_does_not_kill_the_helper(self):
        # get_ipv4_default sys.exit()s when no default exists - the monitor
        # must swallow that and try again later.
        self._arm()
        with mock.patch.object(H, "get_ipv4_default",
                               side_effect=SystemExit("[!] no route")):
            H._check_gateway_change()    # must not raise

    def test_change_is_debounced_then_applied(self):
        self._arm()
        H._gw_pending = None
        H._gw_pending_since = 0.0
        new = ("Wi-Fi", "192.168.2.1", 7)
        with mock.patch.object(H, "get_ipv4_default", return_value=new), \
             mock.patch.object(H, "get_ipv6_default",
                               return_value={"InterfaceAlias": "Wi-Fi",
                                             "NextHop": "fe80::2"}), \
             mock.patch.object(H, "_repoint_pinned_routes",
                               return_value=4) as rep, \
             mock.patch.object(H, "restore_physical_metric"), \
             mock.patch.object(H, "ensure_physical_metric_below_vpn"):
            H._check_gateway_change()          # first sight -> only pending
            rep.assert_not_called()
            H._gw_pending_since = time.time() - 3.0
            H._check_gateway_change()          # confirmed -> apply
        rep.assert_called_once_with("Wi-Fi", "192.168.1.1",
                                    "Wi-Fi", "192.168.2.1",
                                    old6=("Wi-Fi", "fe80::1"),
                                    new6=("Wi-Fi", "fe80::2"))
        self.assertEqual(H._live_mode["phys"], ("Wi-Fi", "192.168.2.1"))

    def test_geo_worker_thread_started_only_when_geo_rows_match(self):
        self._arm()
        H._gw_pending = None
        H._gw_pending_since = 0.0
        new = ("Wi-Fi", "192.168.2.1", 7)
        # _repoint_geo_routes MUST stay mocked: the worker runs against the
        # real module globals and could otherwise issue live netsh calls.
        with mock.patch.object(H, "get_ipv4_default", return_value=new), \
             mock.patch.object(H, "get_ipv6_default", return_value=None), \
             mock.patch.object(H, "_repoint_pinned_routes", return_value=0), \
             mock.patch.object(H, "_repoint_geo_routes", return_value=1) \
                 as rep_geo, \
             mock.patch.object(H, "restore_physical_metric"), \
             mock.patch.object(H, "ensure_physical_metric_below_vpn"):
            H._check_gateway_change()          # no geo rows -> no thread
            rep_geo.assert_not_called()
            H._gw_pending_since = time.time() - 3.0
            H.geoip_added.append(("v4", "5.0.0.0/8", "Wi-Fi",
                                  "192.168.1.1"))
            H._check_gateway_change()
        deadline = time.time() + 5
        while time.time() < deadline:
            if not any(t.name == "geo-repoint"
                       for t in __import__("threading").enumerate()):
                break
            time.sleep(0.05)
        rep_geo.assert_called_once_with("Wi-Fi", "Wi-Fi", "192.168.2.1")


class TestCleanupOrder(_HelperStateCase):
    """The Alt+F4 hole: critical host routes must be removed BEFORE the slow
    bulk geo delete, so an OS kill mid-cleanup can only ever leave geo
    routes (which the sweeps catch by CIDR)."""

    def test_added_routes_removed_before_geo_bulk(self):
        order = []

        def _rm(item):
            order.append(("host", item))

        def _bulk(routes):
            order.append(("geo", list(routes)))

        H.cleaned = False
        H.tun_proc = None
        H.tun2_proc = None
        H.wintun_saved_metric = None
        H.vpn_saved_routes[:] = []
        H.vpn_override_routes[:] = [
            ("v4", "10.0.0.0/1", "wintun", "192.168.123.1")]
        H.added_routes[:] = [
            ("v4", "1.2.3.4/32", "Wi-Fi", "192.168.1.1"),
            ("v4", "192.168.0.0/16", "Wi-Fi", "192.168.1.1"),
        ]
        H.geoip_added[:] = [("v4", "5.0.0.0/8", "Wi-Fi", "192.168.1.1")]
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        old_ctrl = H.CONTROL_FILE
        H.CONTROL_FILE = path
        try:
            with mock.patch.object(H, "remove_route", side_effect=_rm), \
                 mock.patch.object(H, "_remove_routes_bulk",
                                   side_effect=_bulk), \
                 mock.patch.object(H, "_raw_add_route"):
                H.cleanup()
        finally:
            H.CONTROL_FILE = old_ctrl
            try:
                os.unlink(path)
            except OSError:
                pass
        kinds = [k for k, _ in order]
        self.assertIn("geo", kinds)
        self.assertIn("host", kinds)
        # every host-route removal precedes the geo bulk delete
        first_geo = kinds.index("geo")
        self.assertTrue(all(i < first_geo
                            for i, k in enumerate(kinds) if k == "host"),
                        f"cleanup order was {order}")
        self.assertEqual(list(H.geoip_added), [])
        self.assertEqual(list(H.added_routes), [])


class TestOverrideVpnRoutes(_HelperStateCase):
    """Verify override_vpn_routes shadows VPN routes non-destructively via
    _raw_add_route (no netsh delete), preserving the VPN route and its
    persistent-store entry."""

    def setUp(self):
        super().setUp()
        self._saved_iface = H.vpn_override_iface

    def tearDown(self):
        H.vpn_override_iface = self._saved_iface
        super().tearDown()

    def _vpn_rows(self):
        """Two simulated VPN-injected routes."""
        return [
            {"DestinationPrefix": "217.26.222.255/32",
             "NextHop": "10.8.0.1", "RouteMetric": 35},
            {"DestinationPrefix": "217.26.222.0/24",
             "NextHop": "10.8.0.1", "RouteMetric": 100},
        ]

    def _fake_ps_json(self, rows):
        """ps_json returns `rows` for the IPv4 query, [] for IPv6."""
        def _fn(script):
            if "IPv4" in script:
                return rows
            return []
        return _fn

    def test_override_vpn_routes_uses_raw_add_route(self):
        H.vpn_saved_routes[:] = []
        H.vpn_override_routes[:] = []
        with mock.patch.object(H, "_set_wintun_interface_metric"), \
             mock.patch.object(H, "ps_json",
                               side_effect=self._fake_ps_json(self._vpn_rows())), \
             mock.patch.object(H, "_raw_add_route", return_value=True) as raw, \
             mock.patch.object(H, "add_v4") as a4, \
             mock.patch.object(H, "add_v6") as a6:
            H.override_vpn_routes("VPN01", set())
        # _raw_add_route called once per shadowed route (both IPv4 rows)
        self.assertTrue(raw.called)
        self.assertEqual(len(raw.call_args_list), 2)
        for c in raw.call_args_list:
            self.assertEqual(c.args[:1], ("v4",))
            self.assertEqual(c.kwargs.get("metric"), 1)
        # add_v4 / add_v6 must NOT be used for VPN shadow installation
        a4.assert_not_called()
        a6.assert_not_called()
        # ledgers populated
        self.assertEqual(len(H.vpn_saved_routes), 2)
        self.assertEqual(len(H.vpn_override_routes), 2)

    def test_override_vpn_routes_preserves_vpn_route(self):
        """Shadow installation only issues 'add route' - never 'delete route'
        for any VPN prefix (the old add_v4/add_v6 path did)."""
        deletes = []

        def _fake_run(cmd):
            if "delete" in cmd and "route" in cmd:
                deletes.append(list(cmd))
            return (0, "OK", "")

        with mock.patch.object(H, "_set_wintun_interface_metric"), \
             mock.patch.object(H, "ps_json",
                               side_effect=self._fake_ps_json(self._vpn_rows())), \
             mock.patch.object(H, "run", side_effect=_fake_run):
            H.override_vpn_routes("VPN01", set())
        # No delete-route call for any VPN prefix
        vpn_dests = {r["DestinationPrefix"] for r in self._vpn_rows()}
        for d in deletes:
            self.assertNotIn(d[4], vpn_dests, f"VPN route deleted: {d}")
        self.assertEqual(deletes, [])

    def test_vpn_shadow_restore_is_noop_when_route_intact(self):
        """After shadow install via _raw_add_route, the undo path restores
        saved VPN routes via _raw_add_route (add, not delete) and only
        remove_route's the Wintun shadows."""
        H.vpn_saved_routes[:] = []
        H.vpn_override_routes[:] = []
        with mock.patch.object(H, "_set_wintun_interface_metric"), \
             mock.patch.object(H, "ps_json",
                               side_effect=self._fake_ps_json(self._vpn_rows())), \
             mock.patch.object(H, "_raw_add_route", return_value=True) as raw, \
             mock.patch.object(H, "remove_route") as rm:
            H.override_vpn_routes("VPN01", set())
            ok = H._live_set_vpn_shadow(False)
        self.assertFalse(ok)
        # Undo removes only Wintun shadows (iface = TUN, never the VPN iface)
        rm.assert_called()
        for c in rm.call_args_list:
            item = c.args[0]
            self.assertEqual(item[2], H.TUN)
        # Restore re-adds each saved VPN route via _raw_add_route (add, not delete)
        restore_calls = [c for c in raw.call_args_list if c.args[2] == "VPN01"]
        self.assertEqual(len(restore_calls), 2)
        restored_dests = {c.args[1] for c in restore_calls}
        self.assertEqual(restored_dests,
                         {"217.26.222.255/32", "217.26.222.0/24"})
        # Ledgers cleared after restore
        self.assertEqual(len(H.vpn_override_routes), 0)
        self.assertEqual(len(H.vpn_saved_routes), 0)


if __name__ == "__main__":
    unittest.main()

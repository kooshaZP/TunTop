"""Offline tests for the helper's proxy-endpoint LOOP GUARD.

The failure this guards against: everything is fine - server IP set, proxy
client running - and then the TUN goes up, the proxy can no longer reach its
own server, and the connection dies with it. The cause is always the same:
the proxy transport's /32 bypass is missing or pinned to a tunnel adapter, so
the 0/0 and /1 splits we just installed capture it.

Installing the /32s BEFORE the default route is the right order but not a
proof, so the helper now re-reads the table after the default routes are live
and refuses to announce a ready tunnel while a transport would loop.

These tests use fake route rows and patched helpers: no Windows calls, no
Administrator rights, no real adapter.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from tuntop.tunnel import helper


def _row(alias, nexthop="192.168.1.1"):
    return {"DestinationPrefix": "203.0.113.7/32", "InterfaceAlias": alias,
            "NextHop": nexthop, "RouteMetric": 1}


class TestBadEndpointRows(unittest.TestCase):
    """`_bad_endpoint_rows` is the single definition of "this /32 will loop",
    shared by the startup guard and the 15 s self-heal so the two can never
    disagree."""

    def test_physical_route_is_healthy(self):
        bad, healthy = helper._bad_endpoint_rows([_row("Wi-Fi")], over=False)
        self.assertEqual(bad, [])
        self.assertTrue(healthy)

    def test_route_on_our_own_tun_is_bad(self):
        # The classic loop: the server /32 pinned to the tunnel it feeds.
        bad, healthy = helper._bad_endpoint_rows(
            [_row("wintun", "192.168.123.1")], over=False)
        self.assertEqual(len(bad), 1)
        self.assertFalse(healthy)

    def test_foreign_tun_adapters_are_also_bad(self):
        for alias in ("sing-tun Tunnel", "WireGuard Tunnel", "tun2socks",
                      "ZeroTier One"):
            with self.subTest(alias=alias):
                bad, healthy = helper._bad_endpoint_rows(
                    [_row(alias)], over=False)
                self.assertEqual(len(bad), 1, alias)
                self.assertFalse(healthy, alias)

    def test_direct_mode_refuses_a_vpn_interface(self):
        bad, healthy = helper._bad_endpoint_rows(
            [_row("Shirazu-VPN")], over=False)
        self.assertEqual(len(bad), 1)
        self.assertFalse(healthy)

    def test_over_vpn_mode_demands_the_validated_vpn_egress(self):
        vpn_eg = ("Shirazu-VPN", "10.8.0.1")
        good, healthy = helper._bad_endpoint_rows(
            [_row("Shirazu-VPN")], over=True, over_iface=vpn_eg)
        self.assertEqual(good, [])
        self.assertTrue(healthy)
        # ...and a route that resolved onto Wi-Fi is a mode violation.
        bad, healthy = helper._bad_endpoint_rows(
            [_row("Wi-Fi")], over=True, over_iface=vpn_eg)
        self.assertEqual(len(bad), 1)
        self.assertFalse(healthy)

    def test_no_rows_means_no_healthy_route(self):
        bad, healthy = helper._bad_endpoint_rows([], over=False)
        self.assertEqual(bad, [])
        self.assertFalse(healthy)

    def test_a_good_row_alongside_a_stale_bad_one_still_counts_healthy(self):
        rows = [_row("wintun", "192.168.123.1"), _row("Wi-Fi")]
        bad, healthy = helper._bad_endpoint_rows(rows, over=False)
        self.assertEqual(len(bad), 1)
        # Windows keeps the higher-metric copy; the heal removes just the bad
        # one instead of deleting a working bypass.
        self.assertTrue(healthy)


class TestVerifyEndpointsOffTun(unittest.TestCase):
    """The startup guard itself: it must (a) report a loop loudly, (b) try to
    repair it, and (c) only report the problem if the repair did not work."""

    def _guard(self, rows_by_dest, heal_result=None):
        live = {"v4": ["203.0.113.7"], "v6": [], "vpn_routes": [],
                "vless_over_vpn": False, "over": None, "phys": None}
        heal = heal_result if heal_result is not None else []

        def _rows(dest):
            return list(rows_by_dest.get(dest, []))

        with mock.patch.object(helper, "_live_mode", live), \
                mock.patch.object(helper, "get_existing_v4_routes",
                                  side_effect=_rows), \
                mock.patch.object(helper, "_heal_endpoint_routes",
                                  return_value=list(heal)):
            return helper.verify_endpoints_off_tun("test")

    def test_healthy_endpoint_passes_silently(self):
        ok, problems = self._guard({"203.0.113.7/32": [_row("Wi-Fi")]})
        self.assertTrue(ok)
        self.assertEqual(problems, [])

    def test_tunnel_pinned_endpoint_is_reported_and_repaired(self):
        # The table still shows the loop after the heal ran -> a real problem.
        ok, problems = self._guard(
            {"203.0.113.7/32": [_row("wintun", "192.168.123.1")]},
            heal_result=["[HEAL] VLESS 203.0.113.7 bypass re-installed"])
        self.assertFalse(ok)
        self.assertEqual(len(problems), 1)
        self.assertIn("203.0.113.7", problems[0])
        self.assertIn("tunnel adapter", problems[0])

    def test_missing_endpoint_is_reported(self):
        ok, problems = self._guard({})
        self.assertFalse(ok)
        self.assertIn("no /32 bypass route", problems[0])

    def test_repair_that_works_clears_the_problem(self):
        # First read shows the loop; after the heal the table is healthy, so
        # the guard must NOT report a problem (and must not leave the UI in
        # DEGRADED for something it just fixed).
        table = {"203.0.113.7/32": [_row("wintun", "192.168.123.1")]}
        live = {"v4": ["203.0.113.7"], "v6": [], "vpn_routes": [],
                "vless_over_vpn": False, "over": None, "phys": None}
        reads = {"n": 0}

        def _rows(dest):
            reads["n"] += 1
            return list(table.get(dest, []))

        def _heal():
            table["203.0.113.7/32"] = [_row("Wi-Fi")]
            return ["[HEAL] VLESS 203.0.113.7 bypass re-installed"]

        with mock.patch.object(helper, "_live_mode", live), \
                mock.patch.object(helper, "get_existing_v4_routes",
                                  side_effect=_rows), \
                mock.patch.object(helper, "_heal_endpoint_routes",
                                  side_effect=_heal):
            ok, problems = helper.verify_endpoints_off_tun("test")
        self.assertTrue(ok)
        self.assertEqual(problems, [])
        self.assertGreaterEqual(reads["n"], 2)   # re-read after repairing

    def test_no_endpoints_tracked_is_a_pass(self):
        live = {"v4": [], "v6": [], "vpn_routes": [], "vless_over_vpn": False,
                "over": None, "phys": None}
        with mock.patch.object(helper, "_live_mode", live), \
                mock.patch.object(helper, "get_existing_v4_routes",
                                  return_value=[]):
            ok, problems = helper.verify_endpoints_off_tun("test")
        self.assertTrue(ok)
        self.assertEqual(problems, [])

    def test_vpn_endpoint_routes_are_tracked_too(self):
        live = {"v4": [], "v6": [],
                "vpn_routes": [("v4", "198.51.100.9/32", "Wi-Fi", "192.168.1.1")],
                "vless_over_vpn": False, "over": None, "phys": None}
        with mock.patch.object(helper, "_live_mode", live):
            self.assertIn("198.51.100.9", helper._tracked_endpoint_ips())
        # A VPN endpoint route on a tunnel is just as fatal.
        with mock.patch.object(helper, "_live_mode", live), \
                mock.patch.object(helper, "get_existing_v4_routes",
                                  return_value=[_row("wintun", "192.168.123.1")]), \
                mock.patch.object(helper, "_heal_endpoint_routes",
                                  return_value=[]):
            ok, problems = helper.verify_endpoints_off_tun("test")
        self.assertFalse(ok)
        self.assertIn("198.51.100.9", problems[0])


class TestLocalSocksProbe(unittest.TestCase):
    def test_timeout_is_configurable(self):
        # The monitor calls this on a 1 Hz tick; a fixed 1.5 s connect would
        # stall gateway and endpoint healing behind a dead port.
        import inspect
        sig = inspect.signature(helper.test_local_socks)
        self.assertIn("timeout", sig.parameters)
        self.assertEqual(sig.parameters["timeout"].default, 1.5)

    def test_closed_port_reports_down(self):
        with mock.patch("socket.socket") as sock:
            sock.return_value.connect.side_effect = OSError("refused")
            self.assertFalse(helper.test_local_socks(1, timeout=0.01))
            sock.return_value.settimeout.assert_called_once_with(0.01)
            sock.return_value.close.assert_called_once()

    def test_open_port_reports_up(self):
        with mock.patch("socket.socket") as sock:
            sock.return_value.connect.side_effect = None
            self.assertTrue(helper.test_local_socks(10808, timeout=0.5))
            sock.return_value.connect.assert_called_once_with(
                ("127.0.0.1", 10808))


if __name__ == "__main__":
    unittest.main()

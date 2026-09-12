"""Unit tests for the routeops layer (pure logic, no Windows).

The ledger is the single source of route-tracking truth: these tests pin
its list-compatible surface AND its full-fidelity receipts (the whole
reason it exists - a route installed with metric=10 must still be known
with metric=10). The sweep matchers must agree across every exit path.
"""
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from tuntop.network.routeops import RouteLedger, RouteResult, sweeps


class TestRouteLedger(unittest.TestCase):
    def test_list_compatible_surface(self):
        led = RouteLedger("helper")
        led.append(("v4", "1.2.3.4/32", "Wi-Fi", "192.168.1.1"))
        led.extend([("v4", "10.0.0.0/8", "Wi-Fi", "192.168.1.1")])
        self.assertEqual(len(led), 2)
        self.assertTrue(bool(led))
        self.assertIn(("v4", "1.2.3.4/32", "Wi-Fi", "192.168.1.1"), led)
        self.assertEqual(list(led),
                         [("v4", "1.2.3.4/32", "Wi-Fi", "192.168.1.1"),
                          ("v4", "10.0.0.0/8", "Wi-Fi", "192.168.1.1")])
        led.remove(("v4", "1.2.3.4/32", "Wi-Fi", "192.168.1.1"))
        self.assertEqual(len(led), 1)
        with self.assertRaises(ValueError):
            led.remove(("v4", "nope/32", "x", "y"))
        led.clear()
        self.assertFalse(led)

    def test_metric_fidelity_survives_repoint_lookup(self):
        led = RouteLedger("helper")
        led.append(("v4", "192.168.0.0/16", "Wi-Fi", "192.168.1.1"),
                   metric=10)
        led.append(("v4", "1.2.3.4/32", "Wi-Fi", "192.168.1.1"))
        self.assertEqual(
            led.metric_of(("v4", "192.168.0.0/16", "Wi-Fi", "192.168.1.1")),
            10)
        self.assertEqual(
            led.metric_of(("v4", "1.2.3.4/32", "Wi-Fi", "192.168.1.1")), 1)
        self.assertEqual(
            led.metric_of(("v4", "unknown/32", "x", "y"), default=7), 7)

    def test_slice_assignment(self):
        led = RouteLedger("helper")
        led[:] = [("v4", "a/32", "i", "g"), ("v6", "b/128", "i", "")]
        self.assertEqual(len(led), 2)
        with self.assertRaises(TypeError):
            led[0] = ("v4", "c/32", "i", "g")

    def test_thread_safety_under_concurrent_mutation(self):
        led = RouteLedger("geo")
        errors = []

        def _writer(n):
            try:
                for i in range(200):
                    led.append(("v4", f"10.{n}.{i // 250}.0/24", "Wi-Fi", "g"))
                    led.remove(("v4", f"10.{n}.{i // 250}.0/24", "Wi-Fi", "g"))
            except Exception as e:      # pragma: no cover
                errors.append(e)

        threads = [threading.Thread(target=_writer, args=(n,))
                   for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(led), 0)


class TestRouteResult(unittest.TestCase):
    def test_unwrap_converts_systemexit(self):
        def _legacy_fail():
            sys.exit("[!] Cannot determine the gateway.")
        res = RouteResult.unwrap(_legacy_fail)
        self.assertFalse(res.ok)
        self.assertIn("Cannot determine", res.err)

    def test_unwrap_passes_through_value(self):
        res = RouteResult.unwrap(lambda: ("Wi-Fi", "192.168.1.1", 7))
        self.assertTrue(res.ok)
        self.assertEqual(res.value, ("Wi-Fi", "192.168.1.1", 7))


class TestSweeps(unittest.TestCase):
    def test_lan_victims_matches_watchdog_semantics(self):
        rows = [
            {"DestinationPrefix": "192.168.0.0/16", "InterfaceAlias": "Wi-Fi",
             "NextHop": "192.168.1.1"},
            {"DestinationPrefix": "10.0.0.0/8", "InterfaceAlias": "Wi-Fi",
             "NextHop": "On-link"},
            {"DestinationPrefix": "172.16.0.0/12", "InterfaceAlias": "Wi-Fi",
             "NextHop": "192.168.9.9"},          # stale pin
            {"DestinationPrefix": "172.16.0.0/12", "InterfaceAlias": "Eth",
             "NextHop": "192.168.9.9"},          # foreign iface
            {"DestinationPrefix": "203.0.113.0/24", "InterfaceAlias": "Wi-Fi",
             "NextHop": "192.168.1.1"},          # not a LAN prefix
        ]
        victims = sweeps.lan_victims(rows, "Wi-Fi", "192.168.1.1")
        self.assertEqual(victims, [
            ("192.168.0.0/16", "Wi-Fi", "192.168.1.1"),
            ("10.0.0.0/8", "Wi-Fi", "On-link"),
            ("172.16.0.0/12", "Wi-Fi", "192.168.9.9"),
        ])

    def test_geo_victims_exact_prefix_only(self):
        rows = [
            {"DestinationPrefix": "5.0.0.0/8", "InterfaceAlias": "Wi-Fi",
             "NextHop": "g"},
            {"DestinationPrefix": "5.1.2.3/32", "InterfaceAlias": "wintun",
             "NextHop": "t"},      # more-specific inside the range: NOT hit
        ]
        self.assertEqual(sweeps.geo_victims(rows, {"5.0.0.0/8"}),
                         [("5.0.0.0/8", "Wi-Fi", "g")])
        self.assertEqual(sweeps.geo_victims(rows, set()), [])

    def test_host_route_stmts_families(self):
        stmts = sweeps.host_route_stmts(["1.2.3.4", "2606:4700::1111"])
        self.assertEqual(len(stmts), 2)
        self.assertIn("'1.2.3.4/32'", stmts[0])
        self.assertIn("AddressFamily IPv4", stmts[0])
        self.assertIn("'2606:4700::1111/128'", stmts[1])
        self.assertIn("AddressFamily IPv6", stmts[1])


if __name__ == "__main__":
    unittest.main()

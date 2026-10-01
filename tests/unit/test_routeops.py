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

from tuntop.config.defaults import LAN_BYPASS_PREFIXES
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
             "NextHop": "192.168.9.9"},          # FOREIGN static route
            {"DestinationPrefix": "172.16.0.0/12", "InterfaceAlias": "Eth",
             "NextHop": "192.168.9.9"},          # foreign iface
            {"DestinationPrefix": "203.0.113.0/24", "InterfaceAlias": "Wi-Fi",
             "NextHop": "192.168.1.1"},          # not a LAN prefix
        ]
        victims = sweeps.lan_victims(rows, "Wi-Fi", "192.168.1.1")
        # The 172.16.0.0/12 row via 192.168.9.9 is NOT ours and is not
        # selected. "A real next-hop from a previous network" is not a
        # safety property - it is indistinguishable from a corporate static
        # route (a VPN split tunnel, a NAS subnet), and this function's
        # output goes straight into a netsh -f delete on both the [Q] exit
        # sweep and the crash watchdog. Genuinely-installed stale routes are
        # tracked in the RouteLedger (gateway + metric) so the exit sweep can
        # remove exactly what this run installed.
        self.assertEqual(victims, [
            ("192.168.0.0/16", "Wi-Fi", "192.168.1.1"),
            ("10.0.0.0/8", "Wi-Fi", "On-link"),
        ])

    def test_lan_victims_compares_cidrs_canonically(self):
        """Windows reports the canonical form; a prefix with host bits set
        must still match the LAN prefix it belongs to."""
        rows = [
            {"DestinationPrefix": "192.168.1.5/16", "InterfaceAlias": "Wi-Fi",
             "NextHop": "192.168.1.1"},
            {"DestinationPrefix": "2001:db8:0:0:0:0:0:0/32",
             "InterfaceAlias": "Wi-Fi", "NextHop": "::"},
        ]
        self.assertEqual(
            sweeps.lan_victims(rows, "Wi-Fi", "192.168.1.1",
                               prefixes=["192.168.0.0/16",
                                         "2001:db8::/32"]),
            [("192.168.0.0/16", "Wi-Fi", "192.168.1.1"),
             ("2001:db8::/32", "Wi-Fi", "::")])

    def test_lan_victims_interface_compare_is_case_insensitive(self):
        rows = [{"DestinationPrefix": "192.168.0.0/16",
                 "InterfaceAlias": "wi-fi ", "NextHop": "192.168.1.1"}]
        self.assertEqual(sweeps.lan_victims(rows, "Wi-Fi", "192.168.1.1"),
                         [("192.168.0.0/16", "wi-fi ", "192.168.1.1")])

    def test_lan_victims_honours_an_explicit_empty_prefix_list(self):
        """`prefixes=[]` must mean 'match nothing'; `prefixes or DEFAULT`
        silently fell back to the full 7-prefix default - the opposite of
        what the caller asked for."""
        rows = [{"DestinationPrefix": "192.168.0.0/16",
                 "InterfaceAlias": "Wi-Fi", "NextHop": "192.168.1.1"}]
        self.assertEqual(sweeps.lan_victims(rows, "Wi-Fi", "192.168.1.1",
                                           prefixes=[]), [])

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

    def test_geo_victims_match_ipv6_canonically(self):
        """THE regression: parse_geoip rendered IPv6 uncompressed
        ("2001:4860:0:0:0:0:0:0/32") while Get-NetRoute returns
        ("2001:4860::/32"), so a string compare missed EVERY IPv6 geo route
        and they survived every sweep - the bypass intent stayed armed
        against a dead tunnel.

        The prefix is Google's, not 2001:db8::/32: from Python 3.13
        `is_private` includes the documentation ranges, so 2001:db8::/32 is
        now correctly refused by `is_sweepable_geo_cidr` and a test built on
        it started failing for a reason that has nothing to do with the
        canonicalisation it is here to protect. (A documentation prefix is
        also something the install side refuses, so it was never a realistic
        geo range.)"""
        rows = [{"DestinationPrefix": "2001:4860::/32",
                 "InterfaceAlias": "Wi-Fi", "NextHop": "fe80::1"}]
        self.assertEqual(
            sweeps.geo_victims(rows, {"2001:4860:0:0:0:0:0:0/32"}),
            [("2001:4860::/32", "Wi-Fi", "fe80::1")])

    def test_geo_victims_refuse_ranges_the_install_would_refuse(self):
        """The sweep must not be WIDER than the install.

        `geo_victims` filtered nothing, so any prefix in a `.dat`'s country list
        was deleted. `helper._is_routable_bypass_cidr` refuses these before
        they are ever installed, and the invariant geoip.py states is that the
        sweep boundary has to refuse them too. The load-bearing case is CGNAT:
        `100.64.0.0/10` is in LAN_BYPASS_PREFIXES - so `_add_lan_bypass`
        installs it on every run - and it is NOT `is_private` on the 3.10-3.12
        CI matrix (it only became so in 3.13). So the install accepted it as a
        routable country range, the LAN bypass installed the same prefix, and
        the geo sweep then deleted TunTop's own route on every [R]/[F]->5, every
        [Q] and every watchdog pass - while CGNAT (Tailscale, mobile
        broadband) rode the physical NIC against the user's intent in between.
        """
        rows = [{"DestinationPrefix": c, "InterfaceAlias": "Wi-Fi",
                 "NextHop": "g"}
                for c in ("100.64.0.0/10", "10.0.0.0/8", "172.16.0.0/12",
                          "192.168.0.0/16", "169.254.0.0/16", "0.0.0.0/0",
                          "224.0.0.0/4", "127.0.0.0/8", "::/0",
                          "fe80::/10", "2001:db8::/32", "fc00::/7")]
        self.assertEqual(
            sweeps.geo_victims(rows, {r["DestinationPrefix"] for r in rows}),
            [], "the sweep deleted a range the install would have refused")

    def test_geo_victims_still_hit_public_ranges_including_cgnats_neighbours(self):
        """The filter must be a boundary, not a blanket refusal."""
        rows = [{"DestinationPrefix": "5.0.0.0/8", "InterfaceAlias": "Wi-Fi",
                 "NextHop": "g"},
                {"DestinationPrefix": "2606:4700::/32",
                 "InterfaceAlias": "Wi-Fi", "NextHop": "fe80::1"}]
        self.assertEqual(
            sweeps.geo_victims(rows, {"5.0.0.0/8", "2606:4700::/32"}),
            [("5.0.0.0/8", "Wi-Fi", "g"),
             ("2606:4700::/32", "Wi-Fi", "fe80::1")])

    def test_geo_victims_enforce_the_prefix_floor(self):
        """A /4 (v4) or /8 (v6) range is refused by install; the sweep must
        not delete the user's other halves of the address space if one turns
        up in a hand-built CIDR list."""
        rows = [{"DestinationPrefix": "0.0.0.0/4", "InterfaceAlias": "Wi-Fi",
                 "NextHop": "g"},
                {"DestinationPrefix": "::/8", "InterfaceAlias": "Wi-Fi",
                 "NextHop": "fe80::1"}]
        self.assertEqual(sweeps.geo_victims(rows, {"0.0.0.0/4"}), [])
        self.assertEqual(sweeps.geo_victims(rows, {"::/8"}), [])

    def test_cgnat_is_a_lan_bypass_prefix_the_sweep_must_not_eat(self):
        """Tie the two lists together: the prefix the LAN bypass installs is
        exactly the one the geo sweep used to remove."""
        self.assertIn("100.64.0.0/10", list(LAN_BYPASS_PREFIXES))
        self.assertFalse(sweeps.is_sweepable_geo_cidr("100.64.0.0/10"))

    def test_host_route_stmts_families(self):
        stmts = sweeps.host_route_stmts(["1.2.3.4", "2606:4700::1111"])
        self.assertEqual(len(stmts), 2)
        self.assertIn("'1.2.3.4/32'", stmts[0])
        self.assertIn("AddressFamily IPv4", stmts[0])
        self.assertIn("'2606:4700::1111/128'", stmts[1])
        self.assertIn("AddressFamily IPv6", stmts[1])

    def test_host_route_stmts_can_be_scoped_to_an_interface(self):
        """A bare Remove-NetRoute -DestinationPrefix deletes that prefix on
        EVERY interface - the exact pattern routing.py documents as forbidden
        ("TunTop must not delete a route it did not create"). Scoping stops
        the exit sweep from ripping a VPN-client-pinned host route off a
        corporate adapter."""
        stmts = sweeps.host_route_stmts(["1.2.3.4"], aliases=["Wi-Fi", "Eth"])
        self.assertEqual(len(stmts), 1)
        self.assertIn("Where-Object", stmts[0])
        self.assertIn("$_.InterfaceAlias -eq 'Wi-Fi'", stmts[0])
        self.assertIn("$_.InterfaceAlias -eq 'Eth'", stmts[0])

    def test_host_route_stmts_quote_rather_than_strip(self):
        """The old sanitiser stripped apostrophes (replace("'", "")) and left
        ';', '$(...)' and backticks intact. ps_quote doubles them."""
        stmts = sweeps.host_route_stmts(["1.2.3.4'; rm -rf x"])
        self.assertIn("1.2.3.4''; rm -rf x/32", stmts[0])


if __name__ == "__main__":
    unittest.main()

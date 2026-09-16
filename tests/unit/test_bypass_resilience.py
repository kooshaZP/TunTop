"""Offline tests for the 1.0.32 dashboard-side bypass fixes.

Covers the fixes that keep a bypass alive on a hostile machine:

1. `_bypass_routes_healthy`: the refresh cycle verifies that each DIRECT
   entry's routes still exist and are not TUN-pinned (the panel used to
   claim ROUTED DIRECT while a foreign TUN had stripped the route);
2. the bypass pre-clean deletes same-prefix routes pinned to live
   TUN-family adapters too (a Throne sing-tun stale /32 used to survive
   the pre-clean and outrank the fresh bypass);
3. `routing._tun_family_aliases` parses the joined adapter list and fails
   soft to [];
4. `routing._route_rows` parses single + multiple route rows;
5. `routing._get_vpn_ipv4_default` runs its PowerShell script ONCE (a
   duplicated `_ps(ps)` line used to run it twice).

No network, no admin, no real PowerShell - every Windows edge is mocked.
"""
import json
import unittest
from unittest import mock

import tuntop.network.routing as routing
import tuntop.ui.dashboard as dash
from tuntop.routes_txn import RouteTransaction
from tests.fakes import FakeRouter


class TestBypassRoutesHealthy(unittest.TestCase):
    """dash.BTopTui._bypass_routes_healthy with the route table stubbed."""

    def _call(self, rows_by_dest, ips=("1.2.3.4",)):
        def fake_rows(dest, fam="v4"):
            return rows_by_dest.get(dest, [])
        with mock.patch.object(dash, "_route_rows", fake_rows):
            fs = dash.BTopTui.__new__(dash.BTopTui)   # no __init__ needed
            return dash.BTopTui._bypass_routes_healthy(fs, list(ips))

    def test_physical_pin_is_healthy(self):
        self.assertTrue(self._call({
            "1.2.3.4/32": [{"InterfaceAlias": "Wi-Fi",
                            "NextHop": "192.168.1.1"}]}))

    def test_tun_pin_is_unhealthy(self):
        self.assertFalse(self._call({
            "1.2.3.4/32": [{"InterfaceAlias": "throne-tun",
                            "NextHop": "172.19.0.2"}]}))

    def test_missing_route_is_unhealthy(self):
        self.assertFalse(self._call({}))

    def test_v6_destinations_use_the_128_prefix(self):
        seen = []

        def fake_rows(dest, fam="v4"):
            seen.append((dest, fam))
            return [{"InterfaceAlias": "Wi-Fi", "NextHop": "fe80::1"}]
        with mock.patch.object(dash, "_route_rows", fake_rows):
            fs = dash.BTopTui.__new__(dash.BTopTui)
            self.assertTrue(dash.BTopTui._bypass_routes_healthy(
                fs, ["2606::7"]))
        self.assertEqual(seen, [("2606::7/128", "v6")])

    def test_verification_failure_never_blocks_the_resolver(self):
        def boom(*a, **k):
            raise RuntimeError("boom")
        with mock.patch.object(dash, "_route_rows", boom):
            fs = dash.BTopTui.__new__(dash.BTopTui)
            self.assertTrue(dash.BTopTui._bypass_routes_healthy(
                fs, ["1.2.3.4"]))


class TestPreCleanEvictsTunPinned(unittest.TestCase):
    """The pre-clean delete scope must include live TUN-family aliases."""

    class FakeSelf:
        def __init__(self):
            self._live_bypass_added = []
            self.blogs = []

        def _blog(self, m):
            self.blogs.append(m)

        def _get_vless_iface_gateway(self):
            return ("Wi-Fi", "192.168.1.1")

        def _get_vless_iface_gateway_v6(self):
            return None

    def _install(self, router, tun_aliases):
        known_seen = []

        def fake_scoped(dest, fam, known=()):
            known_seen.append(list(known))
            return True, False

        fs = self.FakeSelf()
        with mock.patch.object(dash, "_get_egress_for",
                               lambda ip: ("Wi-Fi", "192.168.1.1")), \
             mock.patch.object(dash, "_tun_family_aliases",
                               lambda: tun_aliases), \
             mock.patch.object(dash, "_del_route_scoped", fake_scoped), \
             mock.patch.object(dash, "RouteTransaction",
                               lambda log=None:
                               RouteTransaction(backend=router.backend(),
                                                log=log)):
            applied = dash.BTopTui._install_bypass_routes(
                fs, "srv.example", ["1.2.3.4"], [], log=False)
        return applied, known_seen

    def test_preclean_scope_includes_live_tun_adapters(self):
        applied, known_seen = self._install(FakeRouter(), ["throne-tun"])
        self.assertEqual(applied, ["1.2.3.4"])
        self.assertEqual(known_seen[0], ["Wi-Fi", "throne-tun"])

    def test_preclean_scope_dedupes_and_keeps_order(self):
        _, known_seen = self._install(FakeRouter(), ["Wi-Fi", "wintun2"])
        # 'Wi-Fi' appears once: planned egress and TUN alias deduplicated.
        self.assertEqual(known_seen[0], ["Wi-Fi", "wintun2"])


class TestTunFamilyAliases(unittest.TestCase):
    def _run(self, out, ok=True):
        seen = []

        def fake_ps(script, timeout=8):
            seen.append(script)
            return ok, out

        with mock.patch.object(routing, "_ps", fake_ps):
            return routing._tun_family_aliases(), seen

    def test_parses_joined_aliases(self):
        result, seen = self._run("throne-tun|wintun2")
        self.assertEqual(result, ["throne-tun", "wintun2"])
        self.assertIn("$tunAliases", seen[0])

    def test_none_or_empty_means_no_tuns(self):
        for out in ("none", "", "No result"):
            result, _ = self._run(out)
            self.assertEqual(result, [])

    def test_ps_failure_is_empty_list(self):
        result, _ = self._run("x", ok=False)
        self.assertEqual(result, [])


class TestRouteRows(unittest.TestCase):
    def _run(self, payload, ok=True):
        seen = []

        def fake_ps(script, timeout=8):
            seen.append(script)
            return ok, payload

        with mock.patch.object(routing, "_ps", fake_ps):
            return routing._route_rows("1.2.3.4/32"), seen

    def test_parses_a_single_row(self):
        rows, seen = self._run(json.dumps(
            {"InterfaceAlias": "Wi-Fi", "NextHop": "192.168.1.1"}))
        self.assertEqual(rows[0]["InterfaceAlias"], "Wi-Fi")
        self.assertIn("DestinationPrefix '1.2.3.4/32'", seen[0])
        self.assertIn("AddressFamily IPv4", seen[0])

    def test_parses_multiple_rows(self):
        rows, _ = self._run(json.dumps([{"InterfaceAlias": "a"},
                                        {"InterfaceAlias": "b"}]))
        self.assertEqual([r["InterfaceAlias"] for r in rows], ["a", "b"])

    def test_no_result_or_failure_is_empty(self):
        self.assertEqual(self._run("No result", ok=False)[0], [])
        self.assertEqual(self._run("", ok=False)[0], [])


class TestVpnDefaultRunsOnce(unittest.TestCase):
    def test_script_runs_a_single_time(self):
        seen = []

        def fake_ps(script, timeout=8):
            seen.append(script)
            return True, json.dumps({"InterfaceAlias": "V",
                                     "NextHop": "10.0.0.1"})

        with mock.patch.object(routing, "_ps", fake_ps):
            self.assertEqual(routing._get_vpn_ipv4_default(),
                             ("V", "10.0.0.1"))
        self.assertEqual(len(seen), 1)


if __name__ == "__main__":
    unittest.main()


"""Integration tier: routing TARGETS for the second SOCKS5 proxy (proxy2).

Exercises the dashboard's REAL _install_bypass_routes with target="proxy2"
against a fake route backend, proving:

* proxy2 routes point at the wintun2 adapter (its own address as next hop),
  NOT at the physical NIC, and never at a default route;
* direct targeting is unchanged (no proxy2 leakage into the default path);
* bookkeeping (_live_bypass_added) records wintun2 routes so the generic
  exit sweep cleans them without caring which target installed them;
* the crash-recovery teardown covers the wintun2 adapter (2.5 - the least
  exercised path, only runs after a hard kill).

Windows edges are patched with fakes exactly like
tests/integration/test_bypass_install_flow.py. No real adapter, no admin.

Run:  python -m unittest discover -s tests -t . -v
"""
import unittest
from unittest import mock

import tuntop.ui.dashboard as dash
import tuntop.network.routing as routing
from tuntop.core.startup_recovery import _wintun_route_count
from tuntop.routes_txn import RouteTransaction
from tests.fakes import FakeRouter

TUN2, TUN2_IP4, TUN2_IP6 = "wintun2", "192.168.124.1", "fd00:dead:beef:1::1"


class FakeSelf:
    """Just the attributes/methods _install_bypass_routes touches."""

    def __init__(self):
        self._live_bypass_added = []
        self.blogs = []

    def _blog(self, msg):
        self.blogs.append(msg)

    def _get_vless_iface_gateway(self):
        return ("Wi-Fi", "192.168.1.1")

    def _get_vless_iface_gateway_v6(self):
        return ("Wi-Fi", "fe80::1")

    def _tun2_constants(self):
        return TUN2, TUN2_IP4, TUN2_IP6


def run_install(ep4, ep6, router, target="direct"):
    """Call the real method with the Windows edges patched to `router`."""
    fs = FakeSelf()
    with mock.patch.object(dash, "_get_egress_for",
                           lambda ip: ("Wi-Fi", "192.168.1.1")), \
         mock.patch.object(dash, "RouteTransaction",
                           lambda log=None:
                           RouteTransaction(backend=router.backend(),
                                            log=log)):
        applied = dash.BTopTui._install_bypass_routes(
            fs, "example.com", ep4, ep6, log=False, target=target)
    return applied, fs


class TestProxy2Targeting(unittest.TestCase):
    def test_proxy2_routes_point_at_wintun2_not_the_physical_nic(self):
        router = FakeRouter()
        applied, fs = run_install(["1.2.3.4"], ["2606::7"], router,
                                  target="proxy2")
        self.assertEqual(applied, ["1.2.3.4", "2606::7"])
        self.assertEqual(router.table[("v4", "1.2.3.4/32")],
                         (TUN2, TUN2_IP4, 1))
        self.assertEqual(router.table[("v6", "2606::7/128")],
                         (TUN2, TUN2_IP6, 1))
        # The physical NIC must NOT appear anywhere in the applied routes.
        for fam, dest, iface, gw in fs._live_bypass_added:
            self.assertEqual(iface, TUN2, f"{dest} must ride {TUN2}")

    def test_proxy2_never_installs_a_default_route(self):
        # CRITICAL invariant: TUN2 only ever receives specific-destination
        # routes. Two adapters fighting over 0/0 is the routing-loop bug this
        # feature must never create.
        router = FakeRouter()
        run_install(["1.2.3.4", "5.6.7.8"], ["2606::7"], router,
                    target="proxy2")
        for (fam, dest) in router.table:
            self.assertNotIn(dest, ("0.0.0.0/0", "::/0",
                                    "0.0.0.0/1", "128.0.0.0/1"))

    def test_proxy2_ignores_the_egress_lookup(self):
        # Even with _get_egress_for poisoned to None, proxy2 routes still go
        # via wintun2 - the second hop has its own next hop by design, and a
        # missing physical egress must not block a proxy2 install.
        router = FakeRouter()
        fs = FakeSelf()
        with mock.patch.object(dash, "_get_egress_for", lambda ip: None), \
             mock.patch.object(dash, "RouteTransaction",
                               lambda log=None:
                               RouteTransaction(backend=router.backend())):
            applied = dash.BTopTui._install_bypass_routes(
                fs, "example.com", ["1.2.3.4"], [], log=False, target="proxy2")
        self.assertEqual(applied, ["1.2.3.4"])
        self.assertEqual(router.table[("v4", "1.2.3.4/32")][0], TUN2)

    def test_rollback_still_applies_for_proxy2(self):
        # A broken v6 add must roll the v4 wintun2 route back, same as direct.
        router = FakeRouter()
        router.silent_fail.add("2606::7/128")
        applied, fs = run_install(["1.2.3.4"], ["2606::7"], router,
                                  target="proxy2")
        self.assertEqual(applied, [])
        self.assertEqual(fs._live_bypass_added, [])
        self.assertNotIn(("v4", "1.2.3.4/32"), router.table)   # rolled back

    def test_bookkeeping_feeds_the_generic_exit_sweep(self):
        # The exit sweep removes whatever (fam, dest, iface, gw) tuples are in
        # _live_bypass_added - it must NOT care which target installed them.
        router = FakeRouter()
        applied, fs = run_install(["1.2.3.4"], ["2606::7"], router,
                                  target="proxy2")
        self.assertEqual(len(fs._live_bypass_added), 2)
        for fam, dest, iface, gw in fs._live_bypass_added:
            self.assertIn((fam, dest), router.table)   # installed + recorded


class TestDirectTargetingUnchanged(unittest.TestCase):
    def test_default_target_still_bypasses_via_physical_nic(self):
        router = FakeRouter()
        applied, fs = run_install(["1.2.3.4"], [], router, target="direct")
        self.assertEqual(applied, ["1.2.3.4"])
        self.assertEqual(router.table[("v4", "1.2.3.4/32")],
                         ("Wi-Fi", "192.168.1.1", 1))
        for fam, dest, iface, gw in fs._live_bypass_added:
            self.assertNotEqual(iface, TUN2)


class TestWintun2CrashRecovery(unittest.TestCase):
    """2.5: a hard kill with proxy2 active must not leave wintun2 behind."""

    def test_routing_teardown_covers_both_adapters(self):
        seen = []

        def fake_ps(script, *a, **k):
            seen.append(script)
            return True, ""

        with mock.patch.object(routing, "_ps", fake_ps):
            routing._teardown_wintun()
        joined = " ".join(seen)
        self.assertIn("'wintun'", joined)
        self.assertIn("'wintun2'", joined)   # the second pipe, not just primary

    def test_route_count_sums_both_adapters(self):
        def fake_ps(script, *a, **k):
            if "Get-NetRoute" not in script:
                return False, ""
            if "'wintun2'" in script:
                return True, "2"
            if "'wintun'" in script:
                return True, "3"
            return False, ""

        with mock.patch.object(routing, "_ps", fake_ps):
            self.assertEqual(_wintun_route_count(), 5)

    def test_dashboard_teardown_also_covers_wintun2(self):
        seen = []

        def fake_ps(script, *a, **k):
            seen.append(script)
            return True, ""

        with mock.patch.object(dash, "_ps", fake_ps):
            dash._teardown_wintun()
        joined = " ".join(seen)
        self.assertIn("'wintun'", joined)
        self.assertIn("'wintun2'", joined)


if __name__ == "__main__":
    unittest.main()



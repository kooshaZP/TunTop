"""Integration tier: the dashboard's REAL bypass-install code path.

Calls BTopTui._install_bypass_routes itself (the actual method, not a
copy) with only the Windows edges patched out: the egress lookup and the
transaction's route backend. Proves the transactional install, the
rollback-on-failure behaviour, and the cleanup bookkeeping the exit sweep
relies on - exactly the invariants that keep the routing table clean.

Run:  python -m unittest discover -s tests -t . -v
"""
import unittest
from unittest import mock

import tuntop.ui.dashboard as dash
from tests.fakes import FakeRouter
from tuntop.routes_txn import RouteTransaction


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


def run_install(ep4, ep6, router, log=False):
    """Call the real method with the Windows edges patched to `router`."""
    fs = FakeSelf()
    with mock.patch.object(dash, "_get_egress_for",
                           lambda ip: ("Wi-Fi", "192.168.1.1")), \
         mock.patch.object(dash, "RouteTransaction",
                           lambda log=None:
                           RouteTransaction(backend=router.backend(),
                                            log=log)):
        applied = dash.BTopTui._install_bypass_routes(
            fs, "example.com", ep4, ep6, log=log)
    return applied, fs


class TestSuccessfulInstall(unittest.TestCase):
    def test_all_v4_routes_applied_and_bookkept(self):
        router = FakeRouter()
        applied, fs = run_install(["1.2.3.4", "5.6.7.8"], [], router)
        self.assertEqual(applied, ["1.2.3.4", "5.6.7.8"])
        self.assertEqual(fs._live_bypass_added,
                         [("v4", "1.2.3.4/32", "Wi-Fi", "192.168.1.1"),
                          ("v4", "5.6.7.8/32", "Wi-Fi", "192.168.1.1")])
        self.assertIn(("v4", "1.2.3.4/32"), router.table)

    def test_both_families_apply_as_one_unit(self):
        router = FakeRouter()
        applied, fs = run_install(["1.2.3.4"], ["2606::7"], router)
        self.assertEqual(applied, ["1.2.3.4", "2606::7"])
        self.assertIn(("v4", "1.2.3.4/32"), router.table)
        self.assertIn(("v6", "2606::7/128"), router.table)
        self.assertEqual(len(fs._live_bypass_added), 2)

    def test_no_v6_gateway_skips_v6_but_installs_v4(self):
        router = FakeRouter()
        fs = FakeSelf()
        fs._get_vless_iface_gateway_v6 = lambda: None
        with mock.patch.object(dash, "_get_egress_for",
                               lambda ip: ("Wi-Fi", "192.168.1.1")), \
             mock.patch.object(dash, "RouteTransaction",
                               lambda log=None:
                               RouteTransaction(backend=router.backend())):
            applied = dash.BTopTui._install_bypass_routes(
                fs, "example.com", ["1.2.3.4"], ["2606::7"], log=False)
        self.assertEqual(applied, ["1.2.3.4"])
        self.assertNotIn(("v6", "2606::7/128"), router.table)


class TestRolledBackInstall(unittest.TestCase):
    def test_one_bad_route_rolls_back_the_whole_entry(self):
        # v6 routes come after v4: a broken v6 add must remove the v4
        # routes again AND leave the bookkeeping empty - the exit sweep
        # must never be asked to clean routes that are not installed.
        router = FakeRouter()
        router.silent_fail.add("2606::7/128")     # silent half-install
        applied, fs = run_install(["1.2.3.4"], ["2606::7"], router)
        self.assertEqual(applied, [])             # nothing counts as applied
        self.assertEqual(fs._live_bypass_added, [])
        self.assertNotIn(("v4", "1.2.3.4/32"), router.table)  # rolled back

    def test_hard_failure_rolls_back_and_logs(self):
        router = FakeRouter()
        router.fail_on["5.6.7.8/32"] = True
        applied, fs = run_install(["1.2.3.4", "5.6.7.8"], [], router,
                                  log=True)
        self.assertEqual(applied, [])
        self.assertNotIn(("v4", "1.2.3.4/32"), router.table)
        self.assertTrue(any("rolled back" in m for m in fs.blogs))
        self.assertTrue(any("5.6.7.8/32" in m for m in fs.blogs))

    def test_no_egress_at_all_installs_nothing(self):
        router = FakeRouter()
        with mock.patch.object(dash, "_get_egress_for",
                               lambda ip: None):
            fs = FakeSelf()
            applied = dash.BTopTui._install_bypass_routes(
                fs, "example.com", ["1.2.3.4"], [], log=False)
        self.assertEqual(applied, [])
        self.assertEqual(router.calls, [])        # backend never touched


if __name__ == "__main__":
    unittest.main()

"""Route-IDENTITY verification tests (1.0.27 / reviewer issue #1 and #2).

Windows keeps SEVERAL routes for one prefix (different iface / next-hop /
metric) - a prefix-only "add verified" is therefore not a verification.
These tests pin the identity-aware contract of routes_txn.Backend
(verify/table) and the pure matchers behind it:

  * an add is only accepted when OUR EXACT route (dest+iface+gateway+metric)
    is present and, for host routes, not shadowed by a foreign better-
    effective-metric route;
  * a remove is judged by OUR route's absence - a foreign co-existing
    same-prefix route must not fail it (and must not be deleted);
  * a failed op must never leak a live route (shadowed add is undone).

Run: python -m unittest discover -s tests -t . -v
"""
import unittest

from tests.fakes import FakeExactRouter
from tuntop.routes_txn import RouteTransaction, _is_host_route, _norm_gw
from tuntop.network.routing import _route_matches_rows, _route_table_rows


def _txn(router):
    return RouteTransaction(backend=router.backend())


class TestPureMatchers(unittest.TestCase):
    ROWS = [
        {"iface": "Wi-Fi", "nexthop": "10.0.0.1", "metric": 1, "ifmetric": 45},
        {"iface": "wintun", "nexthop": "0.0.0.0", "metric": 1, "ifmetric": 2},
    ]

    def test_exact_identity_hit(self):
        self.assertTrue(_route_matches_rows(self.ROWS, "v4", "Wi-Fi",
                                            "10.0.0.1", 1))

    def test_metric_mismatch_is_not_our_route(self):
        self.assertFalse(_route_matches_rows(self.ROWS, "v4", "Wi-Fi",
                                             "10.0.0.1", 5))

    def test_iface_case_insensitive(self):
        self.assertTrue(_route_matches_rows(self.ROWS, "v4", "wi-fi",
                                            "10.0.0.1"))

    def test_gateway_normalization_on_link(self):
        # ''/None/'0.0.0.0' are the same on-link next hop.
        self.assertTrue(_route_matches_rows(self.ROWS, "v4", "wintun",
                                            None, 1))
        self.assertTrue(_route_matches_rows(self.ROWS, "v4", "wintun",
                                            "0.0.0.0", 1))

    def test_v6_on_link_normalization(self):
        rows = [{"iface": "wintun", "nexthop": "::", "metric": 1,
                 "ifmetric": 2}]
        self.assertTrue(_route_matches_rows(rows, "v6", "wintun", ""))
        self.assertTrue(_route_matches_rows(rows, "v6", "wintun", None))

    def test_table_rows_sorted_by_effective(self):
        rows = _route_table_rows(self.ROWS, "v4")
        self.assertEqual(rows[0]["iface"], "wintun")   # 1+2 < 1+45
        self.assertEqual(rows[0]["eff"], 3)

    def test_host_route_gating(self):
        self.assertTrue(_is_host_route("1.2.3.4/32"))
        self.assertTrue(_is_host_route("2606:4700::1111/128"))
        self.assertFalse(_is_host_route("0.0.0.0/0"))
        self.assertFalse(_is_host_route("0.0.0.0/1"))
        self.assertFalse(_is_host_route("10.0.0.0/8"))
        self.assertFalse(_is_host_route("garbage"))

    def test_norm_gw(self):
        self.assertEqual(_norm_gw("v4", ""), "0.0.0.0")
        self.assertEqual(_norm_gw("v6", None), "::")


class TestHelperIdentityPresence(unittest.TestCase):
    """tunnel/helper._route_identity_present (startup path uses the PS row
    shape: InterfaceAlias/NextHop/RouteMetric)."""

    def setUp(self):
        try:
            from tuntop.tunnel.helper import _route_identity_present
        except Exception:                       # non-Windows import guard
            raise unittest.SkipTest("helper module needs Windows")
        self.fn = _route_identity_present

    def test_exact_present(self):
        rows = [{"InterfaceAlias": "Wi-Fi", "NextHop": "10.100.57.243",
                 "RouteMetric": 1}]
        self.assertTrue(self.fn(rows, "v4", "Wi-Fi", "10.100.57.243", 1))

    def test_foreign_iface_not_ours(self):
        rows = [{"InterfaceAlias": "Shirazu-VPN", "NextHop": "0.0.0.0",
                 "RouteMetric": 1}]
        self.assertFalse(self.fn(rows, "v4", "Wi-Fi", "10.100.57.243", 1))

    def test_wrong_metric_not_ours(self):
        rows = [{"InterfaceAlias": "Wi-Fi", "NextHop": "1.2.3.4",
                 "RouteMetric": 25}]
        self.assertFalse(self.fn(rows, "v4", "Wi-Fi", "1.2.3.4", 1))

    def test_on_link_normalization(self):
        rows = [{"InterfaceAlias": "VPN", "NextHop": "0.0.0.0",
                 "RouteMetric": 1}]
        self.assertTrue(self.fn(rows, "v4", "vpn", None, 1))


class TestTransactionIdentity(unittest.TestCase):
    def test_happy_add_verified_by_identity(self):
        r = FakeExactRouter()
        res = _txn(r).add_v4("1.2.3.4/32", "Wi-Fi", "192.168.1.1", 1).commit()
        self.assertTrue(res.ok)
        self.assertEqual(r.table[("v4", "1.2.3.4/32")][0]["iface"], "Wi-Fi")

    def test_silent_half_install_caught(self):
        r = FakeExactRouter()
        r.silent_fail.add("1.2.3.4/32")
        res = _txn(r).add_v4("1.2.3.4/32", "Wi-Fi", "192.168.1.1").commit()
        self.assertFalse(res.ok)
        self.assertIn("exact route", res.failed[0][1])

    def test_misdirected_add_caught(self):
        # netsh "succeeds" but the route lands on a different identity:
        # the old prefix-only check called this a pass; identity says no.
        r = FakeExactRouter()
        r.misdirect["1.2.3.4/32"] = ("wintun", None)
        res = _txn(r).add_v4("1.2.3.4/32", "Wi-Fi", "192.168.1.1").commit()
        self.assertFalse(res.ok)
        self.assertIn("exact route", res.failed[0][1])
        self.assertEqual(r.table[("v4", "1.2.3.4/32")][0]["iface"], "wintun")

    def test_shadowed_host_add_fails_and_is_undone(self):
        # A foreign /32 on a lower-metric interface owns the traffic: the
        # add verifies for presence but must FAIL the transaction - and the
        # failed op must not leave its (shadowed) route live behind.
        r = FakeExactRouter()
        r.ifmetric.update({"VPN": 25, "Wi-Fi": 4270})
        r.seed("1.2.3.4/32", "VPN", "0.0.0.0", 1)      # eff 26 vs our 4271
        res = _txn(r).add_v4("1.2.3.4/32", "Wi-Fi",
                             "10.0.0.1", 1).commit()
        self.assertFalse(res.ok)
        self.assertIn("shadowed", res.failed[0][1])
        self.assertEqual([row["iface"] for row in
                          r.table[("v4", "1.2.3.4/32")]], ["VPN"])

    def test_equal_metric_is_not_a_conflict(self):
        r = FakeExactRouter()
        r.ifmetric.update({"VPN": 25, "Wi-Fi": 25})
        r.seed("1.2.3.4/32", "VPN", "0.0.0.0", 1)
        res = _txn(r).add_v4("1.2.3.4/32", "Wi-Fi",
                             "10.0.0.1", 1).commit()
        self.assertTrue(res.ok)

    def test_default_route_coexistence_never_shadowed(self):
        # The split-default design INTENDS 0.0.0.0/0 to co-exist with the
        # machine's real default: shadow checks apply to host routes only.
        r = FakeExactRouter()
        r.ifmetric.update({"Wi-Fi": 2, "wintun": 4230})
        r.seed("0.0.0.0/0", "Wi-Fi", "192.168.1.1", 0)
        res = _txn(r).add_v4("0.0.0.0/0", "wintun",
                             "192.168.123.1", 1).commit()
        self.assertTrue(res.ok)

    def test_remove_of_foreign_shadowed_prefix_succeeds(self):
        # Deleting OUR /32 while a foreign same-prefix route remains: the
        # old prefix-level post-check reported failure. Identity says:
        # ours is gone = success, foreign untouched.
        r = FakeExactRouter()
        r.seed("9.9.9.9/32", "Static-Router", "10.0.0.1", 5)
        r.add("9.9.9.9/32", "Wi-Fi", "192.168.1.1", 1)
        res = _txn(r).remove_v4("9.9.9.9/32", "Wi-Fi", "192.168.1.1", 1)\
            .commit()
        self.assertTrue(res.ok)
        self.assertEqual([row["iface"] for row in
                          r.table[("v4", "9.9.9.9/32")]], ["Static-Router"])

    def test_delete_silently_failing_is_still_caught(self):
        r = FakeExactRouter()
        r.add("9.9.9.9/32", "Wi-Fi", "192.168.1.1", 1)
        r.fail_deletes = True                    # claims success, no-op
        res = _txn(r).remove_v4("9.9.9.9/32", "Wi-Fi", "192.168.1.1").commit()
        self.assertFalse(res.ok)
        self.assertIn("still in the table", res.failed[0][1])

    def test_remove_idempotent_when_already_gone(self):
        # netsh 'element not found' + our route genuinely absent = success.
        r = FakeExactRouter()
        res = _txn(r).remove_v4("9.9.9.9/32", "Wi-Fi", "192.168.1.1").commit()
        self.assertTrue(res.ok)

    def test_rollback_restores_removed_foreign_identity(self):
        # remove OK, second op fails: rollback re-adds the EXACT removed
        # row (identity preserved on the multi-slot table).
        r = FakeExactRouter()
        r.seed("8.8.8.8/32", "Wi-Fi", "192.168.1.1", 1)
        r.seed("8.8.8.8/32", "Backup", "10.9.8.7", 9)
        r.fail_on["7.7.7.7/32"] = True
        res = _txn(r).remove_v4("8.8.8.8/32", "Wi-Fi", "192.168.1.1", 1) \
            .add_v4("7.7.7.7/32", "Wi-Fi", "192.168.1.1").commit()
        self.assertFalse(res.ok)
        ifaces = sorted(row["iface"] for row in r.table[("v4", "8.8.8.8/32")])
        self.assertEqual(ifaces, ["Backup", "Wi-Fi"])   # ours restored
        self.assertEqual(r.table[("v4", "8.8.8.8/32")][
            ifaces.index("Wi-Fi")]["gateway"], "192.168.1.1")

    def test_legacy_backend_falls_back_to_prefix_exists(self):
        # Backends without verify/table (the old FakeRouter contract) must
        # keep working through the fallback - no behavior change for them.
        from tests.fakes import FakeRouter
        r = FakeRouter()
        res = RouteTransaction(backend=r.backend()) \
            .add_v4("1.1.1.1/32", "Wi-Fi", "10.0.0.1").commit()
        self.assertTrue(res.ok)
        r2 = FakeRouter()
        r2.silent_fail.add("1.1.1.1/32")
        res2 = RouteTransaction(backend=r2.backend()) \
            .add_v4("1.1.1.1/32", "Wi-Fi", "10.0.0.1").commit()
        self.assertFalse(res2.ok)


class TestBackendRemoveTupleUnpack(unittest.TestCase):
    def test_tuple_result_uses_removed_flag(self):
        # The old bool((False, True)) == True bug: a (removed=False,
        # foreign=True) tuple must surface as a FAILED remove.
        from tuntop.routes_txn import Backend, RouteOp
        seen = {}

        def del_v4(dest, iface, gw):
            return (False, True)               # nothing removed, foreign left

        def del_v6(dest, iface, gw):
            return (True, False)

        be = Backend(add_v4=lambda *a: True, exists_v4=lambda d: False,
                     del_v4=del_v4, add_v6=lambda *a: True,
                     exists_v6=lambda d: False, del_v6=del_v6)
        seen["v4"] = be.remove(RouteOp("remove", "v4", "1.1.1.1/32", "X"))
        seen["v6"] = be.remove(RouteOp("remove", "v6", "::1/128", "X"))
        self.assertFalse(seen["v4"])
        self.assertTrue(seen["v6"])


if __name__ == "__main__":
    unittest.main()

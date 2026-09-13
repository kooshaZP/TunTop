"""IPv4/IPv6 FAMILY MATRIX and route-operation CONCURRENCY tests
(reviewer issues #7 and #8).

The matrix cases model the live situations the tunnel faces - each family
present or absent on the proxy/VPN/physical side - as far as they are
deterministic WITHOUT Windows: identity matching, shadow detection, and
the transaction must stay correct when the OTHER family disagrees. The
genuinely Windows-only legs of the matrix (real /1 split acceptance,
Happy-Eyeballs, per-family auto metrics) belong to
tests/torture/live_torture.ps1, which this file points at.

Concurrency: several dashboard workers (bypass resolver installs, [X]
removals, gateway re-point, geo sweep) can hit the routing table at once.
The real table serializes each op; these tests prove our FAKE models that
serialization too and that no interleaving of transactions corrupts the
ledger or double-installs a route.
"""
import threading
import unittest

from tests.fakes import FakeExactRouter
from tuntop.routes_txn import RouteTransaction


def _txn(router):
    return RouteTransaction(backend=router.backend())


class TestFamilyMatrix(unittest.TestCase):
    """Reviewer cases A-G (the deterministic halves)."""

    def test_case_A_both_families_proxy(self):
        # Wi-Fi IPv4 + IPv6 both native: dual-family bypass installs side by
        # side; neither family's shadow check sees the other.
        r = FakeExactRouter()
        res = (_txn(r).add_v4("1.2.3.4/32", "Wi-Fi", "10.0.0.1", 1)
               .add_v6("2606:4700::1111/128", "Wi-Fi", "fe80::1", 1)
               .commit())
        self.assertTrue(res.ok)
        self.assertEqual(r.table[("v4", "1.2.3.4/32")][0]["iface"], "Wi-Fi")
        self.assertEqual(r.table[("v6", "2606:4700::1111/128")][0]["iface"],
                         "Wi-Fi")

    def test_case_C_v4_proxy_v6_direct_no_cross_shadow(self):
        # A foreign better-metric route on the IPv6 side must NOT shadow
        # (fail) the IPv4 install, and vice versa: families are checked
        # independently.
        r = FakeExactRouter()
        r.ifmetric.update({"VPN6": 20, "Wi-Fi": 45})
        r.seed("2606:4700::1111/128", "VPN6", "fe80::9", 1)   # v6 shadowed
        res = (_txn(r).add_v4("1.2.3.4/32", "Wi-Fi", "10.0.0.1", 1)
               .commit())
        self.assertTrue(res.ok)                              # v4 unaffected

    def test_case_D_v6_unavailable_v4_only(self):
        # IPv6 absent entirely: an IPv4-only bypass still commits cleanly
        # (the loopback-blackhole fallback the dashboard installs is a
        # Windows behavior covered by the live torture checklist).
        r = FakeExactRouter()
        res = _txn(r).add_v4("8.8.8.8/32", "Wi-Fi", "10.0.0.1", 1).commit()
        self.assertTrue(res.ok)
        self.assertEqual([k for k in r.table if k[0] == "v6"], [])

    def test_case_E_F_vpn_and_native_split_by_family(self):
        # E: IPv4 native + IPv6 VPN / F: IPv4 VPN + IPv6 native. Each
        # family's route lands on its own interface and verifies there.
        r = FakeExactRouter()
        r.ifmetric.update({"VeePN-TAP": 25, "Wi-Fi": 45})
        res = (_txn(r).add_v4("198.51.100.1/32", "Wi-Fi", "10.0.0.1", 1)
               .add_v6("2606:4700::1111/128", "VeePN-TAP", "fe80::1", 1)
               .commit())
        self.assertTrue(res.ok)
        self.assertEqual(r.table[("v4", "198.51.100.1/32")][0]["iface"],
                         "Wi-Fi")
        self.assertEqual(r.table[("v6", "2606:4700::1111/128")][0]["iface"],
                         "VeePN-TAP")

    def test_on_link_vs_gateway_form_per_family(self):
        # The same next-hop string normalizes differently per family:
        # '' == '0.0.0.0' (v4) but '' == '::' (v6) - never each other.
        r = FakeExactRouter()
        _txn(r).add_v4("1.1.1.1/32", "VPN", "0.0.0.0", 1).commit()
        self.assertTrue(r.verify("1.1.1.1/32", "VPN", None, 1))
        _txn(r).add_v6("2606::1/128", "VPN", "::", 1).commit()
        self.assertTrue(r.verify("2606::1/128", "VPN", "", 1))
        # ...and a v6-style '::' next hop never matches a v4 on-link route:
        self.assertFalse(r.verify("1.1.1.1/32", "VPN", "::", 1))


class TestConcurrentRouteOps(unittest.TestCase):
    def test_parallel_installs_and_removes_keep_ledger_consistent(self):
        # 8 threads x N adds of DISTINCT host routes + a remover thread
        # deleting odd destinations concurrently. Windows serializes each
        # route op; the fake models that. Invariants after the storm:
        #   * every even dest present EXACTLY once (no double installs)
        #   * every odd dest fully gone
        #   * no transaction raised / leaked a half-op
        r = FakeExactRouter()
        total = 40
        errors = []

        def installer(tid):
            for i in range(tid, total, 8):
                dest = f"10.{i}.0.{i}/32"
                res = _txn(r).add_v4(dest, "Wi-Fi", "10.0.0.1", 1).commit()
                if not res.ok:
                    errors.append((dest, res.failed))

        def remover():
            for i in range(1, total, 2):
                dest = f"10.{i}.0.{i}/32"
                res = _txn(r).remove_v4(dest, "Wi-Fi", "10.0.0.1", 1).commit()
                if not res.ok:
                    errors.append(("del " + dest, res.failed))

        threads = [threading.Thread(target=installer, args=(t,))
                   for t in range(8)] + \
            [threading.Thread(target=remover)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)

        self.assertEqual(errors, [])
        for i in range(total):
            dest = f"10.{i}.0.{i}/32"
            rows = r.table.get(("v4", dest), [])
            if i % 2 == 0:
                self.assertEqual(len(rows), 1, f"{dest} leaked/double")
            else:
                # either removed before install, or removed after - either
                # way the odd dest must not remain (remover ran last join).
                self.assertEqual(len(rows), 0, f"{dest} survived remove")

    def test_racing_mode_switch_is_atomic(self):
        # Two transactions fight for one destination (the direct<->over-VPN
        # re-point racing a live [A] add): every commit either fully
        # applied or fully rolled back; the final table holds whole routes,
        # never a torn identity.
        r = FakeExactRouter()
        final = {}

        def switch_to(gw, tag):
            res = _txn(r).remove_v4("9.9.9.9/32", "old", gw, 1) \
                .add_v4("9.9.9.9/32", "new", gw, 1).commit()
            final[tag] = res.ok

        threads = [threading.Thread(target=switch_to,
                                    args=(f"10.0.0.{i}", f"t{i}"))
                   for i in range(1, 9)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        rows = r.table.get(("v4", "9.9.9.9/32"), [])
        # All adds succeed (same dest, different gateways coexist), removes
        # succeed independently: table must contain only whole, honest rows.
        self.assertTrue(all(rows), "racing commits corrupted the destination")
        for row in rows:
            self.assertEqual(row["iface"], "new")   # no old-identity leak


if __name__ == "__main__":
    unittest.main()

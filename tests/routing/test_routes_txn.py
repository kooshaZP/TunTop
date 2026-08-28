"""Unit tests for tunmood.routes_txn - transactional route management.

Uses an in-memory fake backend (no Windows, no admin, no subprocesses) so
all-or-nothing semantics - including rollback under injected failures -
are verified deterministically on any OS.

Run:  python -m unittest discover -s tests -t . -v
"""
import unittest

from tests.fakes import FakeRouter
from tunmood.routes_txn import RouteOp, RouteTransaction


def txn_on(router, *ops_setup):
    txn = RouteTransaction(backend=router.backend())
    for fn in ops_setup:
        fn(txn)
    return txn


class TestHappyPath(unittest.TestCase):
    def test_empty_transaction_is_trivially_ok(self):
        result = txn_on(FakeRouter()).commit()
        self.assertTrue(result.ok)
        self.assertEqual(result.applied, [])

    def test_all_adds_apply_and_verify(self):
        r = FakeRouter()
        result = txn_on(
            r,
            lambda t: t.add_v4("1.2.3.4/32", "Wi-Fi", "192.168.1.1"),
            lambda t: t.add_v6("2606:4700::1111/128", "Wi-Fi", "fe80::1"),
        ).commit()
        self.assertTrue(result.ok)
        self.assertEqual(len(result.applied), 2)
        self.assertIn(("v4", "1.2.3.4/32"), r.table)
        self.assertIn(("v6", "2606:4700::1111/128"), r.table)

    def test_all_removes_apply_and_verify(self):
        r = FakeRouter()
        r.table[("v4", "9.9.9.9/32")] = ("Eth", "10.0.0.1", 5)
        result = txn_on(
            r, lambda t: t.remove_v4("9.9.9.9/32", "Eth", "10.0.0.1")
        ).commit()
        self.assertTrue(result.ok)
        self.assertNotIn(("v4", "9.9.9.9/32"), r.table)

    def test_mixed_add_and_remove(self):
        r = FakeRouter()
        r.table[("v4", "8.8.8.8/32")] = ("Eth", "10.0.0.1", 1)
        result = txn_on(
            r,
            lambda t: t.remove_v4("8.8.8.8/32", "Eth", "10.0.0.1"),
            lambda t: t.add_v4("1.1.1.1/32", "Wi-Fi", "192.168.1.1"),
        ).commit()
        self.assertTrue(result.ok)
        self.assertNotIn(("v4", "8.8.8.8/32"), r.table)
        self.assertIn(("v4", "1.1.1.1/32"), r.table)

    def test_chaining_and_ops_view(self):
        r = FakeRouter()
        txn = (RouteTransaction(backend=r.backend())
               .add_v4("1.2.3.4/32", "Wi-Fi")
               .add_v6("::1/128", "Lo"))
        self.assertEqual(len(txn), 2)
        self.assertEqual([op.action for op in txn.ops], ["add", "add"])


class TestRollback(unittest.TestCase):
    def test_mid_failure_rolls_back_earlier_adds(self):
        # 1.1.1.1 installs, 2.2.2.2 fails -> 1.1.1.1 must be REMOVED again:
        # the table ends exactly as it started (all-or-nothing).
        r = FakeRouter()
        r.fail_on["2.2.2.2/32"] = True
        result = txn_on(
            r,
            lambda t: t.add_v4("1.1.1.1/32", "Wi-Fi", "192.168.1.1"),
            lambda t: t.add_v4("2.2.2.2/32", "Wi-Fi", "192.168.1.1"),
            lambda t: t.add_v4("3.3.3.3/32", "Wi-Fi", "192.168.1.1"),
        ).commit()
        self.assertFalse(result.ok)
        self.assertEqual(len(result.failed), 1)
        self.assertEqual(result.failed[0][0].dest, "2.2.2.2/32")
        self.assertNotIn(("v4", "1.1.1.1/32"), r.table)   # rolled back
        self.assertNotIn(("v4", "3.3.3.3/32"), r.table)   # never attempted
        self.assertEqual([op.dest for op in result.rolled_back],
                         ["1.1.1.1/32"])

    def test_failed_add_after_a_removal_restores_the_removal(self):
        # Remove route A (ok), then a broken add aborts the run -> A must
        # come BACK with its original gateway and metric.
        r = FakeRouter()
        r.table[("v4", "9.9.9.9/32")] = ("Eth", "10.0.0.1", 7)
        r.fail_on["6.6.6.6/32"] = True
        result = txn_on(
            r,
            lambda t: t.remove_v4("9.9.9.9/32", "Eth", "10.0.0.1", metric=7),
            lambda t: t.add_v4("6.6.6.6/32", "Wi-Fi", "192.168.1.1"),
        ).commit()
        self.assertFalse(result.ok)
        self.assertIn(("v4", "9.9.9.9/32"), r.table)      # restored...
        self.assertEqual(r.table[("v4", "9.9.9.9/32")],
                         ("Eth", "10.0.0.1", 7))          # ...verbatim

    def test_rollback_is_reverse_order(self):
        r = FakeRouter()
        r.fail_on["3.3.3.3/32"] = True
        txn_on(
            r,
            lambda t: t.add_v4("1.1.1.1/32", "Wi-Fi"),
            lambda t: t.add_v4("2.2.2.2/32", "Wi-Fi"),
            lambda t: t.add_v4("3.3.3.3/32", "Wi-Fi"),
        ).commit()
        dels = [c for c in r.calls if c[0] == "del"]
        self.assertEqual([d[2] for d in dels],
                         ["2.2.2.2/32", "1.1.1.1/32"])    # reverse order

    def test_silent_half_install_is_caught_by_verify(self):
        # add() returns True but the prefix never lands: the transaction
        # must treat it as a failure and roll back - this is exactly the
        # "netsh said OK" trap the old per-route code fell into.
        r = FakeRouter()
        r.silent_fail.add("5.5.5.5/32")
        result = txn_on(
            r,
            lambda t: t.add_v4("1.1.1.1/32", "Wi-Fi"),
            lambda t: t.add_v4("5.5.5.5/32", "Wi-Fi"),
        ).commit()
        self.assertFalse(result.ok)
        self.assertIn("not in table", result.failed[0][1])
        self.assertNotIn(("v4", "1.1.1.1/32"), r.table)   # rolled back

    def test_stuck_deletion_is_caught_by_verify(self):
        r = FakeRouter()
        r.table[("v4", "9.9.9.9/32")] = ("Eth", "10.0.0.1", 1)
        r.fail_deletes = True
        result = txn_on(
            r, lambda t: t.remove_v4("9.9.9.9/32", "Eth", "10.0.0.1")
        ).commit()
        self.assertFalse(result.ok)
        self.assertIn("still routed", result.failed[0][1])

    def test_rollback_failure_is_recorded_never_raised(self):
        # A backend whose deletes always fail: rollback cannot undo the
        # first add - the result must record the error, not explode.
        r = FakeRouter()
        r.fail_on["2.2.2.2/32"] = True
        be = r.backend()
        be._del["v4"] = lambda dest, iface, gateway: False
        result = RouteTransaction(backend=be).add_v4(
            "1.1.1.1/32", "Wi-Fi").add_v4("2.2.2.2/32", "Wi-Fi").commit()
        self.assertFalse(result.ok)
        self.assertEqual(result.rolled_back, [])
        self.assertEqual(len(result.errors), 1)
        self.assertIn("1.1.1.1/32", result.errors[0])

    def test_raising_backend_is_caught(self):
        r = FakeRouter()

        def explode(dest, iface, gateway, metric=1):
            raise OSError("netsh exploded")

        be = r.backend()
        be._add["v4"] = explode
        result = RouteTransaction(backend=be).add_v4(
            "1.1.1.1/32", "Wi-Fi").commit()
        self.assertFalse(result.ok)
        self.assertIn("OSError", result.failed[0][1])


class TestProgressAndReporting(unittest.TestCase):
    def test_progress_callback_sees_every_op(self):
        r = FakeRouter()
        seen = []
        result = txn_on(
            r,
            lambda t: t.add_v4("1.1.1.1/32", "Wi-Fi"),
            lambda t: t.add_v6("2606::1/128", "Wi-Fi"),
        ).commit(progress=lambda done, total, op:
                 seen.append((done, total, op.dest)))
        self.assertTrue(result.ok)
        self.assertEqual([(d, t) for d, t, _ in seen], [(0, 2), (1, 2)])
        self.assertEqual([s[2] for s in seen],
                         ["1.1.1.1/32", "2606::1/128"])

    def test_broken_progress_callback_does_not_abort(self):
        r = FakeRouter()

        def boom(done, total, op):
            raise RuntimeError("bad UI")

        result = RouteTransaction(backend=r.backend()).add_v4(
            "1.1.1.1/32", "Wi-Fi").commit(progress=boom)
        self.assertTrue(result.ok)

    def test_failed_op_error_text_is_actionable(self):
        r = FakeRouter()
        r.fail_on["2.2.2.2/32"] = True
        lines = []
        RouteTransaction(backend=r.backend(),
                         log=lines.append).add_v4(
            "2.2.2.2/32", "Wi-Fi").commit()
        self.assertTrue(any("aborted" in ln for ln in lines))


if __name__ == "__main__":
    unittest.main()



"""Offline leak-probe tests (no network, no admin, no Windows calls).

Covers the leak-probe mechanics (tuntop/network/leak_probe.py): IP
validation, the corrected verdict matrix, endpoint racing (including the
straggler timeout bound), the health-check result mapping, and the
re-export chain that keeps the dashboard's monitor and the standalone
helper on ONE implementation.
"""
import sys
import os
import time
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from tuntop.network import leak_probe as L
from tuntop.monitor import leak as ML


class TestSingleImplementation(unittest.TestCase):
    """The dashboard monitor must re-export - never re-implement - the
    shared probe, and the helper must delegate to it."""

    def test_monitor_reexports_shared_probe(self):
        self.assertIs(ML.run_leak_probe, L.run_leak_probe)
        self.assertIs(ML.LEAK_TIMEOUT, L.LEAK_TIMEOUT)

    def test_helper_delegates_to_shared_probe(self):
        from tuntop.tunnel import helper as H
        with mock.patch.object(L, "run_leak_probe",
                               return_value=("leak", "msg-x", {})) as probe:
            self.assertEqual(H._leak_probe(10808), ("leak", "msg-x"))
        probe.assert_called_once_with(10808, timeout=5)


class TestValidIp(unittest.TestCase):
    def test_accepts_bare_ipv4(self):
        self.assertEqual(L._valid_ip("1.2.3.4"), "1.2.3.4")

    def test_accepts_bare_ipv6(self):
        self.assertEqual(L._valid_ip("2606:4700::1111"), "2606:4700::1111")

    def test_takes_first_line_only(self):
        self.assertEqual(L._valid_ip("5.6.7.8\nsomething else"), "5.6.7.8")

    def test_strips_whitespace(self):
        self.assertEqual(L._valid_ip("  5.6.7.8  "), "5.6.7.8")

    def test_rejects_html(self):
        self.assertIsNone(L._valid_ip("<html><body>1.2.3.4</body></html>"))

    def test_rejects_empty_and_none(self):
        self.assertIsNone(L._valid_ip(""))
        self.assertIsNone(L._valid_ip(None))
        self.assertIsNone(L._valid_ip("\n"))

    def test_rejects_invalid_octets(self):
        self.assertIsNone(L._valid_ip("999.1.2.3"))
        self.assertIsNone(L._valid_ip("not-an-ip"))


def _leg(ip=None, err=None, ms=0):
    return {"ip": ip, "err": err, "ms": ms}


class TestVerdictMatrix(unittest.TestCase):
    """The corrected semantics: direct == tunnel exit -> OK (nothing
    escapes); direct != tunnel exit -> LEAK."""

    def test_ok_when_exits_match(self):
        status, msg = L._verdict(_leg("1.1.1.1"), _leg("1.1.1.1"), 10808)
        self.assertEqual(status, "ok")
        self.assertIn("no leak", msg.lower())

    def test_leak_when_direct_differs(self):
        status, msg = L._verdict(_leg("9.9.9.9"), _leg("1.1.1.1"), 10808)
        self.assertEqual(status, "leak")
        self.assertIn("9.9.9.9", msg)
        self.assertIn("1.1.1.1", msg)

    def test_no_proxy_when_tunnel_leg_dead(self):
        status, msg = L._verdict(_leg("9.9.9.9"), _leg(None, "refused"), 10808)
        self.assertEqual(status, "no-proxy")
        self.assertIn("10808", msg)

    def test_inconclusive_when_direct_leg_dead(self):
        status, _ = L._verdict(_leg(None, "timeout"), _leg("1.1.1.1"), 10808)
        self.assertEqual(status, "inconclusive")

    def test_no_network_when_both_dead(self):
        status, _ = L._verdict(_leg(None, "x"), _leg(None, "y"), 10808)
        self.assertEqual(status, "no-network")


class TestAsCheckResult(unittest.TestCase):
    def test_ok_passes(self):
        self.assertEqual(ML.as_check_result("ok", "m"), (True, "m"))

    def test_leak_fails(self):
        self.assertEqual(ML.as_check_result("leak", "m"), (False, "m"))

    def test_no_proxy_and_no_network_fail(self):
        self.assertFalse(ML.as_check_result("no-proxy", "m")[0])
        self.assertFalse(ML.as_check_result("no-network", "m")[0])

    def test_inconclusive_passes_with_detail(self):
        # The tunnel leg was proven fine; a mute direct probe is not a
        # tunnel fault.
        self.assertEqual(ML.as_check_result("inconclusive", "m"), (True, "m"))


class TestRaceLeg(unittest.TestCase):
    def test_first_valid_ip_wins_over_junk(self):
        def fake_fetch(scheme, host, path, timeout):
            if host == "api.ipify.org":
                raise OSError("blocked")
            if host == "icanhazip.com":
                return "<html>portal</html>"      # junk: must be discarded
            return "4.3.2.1"
        with mock.patch.object(L, "_ECHO_ENDPOINTS",
                               [("https", "api.ipify.org", "/"),
                                ("http", "icanhazip.com", "/"),
                                ("https", "ifconfig.me", "/ip")]):
            out = L._race_leg(fake_fetch, timeout=2)
        self.assertEqual(out["ip"], "4.3.2.1")

    def test_all_fail_reports_error(self):
        def fake_fetch(scheme, host, path, timeout):
            raise OSError("down")
        out = L._race_leg(fake_fetch, timeout=1)
        self.assertIsNone(out["ip"])
        self.assertIsNotNone(out["err"])

    def test_race_is_concurrent(self):
        def fake_fetch(scheme, host, path, timeout):
            time.sleep(0.3)
            return "4.3.2.1"
        with mock.patch.object(L, "_ECHO_ENDPOINTS",
                               [("https", f"h{i}.example", "/")
                                for i in range(4)]):
            t0 = time.time()
            out = L._race_leg(fake_fetch, timeout=2)
        self.assertEqual(out["ip"], "4.3.2.1")
        self.assertLess(time.time() - t0, 1.0, "endpoints were not raced")


class TestRunLeakProbe(unittest.TestCase):
    def test_status_propagates(self):
        legs = {"direct": _leg("9.9.9.9"), "tunnel": _leg("1.1.1.1")}
        with mock.patch.object(L, "_race_leg", side_effect=[
                legs["direct"], legs["tunnel"]]):
            status, msg, out = L.run_leak_probe(10808)
        self.assertEqual(status, "leak")
        self.assertIn("9.9.9.9", msg)
        self.assertIn("direct", out)

    def test_legs_run_concurrently(self):
        def slow_leg(fetcher, timeout):
            time.sleep(0.3)
            return _leg("1.1.1.1")
        with mock.patch.object(L, "_race_leg", side_effect=slow_leg):
            t0 = time.time()
            status, _, _ = L.run_leak_probe(10808)
        self.assertEqual(status, "ok")
        self.assertLess(time.time() - t0, 1.0, "legs were not concurrent")


class TestRaceStragglerBound(unittest.TestCase):
    def test_race_leg_returns_despite_hung_endpoint(self):
        """Simulates the DNS-blackhole case: getaddrinfo() hangs beyond any
        socket timeout, so the worker thread is still running when the wait
        budget expires. _race_leg must return on budget anyway (it must
        NEVER join the executor) - otherwise the helper's monitor/self-heal
        loop stalls with no ceiling."""
        release = threading.Event()

        def hang(scheme, host, path, timeout):
            # Stands in for an unbounded getaddrinfo(): ignores its
            # timeout, blocked until released (5 s cap so a forgotten
            # release can never hang the suite at interpreter exit).
            release.wait(5)
            return "1.2.3.4"

        with mock.patch.object(L, "_ECHO_ENDPOINTS",
                               [("https", "hang.example", "/")]):
            t0 = time.time()
            out = L._race_leg(hang, timeout=0.5)
            dt = time.time() - t0
            ip_snapshot = out["ip"]
        # Only now let the abandoned worker finish (it may still write into
        # the returned dict afterwards - that is expected and harmless).
        release.set()
        self.assertIsNone(ip_snapshot)
        # The wait budget is timeout + 2; assert we returned close to it
        # instead of blocking for the (unbounded) hang duration.
        self.assertLess(dt, 4.0, f"race leg joined the hung thread ({dt:.1f}s)")


if __name__ == "__main__":
    unittest.main()

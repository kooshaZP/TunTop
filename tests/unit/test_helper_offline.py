"""Offline helper-logic tests (no network, no admin, no Windows calls).

Covers the CONCURRENT monitor probe (see TestProbeTunnelMultiConcurrent) and
the pre-install geo conflict sweep parsing (see TestGeoSweepHits).
"""
import sys
import os
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from tuntop.tunnel import helper as H


class TestProbeTunnelMultiConcurrent(unittest.TestCase):
    def test_success_wins_over_fast_failing_endpoint(self):
        """ipify fails fast (the field-reported handshake case), gstatic is
        slow but succeeds: the verdict must be OK, not the ipify failure."""
        calls = []

        def fake_probe(url, timeout=5):
            calls.append(url)
            if "ipify" in url:
                time.sleep(0.2)
                return False, ("api.ipify.org resolved (...) but fetch "
                               "failed: handshake")
            time.sleep(0.5)
            return True, f"{url} resolved -> 1.2.3.4; public IP = 5.6.7.8"

        with mock.patch.object(H, "_probe_tunnel_once", side_effect=fake_probe):
            t0 = time.time()
            ok, msg = H._probe_tunnel_multi(timeout=4)
            dt = time.time() - t0
        self.assertTrue(ok, f"expected OK, got {msg}")
        self.assertLess(dt, 1.0, "probe was not concurrent")
        self.assertEqual(len(set(calls)), 4,
                         f"expected all 4 endpoints probed, calls={calls}")

    def test_total_failure_lists_every_endpoint(self):
        def fake_fail(url, timeout=5):
            return False, f"{url} resolved but fetch failed: <timeout>"

        with mock.patch.object(H, "_probe_tunnel_once", side_effect=fake_fail):
            ok, msg = H._probe_tunnel_multi(timeout=2)
        self.assertFalse(ok)
        self.assertIn("ipify", msg)
        self.assertIn("gstatic", msg)


class TestGeoSweepHits(unittest.TestCase):
    """Parsing for the pre-install geo conflict sweep: the scan that cleans
    the stale routes an Alt+F4 (hard console close, no cleanup) leaves on the
    physical adapter."""

    def test_parses_and_dedupes_pairs(self):
        out = ("5.0.0.0/8|Wi-Fi\n"
               "5.0.0.0/8|Wi-Fi\n"          # same prefix+iface (diff next-hop) -> deduped
               "31.13.0.0/16|Wi-Fi\n"
               "5.0.0.0/8|Ethernet 2\n")    # same prefix, other iface -> kept
        hits = H._geo_sweep_hits(out, "v4")
        self.assertEqual(sorted(hits), [
            ("v4", "31.13.0.0/16", "Wi-Fi", ""),
            ("v4", "5.0.0.0/8", "Ethernet 2", ""),
            ("v4", "5.0.0.0/8", "Wi-Fi", ""),
        ])

    def test_skips_junk_lines(self):
        out = "\nno pipe here\n|Wi-Fi\n5.0.0.0/8|\n  2.16.0.0/20 | Wi-Fi  \n"
        hits = H._geo_sweep_hits(out, "v4")
        self.assertEqual(hits, [("v4", "2.16.0.0/20", "Wi-Fi", "")])

    def test_empty_input(self):
        self.assertEqual(H._geo_sweep_hits(None, "v4"), [])
        self.assertEqual(H._geo_sweep_hits("", "v6"), [])


if __name__ == "__main__":
    unittest.main()

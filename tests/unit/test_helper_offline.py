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
        self.assertLess(dt, 1.3, "probe was not concurrent"
                        f"(dt={dt:.3f}s)")
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


class TestRejectCompetingTun(unittest.TestCase):
    """The foreign full-tunnel TUN startup guard (v2rayN/xray TUN mode).

    Regression: a competing Wintun adapter owning 0.0.0.0/0 used to be a soft
    warning, so the helper started anyway and the VLESS server /32 bypass fell
    into the foreign TUN the moment it dropped ("the server IP goes to the
    wintun"), surviving closing AND reopening because the foreign adapter
    outlives this program's cleanup. Now it refuses to start."""
    PATH = "tuntop.tunnel.helper.get_foreign_tun_adapters"

    def test_blocks_when_foreign_tun_owns_default(self):
        with mock.patch(self.PATH, return_value=[("xray_tun", "yes")]):
            with self.assertRaises(SystemExit) as cm:
                H.reject_competing_tun()
        msg = str(cm.exception)
        self.assertIn("TUN CONFLICT", msg)
        self.assertIn("xray_tun", msg)
        self.assertNotIn("left untouched", msg)

    def test_blocks_when_any_of_many_owns_default(self):
        with mock.patch(self.PATH, return_value=[("wireguard", "no"),
                                                 ("v2rayN", "yes")]):
            with self.assertRaises(SystemExit):
                H.reject_competing_tun()

    def test_lets_tun_without_default_pass_and_notes_it(self):
        with mock.patch(self.PATH, return_value=[("sing-tun Tunnel", "no")]):
            with mock.patch.object(H, "print") as pr:
                H.reject_competing_tun()
        joined = "\n".join(str(v) for args, _kw in pr.call_args_list
                           for v in args)
        self.assertIn("left untouched", joined)

    def test_no_foreign_tun_is_a_noop(self):
        with mock.patch(self.PATH, return_value=[]):
            H.reject_competing_tun()  # must not raise


class TestStartProxy2Pipe(unittest.TestCase):
    """Tests for start_tun2socks_pipe()'s fatal/non-fatal paths.

    The proxy2 pipe (TUN2) must never sys.exit the helper when the second
    SOCKS5 proxy is not running - that would take the primary tunnel down too
    and trigger the recovery engine's restart loop. Only the primary pipe
    (fatal=True, the default) should sys.exit on a dead proxy port."""

    def test_non_fatal_returns_none_when_socks_dead(self):
        """fatal=False: dead SOCKS5 must return None, NOT raise SystemExit."""
        with mock.patch.object(H, "test_local_socks", return_value=False), \
             mock.patch.object(H, "print"):
            result = H.start_tun2socks_pipe(
                H.TUN2, H.TUN2_IP4, H.TUN2_IP6, 2080, "tun2socks.exe",
                fatal=False)
        self.assertIsNone(result)

    def test_fatal_still_exits_on_dead_socks(self):
        """fatal=True (default for the primary pipe): dead SOCKS5 must sys.exit."""
        with mock.patch.object(H, "test_local_socks", return_value=False), \
             mock.patch.object(H, "print"):
            with self.assertRaises(SystemExit) as cm:
                H.start_tun2socks_pipe(
                    H.TUN, "10.0.0.1", "fd00::1", 2080, "tun2socks.exe")
        msg = str(cm.exception)
        self.assertIn("127.0.0.1:2080", msg)

    def test_fatal_default_param_preserves_exit(self):
        """Regression guard: calling without fatal= (defaults to True) must
        still sys.exit, preserving the original primary-pipe behavior."""
        with mock.patch.object(H, "test_local_socks", return_value=False), \
             mock.patch.object(H, "print"):
            with self.assertRaises(SystemExit):
                H.start_tun2socks_pipe(
                    H.TUN2, H.TUN2_IP4, H.TUN2_IP6, 2080, "tun2socks.exe")

    def test_non_fatal_proceeds_when_socks_alive(self):
        """fatal=False: alive SOCKS5 proceeds to spawn tun2socks and returns
        a real Popen handle whose command targets wintun2."""
        fake_proc = mock.Mock()
        fake_proc.poll.return_value = None  # process alive
        fake_proc.wait.return_value = 0

        with mock.patch.object(H, "test_local_socks", return_value=True), \
             mock.patch.object(H, "subprocess") as m_sub, \
             mock.patch("time.sleep"), \
             mock.patch.object(H, "wait_for_tun", return_value=True), \
             mock.patch.object(H, "_set_wintun_addresses_plain") as m_addr:
            m_sub.Popen.return_value = fake_proc
            proc = H.start_tun2socks_pipe(
                H.TUN2, H.TUN2_IP4, H.TUN2_IP6, 2080, "tun2socks.exe",
                fatal=False)

        self.assertIs(proc, fake_proc)
        cmd = m_sub.Popen.call_args[0][0]
        self.assertIn("--device", cmd)
        self.assertIn(H.TUN2, cmd)  # "wintun2"
        self.assertIn("--proxy", cmd)
        self.assertIn("socks5://127.0.0.1:2080", cmd)
        m_addr.assert_called_once()


if __name__ == "__main__":
    unittest.main()

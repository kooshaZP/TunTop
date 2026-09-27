"""Tests for the two start/stop latency fixes.

Both were reported as "it takes a lot of time":

* START - the tunnel sat on "Verifying the tunnel is stable..." for tens of
  seconds. Two causes: socket.getaddrinfo() has NO timeout parameter (Windows
  walks every configured resolver with its own multi-second timeout when one is
  unreachable, which is exactly the state plain UDP/53 is in when it has to
  traverse a SOCKS5 tunnel), and nothing bounded the verification round. A
  DNS failure was then retried a second time - another full resolve sweep -
  immediately before the DoH escalation that actually fixes it.

* STOP - "Stopping tunnel helper (clears its own routes)" took tens of
  seconds because cleanup() removed every route we own with a separate
  `netsh` PROCESS, serially, while the batched `netsh -f` mechanism already
  existed and was used only for the geoip sweep.

No Windows calls: the routing/shell layers are mocked. Runs anywhere.
"""
import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from tuntop.tunnel import helper as H


class TestVerifyBudget(unittest.TestCase):
    def test_budget_is_bounded_and_small(self):
        # A healthy tunnel verifies in well under a second; the ceiling only
        # ever applies to a broken one, and it must be small enough that the
        # start sequence stays usable.
        self.assertLessEqual(H._VERIFY_BUDGET, 25.0)
        self.assertLessEqual(H._VERIFY_ROUND_BUDGET,
                             H._VERIFY_BUDGET)

    def test_a_wedged_resolve_cannot_hold_the_start_open(self):
        """A probe stuck inside getaddrinfo must not block the round: this is
        the exact stall the user saw, and it is unbounded because
        getaddrinfo ignores every timeout we can pass."""
        def _wedged(url, timeout=5):
            time.sleep(30)          # simulates a hanging resolve
            return False, "DNS resolve x: [Errno 11001] getaddrinfo failed"
        t0 = time.monotonic()
        with mock.patch.object(H, "_probe_tunnel_once", side_effect=_wedged):
            ok = H.wait_for_tunnel_stable(timeout=5, budget=2.0)
        elapsed = time.monotonic() - t0
        self.assertFalse(ok)
        self.assertLess(elapsed, 10.0,
                        f"wait_for_tunnel_stable blocked for {elapsed:.1f}s")

    def test_a_healthy_tunnel_still_returns_true_fast(self):
        """The budget must not make a WORKING tunnel wait or fail."""
        calls = []

        def _ok(url, timeout=5):
            calls.append(url)
            return True, "host resolved -> 1.2.3.4; public IP = 1.2.3.4"
        t0 = time.monotonic()
        with mock.patch.object(H, "_probe_tunnel_once", side_effect=_ok):
            ok = H.wait_for_tunnel_stable(timeout=5, budget=20.0)
        self.assertTrue(ok)
        self.assertLess(time.monotonic() - t0, 5.0)

    def test_a_dns_failure_is_not_retried(self):
        """Retrying a dead resolver cost a whole extra resolve sweep. One
        attempt is enough to trigger the DoH escalation that fixes it."""
        n = []

        def _dns_fail(url, timeout=5):
            n.append(url)
            return False, f"DNS resolve {_host(url)}: [Errno 11001] getaddrinfo failed"
        with mock.patch.object(H, "_probe_tunnel_once", side_effect=_dns_fail), \
                mock.patch.object(H, "_ACTIVE_DNS_MODE", "plain"), \
                mock.patch.object(H, "run_ps"), \
                mock.patch.object(H, "configure_tun"):
            H.wait_for_tunnel_stable(timeout=1, budget=4.0)
        self.assertEqual(len(n), len(H._VERIFY_URLS),
                         "each endpoint was retried; DNS failures must "
                         "give up after the first try")

    def test_a_fetch_failure_still_gets_its_retries(self):
        """Only DNS failures fast-path. A resolved-but-failed fetch can be
        transient, so the retry budget must remain."""
        n = []

        def _fetch_fail(url, timeout=5):
            n.append(url)
            return False, f"{_host(url)} resolved (1.2.3.4) but fetch failed: timeout"
        with mock.patch.object(H, "_probe_tunnel_once", side_effect=_fetch_fail), \
                mock.patch.object(H, "_ACTIVE_DNS_MODE", "plain"), \
                mock.patch.object(H, "time", wraps=time):
            H.wait_for_tunnel_stable(timeout=1, budget=2.0)
        self.assertGreater(len(n), len(H._VERIFY_URLS),
                           "non-DNS failures lost their retries")

    def test_doh_escalation_is_skipped_when_out_of_budget(self):
        """No point reconfiguring the resolver and flushing the DNS cache when
        there is no time left to verify the result."""
        with mock.patch.object(H, "_probe_tunnel_once",
                               side_effect=lambda u, timeout=5:
                               (False, "DNS resolve x: [Errno 11001] failed")), \
                mock.patch.object(H, "_ACTIVE_DNS_MODE", "auto"), \
                mock.patch.object(H, "configure_tun") as cfg, \
                mock.patch.object(H, "run_ps") as ps:
            H.wait_for_tunnel_stable(timeout=1, budget=0.05)
        cfg.assert_not_called()
        ps.assert_not_called()

    def test_doh_escalation_still_runs_with_budget_available(self):
        """...and the designed repair for broken plain DNS must survive the
        budget - it is what actually makes the tunnel work."""
        seen = []

        def _probe(url, timeout=5):
            seen.append(url)
            if len(seen) <= len(H._VERIFY_URLS):
                return False, "DNS resolve x: [Errno 11001] getaddrinfo failed"
            return True, "host resolved -> 1.2.3.4"
        with mock.patch.object(H, "_probe_tunnel_once", side_effect=_probe), \
                mock.patch.object(H, "_ACTIVE_DNS_MODE", "auto"), \
                mock.patch.object(H, "configure_tun") as cfg, \
                mock.patch.object(H, "run_ps"):
            ok = H.wait_for_tunnel_stable(timeout=1, budget=20.0)
        cfg.assert_called_once()
        self.assertTrue(ok)


class TestRemoveRouteNetshArguments(unittest.TestCase):
    """An on-link route (gateway '') must be deleted WITHOUT a next-hop token.
    The v4 branch appended the gateway unconditionally, so netsh received an
    empty argument, rejected the command, and the route survived every
    teardown - the exact leak the on-link normalization in 1.0.43 made
    reachable."""

    def _cmd(self, item):
        calls = []
        with mock.patch.object(H, "run",
                               side_effect=lambda c, *a, **k:
                               calls.append(list(c)) or (0, "", "")):
            H.remove_route(item)
        return calls[0]

    def test_v4_on_link_omits_the_token(self):
        cmd = self._cmd(("v4", "185.64.178.62/32", "Shirazu-VPN", ""))
        self.assertEqual(cmd[:6], ["netsh", "interface", "ipv4", "delete",
                                   "route", "185.64.178.62/32"])
        self.assertEqual(len(cmd), 7)          # + iface, no empty gateway
        self.assertNotIn("", cmd)

    def test_v4_zero_gateway_omits_the_token(self):
        cmd = self._cmd(("v4", "10.0.0.0/8", "Wi-Fi", "0.0.0.0"))
        self.assertNotIn("0.0.0.0", cmd)

    def test_v4_real_gateway_is_passed(self):
        cmd = self._cmd(("v4", "1.2.3.4/32", "Wi-Fi", "192.168.1.1"))
        self.assertIn("192.168.1.1", cmd)

    def test_v6_unchanged(self):
        cmd = self._cmd(("v6", "2001:db8::/128", "Wi-Fi", ""))
        self.assertNotIn("", cmd)


class TestGeoWarningIsNotDuplicated(unittest.TestCase):
    def test_only_one_advisory_is_printed(self):
        """--geoip without --geoip-code produced the identical warning twice
        (once in the pre-flight check, once inside the worker thread)."""
        src = open(H.__file__, encoding="utf-8").read()
        # Count the print STATEMENTS, not a rendered string: the message is
        # built by implicit concatenation, so a full-sentence match is brittle.
        self.assertEqual(
            src.count("given without --geoip-code"),
            1,
            "the '--geoip given without --geoip-code' advisory is printed "
            "from more than one place again")


def _host(url):
    try:
        return url.split("//", 1)[1].split("/", 1)[0]
    except IndexError:
        return url


if __name__ == "__main__":
    unittest.main()

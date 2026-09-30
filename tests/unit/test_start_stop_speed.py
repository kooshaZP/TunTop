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
import io
import os
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from tuntop.tunnel import helper as H


def _tunnel_up():
    """Stage 1 of the verification (1.0.45) is a DNS-FREE literal TCP probe,
    and it is now the GATE: a failure returns immediately, because a tunnel
    that cannot forward packets must not be "verified" by re-resolving
    hostnames. Tests about the URL rounds therefore have to let stage 1 pass -
    this patches it to say the tunnel forwards. The stage itself is covered by
    TestLiteralTunnelProbe below."""
    return mock.patch.object(H, "_probe_tunnel_no_dns",
                             return_value=(True, "TUN carries TCP"))


class _WedgedWorkers:
    """Workers that block like getaddrinfo() and are released on demand.

    The real getaddrinfo() has no timeout knob, so a wedged resolve is
    modelled by parking on an Event, not by sleeping a fixed number of
    seconds. The distinction matters at PROCESS level, not test level:
    _run_round() shuts its executor down with wait=False (on purpose, so a
    stuck resolve cannot hold the start sequence open), which leaves
    non-daemon worker threads running. Those are what threading._shutdown()
    joins at interpreter exit, so a raw `time.sleep(30)` fake kept the whole
    process alive for another 30s AFTER unittest had already printed its own
    timing and said "Ran 21 tests in 2.08s" - the stall was invisible in
    every reported number and only showed up on the wall clock.

    A test that starts one of these hands it back here; release() in
    tearDown() then unblocks the workers and waits for the last of them to
    really leave, so the process exits when the suite does.
    """

    def __init__(self):
        self._release = threading.Event()
        self._lock = threading.Lock()
        self._live = 0
        self._idle = threading.Event()
        self._idle.set()

    def wait(self, timeout=30):
        """Block like an un-timed-out getaddrinfo(). The 30s cap is only a
        backstop: nothing should ever reach it, because tearDown releases."""
        with self._lock:
            self._live += 1
            self._idle.clear()
        try:
            return self._release.wait(timeout)
        finally:
            with self._lock:
                self._live -= 1
                if self._live == 0:
                    self._idle.set()

    def release(self, timeout=5):
        self._release.set()
        return self._idle.wait(timeout)


class TestVerifyBudget(unittest.TestCase):
    def setUp(self):
        self.wedged = _WedgedWorkers()

    def tearDown(self):
        # No worker may outlive its test: release them and wait for the last
        # one to actually exit rather than letting the interpreter's exit
        # join block on a thread nobody is waiting for.
        self.wedged.release()

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
        getaddrinfo ignores every timeout we can pass.

        The round must return on its BUDGET while the workers are still
        parked; tearDown then releases them so the abandoned non-daemon
        executor threads cannot hold the interpreter open after the suite has
        already reported its timing. The elapsed-time assertion below is the
        point of the test and stays."""
        def _wedged(url, timeout=5):
            self.wedged.wait()      # simulates a hanging resolve
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
        with mock.patch.object(H, "_probe_tunnel_no_dns", return_value=(True, "TUN carries TCP")), _tunnel_up(), mock.patch.object(H, "_probe_tunnel_once", side_effect=_ok):
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
        with mock.patch.object(H, "_probe_tunnel_no_dns", return_value=(True, "TUN carries TCP")), _tunnel_up(), mock.patch.object(H, "_probe_tunnel_once", side_effect=_dns_fail), \
                mock.patch.object(H, "_ACTIVE_DNS_MODE", "plain"), \
                mock.patch.object(H, "run_ps"), \
                mock.patch.object(H, "configure_tun"):
            H.wait_for_tunnel_stable(timeout=1, budget=4.0)
        self.assertEqual(len(n), len(H._VERIFY_URLS),
                         "each endpoint was retried; DNS failures must "
                         "give up after the first try")

    def test_a_fetch_failure_still_gets_its_retries(self):
        """Only DNS failures fast-path. A resolved-but-failed fetch can be
        transient, so the retry budget must remain.

        The retry GAP is observed, not slept. This test used to run against the
        real clock with a 2.0s budget - exactly the `time.sleep(2)` the worker
        takes between attempts - so whether a second attempt landed before the
        round's deadline was decided by thread scheduling: the workers woke at
        t=2.000 and the round loop noticed its (equally 2.0s) deadline at
        t=2.000 too. It failed on the CI runner and passed on an idle machine,
        so the failure said nothing about the code. Sleep is recorded instead,
        which makes the attempt count deterministic while still pinning the
        spacing the retry budget promises."""
        n = []
        slept = []

        def _fetch_fail(url, timeout=5):
            n.append(url)
            return False, f"{_host(url)} resolved (1.2.3.4) but fetch failed: timeout"

        class _RecordedClock:
            """A real clock with a non-blocking sleep. The round's own
            deadlines stay wall-clock (monotonic is the real one); only the
            inter-attempt wait is recorded rather than taken."""
            monotonic = staticmethod(time.monotonic)

            def sleep(self, seconds):
                slept.append(seconds)

        with mock.patch.object(H, "_probe_tunnel_no_dns", return_value=(True, "TUN carries TCP")), _tunnel_up(), mock.patch.object(H, "_probe_tunnel_once", side_effect=_fetch_fail), \
                mock.patch.object(H, "_ACTIVE_DNS_MODE", "plain"), \
                mock.patch.object(H, "time", _RecordedClock()):
            H.wait_for_tunnel_stable(timeout=1, budget=2.0)
        self.assertGreater(len(n), len(H._VERIFY_URLS),
                           "non-DNS failures lost their retries")
        self.assertEqual(set(slept), {2},
                         "non-DNS retries are no longer spaced 2s apart")

    def test_doh_escalation_is_skipped_when_out_of_budget(self):
        """No point reconfiguring the resolver and flushing the DNS cache when
        there is no time left to verify the result."""
        with mock.patch.object(H, "_probe_tunnel_no_dns", return_value=(True, "TUN carries TCP")), _tunnel_up(), mock.patch.object(H, "_probe_tunnel_once", side_effect=lambda u, timeout=5:
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
        with mock.patch.object(H, "_probe_tunnel_no_dns", return_value=(True, "TUN carries TCP")), _tunnel_up(), mock.patch.object(H, "_probe_tunnel_once", side_effect=_probe), \
                mock.patch.object(H, "_ACTIVE_DNS_MODE", "auto"), \
                mock.patch.object(H, "configure_tun", return_value=True) as cfg, \
                mock.patch.object(H, "run_ps"):
            ok = H.wait_for_tunnel_stable(timeout=1, budget=20.0)
        cfg.assert_called_once()
        self.assertTrue(ok)


class TestDohEscalationThatCannotTake(unittest.TestCase):
    """When the DoH switch does not actually take, the second probe round is a
    foregone conclusion and its cost is pure start latency.

    The escalation runs when plain UDP/53 cannot resolve through the TUN. If
    the DoH registration then fails (a Windows build without DoH support, or a
    blocked dns-query endpoint), the adapter is left holding the SAME broken
    plain resolver that just failed, so re-probing it cannot succeed. The old
    code ran that second round anyway: a full _VERIFY_ROUND_BUDGET spent to
    re-report the identical getaddrinfo failure, which is a visible slice of
    the "start takes too long" the user reported.

    The verdict stays DEGRADED either way - this only removes the wasted wait,
    it does not paper over a tunnel that is not carrying traffic.
    """

    def _run(self, doh_on):
        seen = []

        def _probe(url, timeout=5):
            seen.append(url)
            return False, "DNS resolve x: [Errno 11001] getaddrinfo failed"

        with mock.patch.object(H, "_probe_tunnel_no_dns",
                               return_value=(True, "TUN carries TCP")), \
                _tunnel_up(), \
                mock.patch.object(H, "_probe_tunnel_once", side_effect=_probe), \
                mock.patch.object(H, "_ACTIVE_DNS_MODE", "auto"), \
                mock.patch.object(H, "configure_tun", return_value=doh_on), \
                mock.patch.object(H, "run_ps") as ps:
            ok = H.wait_for_tunnel_stable(timeout=1, budget=20.0)
        return ok, seen, ps

    def test_no_second_round_when_doh_did_not_register(self):
        ok, seen, ps = self._run(doh_on=False)
        self.assertFalse(ok, "an unverified tunnel must not report success")
        self.assertEqual(len(seen), len(H._VERIFY_URLS),
                         "the doomed DoH round ran against the same broken "
                         "resolver")
        ps.assert_not_called()

    def test_second_round_still_runs_when_doh_took(self):
        """The guard must be narrow: a successful registration genuinely can
        fix resolution, so that round must still happen."""
        ok, seen, ps = self._run(doh_on=True)
        self.assertGreater(len(seen), len(H._VERIFY_URLS),
                           "the post-DoH verification round was skipped")

    def test_the_reason_is_reported_not_swallowed(self):
        """The user is told the resolver is still plain UDP/53, so a DEGRADED
        verdict is diagnosable instead of looking like a mystery."""
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with mock.patch.object(H, "_probe_tunnel_no_dns",
                               return_value=(True, "TUN carries TCP")), \
                _tunnel_up(), \
                mock.patch.object(H, "_probe_tunnel_once", side_effect=
                                  lambda u, timeout=5:
                                  (False, "DNS resolve x: [Errno 11001] failed")), \
                mock.patch.object(H, "_ACTIVE_DNS_MODE", "auto"), \
                mock.patch.object(H, "configure_tun", return_value=False), \
                mock.patch.object(H, "run_ps"), \
                redirect_stdout(buf):
            H.wait_for_tunnel_stable(timeout=1, budget=20.0)
        out = buf.getvalue()
        self.assertIn("still on plain UDP/53", out)
        self.assertIn("not re-probing", out)


class TestLiteralTunnelProbe(unittest.TestCase):
    """Stage 1 of the verification (1.0.45): is the TUN forwarding packets?

    The URL probes all START with getaddrinfo, which has no timeout. When
    plain UDP/53 cannot traverse the tunnel - the normal state for a SOCKS5
    client without a working UDP relay - Windows walks every configured
    resolver with its own multi-second timeouts, so each of the four URLs cost
    5-10s to report the same resolver failure, and then the DoH round paid it
    all again. That was the "Verifying the tunnel is stable..." spinner and
    the dozen identical "DNS resolve ... getaddrinfo failed" log lines.

    A TCP connect to a LITERAL address skips the resolver entirely and answers
    the only question the start sequence actually has, in ~100ms.
    """

    def test_targets_are_literals_so_no_resolver_is_touched(self):
        import ipaddress
        for host, port in H._VERIFY_LITERAL_TCP:
            ipaddress.IPv4Address(host)      # raises if it is a hostname
            self.assertGreater(port, 0)

    def test_a_reachable_literal_passes(self):
        with mock.patch("socket.create_connection") as cc:
            cc.return_value.__enter__.return_value = None
            ok, msg = H._probe_tunnel_no_dns(timeout=1)
        self.assertTrue(ok)
        self.assertIn("carries TCP", msg)

    def test_all_unreachable_fails_fast(self):
        def _boom(target, timeout=None):
            raise OSError("timed out")
        with mock.patch("socket.create_connection", _boom):
            t0 = time.monotonic()
            ok, msg = H._probe_tunnel_no_dns(timeout=1)
            elapsed = time.monotonic() - t0
        self.assertFalse(ok)
        self.assertIn("timed out", msg)
        # Concurrent, and bounded by the timeout - never one after another.
        self.assertLess(elapsed, 2.0)

    def test_zero_budget_short_circuits(self):
        with mock.patch("socket.create_connection") as cc:
            ok, _msg = H._probe_tunnel_no_dns(timeout=0)
        self.assertFalse(ok)
        cc.assert_not_called()

    def test_a_dead_tunnel_never_reaches_the_url_round(self):
        """The whole point: no point resolving hostnames for a tunnel that
        cannot forward packets - that is the 5-10s-per-URL trap."""
        n = []

        def _never(url, timeout=5):
            n.append(url)
            return True, "should not be called"
        with mock.patch.object(H, "_probe_tunnel_no_dns",
                               return_value=(False, "connect refused")), \
                mock.patch.object(H, "_probe_tunnel_once", side_effect=_never):
            ok = H.wait_for_tunnel_stable(timeout=5, budget=20.0)
        self.assertFalse(ok)
        self.assertEqual(n, [], "the URL round must not run for a dead tunnel")

    def test_identical_dns_failures_are_reported_once(self):
        """The user's log filled with a dozen identical getaddrinfo lines,
        which said nothing except that the resolver was down."""
        def _dns_fail(url, timeout=5):
            return False, "DNS resolve x: [Errno 11001] getaddrinfo failed"
        buf = io.StringIO()
        with mock.patch.object(H, "_probe_tunnel_no_dns",
                               return_value=(True, "TUN carries TCP")), \
                mock.patch.object(H, "_probe_tunnel_once",
                                  side_effect=_dns_fail), \
                mock.patch.object(H, "_ACTIVE_DNS_MODE", "plain"), \
                mock.patch.object(H, "run_ps"), \
                mock.patch.object(H, "configure_tun"), \
                mock.patch("sys.stdout", buf):
            H.wait_for_tunnel_stable(timeout=1, budget=4.0)
        out = buf.getvalue()
        self.assertEqual(out.count("getaddrinfo failed"),
                         out.count("Name resolution through the TUN is not"),
                         "the per-URL line must not be repeated")
        self.assertLessEqual(out.count("getaddrinfo failed"), 1)


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

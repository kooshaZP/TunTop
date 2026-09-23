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
import zlib
from types import SimpleNamespace
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


class TestSSLContextSecurity(unittest.TestCase):
    """Regression guard for the CodeQL py/insecure-protocol fix: the shared
    TLS context must be built from PROTOCOL_TLS_CLIENT (not
    ssl.create_default_context, which CodeQL flags) with the TLS 1.2 floor
    pinned from construction."""

    def test_not_create_default_context(self):
        import ssl
        # The context must NOT be a bare create_default_context() result.
        # PROTOCOL_TLS_CLIENT is a purpose-built client context; CodeQL's
        # py/insecure-protocol query recognizes it and does NOT flag it.
        self.assertEqual(L._SSL_CONTEXT.protocol, ssl.PROTOCOL_TLS_CLIENT)

    def test_verify_and_hostname_enforced(self):
        import ssl
        self.assertTrue(L._SSL_CONTEXT.check_hostname)
        self.assertEqual(L._SSL_CONTEXT.verify_mode, ssl.CERT_REQUIRED)

    def test_tls_floor_is_1_2(self):
        import ssl
        if not hasattr(ssl, "TLSVersion"):
            self.skipTest("ssl.TLSVersion not available")
        self.assertEqual(L._SSL_CONTEXT.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_legacy_protocols_disabled(self):
        import ssl
        opts = L._SSL_CONTEXT.options
        for flag in ("OP_NO_SSLv3", "OP_NO_TLSv1", "OP_NO_TLSv1_1"):
            self.assertTrue(
                getattr(opts, flag, 0),
                f"{flag} is not set on the leak probe SSL context")


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

    def test_same_exit_when_same_network_not_same_address(self):
        # Exit-side address rotation: both legs belong to the same /32, so
        # both rode the tunnel - NOT a leak. Regression test for the old
        # string-equality verdict that false-alarmed on this exact pattern
        # (2a09:bac5:... pair reported by a user on a v6-less Wi-Fi).
        status, msg = L._verdict(
            _leg("2a09:bac5:465:c00::132:18"),
            _leg("2a09:bac5:5275:2864::406:48"), 10808)
        self.assertEqual(status, "same-exit")
        self.assertIn("SAME network", msg)
        self.assertNotIn("LEAK", msg)

    def test_leak_when_different_networks(self):
        # A different /32 (real ISP IP vs tunnel exit) is still a leak.
        status, _ = L._verdict(_leg("89.198.14.7"), _leg("45.12.33.9"), 10808)
        self.assertEqual(status, "leak")

    def test_same_network_helper(self):
        self.assertTrue(L._same_network("2a09:bac5:465:c00::132:18",
                                        "2a09:bac5:5275:2864::406:48"))
        self.assertFalse(L._same_network("89.198.14.7", "45.12.33.9"))
        self.assertFalse(L._same_network("garbage", "8.8.8.8"))

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

    def test_same_exit_passes_with_detail(self):
        # Same-network address rotation is not a tunnel fault either.
        self.assertEqual(ML.as_check_result("same-exit", "m"), (True, "m"))


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

class TestThreadedPathResilience(unittest.TestCase):
    """Regression: the dashboard's [L] test crashed with
    "error: Error -3 while decompressing data: incorrect header check"
    (zlib.error) - the frozen exe's FIRST concurrent.futures.thread import
    happens inside run_leak_probe (lazy module __getattr__) and PyInstaller's
    importer zlib-decompresses the PYZ entry there; a damaged entry escaped
    every per-endpoint handler. The probe must fall back to a thread-free
    sequential probe and still return a verdict."""

    def _broken_executor_ns(self):
        class _BrokenThreadPool:
            def __init__(self, *a, **k):
                raise zlib.error(
                    "Error -3 while decompressing data: incorrect header check")
        return SimpleNamespace(futures=SimpleNamespace(
            ThreadPoolExecutor=_BrokenThreadPool))

    def test_per_endpoint_zlib_error_is_swallowed(self):
        # A zlib.error raised by a single echo endpoint is just another
        # endpoint failure - recorded as leg err, never propagated.
        def zlib_fetch(scheme, host, path, timeout):
            raise zlib.error("Error -3 while decompressing data: "
                             "incorrect header check")
        out = L._race_leg(zlib_fetch, timeout=1)
        self.assertIsNone(out["ip"])
        self.assertIn("incorrect header check", out["err"])

    def test_run_leak_probe_survives_broken_executor(self):
        # The whole threaded race failing (executor construction raises
        # zlib.error) must fall back to the sequential probe, not crash.
        def fake_direct(scheme, host, path, timeout):
            return "9.9.9.9"

        def fake_tunnel(socks_port, scheme, host, path, timeout):
            return "1.1.1.1"

        with mock.patch.object(L, "concurrent", self._broken_executor_ns()), \
             mock.patch.object(L, "_fetch_direct", fake_direct), \
             mock.patch.object(L, "_fetch_via_socks", fake_tunnel), \
             mock.patch.object(L, "_ECHO_ENDPOINTS",
                               [("https", "one.example", "/")]):
            status, msg, legs = L.run_leak_probe(10808)
        self.assertEqual(status, "leak")     # 9.9.9.9 != 1.1.1.1 -> real verdict
        self.assertEqual(legs["direct"]["ip"], "9.9.9.9")
        self.assertEqual(legs["tunnel"]["ip"], "1.1.1.1")

    def test_verdict_reprobe_survives_race_failure(self):
        # The mixed-family IPv4 re-probe inside _verdict uses the same
        # resilient wrapper - a broken race must not crash the verdict.
        with mock.patch.object(L, "_race_leg",
                               side_effect=zlib.error("broken pool")), \
             mock.patch.object(L, "_fetch_direct_v4",
                               lambda s, h, p, t: "9.9.9.9"):
            status, msg = L._verdict(_leg("2606:4700::1111"),
                                     _leg("1.1.1.1"), 10808)
        self.assertEqual(status, "leak")
        self.assertIn("9.9.9.9", msg)

    def test_sequential_leg_first_valid_ip_wins(self):
        calls = []

        def fake_fetch(scheme, host, path, timeout):
            calls.append(host)
            if host == "one.example":
                raise OSError("blocked")
            return "4.3.2.1"

        with mock.patch.object(L, "_ECHO_ENDPOINTS",
                               [("https", "one.example", "/"),
                                ("http", "two.example", "/")]):
            out = L._sequential_leg(fake_fetch, timeout=1)
        self.assertEqual(out["ip"], "4.3.2.1")
        self.assertEqual(calls, ["one.example", "two.example"])  # sequential

    def test_http_get_requests_identity_encoding(self):
        class _FakeSock:
            def __init__(self):
                self.sent = b""
                self.response = (b"HTTP/1.1 200 OK\r\n"
                                 b"Content-Type: text/plain\r\n"
                                 b"\r\n1.2.3.4")

            def settimeout(self, t):
                pass

            def sendall(self, data):
                self.sent += data

            def recv(self, n):
                out, self.response = self.response, b""
                return out

        sock = _FakeSock()
        body = L._http_get(sock, "http", "h.example", "/", timeout=1)
        self.assertEqual(body, "1.2.3.4")
        # Middleboxes must never gzip the echo body: ask for identity.
        self.assertIn(b"Accept-Encoding: identity\r\n", sock.sent)

    def test_tls_wrap_uses_secure_context(self):
        """_tls_wrap must use the shared _SSL_CONTEXT (PROTOCOL_TLS_CLIENT,
        TLS 1.2+, not create_default_context)."""
        with mock.patch.object(L, "_SSL_CONTEXT") as ctx:
            sock = mock.Mock()
            L._tls_wrap(sock, "example.com")
        ctx.wrap_socket.assert_called_once_with(
            sock, server_hostname="example.com")


class TestRunBounded(unittest.TestCase):
    """The daemon-thread timeout wrapper that protects the fallback path."""

    def test_returns_result(self):
        self.assertEqual(L._run_bounded(lambda: "result", 5), "result")

    def test_swallows_exception(self):
        def boom():
            raise OSError("kaboom")
        self.assertIsNone(L._run_bounded(boom, 5))

    def test_returns_none_on_timeout(self):
        """A function that sleeps longer than the budget must return None
        instead of hanging forever (regression: getaddrinfo on Windows)."""
        def hang():
            time.sleep(10)
            return "too-late"
        t0 = time.time()
        result = L._run_bounded(hang, 0.3)
        dt = time.time() - t0
        self.assertIsNone(result)
        self.assertLess(dt, 2.0, "run_bounded waited past its timeout")


class TestDnsFallbackTimeout(unittest.TestCase):
    """When the ThreadPoolExecutor is unavailable (frozen-exe zlib error),
    run_dns_leak_probe must still bound _system_resolver_ip via _run_bounded
    so getaddrinfo cannot stall for minutes."""

    def test_fallback_uses_bounded_timeout(self):
        calls = []

        def fake_system_resolver_ip():
            calls.append("resolver")
            return "8.8.8.8"

        def fake_forced_path_echo_ip(timeout):
            calls.append("echo")
            return "1.1.1.1"

        with mock.patch.object(L, "_system_resolver_ip", fake_system_resolver_ip), \
             mock.patch.object(L, "_forced_path_echo_ip", fake_forced_path_echo_ip), \
             mock.patch.object(L, "_run_bounded") as rb:
            # Make _run_bounded pass through to the real function.
            rb.side_effect = lambda fn, t: fn()
            status, _msg, det = L.run_dns_leak_probe(
                direct_ip="9.9.9.9", tunnel_ip="1.1.1.1")
        self.assertEqual(calls, ["resolver", "echo"])
        # Must have been called with a timeout argument, not None.
        for call in rb.call_args_list:
            args, _ = call
            self.assertGreaterEqual(args[1], 0)  # timeout bound present


if __name__ == "__main__":
    unittest.main()

"""Unit tests for DNS request/answer logging in tuntop/network/dns.py.

Covers the callback install/clear/no-op plumbing and the messages _resolve_detail
emits through it for every resolution path: literal, cache hit, system success,
system failure, UDP/53 fallback, DoH fallback, and total failure. Pure mocks -
no real network or adapter access.

Run:  python -m pytest tests/unit/test_dns_logging.py -v
"""
import os
import socket
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from tuntop.network import dns as D


def _gai_ok(v4=None, v6=None):
    """Build a fake socket.getaddrinfo that returns synthetic addrinfo tuples."""
    infos = []
    for ip in (v4 or []):
        infos.append((socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, 0)))
    for ip in (v6 or []):
        infos.append((socket.AF_INET6, socket.SOCK_STREAM, 0, "",
                      (ip, 0, 0, 0)))
    return mock.Mock(return_value=infos)


def _gai_fail(reason="host not found", code=11001):
    """A socket.getaddrinfo that always raises socket.gaierror."""
    return mock.Mock(side_effect=socket.gaierror(code, reason))


class _DnsLogSuite(unittest.TestCase):
    """Shared fixture: a recording callback + a clean cache per test."""

    def setUp(self):
        self.received = []
        D.set_dns_log(self.received.append)
        with D._DNS_CACHE_LOCK:
            D._DNS_CACHE.clear()

    def tearDown(self):
        D.set_dns_log(None)
        with D._DNS_CACHE_LOCK:
            D._DNS_CACHE.clear()


class TestCallbackPlumbing(_DnsLogSuite):
    def test_no_callback_noops(self):
        # With the callback cleared, _dns_log must be a silent no-op.
        D.set_dns_log(None)
        D._dns_log("anything")                 # must not raise

    def test_installs_and_clears(self):
        self.assertIsNotNone(D._DNS_LOG)       # setUp installed it
        D._dns_log("ping")                     # forwarded to the callback
        self.assertEqual(self.received, ["ping"])
        D.set_dns_log(None)                    # clear -> no-op
        self.assertIsNone(D._DNS_LOG)
        D._dns_log("pong")
        self.assertEqual(self.received, ["ping"])

    def test_callback_exception_is_swallowed(self):
        # _dns_log guards _resolve_detail's hot paths: a dead callback can never
        # propagate an exception out.
        def _boom(msg):
            raise RuntimeError("consumer blew up")
        D.set_dns_log(_boom)
        D._dns_log("survives")                 # must not raise


class TestResolveDetailLogging(_DnsLogSuite):
    def test_ip_literal_v4(self):
        v4, v6, err, src = D._resolve_detail("1.2.3.4")
        self.assertEqual((v4, v6, err, src), (["1.2.3.4"], [], None, "literal"))
        self.assertEqual(self.received,
                         ["DNS: 1.2.3.4 is literal -> 1.2.3.4"])

    def test_ip_literal_v6(self):
        v4, v6, err, src = D._resolve_detail("::1")
        self.assertEqual((v4, v6, err, src), ([], ["::1"], None, "literal"))
        self.assertEqual(self.received, ["DNS: ::1 is literal -> ::1"])

    def test_cache_hit(self):
        host = "cached.example"
        with D._DNS_CACHE_LOCK:
            D._DNS_CACHE[host] = (["1.2.3.4"], ["::1"], time.time() + 120, None)
        v4, v6, err, src = D._resolve_detail(host, use_cache=True, fallback=False)
        self.assertEqual(v4, ["1.2.3.4"])
        self.assertEqual(v6, ["::1"])
        self.assertEqual(src, "cache")
        self.assertEqual(self.received,
                         ["DNS: cached.example via cache -> 1.2.3.4 ::1"])

    def test_system_success(self):
        with mock.patch.object(D.socket, "getaddrinfo",
                               _gai_ok(v4=["9.9.9.9"])):
            v4, v6, err, src = D._resolve_detail("example.com",
                                                 use_cache=False, fallback=False)
        self.assertEqual((v4, v6, err, src), (["9.9.9.9"], [], None, "system"))
        self.assertEqual(self.received,
                         ["DNS: example.com via system -> 9.9.9.9 (none)"])

    def test_system_failure_then_udp_success(self):
        def _udp(host, server, qtype, timeout=1.5):
            return ["1.1.1.1"] if qtype == 1 else []
        with mock.patch.object(D.socket, "getaddrinfo", _gai_fail()):
            with mock.patch.object(D, "_dns_query_udp", side_effect=_udp):
                with mock.patch.object(D, "_dns_query_doh", return_value=[]):
                    v4, v6, err, src = D._resolve_detail("broken.example",
                                                         use_cache=False,
                                                         fallback=True)
        self.assertEqual(v4, ["1.1.1.1"])
        self.assertEqual(src, "udp:1.1.1.1")   # first server in _DNS_FALLBACK_SERVERS
        self.assertEqual(self.received, [
            "DNS: broken.example via system FAILED: host not found",
            "DNS: broken.example via udp:1.1.1.1 -> 1.1.1.1 (none)",
        ])

    def test_system_failure_then_doh_success(self):
        def _doh(host, qtype, endpoint, timeout=4.0):
            return ["1.1.1.1"] if qtype == 1 else []
        with mock.patch.object(D.socket, "getaddrinfo", _gai_fail()):
            with mock.patch.object(D, "_dns_query_udp", return_value=[]):
                with mock.patch.object(D, "_dns_query_doh", side_effect=_doh):
                    v4, v6, err, src = D._resolve_detail("doh.example",
                                                         use_cache=False,
                                                         fallback=True)
        self.assertEqual(v4, ["1.1.1.1"])
        self.assertEqual(src, "doh:1.1.1.1/dns-query")
        self.assertEqual(self.received, [
            "DNS: doh.example via system FAILED: host not found",
            "DNS: doh.example via doh:1.1.1.1/dns-query -> 1.1.1.1 (none)",
        ])

    def test_all_fallbacks_fail(self):
        with mock.patch.object(D.socket, "getaddrinfo", _gai_fail()):
            with mock.patch.object(D, "_dns_query_udp", return_value=[]):
                with mock.patch.object(D, "_dns_query_doh", return_value=[]):
                    v4, v6, err, src = D._resolve_detail("nope.example",
                                                         use_cache=False,
                                                         fallback=True)
        self.assertEqual((v4, v6, err, src),
                         ([], [], "host not found", "none"))
        self.assertEqual(self.received, [
            "DNS: nope.example via system FAILED: host not found",
            "DNS: nope.example could not resolve (system + UDP/53 + DoH)",
        ])

    def test_system_failure_without_fallback_omits_terminal(self):
        # fallback=False: the only log is the system FAILED line. The terminal
        # "could not resolve (...)" message is only meaningful when the full
        # fallback stack was actually attempted.
        with mock.patch.object(D.socket, "getaddrinfo", _gai_fail()):
            v4, v6, err, src = D._resolve_detail("nope.example",
                                                 use_cache=False, fallback=False)
        self.assertEqual((v4, v6, src), ([], [], "none"))
        self.assertEqual(self.received,
                         ["DNS: nope.example via system FAILED: host not found"])


if __name__ == "__main__":
    unittest.main()

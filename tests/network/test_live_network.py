"""Network tier - tests that touch the REAL network.

These are the only tests in the suite that need live Internet access.
They are SKIPPED unless the TUNTOP_NET_TESTS environment variable is set,
so CI and offline machines run the full suite without them:

    TUNTOP_NET_TESTS=1 python -m unittest discover -s tests -t . -v

Run them after touching netdns resolution paths or before a release - a
green offline suite does not prove the fallback stack still works.

Run:  TUNTOP_NET_TESTS=1 python -m unittest discover -s tests -t . -v
"""
import os
import socket
import unittest

from tuntop.netdns import _dns_query_doh, _dns_query_udp, _resolve_detail

_LIVE = unittest.skipUnless(os.environ.get("TUNTOP_NET_TESTS"),
                            "live-network test; set TUNTOP_NET_TESTS=1 to run")


class TestSystemResolution(unittest.TestCase):
    @_LIVE
    def test_resolve_a_real_domain(self):
        v4, v6, err, source = _resolve_detail("example.com",
                                              use_cache=False)
        self.assertIsNone(err)
        self.assertTrue(v4 or v6)
        self.assertEqual(source, "system")

    @_LIVE
    def test_literal_ips_short_circuit_dns(self):
        v4, v6, err, source = _resolve_detail("192.0.2.1", use_cache=False)
        self.assertIsNone(err)
        self.assertEqual((v4, v6, source), (["192.0.2.1"], [], "literal"))
        v4, v6, err, source = _resolve_detail("2606:4700::1111",
                                              use_cache=False)
        self.assertEqual((v4, source), (["2606:4700::1111"], "literal"))


class TestFallbackStack(unittest.TestCase):
    @_LIVE
    def test_udp_fallback_against_public_resolver(self):
        a = _dns_query_udp("example.com", "1.1.1.1", 1)
        self.assertTrue(a)                     # at least one A record

    @_LIVE
    def test_doh_fallback_against_cloudflare(self):
        a = _dns_query_doh("example.com", 1, "https://1.1.1.1/dns-query")
        self.assertTrue(a)


class TestConnectivity(unittest.TestCase):
    @_LIVE
    def test_tcp_443_egress(self):
        # The same check the dashboard's health panel performs.
        with socket.create_connection(("1.1.1.1", 443), timeout=5):
            pass


if __name__ == "__main__":
    unittest.main()

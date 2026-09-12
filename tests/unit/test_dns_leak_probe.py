"""Offline DNS-leak-probe tests (no network, no admin, no resolver calls).

Covers tuntop/network/leak_probe.py's DNS half: the UDP/53 packet builder,
name skipping (plain + compression pointers + malformed), reply parsing
(A + TXT + compressed names), the verdict matrix with mocked probe legs,
and the re-export chain that keeps the dashboard on ONE implementation.
"""
import sys
import os
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from tuntop.network import leak_probe as L
from tuntop.monitor import leak as ML


def _name(labels):
    """Wire-format DNS name (no compression)."""
    return b"".join(bytes((len(l),)) + l for l in labels) + b"\x00"


def _reply(answers, qname_labels=(b"o-o", b"myaddr", b"l", b"google", b"com")):
    """Build a NOERROR reply with a question at offset 12 and the given
    answers (list of (rtype, rdata)); every answer name is compressed to a
    pointer at offset 12 - the exact shape real resolvers send."""
    header = (b"\xab\xcd"                       # id
              + b"\x81\x80"                     # QR+RD+RA
              + (1).to_bytes(2, "big")          # qdcount
              + len(answers).to_bytes(2, "big")  # ancount
              + b"\x00\x00\x00\x00")            # ns/ar count
    question = _name(qname_labels) + (1).to_bytes(2, "big") \
        + (1).to_bytes(2, "big")                # type A, class IN
    body = b""
    for rtype, rdata in answers:
        body += (b"\xc0\x0c"                    # name -> pointer to offset 12
                 + rtype.to_bytes(2, "big")
                 + (1).to_bytes(2, "big")       # class IN
                 + (60).to_bytes(4, "big")      # TTL
                 + len(rdata).to_bytes(2, "big")
                 + rdata)
    return header + question + body


class TestDnsBuildQuery(unittest.TestCase):
    def test_query_layout(self):
        q = L._dns_build_query("whoami.akamai.net", L._DNS_TYPE_A)
        self.assertEqual(q[0:2], b"\x1f\x2e")   # id
        self.assertEqual(q[2:4], b"\x01\x00")   # RD=1
        self.assertEqual(q[4:6], b"\x00\x01")   # qdcount=1
        self.assertTrue(q.endswith(b"\x00\x00\x01\x00\x01"))  # root + A + IN
        self.assertIn(b"\x06whoami\x06akamai\x03net\x00", q)

    def test_query_txt_type(self):
        q = L._dns_build_query("o-o.myaddr.l.google.com", L._DNS_TYPE_TXT)
        self.assertIn(b"\x06myaddr\x01l\x06google\x03com\x00", q)
        self.assertEqual(q[-4:], b"\x00\x10\x00\x01")   # type TXT, class IN

    def test_empty_labels_are_skipped(self):
        q = L._dns_build_query("a..b", L._DNS_TYPE_A)
        # Empty parts are dropped, so 'a' and 'b' stay in ONE name
        # (no root marker between them).
        self.assertIn(b"\x01a\x01b\x00", q)


class TestDnsSkipName(unittest.TestCase):
    def test_plain_name(self):
        msg = _name([b"ab", b"cd"]) + b"TRAILING"
        self.assertEqual(L._dns_skip_name(msg, 0), len(msg) - 8)

    def test_compressed_pointer_returns_tail_offset(self):
        full = _name([b"x", b"y"])
        msg = full + b"\xc0\x00" + b"MORE"
        self.assertEqual(L._dns_skip_name(msg, len(full)), len(msg) - 4)

    def test_pointer_cycle_is_malformed(self):
        # A pointer that points at itself must terminate as None, not hang
        # the worker thread (regression guard for the parse-timeout hole).
        self.assertIsNone(L._dns_skip_name(b"\xc0\x00" + b"pad", 0))

    def test_truncated_name_is_malformed(self):
        self.assertIsNone(L._dns_skip_name(b"\x05ab", 0))


class TestDnsParseReply(unittest.TestCase):
    def test_a_record(self):
        self.assertEqual(L._dns_parse_reply(
            _reply([(L._DNS_TYPE_A, bytes([1, 2, 3, 4]))])), "1.2.3.4")

    def test_txt_record_joins_strings(self):
        self.assertEqual(L._dns_parse_reply(
            _reply([(L._DNS_TYPE_TXT, bytes([7]) + b"5.6.7.8")])), "5.6.7.8")

    def test_other_types_are_skipped(self):
        # A CNAME first, then the A record: only the A yields an IP.
        msg = _reply([(5, _name([b"alias"])),
                      (L._DNS_TYPE_A, bytes([9, 8, 7, 6]))])
        self.assertEqual(L._dns_parse_reply(msg, (L._DNS_TYPE_A,)), "9.8.7.6")

    def test_short_garbage_is_none(self):
        self.assertIsNone(L._dns_parse_reply(b"\x00"))
        self.assertIsNone(L._dns_parse_reply(b"HTTP/1.1 portal page"))

    def test_truncated_answer_is_none(self):
        msg = _reply([(L._DNS_TYPE_A, bytes([1, 2, 3, 4]))])
        self.assertIsNone(L._dns_parse_reply(msg[:-2]))


if __name__ == "__main__":
    unittest.main()


class TestVerdictMatrix(unittest.TestCase):
    """direct_ip = the real (ISP) egress, tunnel_ip = the tunnel exit,
    expected = the tunnel's configured DNS (resolver-identity shortcut)."""

    def test_resolver_on_isp_network_is_a_leak(self):
        with mock.patch.object(L, "_system_resolver_ip",
                               return_value="81.2.3.4"), \
             mock.patch.object(L, "_forced_path_echo_ip", return_value=None):
            status, msg, _det = L.run_dns_leak_probe(
                direct_ip="81.2.3.9", tunnel_ip="104.16.1.1",
                expected_dns=["8.8.8.8"])
        self.assertEqual(status, "dns-leak")
        self.assertIn("DNS LEAK", msg)

    def test_forced_udp53_via_isp_is_a_leak(self):
        with mock.patch.object(L, "_system_resolver_ip", return_value=None), \
             mock.patch.object(L, "_forced_path_echo_ip",
                               return_value="81.2.3.4"):
            status, msg, _det = L.run_dns_leak_probe(
                direct_ip="81.2.3.9", tunnel_ip="104.16.1.1")
        self.assertEqual(status, "dns-leak")

    def test_resolver_matching_tunnel_dns_is_ok(self):
        with mock.patch.object(L, "_system_resolver_ip",
                               return_value="8.8.8.8"), \
             mock.patch.object(L, "_forced_path_echo_ip", return_value=None):
            status, msg, _det = L.run_dns_leak_probe(
                direct_ip="81.2.3.9", tunnel_ip="104.16.1.1",
                expected_dns=["8.8.8.8"])
        self.assertEqual(status, "ok")
        self.assertIn("no DNS leak", msg)

    def test_forced_udp53_via_tunnel_exit_is_ok(self):
        with mock.patch.object(L, "_system_resolver_ip", return_value=None), \
             mock.patch.object(L, "_forced_path_echo_ip",
                               return_value="104.16.1.7"):
            status, _msg, det = L.run_dns_leak_probe(
                direct_ip="81.2.3.9", tunnel_ip="104.16.1.1")
        self.assertEqual(status, "ok")
        self.assertEqual(det["echo"], "104.16.1.7")

    def test_no_answers_at_all_is_no_dns(self):
        with mock.patch.object(L, "_system_resolver_ip", return_value=None), \
             mock.patch.object(L, "_forced_path_echo_ip", return_value=None):
            status, msg, det = L.run_dns_leak_probe(direct_ip="81.2.3.9")
        self.assertEqual(status, "no-dns")
        self.assertIsNone(det["resolver"])
        self.assertIsNone(det["echo"])

    def test_answers_without_reference_points_is_unknown(self):
        with mock.patch.object(L, "_system_resolver_ip",
                               return_value="6.6.6.6"), \
             mock.patch.object(L, "_forced_path_echo_ip", return_value=None):
            status, _msg, _det = L.run_dns_leak_probe()
        self.assertEqual(status, "unknown")

    def test_leak_evidence_wins_over_dns_match(self):
        # The forced path proves a UDP/53 escape even while the resolver
        # identity looks fine (e.g. the tunnel's resolver is reachable via
        # the physical NIC): the probe must NOT report ok.
        with mock.patch.object(L, "_system_resolver_ip",
                               return_value="8.8.8.8"), \
             mock.patch.object(L, "_forced_path_echo_ip",
                               return_value="81.2.3.4"):
            status, _msg, _det = L.run_dns_leak_probe(
                direct_ip="81.2.3.9", tunnel_ip="104.16.1.1",
                expected_dns=["8.8.8.8"])
        self.assertEqual(status, "dns-leak")


class TestSingleImplementation(unittest.TestCase):
    def test_monitor_reexports_dns_probe(self):
        self.assertIs(ML.run_dns_leak_probe, L.run_dns_leak_probe)
"""Routing-tier tests for tunmood.netdns - pure functions only.

Covers URL normalisation and the raw DNS wire format (query building +
answer parsing, including name compression and truncation tolerance).
No sockets are opened: responses are hand-crafted byte strings.

Run:  python -m unittest discover -s tests -t . -v
"""
import socket
import struct
import unittest

from tunmood.netdns import _dns_build_query, _dns_parse_answers, _host_from_url


def dns_response(answers, qname=b"\x07example\x03com\x00", qtype=1):
    """Hand-craft a minimal DNS response: one question + the given
    (rtype, rdata) answer records (names are compression pointers to the
    question name at offset 12, exactly like real resolvers send)."""
    tid, flags = 0x1234, 0x8180
    qd, an = 1, len(answers)
    pkt = struct.pack(">HHHHHH", tid, flags, qd, an, 0, 0)
    pkt += qname + struct.pack(">HH", qtype, 1)
    for rtype, rdata in answers:
        pkt += b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, 300, len(rdata))
        pkt += rdata
    return pkt


class TestHostFromUrl(unittest.TestCase):
    def test_plain_hosts_pass_through(self):
        self.assertEqual(_host_from_url("1.2.3.4"), "1.2.3.4")
        self.assertEqual(_host_from_url("example.com"), "example.com")

    def test_urls_are_stripped(self):
        self.assertEqual(_host_from_url("https://www.whatismyip.com/"),
                         "www.whatismyip.com")
        self.assertEqual(_host_from_url("http://example.com:8443/x?y=1#z"),
                         "example.com")
        self.assertEqual(_host_from_url("//cdn.example.com/a"), "cdn.example.com")

    def test_userinfo_and_ports(self):
        self.assertEqual(_host_from_url("user:pw@example.com:8443/x"),
                         "example.com")
        self.assertEqual(_host_from_url("proxy.local:10808"), "proxy.local")

    def test_ipv6_literals(self):
        self.assertEqual(_host_from_url("[2606:4700::1111]:443"),
                         "2606:4700::1111")
        self.assertEqual(_host_from_url("2606:4700::1111"),
                         "2606:4700::1111")     # bare v6 left alone

    def test_junk_is_normalized_not_fatal(self):
        self.assertEqual(_host_from_url(None), "")
        self.assertEqual(_host_from_url("   "), "")
        self.assertEqual(_host_from_url('"https://Example.COM."'),
                         "example.com")          # quotes, case, trailing dot


class TestDnsBuildQuery(unittest.TestCase):
    def test_header_layout(self):
        tid, pkt = _dns_build_query("example.com", 1)
        self.assertEqual(pkt[2:4], b"\x01\x00")       # RD flag
        self.assertEqual(pkt[4:6], b"\x00\x01")       # QDCOUNT=1
        self.assertEqual(pkt[6:12], b"\x00" * 6)      # AN/NS/AR = 0
        self.assertEqual(int.from_bytes(pkt[:2], "big"), tid)

    def test_question_encoding(self):
        _tid, pkt = _dns_build_query("a.b.example", 28)
        body = pkt[12:]
        self.assertEqual(body, b"\x01a\x01b\x07example\x00"
                               + (28).to_bytes(2, "big")
                               + (1).to_bytes(2, "big"))

    def test_transaction_ids_differ_usually(self):
        ids = {_dns_build_query("x.com", 1)[0] for _ in range(20)}
        self.assertGreater(len(ids), 1)               # not a fixed tid


class TestDnsParseAnswers(unittest.TestCase):
    def test_a_record(self):
        pkt = dns_response([(1, bytes([8, 8, 8, 8]))])
        self.assertEqual(_dns_parse_answers(pkt, 1), ["8.8.8.8"])

    def test_aaaa_record(self):
        rdata = socket.inet_pton(socket.AF_INET6, "2606:4700::1111")
        pkt = dns_response([(28, rdata)], qtype=28)
        self.assertEqual(_dns_parse_answers(pkt, 28), ["2606:4700::1111"])

    def test_wrong_type_is_ignored(self):
        pkt = dns_response([(1, bytes([8, 8, 8, 8]))])
        self.assertEqual(_dns_parse_answers(pkt, 28), [])   # wanted AAAA

    def test_compression_pointer_and_dedup(self):
        pkt = dns_response([(1, bytes([1, 1, 1, 1])),
                            (1, bytes([1, 1, 1, 1]))])      # same A twice
        self.assertEqual(_dns_parse_answers(pkt, 1), ["1.1.1.1"])

    def test_truncated_packet_never_raises(self):
        pkt = dns_response([(1, bytes([8, 8, 8, 8]))])
        self.assertEqual(_dns_parse_answers(pkt[:20], 1), [])
        self.assertEqual(_dns_parse_answers(b"\x00" * 5, 1), [])
        self.assertEqual(_dns_parse_answers(b"", 1), [])

    def test_cname_chain_is_skipped_to_the_a_record(self):
        # answer 1: CNAME (type 5) with a new name; answer 2: the A record.
        pkt = dns_response([(5, b"\x03www" + b"\xc0\x0c\x00"),
                            (1, bytes([9, 9, 9, 9]))])
        self.assertEqual(_dns_parse_answers(pkt, 1), ["9.9.9.9"])


if __name__ == "__main__":
    unittest.main()

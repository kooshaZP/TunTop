"""Routing-tier tests for tunmood.helper's pure logic.

The geoip file parser's protobuf primitives, PowerShell string quoting,
and the routable-CIDR safety filter that keeps bad geoip.dat ranges from
shadowing the user's LAN. No Windows calls, no admin, no files.

Run:  python -m unittest discover -s tests -t . -v
"""
import unittest

from tunmood.helper import (
    _is_routable_bypass_cidr, _read_bytes, _read_varint, ps_quote,
)


class TestVarint(unittest.TestCase):
    def test_single_byte(self):
        self.assertEqual(_read_varint(b"\x05", 0), (5, 1))

    def test_zero(self):
        self.assertEqual(_read_varint(b"\x00", 0), (0, 1))

    def test_multi_byte(self):
        # 300 = 0b100101100 -> varint b"\xac\x02"
        self.assertEqual(_read_varint(b"\xac\x02", 0), (300, 2))

    def test_large_value_four_bytes(self):
        buf = bytes([0x80 | 0x7F, 0x80 | 0x7F, 0x80 | 0x7F, 0x7F])
        value, pos = _read_varint(buf, 0)
        self.assertEqual(value, 0x0FFFFFFF)
        self.assertEqual(pos, 4)

    def test_continues_from_offset(self):
        buf = b"\xff\x01\x02"          # varint 255 (two bytes) then byte 2
        value, pos = _read_varint(buf, 0)
        self.assertEqual((value, pos), (255, 2))
        self.assertEqual(buf[pos], 2)


class TestReadBytes(unittest.TestCase):
    def test_length_prefixed_read(self):
        buf = b"\x03abc\x00zz"
        data, pos = _read_bytes(buf, 0)
        self.assertEqual(data, b"abc")
        self.assertEqual(pos, 4)

    def test_empty_payload(self):
        data, pos = _read_bytes(b"\x00tail", 0)
        self.assertEqual(data, b"")
        self.assertEqual(pos, 1)

    def test_truncated_payload_returns_what_is_there(self):
        data, _pos = _read_bytes(b"\x05ab", 0)
        self.assertEqual(data, b"ab")       # tolerant, never raises


class TestPsQuote(unittest.TestCase):
    def test_plain_string_unchanged(self):
        self.assertEqual(ps_quote("wintun"), "wintun")

    def test_embedded_quote_is_doubled(self):
        self.assertEqual(ps_quote("Bob's VPN"), "Bob''s VPN")

    def test_cannot_break_out_of_literal(self):
        # A hostile interface name must stay inside the quoted literal.
        evil = "x' | Remove-NetRoute -Confirm:$false | echo '"
        quoted = ps_quote(evil)
        self.assertFalse("'" in quoted.replace("''", ""))


class TestRoutableBypassCidr(unittest.TestCase):
    def test_public_ranges_are_routable(self):
        self.assertTrue(_is_routable_bypass_cidr("8.8.8.0/24"))
        self.assertTrue(_is_routable_bypass_cidr("1.0.1.0/24"))     # real CN
        self.assertTrue(_is_routable_bypass_cidr("114.114.114.0/24"))

    def test_private_lan_is_never_routable(self):
        for cidr in ("10.0.0.0/8", "192.168.1.0/24", "172.16.0.0/12"):
            self.assertFalse(_is_routable_bypass_cidr(cidr), cidr)

    def test_loopback_linklocal_multicast_reserved(self):
        for cidr in ("127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4",
                     "240.0.0.0/4", "2001:db8::/32"):
            self.assertFalse(_is_routable_bypass_cidr(cidr), cidr)

    def test_wintun_own_net_is_protected(self):
        # The ranges that would shadow the Wintun next-hop (192.168.123.1 /
        # fd00:dead:beef::1) must never be installed as direct routes.
        self.assertFalse(_is_routable_bypass_cidr("192.168.123.0/24"))
        self.assertFalse(_is_routable_bypass_cidr("192.168.123.55/32"))
        self.assertFalse(_is_routable_bypass_cidr("fd00:dead:beef::/64"))

    def test_garbage_is_rejected_not_raised(self):
        self.assertFalse(_is_routable_bypass_cidr("not a cidr"))
        self.assertFalse(_is_routable_bypass_cidr("300.300.300.0/24"))
        self.assertFalse(_is_routable_bypass_cidr(""))


if __name__ == "__main__":
    unittest.main()

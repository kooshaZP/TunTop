"""Routing-tier tests for tuntop.helper's pure logic.

The geoip file parser's protobuf primitives, PowerShell string quoting,
and the routable-CIDR safety filter that keeps bad geoip.dat ranges from
shadowing the user's LAN. No Windows calls, no admin, no files.

Run:  python -m unittest discover -s tests -t . -v
"""
import unittest

from tuntop.tunnel.helper import (
    VPN_IFACE_RE, _geo_overlaps_protected, _is_routable_bypass_cidr,
    _read_bytes, _read_varint, collect_protected_geo_prefixes, ps_quote,
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


class TestGeoOverlapsProtected(unittest.TestCase):
    """geoip must never own (install OR remove) a prefix that already has its
    own egress: the tunnel's endpoint /32s and the user's bypass entries."""

    def test_exact_match_is_protected(self):
        # A geoip.dat that ships the VLESS server's own /32 (the exact route
        # the helper installed) would otherwise be swept + re-pointed.
        self.assertTrue(_geo_overlaps_protected("1.2.3.4/32", ["1.2.3.4/32"]))

    def test_geo_inside_protected_range_is_protected(self):
        # User bypasses 5.0.0.0/16; a more-specific geo /24 inside it must be
        # skipped so the bypass range keeps the egress its entry names.
        self.assertTrue(_geo_overlaps_protected("5.5.10.0/24", ["5.5.0.0/16"]))
        self.assertTrue(_geo_overlaps_protected("5.5.0.0/17", ["5.5.0.0/16"]))

    def test_geo_covering_protected_host_is_kept(self):
        # The common case: the server IP sits INSIDE a broad geo range.  The
        # geo route stays (it is still useful for the rest of the range) and
        # the endpoint's /32 wins by longest-prefix - so a broader geo CIDR
        # is NOT a conflict.
        self.assertFalse(_geo_overlaps_protected("5.5.0.0/16", ["5.5.10.7/32"]))

    def test_unrelated_and_version_mismatch(self):
        self.assertFalse(_geo_overlaps_protected("9.9.9.0/24", ["1.2.3.4/32"]))
        self.assertFalse(_geo_overlaps_protected("2001:db8::/32", ["1.2.3.4/32"]))
        self.assertFalse(_geo_overlaps_protected("1.2.3.0/24", ["2001:db8::/32"]))

    def test_bad_input_never_raises(self):
        self.assertFalse(_geo_overlaps_protected("garbage", ["1.2.3.4/32"]))
        self.assertFalse(_geo_overlaps_protected("1.2.3.0/24", ["garbage", ""]))

    def test_bare_host_cidr_normalizes_to_32(self):
        # ip_network("1.2.3.4") == 1.2.3.4/32, so a bare host geo entry still
        # matches the endpoint's explicit /32.
        self.assertTrue(_geo_overlaps_protected("1.2.3.4", ["1.2.3.4/32"]))

    def test_empty_protected_never_conflicts(self):
        self.assertFalse(_geo_overlaps_protected("1.2.3.0/24", ()))


class TestCollectProtectedGeoPrefixes(unittest.TestCase):
    def test_endpoint_ips_become_host_routes(self):
        prot = collect_protected_geo_prefixes(
            server_v4=["1.2.3.4"], server_v6=["2001:db8::1"],
            bypass_v4=["5.6.7.8"], vpn_v4=["9.9.9.9"],
            proxy2_v4=["10.20.30.40"], proxy2_v6=["fd00::2"],
        )
        for want in ("1.2.3.4/32", "5.6.7.8/32", "9.9.9.9/32",
                     "10.20.30.40/32", "2001:db8::1/128", "fd00::2/128"):
            self.assertIn(want, prot)

    def test_deduplicates(self):
        prot = collect_protected_geo_prefixes(
            server_v4=["1.2.3.4", "1.2.3.4"], bypass_v4=["1.2.3.4"])
        self.assertEqual(prot, ["1.2.3.4/32"])

    def test_cidr_entries_pass_through(self):
        prot = collect_protected_geo_prefixes(cidr_entries=["5.5.0.0/16"])
        self.assertEqual(prot, ["5.5.0.0/16"])

    def test_bad_cidr_entries_are_dropped(self):
        # Bare hosts are NOT cidr_entries (they are resolved upstream into
        # /32s) and garbage must never reach the route layer.
        prot = collect_protected_geo_prefixes(
            cidr_entries=["example.com", "not a cidr", "300.1.2.3/24"])
        self.assertEqual(prot, [])

    def test_empty_inputs(self):
        self.assertEqual(collect_protected_geo_prefixes(), [])


class TestVpnIfaceDetection(unittest.TestCase):
    """The VPN alias heuristic must catch every built-in Windows VPN tunnel
    type yet never flag the physical NIC or the Wintun adapter (flagging
    Wintun would make us exclude our own tunnel interface)."""

    def _matches(self, alias):
        # VPN_IFACE_RE is a raw-string pattern (injected into PowerShell via
        # %-formatting), so compile it for matching with the inline (?i) flag.
        import re
        return re.search(VPN_IFACE_RE, alias, re.IGNORECASE) is not None

    def test_builtin_vpn_types_are_detected(self):
        for alias in ("My VPN", "PPTP Connection", "L2TP VPN", "SSTP",
                      "IKEv2", "WAN Miniport (IKEv2)", "vpn0"):
            self.assertTrue(self._matches(alias), alias)

    def test_physical_and_tun_adapters_are_not_flagged(self):
        for alias in ("Wi-Fi", "Ethernet", "Ethernet 2", "Local Area Connection",
                      "Wintun", "wintun Tunnel", "Loopback Pseudo-Interface"):
            self.assertFalse(self._matches(alias), alias)

    def test_case_insensitive(self):
        self.assertTrue(self._matches("Shirazu-VPN"))
        self.assertTrue(self._matches("pptp"))
        self.assertFalse(self._matches("WINTUN"))  # still not a VPN alias


if __name__ == "__main__":
    unittest.main()

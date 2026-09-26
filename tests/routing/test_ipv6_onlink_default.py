"""Regression tests: IPv6 on-link default routes are accepted, not filtered.

Root cause: the IPv6 default-route lookup functions in helper.py and
routing.py carried a `$_ -ne '::'` Where-Object filter copied from the IPv4
`0.0.0.0` pattern.  On IPv6, an on-link route (NextHop = '::') is the NORMAL
form of a default route on a physical adapter - the next-hop is resolved via
neighbor discovery, so there is no gateway address.  Filtering these out made
get_ipv6_default() return None whenever a system only had on-link IPv6
defaults, which silently skipped all IPv6 geo/host bypass installs.

Fix: the `-ne '::'` filter was removed from all four IPv6 default lookups
(get_ipv6_default, get_vpn_ipv6_default, _get_ipv6_default, _get_vpn_ipv6_default)
and the NextHop is normalized from '::' to '' on all return paths.

These tests pin:
  * on-link IPv6 defaults are accepted (not filtered) and normalized to '';
  * real IPv6 gateways pass through unchanged;
  * the generated PowerShell no longer contains `-ne '::'`;
  * add_v6() treats an existing on-link route as already-correct (no stale
    delete);
  * add_geoip_bypass()'s netsh script for an on-link v6 install has no
    double-space / empty-token gateway.

Run: python -m unittest discover -s tests -t . -v
"""
import contextlib
import io
import json
import os
import unittest
from unittest import mock

from tuntop.tunnel import helper as H
from tuntop.network import routing


def _capture_ps(seen, return_value):
    """Return a fake _ps that records the script and yields return_value."""
    def _fn(script, timeout=8):
        seen.append(script)
        return True, return_value
    return _fn


class TestGetIpv6DefaultOnLink(unittest.TestCase):
    """get_ipv6_default() in helper.py must accept on-link (::) routes and
    normalize NextHop to ''."""

    def _ps_json_mock(self, return_value):
        return mock.patch.object(H, "ps_json", return_value=return_value)

    def test_on_link_is_accepted_and_normalized(self):
        # Before the fix, the -ne '::' filter caused ps_json to return a
        # route that the script itself would have filtered.  By mocking
        # ps_json directly we test the Python-side normalization that runs
        # AFTER ps_json returns.
        with self._ps_json_mock({"InterfaceAlias": "Wi-Fi", "NextHop": "::"}):
            d = H.get_ipv6_default()
        self.assertIsNotNone(d)
        self.assertEqual(d["InterfaceAlias"], "Wi-Fi")
        self.assertEqual(d["NextHop"], "")

    def test_real_gateway_passthrough(self):
        with self._ps_json_mock({"InterfaceAlias": "Ethernet",
                                  "NextHop": "fe80::1"}):
            d = H.get_ipv6_default()
        self.assertEqual(d["InterfaceAlias"], "Ethernet")
        self.assertEqual(d["NextHop"], "fe80::1")

    def test_no_onlink_filter_in_script(self):
        """The helper's get_ipv6_default script must NOT contain the
        '-ne '::'' filter that used to exclude on-link IPv6 routes."""
        with mock.patch.object(H, "ps_json", return_value={
            "InterfaceAlias": "Wi-Fi", "NextHop": "fe80::1"}):
            H.get_ipv6_default()
        # Re-capture the script by intercepting ps_json's argument.
        seen = []
        with mock.patch.object(H, "ps_json",
                               side_effect=lambda s: seen.append(s)
                               or {"InterfaceAlias": "Wi-Fi", "NextHop": "::"}):
            H.get_ipv6_default()
        self.assertEqual(len(seen), 1)
        self.assertNotIn("-ne '::'", seen[0])

    def test_vpn_on_link_is_accepted_and_normalized(self):
        with self._ps_json_mock({"InterfaceAlias": "MyVPN", "NextHop": "::"}):
            d = H.get_vpn_ipv6_default("MyVPN")
        self.assertIsNotNone(d)
        self.assertEqual(d[0], "MyVPN")
        self.assertEqual(d[1], "")


class TestRoutingIpv6DefaultOnLink(unittest.TestCase):
    """_get_ipv6_default() and _get_vpn_ipv6_default() in routing.py must
    accept on-link (::) routes and return ('', '')-normalized tuples."""

    def test_get_ipv6_default_normalizes_onlink(self):
        with mock.patch.object(routing, "_ps",
                               return_value=(True,
                                             json.dumps({"InterfaceAlias": "Wi-Fi",
                                                         "NextHop": "::"}))):
            result = routing._get_ipv6_default()
        self.assertEqual(result, ("Wi-Fi", ""))

    def test_get_vpn_ipv6_default_normalizes_onlink(self):
        with mock.patch.object(routing, "_ps",
                               return_value=(True,
                                             json.dumps({"InterfaceAlias": "VPN01",
                                                         "NextHop": "::"}))):
            result = routing._get_vpn_ipv6_default("VPN01")
        self.assertEqual(result, ("VPN01", ""))

    def test_get_ipv6_default_real_gateway(self):
        with mock.patch.object(routing, "_ps",
                               return_value=(True,
                                             json.dumps({"InterfaceAlias": "Wi-Fi",
                                                         "NextHop": "fe80::1"}))):
            result = routing._get_ipv6_default()
        self.assertEqual(result, ("Wi-Fi", "fe80::1"))

    def test_vpn_ipv6_default_no_filter_in_script(self):
        seen = []
        with mock.patch.object(routing, "_ps", _capture_ps(seen,
                json.dumps({"InterfaceAlias": "VPN01", "NextHop": "::"}))):
            routing._get_vpn_ipv6_default("Bob's VPN")
        self.assertEqual(len(seen), 1)
        self.assertNotIn("-ne '::'", seen[0])

    def test_ipv6_default_no_filter_in_script(self):
        seen = []
        with mock.patch.object(routing, "_ps", _capture_ps(seen,
                json.dumps({"InterfaceAlias": "Wi-Fi", "NextHop": "::"}))):
            routing._get_ipv6_default()
        self.assertEqual(len(seen), 1)
        self.assertNotIn("-ne '::'", seen[0])

    def test_get_vpn_ipv6_default_quotes_interface(self):
        seen = []
        with mock.patch.object(routing, "_ps", _capture_ps(seen,
                json.dumps({"InterfaceAlias": "Bob", "NextHop": "::"}))):
            routing._get_vpn_ipv6_default("Bob's VPN")
        self.assertIn("-InterfaceAlias 'Bob''s VPN'", seen[0])


class TestAddV6OnLinkRecognition(unittest.TestCase):
    """add_v6() must recognize an existing on-link route (NextHop '::') as
    already-correct when the caller passes gateway=''.

    Before the fix: r_gw stayed '::', same_gateway compared '::' != '' ->
    False, so the route was treated as STALE and a redundant delete+re-add
    was issued."""

    def test_existing_onlink_match_no_stale_delete(self):
        deletes = []

        def fake_run(cmd, check=False, timeout=15):
            if "delete" in cmd:
                deletes.append(list(cmd))
            return (0, "Ok.", "")

        with mock.patch.object(H, "get_existing_v6_routes",
                               return_value=[{"InterfaceAlias": "Wi-Fi",
                                              "NextHop": "::"}]), \
             mock.patch.object(H, "run", side_effect=fake_run), \
             mock.patch.object(H, "_route_identity_present",
                               return_value=True):
            H.add_v6("2001:db8::1111/128", "Wi-Fi", gateway="")

        # Before the fix: r_gw stayed '::', same_gateway compared '::' != ''
        # -> False -> the existing route was treated as STALE, issuing a
        # stale delete INSIDE the loop (in addition to the persistent->active
        # conversion delete at line 1252).  That is 2 delete calls.
        # After the fix: the on-link route normalizes to '' and matches, so
        # found_correct=True and NO stale delete is issued - only the single
        # persistent->active conversion delete remains.
        self.assertEqual(len(deletes), 1,
                         f"expected only the conversion delete, got {len(deletes)}: {deletes}")
        # The conversion delete must have no gateway token (gateway='').
        self.assertEqual(len(deletes[0]), 7,
                         f"conversion delete should have no gateway token: {deletes[0]}")
        self.assertNotIn("fe80", str(deletes[0]))

    def test_existing_real_gateway_match(self):
        deletes = []

        def fake_run(cmd, check=False, timeout=15):
            if "delete" in cmd:
                deletes.append(list(cmd))
            return (0, "Ok.", "")

        with mock.patch.object(H, "get_existing_v6_routes",
                               return_value=[{"InterfaceAlias": "Wi-Fi",
                                              "NextHop": "fe80::1"}]), \
             mock.patch.object(H, "run", side_effect=fake_run), \
             mock.patch.object(H, "_route_identity_present",
                               return_value=True):
            H.add_v6("2001:db8::1111/128", "Wi-Fi", gateway="fe80::1")

        # Real gateway matches without normalization - only the conversion
        # delete, and it DOES carry the gateway token since gateway is truthy.
        self.assertEqual(len(deletes), 1)
        self.assertEqual(len(deletes[0]), 8,
                         f"conversion delete should carry gateway: {deletes[0]}")


class TestGeoInstallOnLinkNetsh(unittest.TestCase):
    """add_geoip_bypass() must produce a netsh script with no double-space or
    empty-gateway token when installing on-link IPv6 routes (gw='').

    Before the fix: the format string '%s %s %s %s' emitted a bare double
    space when gw was empty, and netsh rejected it as an invalid token."""

    def setUp(self):
        self._saved_geoip_added = list(H.geoip_added)
        self._saved_diag_seen = set(H._GEO_DIAG_SEEN)

    def tearDown(self):
        H.geoip_added[:] = self._saved_geoip_added
        H._GEO_DIAG_SEEN.clear()
        H._GEO_DIAG_SEEN.update(self._saved_diag_seen)

    def _run_geo_with_capture(self, v6gw):
        """Call add_geoip_bypass with a single v6 CIDR; return the captured
        netsh script content written to the temp file."""
        scripts = []

        def fake_run(cmd, check=False, timeout=15):
            if len(cmd) >= 3 and cmd[0:3] == ["netsh", "-f", cmd[2]]:
                path = cmd[2]
                if os.path.exists(path):
                    with open(path, "r") as f:
                        scripts.append(f.read())
            return (0, "Ok.", "")

        with mock.patch.object(H, "get_vpn_ipv4_default",
                               return_value=None), \
             mock.patch.object(H, "ensure_physical_metric_below_vpn") as _, \
             mock.patch.object(H, "_geo_remove_conflicts") as _, \
             mock.patch.object(H, "run", side_effect=fake_run):
            H.add_geoip_bypass(
                "cn", ["2606:4700::/32"],
                "Wi-Fi", "192.168.1.1",
                v6iface="Wi-Fi", v6gw=v6gw,
            )
        return scripts

    def test_on_link_v6_no_double_space(self):
        scripts = self._run_geo_with_capture(v6gw="")
        self.assertTrue(scripts, "expected at least one netsh script")
        for s in scripts:
            # No double-space: "add route PREFIX "IFACE" metric"
            self.assertNotIn('"Wi-Fi"  metric', s)
            self.assertIn('"Wi-Fi" metric', s)

    def test_on_link_v6_no_gateway_token(self):
        scripts = self._run_geo_with_capture(v6gw="")
        self.assertTrue(scripts)
        for s in scripts:
            # Each add route line must end with the interface, metric, store -
            # no trailing empty gateway token.
            for line in s.strip().splitlines():
                if "add route" in line:
                    self.assertTrue(line.rstrip().endswith(
                        '"Wi-Fi" metric=1 store=active'),
                        f"line has unexpected gateway token: {line!r}")

    def test_real_gateway_v6_includes_gateway(self):
        scripts = self._run_geo_with_capture(v6gw="fe80::1")
        self.assertTrue(scripts)
        for s in scripts:
            for line in s.strip().splitlines():
                if "add route" in line:
                    self.assertIn('"Wi-Fi" fe80::1 metric=1 store=active',
                                  line)

    def test_missing_v6_egress_is_reported_as_skipped(self):
        """Parsed IPv6 CIDRs must not be advertised as installed when the
        selected target has no IPv6 interface/next-hop.  This is the normal
        state on an IPv4-only Wi-Fi network: the 1036 IR IPv6 prefixes remain
        in geoip.dat, but only the IPv4 batches can be scheduled."""
        out = io.StringIO()

        def fake_run(cmd, check=False, timeout=15):
            return (0, "Ok.", "")

        with mock.patch.object(H, "get_vpn_ipv4_default",
                               return_value=None), \
             mock.patch.object(H, "ensure_physical_metric_below_vpn"), \
             mock.patch.object(H, "_geo_remove_conflicts"), \
             mock.patch.object(H, "run", side_effect=fake_run), \
             contextlib.redirect_stdout(out):
            rows = H.add_geoip_bypass(
                "ir", ["5.0.0.0/16", "2606:4700::/32"],
                "Wi-Fi", "10.99.205.162",
                v6iface=None, v6gw=None,
            )

        text = out.getvalue()
        self.assertIn("1 IPv4 via Wi-Fi (gw=10.99.205.162)", text)
        self.assertIn("1 IPv6 skipped (no usable IPv6 egress", text)
        self.assertNotIn("1 IPv4, 1 IPv6", text)
        self.assertIn("loaded=0 total=1", text)
        self.assertNotIn("loaded=0 total=2", text)
        self.assertEqual(rows, [("v4", "5.0.0.0/16", "Wi-Fi",
                                 "10.99.205.162")])


if __name__ == "__main__":
    unittest.main()

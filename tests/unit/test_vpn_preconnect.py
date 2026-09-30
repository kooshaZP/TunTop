"""Offline tests for the Windows-VPN pre-connect bypass (tuntop/tunnel/helper.py).

THE BUG THIS EXISTS FOR
-----------------------
`get_active_windows_vpn_servers()` used to filter on
`ConnectionStatus -eq 'Connected'`, so a VPN profile that was CONFIGURED but
not yet connected got no `/32` bypass for its `ServerAddress`. A Windows VPN's
IKE / L2TP / PPP handshake goes to that address *before* the profile ever
reaches Connected, so Wintun's `0.0.0.0/1` + `128.0.0.0/1` splits captured the
handshake and the connect attempt died inside the tunnel with a
transport-level RAS error ("the specified port is already in use" / "the
specified protocol is already open").

The rescue could not fire. The dashboard's `vpn_endpoint_reapply` one-shot
(`BTopTui._on_vpn_arrived`) triggers on a `None -> Connected` transition, and
a failed attempt never produces one - so the user was stuck retrying against a
tunnel that guaranteed the failure, with the only escape being to stop TunTop.

Nothing in TunTop binds UDP 500/4500/1701, so this is routing capture, not a
port conflict.

`resolve_vpn_endpoint_physical()` is the second half. `resolve_all()` uses
`socket.getaddrinfo`, i.e. the SYSTEM resolver - which, while the guard is up,
is the catch-all NRPT rule pointing at the TUNNEL's resolvers. For a
split-horizon corporate gateway that returns the wrong address set (so the
`/32` pins an address the physical path never uses) or nothing at all.

Everything here stubs `ps_json` / `_raw_add_route`, so no PowerShell, no
registry and no routing table is ever touched.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))

import tuntop.tunnel.helper as H  # noqa: E402


def _script_of(mocked, idx=0):
    return mocked.call_args_list[idx][0][0]


class TestConnectedOnlyFilter(unittest.TestCase):
    """`connected_only` is the whole fix, and it is one WHERE clause."""

    def _script(self, **kw):
        with mock.patch.object(H, "ps_json", return_value=[]) as pj:
            H.get_active_windows_vpn_servers(**kw)
        return _script_of(pj)

    def test_the_default_still_filters_on_connected(self):
        """Callers that genuinely want only live VPNs (a default-route
        lookup, a shadow pass) must keep the old behaviour - broadening it
        everywhere would report a profile as usable when it is not."""
        self.assertIn("ConnectionStatus -eq 'Connected'",
                      self._script())

    def test_connected_only_false_drops_the_status_filter(self):
        s = self._script(connected_only=False)
        self.assertNotIn("ConnectionStatus", s)
        # ...but the ServerAddress requirement stays: a profile with no
        # gateway has nothing to bypass.
        self.assertIn("Where-Object {$_.ServerAddress}", s)

    def test_both_variants_read_both_profile_scopes(self):
        for kw in ({}, {"connected_only": False}):
            with self.subTest(**kw):
                s = self._script(**kw)
                self.assertIn("Get-VpnConnection -AllUserConnection", s)
                self.assertIn("Sort-Object Name, ServerAddress -Unique", s)

    def test_connected_false_is_what_the_bypass_installers_ask_for(self):
        """A regression here is invisible until someone retries a failed VPN
        connect, so the two call sites are pinned to the string."""
        import inspect
        src = inspect.getsource(H._live_apply_vpn_bypass_routes)
        self.assertIn("connected_only=False", src)
        main_src = inspect.getsource(H.main)
        self.assertIn("get_active_windows_vpn_servers(connected_only=False)",
                      main_src)

    def test_disconnected_profiles_are_returned(self):
        with mock.patch.object(H, "ps_json", return_value=[
                {"Name": "Corp", "ServerAddress": "203.0.113.7"}]):
            got = H.get_active_windows_vpn_servers(connected_only=False)
        self.assertEqual(got, [("Corp", "203.0.113.7")])


class TestResolveVpnEndpointPhysical(unittest.TestCase):
    def test_an_ip_literal_short_circuits_with_no_shell(self):
        """The common case, and it must work on a machine whose DNS is
        entirely broken - which is exactly the machine that needs the bypass
        to already be there."""
        for ip in ("203.0.113.7", "2001:db8::1"):
            with self.subTest(ip=ip), mock.patch.object(H, "ps_json") as pj:
                v4, v6, got = H.resolve_vpn_endpoint_physical(ip)
            self.assertTrue(got)
            pj.assert_not_called()
            self.assertEqual(v4 + v6, [ip])

    def test_a_hostname_queries_the_physical_adapters_resolvers(self):
        with mock.patch.object(H, "ps_json", return_value={
                "v4": ["203.0.113.7"], "v6": []}) as pj:
            v4, v6, got = H.resolve_vpn_endpoint_physical("vpn.example.com")
        self.assertTrue(got)
        self.assertEqual((v4, v6), (["203.0.113.7"], []))
        s = _script_of(pj)
        self.assertIn("Get-DnsClientServerAddress", s)
        self.assertIn("Resolve-DnsName", s)
        self.assertIn("-DnsOnly", s)
        self.assertIn("'vpn.example.com'", s)

    def test_the_tunnel_resolvers_are_never_asked(self):
        """The bug: the system resolver IS the catch-all guard while the
        tunnel is up, so asking it re-creates the very answer set that cannot
        reach the gateway."""
        with mock.patch.object(H, "ps_json", return_value={
                "v4": ["1.1.1.1"], "v6": []}) as pj:
            H.resolve_vpn_endpoint_physical("vpn.example.com")
        s = _script_of(pj)
        self.assertIn("$tunAliases -notcontains", s)
        self.assertIn("$vpnAliases -notcontains", s)
        # The loopback and the TUN's own resolvers are also excluded, so a
        # Wintun adapter publishing 8.8.8.8 cannot be the answer either.
        self.assertIn("127.0.0.1", s)
        self.assertIn("-ne '::1'", s)

    def test_a_name_only_the_tunnel_can_answer_installs_nothing(self):
        """`resolved=False` means "leave it alone", NOT "give up". A corporate
        DNS reachable solely over the VPN needs the gateway to ride the
        tunnel, and pinning it to the physical adapter would break it."""
        for d in ({}, {"v4": [], "v6": []}, None, "no result"):
            with self.subTest(d=d), mock.patch.object(
                    H, "ps_json", return_value=d):
                self.assertEqual(
                    H.resolve_vpn_endpoint_physical("gw.corp.example"),
                    ([], [], False))

    def test_a_raising_probe_is_not_an_answer(self):
        with mock.patch.object(H, "ps_json", side_effect=OSError("timeout")):
            self.assertEqual(
                H.resolve_vpn_endpoint_physical("gw.corp.example"),
                ([], [], False))

    def test_a_broken_json_shape_is_not_an_answer(self):
        with mock.patch.object(H, "ps_json", return_value=["203.0.113.7"]):
            self.assertEqual(
                H.resolve_vpn_endpoint_physical("gw.corp.example"),
                ([], [], False))

    def test_empty_input_is_handled(self):
        for s in ("", None, "   "):
            with self.subTest(s=s):
                self.assertEqual(H.resolve_vpn_endpoint_physical(s),
                                 ([], [], False))

    def test_a_url_shaped_address_is_unwrapped(self):
        with mock.patch.object(H, "ps_json", return_value={
                "v4": ["203.0.113.7"], "v6": []}) as pj:
            H.resolve_vpn_endpoint_physical("vpn.example.com:1701")
        self.assertIn("'vpn.example.com'", _script_of(pj))


class TestStartupUsesPreConnectBypass(unittest.TestCase):
    """The startup install path, exercised with its own collaborators stubbed
    so the decision - which endpoints get a bypass - is the thing under test."""

    def setUp(self):
        self.saved = (H.vpn_override_routes, list(H.vpn_saved_routes),
                      H.vpn_override_iface)
        H.vpn_override_routes.clear()
        H.vpn_saved_routes.clear()

    def tearDown(self):
        H.vpn_override_routes.clear()
        H.vpn_override_routes.extend(self.saved[0])
        H.vpn_saved_routes[:] = self.saved[1]
        H.vpn_override_iface = self.saved[2]

    def test_the_live_enable_path_installs_a_bypass_for_a_disconnected_one(self):
        """The end-to-end shape of the fix, at the function the [Y] toggle and
        the arrival one-shot both go through."""
        H._live_mode["args"] = None
        added = []

        def fake_add_v4(dest, iface, gw, metric=1):
            added.append((dest, iface))
            return True

        with mock.patch.object(
                H, "get_active_windows_vpn_servers",
                return_value=[("Corp", "203.0.113.7")]) as src, \
                mock.patch.object(H, "add_v4", side_effect=fake_add_v4), \
                mock.patch.object(H, "get_ipv6_default", return_value=None), \
                mock.patch.object(H, "_direct_bypass_egress",
                                  return_value=("Wi-Fi", "192.168.1.1")), \
                mock.patch.object(H, "_live_set_vpn_shadow", return_value=False):
            H._live_mode["no_vpn_bypass"] = False
            H._live_mode["vless_over_vpn"] = False
            lines = H._live_apply_vpn_bypass_routes(True)
        src.assert_called_once_with(connected_only=False)
        self.assertEqual(added, [("203.0.113.7/32", "Wi-Fi")])
        self.assertTrue(any("VPN endpoint bypass installed live" in ln
                            for ln in lines))

    def test_an_unresolvable_endpoint_is_reported_not_installed(self):
        H._live_mode["args"] = None
        added = []
        with mock.patch.object(
                H, "get_active_windows_vpn_servers",
                return_value=[("Corp", "gw.corp.example")]), \
                mock.patch.object(H, "add_v4",
                                  side_effect=lambda *a, **k: added.append(a)
                                  or True), \
                mock.patch.object(H, "resolve_vpn_endpoint_physical",
                                  return_value=([], [], False)), \
                mock.patch.object(H, "get_ipv6_default", return_value=None), \
                mock.patch.object(H, "_live_set_vpn_shadow", return_value=False):
            H._live_mode["no_vpn_bypass"] = False
            H._live_mode["vless_over_vpn"] = False
            lines = H._live_apply_vpn_bypass_routes(True)
        self.assertEqual(added, [], "a /32 was installed for an address we "
                                    "never resolved")
        self.assertTrue(any("--vpn-server" in ln for ln in lines),
                        "the operator is not told how to pin it by hand")

    def test_a_failed_install_still_lands_in_the_pending_retry_list(self):
        """The 15 s self-heal consumes `vpn_pending`. A dropped row here is the
        "the VPN server traffic goes into the tun" report that list was
        added for."""
        H._live_mode["args"] = None
        with mock.patch.object(
                H, "get_active_windows_vpn_servers",
                return_value=[("Corp", "203.0.113.7")]), \
                mock.patch.object(H, "add_v4", return_value=False), \
                mock.patch.object(H, "get_ipv6_default", return_value=None), \
                mock.patch.object(H, "_direct_bypass_egress",
                                  return_value=("Wi-Fi", "192.168.1.1")), \
                mock.patch.object(H, "_live_set_vpn_shadow", return_value=False):
            H._live_mode["no_vpn_bypass"] = False
            H._live_mode["vless_over_vpn"] = False
            lines = H._live_apply_vpn_bypass_routes(True)
        self.assertIn(("v4", "203.0.113.7/32"), H._live_mode["vpn_pending"])
        self.assertTrue(any("retries them every 15s" in ln for ln in lines))
        H._live_mode["vpn_pending"] = []


class TestOverrideReceiptAfterAdd(unittest.TestCase):
    """The `vpn_saved_routes` receipt must be written only after a confirmed
    install.

    It used to be appended BEFORE `_raw_add_route` reported back, so a failed
    add left a receipt for a route that was never installed - and
    `_live_set_vpn_shadow()` treats a non-empty `vpn_saved_routes` as "already
    shadowed" and returns True without retrying. One transient add failure
    therefore latched the VPN-route shadowing off for the rest of the session:
    the VPN's /32s kept escaping the tunnel while every TunTop health row
    stayed green.
    """

    def setUp(self):
        H.vpn_override_routes.clear()
        H.vpn_saved_routes.clear()
        self.saved = (H.geoip_added, H._raw_add_route, H._vpn_saved_lock)
        H.geoip_added = []

    def tearDown(self):
        H.geoip_added = self.saved[0]
        H._raw_add_route = self.saved[1]
        H.vpn_override_routes.clear()
        H.vpn_saved_routes.clear()

    def _rows(self):
        return [{"DestinationPrefix": "10.0.0.0/8", "NextHop": "0.0.0.0",
                 "RouteMetric": 5}]

    def _one_family(self, returncode=None):
        """override_vpn_routes walks IPv4 then IPv6. Feed the route table to
        the IPv4 pass and nothing to the IPv6 one, so the ledgers hold exactly
        one entry and the counts below mean what they say."""
        return mock.patch.object(H, "ps_json",
                                 side_effect=[self._rows(), []])

    def test_a_failed_add_leaves_both_ledgers_empty(self):
        with self._one_family(), \
                mock.patch.object(H, "_set_wintun_interface_metric"), \
                mock.patch.object(H, "_raw_add_route", return_value=False):
            H.override_vpn_routes("Corp-VPN", skip_ips=set())
        self.assertEqual(list(H.vpn_override_routes), [])
        self.assertEqual(H.vpn_saved_routes, [],
                         "a restore receipt was written for a route that was "
                         "never installed")

    def test_a_failed_add_leaves_the_shadow_retryable(self):
        """The user-visible consequence: with the ledgers empty, a second pass
        is still willing to shadow. This is the assertion that would have
        caught the bug."""
        with self._one_family(), \
                mock.patch.object(H, "_set_wintun_interface_metric"), \
                mock.patch.object(H, "_raw_add_route", return_value=False):
            H.override_vpn_routes("Corp-VPN", skip_ips=set())
        H.vpn_override_iface = "Corp-VPN"
        self.assertFalse(list(H.vpn_override_routes))
        # _live_set_vpn_shadow's "already shadowed" gate.
        self.assertFalse(H.vpn_override_routes or H.vpn_saved_routes)
        H.vpn_override_iface = None

    def test_a_successful_add_records_both(self):
        with self._one_family(), \
                mock.patch.object(H, "_set_wintun_interface_metric"), \
                mock.patch.object(H, "_raw_add_route", return_value=True):
            H.override_vpn_routes("Corp-VPN", skip_ips=set())
        self.assertEqual(len(list(H.vpn_override_routes)), 1)
        self.assertEqual(len(H.vpn_saved_routes), 1)
        fam, prefix, iface, gw, metric = H.vpn_saved_routes[0]
        self.assertEqual((fam, prefix, iface, metric),
                         ("v4", "10.0.0.0/8", "Corp-VPN", 5))

    def test_a_partial_failure_keeps_the_successful_ones_only(self):
        calls = {"n": 0}

        def flaky(*a, **k):
            calls["n"] += 1
            return calls["n"] == 1

        with self._one_family(), \
                mock.patch.object(H, "_set_wintun_interface_metric"), \
                mock.patch.object(H, "_raw_add_route", side_effect=flaky):
            H.override_vpn_routes("Corp-VPN", skip_ips=set())
        self.assertEqual(len(list(H.vpn_override_routes)), 1)
        self.assertEqual(len(H.vpn_saved_routes), 1)


if __name__ == "__main__":
    unittest.main()

"""The per-IP egress lookup must be ONE script for BOTH processes.

The dashboard mirror (network/routing._get_egress_for) is copy-paste
descended from the helper's get_egress_for - and it DRIFTED: it filtered
TUN adapters but NOT VPN-pattern interfaces. With a Windows VPN connected,
Find-NetRoute resolved the server's egress onto the VPN adapter, the
dashboard pinned the server's /32 bypass onto the VPN, and the "direct"
bypass rode the VPN or looped into the TUN ("server bypass doesn't work"
while BYPASS LIST claims ROUTED DIRECT). Both sides now import the WHOLE
script from egress_scripts.egress_lookup_ps(); this file pins that.
"""
import inspect
import unittest
from unittest import mock

from tuntop.config.defaults import VPN_IFACE_RE
from tuntop.network import egress_scripts as es
from tuntop.network import routing
from tuntop.tunnel import helper as h


class TestSharedEgressScript(unittest.TestCase):
    def test_both_sides_emit_identical_scripts(self):
        routed, helperd = [], []

        def fake_ps(script, timeout=8):
            routed.append(script)
            return True, "{}"

        def fake_pj(script, timeout=10):
            helperd.append(script)
            return {}
        for exclude in (True, False):
            del routed[:]
            del helperd[:]
            with mock.patch.object(routing, "_ps", fake_ps):
                routing._get_egress_for("1.2.3.4", exclude_vpn=exclude)
            with mock.patch.object(h, "ps_json", fake_pj):
                h.get_egress_for("1.2.3.4", exclude_vpn=exclude)
            self.assertEqual(routed[0], helperd[0])

    def test_vpn_exclusion_present_by_default(self):
        ps = es.egress_lookup_ps("1.2.3.4")
        # The primary Find-NetRoute filter AND the strict default-route
        # fallback both exclude VPN-pattern interfaces.
        self.assertEqual(ps.count("-notmatch"), 2)
        self.assertIn(VPN_IFACE_RE, ps)

    def test_over_vpn_relaxes_only_the_primary_lookup(self):
        # exclude_vpn=False drops the VPN clause from the PRIMARY lookup;
        # the strict-then-relaxed default-route fallback ladder keeps its
        # strict (VPN-excluding) first stage, exactly like the helper did.
        ps = es.egress_lookup_ps("1.2.3.4", exclude_vpn=False)
        self.assertEqual(ps.count("-notmatch"), 1)
        self.assertIn("$tunAliases -notcontains", ps)

    def test_ip_is_quoted(self):
        self.assertIn("-RemoteIPAddress '1.2.3.4'",
                      es.egress_lookup_ps("1.2.3.4"))

    def test_hostile_ip_cannot_break_out(self):
        evil = "1.2.3.4' | Remove-NetRoute -Confirm:$false | echo '"
        ps = es.egress_lookup_ps(evil)
        self.assertNotIn(evil, ps)
        self.assertIn("1.2.3.4'' | Remove-NetRoute", ps)

    def test_strict_then_relaxed_fallback_ladder(self):
        ps = es.egress_lookup_ps("1.2.3.4")
        self.assertEqual(ps.count("Get-NetRoute -AddressFamily IPv4 "
                                  "-DestinationPrefix '0.0.0.0/0'"), 2)
        # The VPN exclusion lives in the PRIMARY clause and in the strict
        # first fallback (the regex literal, not $vpnAliases - that
        # preamble belongs to the physical-default lookup).
        self.assertEqual(ps.count(VPN_IFACE_RE), 2)

    def test_over_vpn_ladder_relaxes_to_one(self):
        ps = es.egress_lookup_ps("1.2.3.4", exclude_vpn=False)
        self.assertEqual(ps.count(VPN_IFACE_RE), 1)

    def test_no_unsubstituted_placeholders(self):
        # The 1.0.28 bug class: a literal '%s' (or leftover __TOKEN__) where
        # a regex belonged made an exclusion a silent NO-OP.
        for exclude in (True, False):
            ps = es.egress_lookup_ps("1.2.3.4", exclude_vpn=exclude)
            self.assertNotIn("__", ps)
            self.assertNotIn("'%s'", ps)

    def test_preamble_present(self):
        ps = es.egress_lookup_ps("1.2.3.4")
        # 1.0.33: the preamble seeds $tunAliases with OUR OWN aliases
        # (name-based, immune to a description blind spot) and then appends
        # every adapter matching the TUN driver on description OR name.
        self.assertIn(f"$tunAliases = @('{es.TUN}', '{es.TUN2}')", ps)
        self.assertIn("InterfaceDescription", ps)
        self.assertIn("-or ($_.Name -match", ps)
        self.assertIn("ForEach-Object { $tunAliases += $_ }", ps)


class TestConsumersDelegate(unittest.TestCase):
    def test_helper_delegates(self):
        self.assertIn("egress_lookup_ps", inspect.getsource(h.get_egress_for))

    def test_routing_delegates(self):
        self.assertIn("egress_lookup_ps",
                      inspect.getsource(routing._get_egress_for))

    def test_no_vpn_regex_hardcoded_in_consumers(self):
        # Same rule as test_egress_scripts_drift: the regex literal may only
        # live in config.defaults / egress_scripts.
        for mod in (routing, h):
            src = inspect.getsource(mod)
            offenders = [ln.strip()[:80] for ln in src.splitlines()
                         if VPN_IFACE_RE in ln
                         and not ln.strip().startswith("#")]
            self.assertEqual(offenders, [], mod.__name__)


class TestIsVpnIface(unittest.TestCase):
    def test_vpn_aliases_match(self):
        for alias in ("Shirazu-VPN", "VPN Client Adapter - VPN",
                      "WAN Miniport (PPTP)", "reza_U (IKEv2)"):
            self.assertTrue(es.is_vpn_iface(alias), alias)

    def test_physical_nics_never_match(self):
        for alias in ("Intel(R) Wi-Fi 7 BE200 320MHz",
                      "Realtek PCIe GbE Family Controller", "Ethernet", ""):
            self.assertFalse(es.is_vpn_iface(alias), alias)


if __name__ == "__main__":
    unittest.main()

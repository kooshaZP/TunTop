"""Egress script DRIFT guard (reviewer issue #5).

The same PowerShell text is consumed by TWO processes (tuntop/tunnel/
helper.py and tuntop/network/routing.py). Historically each kept its own
copy and fixes landed in only one - the exact bug class behind several
1.0.x releases. Since 1.0.28 both import tuntop.network.egress_scripts;
this file FAILS the suite if a copy-paste ever reappears:

  1. the preambles/filters built by both sides are byte-identical to the
     egress_scripts source (modulo surrounding whitespace);
  2. the VPN alias regex literal exists in exactly ONE module.
"""
import inspect
import unittest

from tuntop.config.defaults import VPN_IFACE_RE
from tuntop.network import egress_scripts as es
from tuntop.network import routing
from tuntop.tunnel import helper as h


class TestPreamblesAreIdentical(unittest.TestCase):
    def test_tun_alias_preamble(self):
        self.assertEqual(h._tun_alias_powershell(), es.tun_alias_ps())
        self.assertEqual(routing._tun_alias_powershell(), es.tun_alias_ps())

    def test_vpn_alias_preamble(self):
        self.assertEqual(h._vpn_alias_powershell().strip(),
                         es.vpn_alias_ps().strip())
        self.assertEqual(routing._vpn_alias_powershell().strip(),
                         es.vpn_alias_ps().strip())

    def test_v4_default_filter(self):
        self.assertEqual(h._v4_default_filter(True),
                         es.v4_default_filter_ps(True))
        self.assertEqual(h._v4_default_filter(False),
                         es.v4_default_filter_ps(False))


class TestVpnRegexSingleSource(unittest.TestCase):
    """The VPN alias regex may exist as a literal in config.defaults and
    egress_scripts ONLY; any occurrence in a consuming module's code line
    means a copy re-fragmented."""

    def _offenders(self, module):
        src = inspect.getsource(module)
        out = []
        for n, line in enumerate(src.splitlines(), 1):
            if VPN_IFACE_RE in line:
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if module is es and "VPN_ALIAS_PS_RE" in stripped:
                    continue
                out.append(f"{module.__name__}:{n}: {stripped[:80]}")
        return out

    def test_routing_has_no_hardcoded_vpn_regex(self):
        self.assertEqual(self._offenders(routing), [])

    def test_helper_has_no_hardcoded_vpn_regex(self):
        self.assertEqual(self._offenders(h), [])


class TestScriptShape(unittest.TestCase):
    def test_vpn_preamble_builds_both_families(self):
        ps = es.vpn_alias_ps()
        self.assertIn("$vpnAliases = @(", ps)
        self.assertIn("-DestinationPrefix '0.0.0.0/0'", ps)
        self.assertIn("-DestinationPrefix '::/0'", ps)
        self.assertIn(VPN_IFACE_RE, ps)

    def test_tun_preamble_uses_driver_not_alias(self):
        ps = es.tun_alias_ps()
        self.assertIn("InterfaceDescription", ps)
        self.assertIn(es.TUN_DRIVER_RE, ps)
        # The alias-prefix approach that 1.0.24/1.0.25 shipped (and that
        # xray's 'xray_tun' defeated) must not come back:
        self.assertNotIn("^wintun", ps)

    def test_v4_filter_tun_predicate_is_variable(self):
        self.assertIn("$tunAliases -notcontains", es.v4_default_filter_ps())
        self.assertIn(VPN_IFACE_RE, es.v4_default_filter_ps(True))
        self.assertNotIn(VPN_IFACE_RE, es.v4_default_filter_ps(False))


class TestIpv4DefaultBodySingleSourced(unittest.TestCase):
    """The FULL physical-default lookup script (preambles + 3-stage
    fallback) must also be shared. 1.0.28 single-sourced only the
    preambles - and the two get_ipv4_default() BODIES kept drifting: the
    helper's CIM fallback had a literal '%s' where the VPN-alias regex
    belonged. A '%s' regex matches nothing, so the VPN exclusion there was
    a silent NO-OP: with a full-tunnel VPN connected (which deletes the
    physical default route) the fallback returned the VPN's gateway as the
    "physical" egress, the VLESS server's /32 bypass rode the VPN and
    looped back into the TUN. Both sides now run ONE script from
    egress_scripts.ipv4_default_ps()."""

    def test_both_consumers_use_the_shared_script(self):
        self.assertIn("ipv4_default_ps()",
                      inspect.getsource(h.get_ipv4_default))
        self.assertIn("ipv4_default_ps()",
                      inspect.getsource(routing._get_ipv4_default))

    def test_no_stale_placeholder_or_literal_substitution(self):
        ps = es.ipv4_default_ps()
        self.assertNotIn("'%s'", ps)      # the 1.0.27/28 silent no-op bug
        self.assertNotIn("__VPN", ps)     # no unsubstituted placeholder
        self.assertNotIn("__SELECT__", ps)

    def test_cim_fallback_excludes_vpns(self):
        ps = es.ipv4_default_ps()
        start = ps.index("Win32_NetworkAdapterConfiguration")
        end = ps.index("Last resort only")
        cim = ps[start:end]
        self.assertIn("$tunAliases -notcontains", cim)
        self.assertIn("$vpnAliases -contains", cim)

    def test_effective_metric_sort_everywhere(self):
        ps = es.ipv4_default_ps()
        self.assertIn("[int]$_.RouteMetric + [int]$_.InterfaceMetric", ps)


if __name__ == "__main__":
    unittest.main()

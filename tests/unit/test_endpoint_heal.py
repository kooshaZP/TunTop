"""Offline tests for the endpoint-bypass self-heal (_heal_endpoint_routes).

Seen live (1.0.30): Throne's 'sing-tun Tunnel' adapter owns 176.0.0.0/4 (a
quarter of IPv4) and was INVISIBLE to the then-Wintun-only driver filter, so
the VLESS server /32 got pinned onto it - and vanished when the adapter
churned. The server's traffic then looped into TunTop's own TUN (the
'192.168.123.1 -> server:443' rows) while the BYPASS LIST still claimed
ROUTED DIRECT. The heal must: (a) re-install a MISSING /32 via the
mode-appropriate egress, (b) evict + re-install one pinned to a TUN-family
interface, (c) leave healthy routes alone, (d) respect the [V]
vless-over-vpn mode - and the TUN detector must recognise 'sing-tun Tunnel'
while never matching a physical NIC or a plain-named Windows VPN.
"""
import copy
import unittest
from unittest import mock

from tuntop.network import egress_scripts as es
from tuntop.tunnel import helper


def _row(iface, gw="10.0.0.1"):
    return {"InterfaceAlias": iface, "NextHop": gw}


class TestTunIfaceDetector(unittest.TestCase):
    """TUN_DRIVER_RE is the single source: the PS $tunAliases preamble AND
    the Python-side heal predicate must both see every tunnel flavour."""

    def test_foreign_tuns_match(self):
        for alias in ("throne-tun", "sing-tun Tunnel", "Wintun", "wintun2",
                      "WireGuard Tunnel", "Tailscale Tunnel",
                      "OpenVPN Data Channel Offload", "TAP-Windows Adapter V9"):
            self.assertTrue(es.is_tun_iface(alias), alias)

    def test_physical_and_plain_named_adapters_never_match(self):
        for alias in ("Intel(R) Wi-Fi 7 BE200 320MHz", "Ethernet",
                      "Realtek PCIe GbE Family Controller", "reza_U",
                      "Shirazu-VPN", ""):
            self.assertFalse(es.is_tun_iface(alias), alias)

    def test_preamble_detects_sing_tun(self):
        ps = es.tun_alias_ps()
        self.assertIn("sing-tun", ps)
        self.assertNotIn("^wintun", ps)   # the 1.0.24/25 alias-prefix bug


class TestHealEndpointRoutes(unittest.TestCase):
    def setUp(self):
        self.helper = helper
        self._saved = copy.deepcopy(helper._live_mode)
        helper._live_mode.update({
            "v4": ["188.114.97.6"], "v6": [],
            "vpn_routes": [], "vless_over_vpn": False,
            "phys": ("Wi-Fi", "192.168.1.1"),
        })

    def tearDown(self):
        helper._live_mode.clear()
        helper._live_mode.update(self._saved)

    def test_missing_bypass_is_reinstalled_via_physical(self):
        with mock.patch.object(helper, "get_existing_v4_routes",
                               return_value=[]), \
                mock.patch.object(helper, "get_egress_for",
                                  return_value=("Wi-Fi", "192.168.1.1")) as eg, \
                mock.patch.object(helper, "add_v4", return_value=True) as add:
            lines = helper._heal_endpoint_routes()
        eg.assert_called_once_with("188.114.97.6", exclude_vpn=True)
        add.assert_called_once_with("188.114.97.6/32", "Wi-Fi",
                                    "192.168.1.1", metric=1)
        self.assertTrue(any("[HEAL]" in ln for ln in lines))

    def test_tun_pinned_bypass_is_evicted_and_reinstalled(self):
        with mock.patch.object(helper, "get_existing_v4_routes",
                               return_value=[_row("throne-tun", "172.19.0.2")]), \
                mock.patch.object(helper, "remove_route") as rm, \
                mock.patch.object(helper, "get_egress_for",
                                  return_value=("Wi-Fi", "192.168.1.1")), \
                mock.patch.object(helper, "add_v4", return_value=True):
            lines = helper._heal_endpoint_routes()
        rm.assert_called_once_with(("v4", "188.114.97.6/32",
                                    "throne-tun", "172.19.0.2"))
        self.assertTrue(any("[HEAL]" in ln for ln in lines))

    def test_healthy_bypass_is_left_alone(self):
        with mock.patch.object(helper, "get_existing_v4_routes",
                               return_value=[_row("Wi-Fi")]), \
                mock.patch.object(helper, "get_egress_for") as eg, \
                mock.patch.object(helper, "add_v4") as add, \
                mock.patch.object(helper, "remove_route") as rm:
            self.assertEqual(helper._heal_endpoint_routes(), [])
        eg.assert_not_called()
        add.assert_not_called()
        rm.assert_not_called()

    def test_over_vpn_mode_uses_vpn_egress(self):
        helper._live_mode["vless_over_vpn"] = True
        helper._live_mode["over"] = ("reza_U", "10.0.0.1")
        with mock.patch.object(helper, "get_existing_v4_routes",
                               return_value=[]), \
                mock.patch.object(helper, "get_egress_for",
                                  return_value=("reza_U", "10.0.0.1")) as eg, \
                mock.patch.object(helper, "add_v4", return_value=True) as add:
            helper._heal_endpoint_routes()
        eg.assert_called_once_with("188.114.97.6", exclude_vpn=False)
        add.assert_called_once_with("188.114.97.6/32", "reza_U",
                                    "10.0.0.1", metric=1)

    def test_no_egress_reports_and_keeps_retrying(self):
        # Live resolution fails AND no startup-captured fallback exists:
        # report and keep the cycle going, never add a bogus route.
        helper._live_mode["phys"] = (None, None)
        with mock.patch.object(helper, "get_existing_v4_routes",
                               return_value=[]), \
                mock.patch.object(helper, "get_egress_for", return_value=None), \
                mock.patch.object(helper, "add_v4") as add:
            lines = helper._heal_endpoint_routes()
        add.assert_not_called()
        self.assertTrue(any("retrying" in ln for ln in lines))

    def test_vpn_endpoint_bypass_is_healed_too(self):
        helper._live_mode["vpn_routes"] = [
            ("v4", "10.7.0.1/32", "Wi-Fi", "192.168.1.1")]

        def _rows(dest):
            # The VLESS endpoint is healthy; only the VPN endpoint is gone.
            return [_row("Wi-Fi")] if dest == "188.114.97.6/32" else []

        with mock.patch.object(helper, "get_existing_v4_routes",
                               side_effect=_rows), \
                mock.patch.object(helper, "get_egress_for",
                                  return_value=("Wi-Fi", "192.168.1.1")) as eg, \
                mock.patch.object(helper, "add_v4", return_value=True) as add:
            lines = helper._heal_endpoint_routes()
        eg.assert_called_once_with("10.7.0.1", exclude_vpn=True)
        add.assert_called_once_with("10.7.0.1/32", "Wi-Fi",
                                    "192.168.1.1", metric=1)
        self.assertTrue(any("VPN endpoint" in ln for ln in lines))


if __name__ == "__main__":
    unittest.main()

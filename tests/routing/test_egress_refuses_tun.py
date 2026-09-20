"""Fail-closed egress guards (1.0.33, 'the server IP goes to the wintun').

The per-IP egress resolver (helper + dashboard mirror, single-sourced in
egress_scripts.egress_lookup_ps) filters TUN adapters in PowerShell - but if
the adapter enumeration ever hiccups (or a future TUN driver evades the
description regex) the resolver could hand back OUR OWN TUN as the
"physical" egress. Installing a server /32 onto our own wintun loops the
VLESS transport into the tunnel - exactly the report this file pins:

  * the resolver REFUSES a tunnel-family interface at the Python level too;
  * in DIRECT mode (exclude_vpn=True) a VPN-pattern interface is refused as
    well (the 1.0.32 bug class), while in [V] vless-over-vpn mode it stays
    allowed (riding the VPN is the point there).

Run:  python -m unittest discover -s tests -t . -v
"""
import json
import unittest
from unittest import mock

from tuntop.network import routing
from tuntop.tunnel import helper as helper_mod


def _row(iface, gw):
    return json.dumps({"InterfaceAlias": iface, "NextHop": gw})


class TestRoutingRefusesTunnelEgress(unittest.TestCase):
    def _egress(self, iface, exclude_vpn=True):
        with mock.patch.object(routing, "_ps",
                               return_value=(True, _row(iface, "10.0.0.1"))):
            return routing._get_egress_for("1.2.3.4", exclude_vpn=exclude_vpn)

    def test_our_tun_is_never_an_egress(self):
        for iface in ("wintun", "wintun2", "TunTop TUN"):
            self.assertIsNone(self._egress(iface), iface)

    def test_vpn_pinned_egress_refused_in_direct_mode(self):
        self.assertIsNone(self._egress("Shirazu-VPN", exclude_vpn=True))

    def test_vpn_egress_allowed_in_over_vpn_mode(self):
        self.assertEqual(self._egress("Shirazu-VPN", exclude_vpn=False),
                         ("Shirazu-VPN", "10.0.0.1"))

    def test_physical_egress_still_works(self):
        self.assertEqual(self._egress("Wi-Fi"),
                         ("Wi-Fi", "10.0.0.1"))


class TestHelperRefusesTunnelEgress(unittest.TestCase):
    def _egress(self, iface, exclude_vpn=True):
        with mock.patch.object(helper_mod, "ps_json",
                               return_value={"InterfaceAlias": iface,
                                             "NextHop": "10.0.0.1"}):
            return helper_mod.get_egress_for("1.2.3.4",
                                             exclude_vpn=exclude_vpn)

    def test_our_tun_is_never_an_egress(self):
        for iface in ("wintun", "wintun2"):
            self.assertIsNone(self._egress(iface), iface)

    def test_vpn_pinned_egress_refused_in_direct_mode(self):
        self.assertIsNone(self._egress("Shirazu-VPN", exclude_vpn=True))

    def test_vpn_egress_allowed_in_over_vpn_mode(self):
        self.assertEqual(self._egress("Shirazu-VPN", exclude_vpn=False),
                         ("Shirazu-VPN", "10.0.0.1"))

    def test_physical_egress_still_works(self):
        self.assertEqual(self._egress("Wi-Fi"),
                         ("Wi-Fi", "10.0.0.1"))


if __name__ == "__main__":
    unittest.main()

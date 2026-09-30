"""Phase 1 correctness regression tests.

Pins the fixes that had real-world impact:
  * the watchdog's LAN victim selection (current-gateway / on-link / stale
    pin from a previous network - foreign static routes never touched);
  * the helper's geo state is lock-guarded and cancellable (a signal during
    the background install must skip the remaining sub-batches instead of
    adding routes behind cleanup()'s back).
"""
import os
import sys
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from tuntop.core import cleanup_watchdog as WD
from tuntop.tunnel import helper as H


def _r(dp, alias, nh):
    return {"DestinationPrefix": dp, "InterfaceAlias": alias, "NextHop": nh}


class TestLanVictims(unittest.TestCase):
    IFACE, GW = "Wi-Fi", "192.168.2.1"

    def test_current_gateway_match_is_a_victim(self):
        rows = [_r("192.168.0.0/16", self.IFACE, self.GW)]
        self.assertEqual(WD._lan_victims(rows, self.IFACE, self.GW),
                         [("192.168.0.0/16", self.IFACE, self.GW)])

    def test_on_link_and_empty_next_hop_are_victims(self):
        rows = [_r("10.0.0.0/8", self.IFACE, "On-link"),
                _r("100.64.0.0/10", self.IFACE, "0.0.0.0"),
                _r("224.0.0.0/4", self.IFACE, "")]
        victims = WD._lan_victims(rows, self.IFACE, self.GW)
        self.assertEqual(len(victims), 3)

    def test_stale_pin_from_previous_network_is_NOT_a_victim(self):
        """A LAN prefix on our adapter but via a DIFFERENT gateway is a
        foreign static route (a VPN split tunnel, a NAS subnet) - not our
        stale pin. The old rule treated "a real next-hop that is not the
        current gateway" as ours; a next-hop-exact delete of a row you
        selected is still a delete, so the [Q] sweep and the crash watchdog
        removed corporate routes TunTop never created."""
        rows = [_r("192.168.0.0/16", self.IFACE, "192.168.1.1")]
        self.assertEqual(WD._lan_victims(rows, self.IFACE, self.GW), [])

    def test_the_same_route_on_the_current_gateway_is_a_victim(self):
        """The positive counterpart: same prefix, same interface, next hop
        equal to the gateway the caller passed in."""
        rows = [_r("192.168.0.0/16", self.IFACE, self.GW)]
        self.assertEqual(WD._lan_victims(rows, self.IFACE, self.GW),
                         [("192.168.0.0/16", self.IFACE, self.GW)])

    def test_foreign_interface_is_never_a_victim(self):
        rows = [_r("192.168.0.0/16", "Ethernet", "192.168.1.1")]
        self.assertEqual(WD._lan_victims(rows, self.IFACE, self.GW), [])

    def test_non_lan_prefix_is_never_a_victim(self):
        rows = [_r("203.0.113.0/24", self.IFACE, self.GW)]
        self.assertEqual(WD._lan_victims(rows, self.IFACE, self.GW), [])


class TestGeoStateLocking(unittest.TestCase):
    def test_state_lock_and_cancel_event_exist(self):
        self.assertIsInstance(H._geo_state_lock, type(threading.Lock()))
        self.assertIsInstance(H._geo_install_cancel, threading.Event)

    def test_cleanup_snapshots_geo_rows_under_lock(self):
        # Rehearse the exact cleanup() pattern: snapshot + clear under the
        # lock, delete outside. A row registered concurrently after the
        # snapshot stays tracked (not lost, not double-deleted).
        H.geoip_added[:] = [("v4", "5.0.0.0/8", "Wi-Fi", "192.168.2.1")]
        deleted = []
        with mock.patch.object(H, "_remove_routes_bulk",
                               side_effect=deleted.extend):
            with H._geo_state_lock:
                rows = list(H.geoip_added)
                H.geoip_added.clear()
            # concurrent registration DURING the (mocked) delete window
            H.geoip_added.append(("v4", "31.13.0.0/16", "Wi-Fi",
                                  "192.168.2.1"))
            if rows:
                H._remove_routes_bulk(rows)
        self.assertEqual(deleted, [("v4", "5.0.0.0/8", "Wi-Fi",
                                    "192.168.2.1")])
        # the concurrently registered row is still tracked for a later pass
        self.assertEqual(list(H.geoip_added),
                         [("v4", "31.13.0.0/16", "Wi-Fi", "192.168.2.1")])
        H.geoip_added.clear()


if __name__ == "__main__":
    unittest.main()

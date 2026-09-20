"""Offline tests for the live [V]/[Y] mode channel (no network, no admin).

The dashboard pushes ``vless_over_vpn`` / ``no_vpn_bypass`` through the SAME
control file the [N] DNS handoff uses. ``poll_control_file`` must apply the
mode keys WITHOUT a tunnel restart: record the new mode, update the launch
args, and - on a refused switch (e.g. VLESS-over-VPN with no connected VPN) -
keep the old mode so the dashboard and the running helper never disagree.
The live switches themselves are exercised with mocked route primitives.
"""
import copy
import json
import os
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from tuntop.tunnel import helper


class TestPollControlFileModeKeys(unittest.TestCase):
    """Channel semantics: absent key = no change; a present bool = the mode
    the dashboard now runs."""

    def setUp(self):
        self.helper = helper
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        self.path = path
        self._saved = (helper.CONTROL_FILE, helper._control_mtime,
                       copy.deepcopy(helper._live_mode))
        helper.CONTROL_FILE = path
        helper._control_mtime = 0.0
        helper._live_mode.update({
            "args": SimpleNamespace(vless_over_vpn=False,
                                    no_vpn_bypass=False, vpn_server=None),
            "vless_over_vpn": False,
            "no_vpn_bypass": False,
        })

    def tearDown(self):
        h = self.helper
        (h.CONTROL_FILE, h._control_mtime, h._live_mode) = self._saved
        os.unlink(self.path)

    def _write(self, payload):
        time.sleep(0.02)          # mtime resolution guard
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(payload, f)

    def test_vless_toggle_is_applied_and_recorded(self):
        self._write({"vless_over_vpn": True})
        with mock.patch.object(self.helper, "_live_switch_vless",
                               return_value=(True, ["[+] re-routed"])) as sw:
            self.assertTrue(self.helper.poll_control_file())
        sw.assert_called_once_with(True)
        self.assertTrue(self.helper._live_mode["vless_over_vpn"])
        self.assertTrue(self.helper._live_mode["args"].vless_over_vpn)

    def test_same_mode_means_no_change(self):
        self._write({"vless_over_vpn": False})   # already OFF
        with mock.patch.object(self.helper, "_live_switch_vless") as sw:
            self.assertFalse(self.helper.poll_control_file())
        sw.assert_not_called()

    def test_refused_switch_keeps_old_mode(self):
        # e.g. VLESS-over-VPN with no connected VPN: the channel is consumed
        # (returns False overall - nothing applied) but the recorded mode
        # and the launch args stay on the OLD value, never out of sync.
        self._write({"vless_over_vpn": True})
        with mock.patch.object(self.helper, "_live_switch_vless",
                               return_value=(False, ["[!] refused"])):
            self.assertFalse(self.helper.poll_control_file())
        self.assertFalse(self.helper._live_mode["vless_over_vpn"])
        self.assertFalse(self.helper._live_mode["args"].vless_over_vpn)

    def test_vpn_bypass_toggle_is_applied_and_recorded(self):
        self._write({"no_vpn_bypass": True})
        with mock.patch.object(self.helper, "_live_switch_vpn_bypass",
                               return_value=(True, ["[-] removed"])) as sw:
            self.assertTrue(self.helper.poll_control_file())
        sw.assert_called_once_with(True)
        self.assertTrue(self.helper._live_mode["no_vpn_bypass"])
        self.assertTrue(self.helper._live_mode["args"].no_vpn_bypass)

    def test_both_keys_in_one_write_are_applied_together(self):
        self._write({"vless_over_vpn": True, "no_vpn_bypass": True})
        with mock.patch.object(self.helper, "_live_switch_vless",
                               return_value=(True, [])), \
             mock.patch.object(self.helper, "_live_switch_vpn_bypass",
                               return_value=(True, [])):
            self.assertTrue(self.helper.poll_control_file())
        self.assertTrue(self.helper._live_mode["vless_over_vpn"])
        self.assertTrue(self.helper._live_mode["no_vpn_bypass"])

    def test_mode_keys_do_not_trigger_dns_reapply(self):
        # A mode write with NO dns keys must not call configure_tun: the
        # DNS re-apply belongs to the DNS keys only.
        self._write({"vless_over_vpn": True})
        calls = []
        with mock.patch.object(self.helper, "_live_switch_vless",
                               return_value=(True, [])), \
             mock.patch.object(self.helper, "configure_tun",
                               side_effect=lambda *a, **k: calls.append(a)):
            self.assertTrue(self.helper.poll_control_file())
        self.assertEqual(calls, [])


class TestPollControlFileServers(unittest.TestCase):
    """The 'servers'/'server_endpoints' keys carry a live [U] server change
    from the dashboard into the helper's tracked endpoint list."""

    def setUp(self):
        self.helper = helper
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        self.path = path
        self._saved = (helper.CONTROL_FILE, helper._control_mtime)
        helper.CONTROL_FILE = path
        helper._control_mtime = 0.0

    def tearDown(self):
        (h) = self.helper
        (h.CONTROL_FILE, h._control_mtime) = self._saved
        os.unlink(self.path)

    def _write(self, payload):
        time.sleep(0.02)          # mtime resolution guard
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(payload, f)

    def test_servers_key_is_applied(self):
        self._write({"servers": ["1.2.3.4"],
                     "server_endpoints": {"1.2.3.4": {"v4": ["1.2.3.4"],
                                                      "v6": []}}})
        with mock.patch.object(self.helper, "_live_apply_servers",
                               return_value=["[+] [U] ok"]) as apply_:
            self.assertTrue(self.helper.poll_control_file())
        apply_.assert_called_once_with(["1.2.3.4"],
                                       {"1.2.3.4": {"v4": ["1.2.3.4"],
                                                    "v6": []}})

    def test_non_list_servers_is_ignored(self):
        self._write({"servers": "1.2.3.4"})     # malformed: not a list
        with mock.patch.object(self.helper, "_live_apply_servers") as apply_:
            self.assertFalse(self.helper.poll_control_file())
        apply_.assert_not_called()


class TestLiveApplyServers(unittest.TestCase):
    """_live_apply_servers reconciles the helper's tracked endpoints with a
    live [U] server change. Mocked route primitives - no Windows."""

    def setUp(self):
        self.helper = helper
        self._saved = copy.deepcopy(helper._live_mode)
        helper._live_mode.update({
            "args": SimpleNamespace(vless_over_vpn=False, no_vpn_bypass=False,
                                    server=["9.9.9.9"]),
            "v4": ["9.9.9.9"], "v6": [],
            "vless_over_vpn": False, "no_vpn_bypass": False,
            "phys": ("Wi-Fi", "192.168.1.1"),
        })

    def tearDown(self):
        helper._live_mode.clear()
        helper._live_mode.update(self._saved)

    def test_replace_drops_old_and_installs_new(self):
        with mock.patch.object(helper, "_remove_host_routes_v4") as rm, \
             mock.patch.object(helper, "get_egress_for",
                               return_value=("Wi-Fi", "192.168.1.1")) as eg, \
             mock.patch.object(helper, "add_v4", return_value=True) as add:
            lines = helper._live_apply_servers(
                ["1.2.3.4"], {"1.2.3.4": {"v4": ["1.2.3.4"], "v6": []}})
        # Called for the dropped old server AND as the pre-clean before the
        # fresh install (the startup pattern - a stale copy can never
        # outrank the new route).
        rm.assert_any_call("9.9.9.9/32")
        rm.assert_any_call("1.2.3.4/32")
        self.assertEqual(rm.call_count, 2)
        eg.assert_called_once_with("1.2.3.4", exclude_vpn=True)
        add.assert_called_once_with("1.2.3.4/32", "Wi-Fi", "192.168.1.1",
                                    metric=1)
        self.assertEqual(helper._live_mode["v4"], ["1.2.3.4"])
        self.assertEqual(helper._live_mode["args"].server, ["1.2.3.4"])
        self.assertTrue(any("9.9.9.9" in ln for ln in lines))

    def test_add_mode_keeps_untouched_server_endpoints(self):
        # ADD mode: the map from the dashboard covers EVERY current server
        # (the dashboard completes it), so the untouched server's endpoint
        # is re-installed (adopted under the helper's tracking), not lost.
        with mock.patch.object(helper, "_remove_host_routes_v4") as rm, \
             mock.patch.object(helper, "get_egress_for",
                               return_value=("Wi-Fi", "192.168.1.1")), \
             mock.patch.object(helper, "add_v4", return_value=True):
            helper._live_apply_servers(
                ["9.9.9.9", "1.2.3.4"],
                {"9.9.9.9": {"v4": ["9.9.9.9"], "v6": []},
                 "1.2.3.4": {"v4": ["1.2.3.4"], "v6": []}})
        self.assertEqual(sorted(helper._live_mode["v4"]),
                         ["1.2.3.4", "9.9.9.9"])

    def test_unresolved_everything_keeps_tracked_state(self):
        """A transient resolution failure must NEVER strip the tracked
        endpoints - the self-heal would stop covering working servers."""
        with mock.patch.object(helper, "_remove_host_routes_v4") as rm, \
             mock.patch.object(helper, "add_v4") as add:
            lines = helper._live_apply_servers(
                ["1.2.3.4"], {"1.2.3.4": {"v4": [], "v6": []}})
        rm.assert_not_called()
        add.assert_not_called()
        self.assertEqual(helper._live_mode["v4"], ["9.9.9.9"])
        self.assertEqual(helper._live_mode["args"].server, ["9.9.9.9"])
        self.assertTrue(any("kept unchanged" in ln for ln in lines))

    def test_egress_falls_back_to_last_known_good_phys(self):
        # egress lookup fails: the install rides the last-known-good
        # physical egress captured at startup (never the tunnel), and the
        # tracked list still carries the new server so the self-heal and
        # the gateway re-point cover it.
        with mock.patch.object(helper, "_remove_host_routes_v4"), \
             mock.patch.object(helper, "get_egress_for", return_value=None), \
             mock.patch.object(helper, "add_v4", return_value=True) as add:
            helper._live_apply_servers(
                ["1.2.3.4"], {"1.2.3.4": {"v4": ["1.2.3.4"], "v6": []}})
        add.assert_called_once_with("1.2.3.4/32", "Wi-Fi", "192.168.1.1",
                                    metric=1)
        self.assertEqual(helper._live_mode["v4"], ["1.2.3.4"])


class TestLiveSwitchVless(unittest.TestCase):
    """_live_switch_vless(True/False) with the Windows primitives mocked."""

    def setUp(self):
        self.helper = helper
        self._saved_mode = copy.deepcopy(helper._live_mode)
        self._saved_vpn = (helper.vpn_override_iface,
                           list(helper.vpn_override_routes),
                           list(helper.vpn_saved_routes))
        helper._live_mode.update({
            "args": SimpleNamespace(vpn_interface=None, vpn_server=None),
            "vless_over_vpn": False,
            "no_vpn_bypass": False,
            "v4": ["1.2.3.4"],
            "v6": [],
            "phys": ("Ethernet", "192.168.1.1"),
            "vpn_conn": None,
            "vpn_routes": [],
        })

    def tearDown(self):
        h = self.helper
        h._live_mode.clear()
        h._live_mode.update(self._saved_mode)
        h.vpn_override_routes[:] = self._saved_vpn[1]
        h.vpn_saved_routes[:] = self._saved_vpn[2]
        h.vpn_override_iface = self._saved_vpn[0]

    def test_on_without_connected_vpn_is_refused(self):
        with mock.patch.object(self.helper, "_live_set_vpn_shadow",
                               return_value=False), \
             mock.patch.object(self.helper, "get_vpn_ipv4_default",
                               return_value=None):
            ok, lines = self.helper._live_switch_vless(True)
        self.assertFalse(ok)
        self.assertTrue(any("refused" in ln for ln in lines))
        self.assertIsNone(self.helper._live_mode.get("vpn_conn"))

    def test_on_repoints_endpoints_via_vpn(self):
        add = mock.Mock(return_value=True)
        with mock.patch.object(self.helper, "_live_set_vpn_shadow",
                               return_value=False), \
             mock.patch.object(self.helper, "get_vpn_ipv4_default",
                               return_value=("MyVPN", "10.0.0.1")), \
             mock.patch.object(self.helper, "get_vpn_ipv6_default",
                               return_value=None), \
             mock.patch.object(self.helper, "get_egress_for",
                               return_value=("MyVPN", "10.0.0.1")), \
             mock.patch.object(self.helper, "add_v4", add):
            ok, lines = self.helper._live_switch_vless(True)
        self.assertTrue(ok)
        add.assert_called_once_with("1.2.3.4/32", "MyVPN", "10.0.0.1",
                                    metric=1)
        self.assertEqual(self.helper._live_mode["vpn_conn"], "MyVPN")
        self.assertEqual(self.helper._live_mode["over"], ("MyVPN", "10.0.0.1"))

    def test_on_rejected_add_reports_not_ok(self):
        with mock.patch.object(self.helper, "_live_set_vpn_shadow",
                               return_value=False), \
             mock.patch.object(self.helper, "get_vpn_ipv4_default",
                               return_value=("MyVPN", "10.0.0.1")), \
             mock.patch.object(self.helper, "get_vpn_ipv6_default",
                               return_value=None), \
             mock.patch.object(self.helper, "get_egress_for",
                               return_value=("MyVPN", "10.0.0.1")), \
             mock.patch.object(self.helper, "add_v4", return_value=False):
            ok, _lines = self.helper._live_switch_vless(True)
        self.assertFalse(ok)      # dashboard-visible failure, not silence

    def test_off_repoints_endpoints_via_physical(self):
        add = mock.Mock(return_value=True)
        self.helper._live_mode["vless_over_vpn"] = True
        self.helper._live_mode["vpn_conn"] = "MyVPN"
        self.helper._live_mode["over"] = ("MyVPN", "10.0.0.1")
        with mock.patch.object(self.helper, "get_ipv6_default",
                               return_value=None), \
             mock.patch.object(self.helper, "get_egress_for",
                               return_value=("Ethernet", "192.168.1.1")), \
             mock.patch.object(self.helper, "add_v4", add), \
             mock.patch.object(self.helper, "_live_set_vpn_shadow",
                               return_value=False):
            ok, _lines = self.helper._live_switch_vless(False)
        self.assertTrue(ok)
        add.assert_called_once_with("1.2.3.4/32", "Ethernet",
                                    "192.168.1.1", metric=1)

    def test_v6_endpoint_without_gateway_rides_the_tun(self):
        # IPv4-only VPN in over-VPN mode: the direct /128 is dropped (the
        # endpoint rides the TUN splits), exactly like a fresh start.
        self.helper._live_mode["v6"] = ["2606:4700::1111"]
        with mock.patch.object(self.helper, "_live_set_vpn_shadow",
                               return_value=False), \
             mock.patch.object(self.helper, "get_vpn_ipv4_default",
                               return_value=("MyVPN", "10.0.0.1")), \
             mock.patch.object(self.helper, "get_vpn_ipv6_default",
                               return_value=None), \
             mock.patch.object(self.helper, "get_egress_for",
                               return_value=("MyVPN", "10.0.0.1")), \
             mock.patch.object(self.helper, "add_v4", return_value=True), \
             mock.patch.object(self.helper, "get_existing_v6_routes",
                               return_value=[{"InterfaceAlias": "Ethernet",
                                              "NextHop": "fe80::1"}]), \
             mock.patch.object(self.helper, "remove_route") as rm:
            ok, _lines = self.helper._live_switch_vless(True)
        self.assertTrue(ok)
        rm.assert_called_once_with(
            ("v6", "2606:4700::1111/128", "Ethernet", "fe80::1"))


class TestVpnArrivalReapply(unittest.TestCase):
    """Regression: a Windows VPN connecting AFTER tunnel start got NO endpoint
    bypass - startup only resolves VPNs already connected, and nothing re-ran
    that resolution later. The Wintun split-defaults then captured the VPN's
    own control/data traffic and the VPN died inside the tunnel ("the server
    (reza_U) traffic goes into the tuntop"). The dashboard's _on_vpn_arrived
    now writes a one-shot `vpn_endpoint_reapply` control key; poll_control_file
    must run the enable side of the [Y] toggle (+ shadow) in response, gated
    on the same startup conditions."""

    def setUp(self):
        self.helper = helper
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        self.path = path
        self._saved = (helper.CONTROL_FILE, helper._control_mtime,
                       copy.deepcopy(helper._live_mode))
        helper.CONTROL_FILE = path
        helper._control_mtime = 0.0
        helper._live_mode.update({
            "args": SimpleNamespace(vless_over_vpn=False,
                                    no_vpn_bypass=False, vpn_server=None),
            "vless_over_vpn": False,
            "no_vpn_bypass": False,
        })

    def tearDown(self):
        h = self.helper
        (h.CONTROL_FILE, h._control_mtime, h._live_mode) = self._saved
        os.unlink(self.path)

    def _write(self, payload):
        time.sleep(0.02)          # mtime resolution guard
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(payload, f)

    def test_reapply_installs_endpoint_bypass_and_shadow(self):
        self._write({"vpn_endpoint_reapply": True})
        with mock.patch.object(self.helper, "_live_apply_vpn_bypass_routes",
                               return_value=["[+] VPN endpoint bypass "
                                             "installed live (1 route(s))."]) as ap, \
                mock.patch.object(self.helper, "_live_set_vpn_shadow",
                                  return_value=True) as sh:
            self.assertTrue(self.helper.poll_control_file())
        ap.assert_called_once_with(True)
        sh.assert_called_once_with(True)

    def test_reapply_applies_even_if_shadow_refused(self):
        # No connected VPN for the shadow step is fine: the endpoint bypass
        # install itself must still count as an applied change.
        self._write({"vpn_endpoint_reapply": True})
        with mock.patch.object(self.helper, "_live_apply_vpn_bypass_routes",
                               return_value=[]) as ap, \
                mock.patch.object(self.helper, "_live_set_vpn_shadow",
                                  return_value=False):
            self.assertTrue(self.helper.poll_control_file())
        ap.assert_called_once_with(True)

    def test_reapply_skipped_when_vpn_bypass_disabled(self):
        self.helper._live_mode["no_vpn_bypass"] = True
        self._write({"vpn_endpoint_reapply": True})
        with mock.patch.object(self.helper, "_live_apply_vpn_bypass_routes") as ap, \
                mock.patch.object(self.helper, "_live_set_vpn_shadow") as sh:
            self.assertFalse(self.helper.poll_control_file())
        ap.assert_not_called()
        sh.assert_not_called()

    def test_reapply_skipped_when_vless_over_vpn(self):
        self.helper._live_mode["vless_over_vpn"] = True
        self._write({"vpn_endpoint_reapply": True})
        with mock.patch.object(self.helper, "_live_apply_vpn_bypass_routes") as ap, \
                mock.patch.object(self.helper, "_live_set_vpn_shadow") as sh:
            self.assertFalse(self.helper.poll_control_file())
        ap.assert_not_called()
        sh.assert_not_called()


class TestVpnArrivalWritesControlKey(unittest.TestCase):
    """The dashboard's _on_vpn_arrived must ASK the helper to re-apply the VPN
    endpoint bypass (one-shot control key) - re-applying only the dashboard's
    own [vpn] bypass entries and geo routes left the VPN's own server without
    a /32 bypass, which is what killed the VPN inside the tunnel."""

    def _fake_ui(self, no_vpn_bypass=False, vless_over_vpn=False):
        import argparse
        import threading
        import tuntop.ui.dashboard as dash
        return dash, SimpleNamespace(
            ns=argparse.Namespace(no_vpn_bypass=no_vpn_bypass,
                                  vless_over_vpn=vless_over_vpn,
                                  geoip=None, geoip_code=""),
            _vpn_status="reza_U",
            _bypass_stores=mock.Mock(return_value=({}, {})),
            _bypass_res_lock=threading.Lock(),
            _geo_target=mock.Mock(return_value="physical"),
            _geo_applied_target=None,
            _blog=mock.Mock(),
            _write_control_file=mock.Mock(),
        )

    def test_arrival_asks_helper_to_reapply(self):
        dash, fake = self._fake_ui()
        dash.BTopTui._on_vpn_arrived(fake)
        fake._write_control_file.assert_called_once_with(
            extra={"vpn_endpoint_reapply": True})

    def test_arrival_silent_when_bypass_disabled(self):
        dash, fake = self._fake_ui(no_vpn_bypass=True)
        dash.BTopTui._on_vpn_arrived(fake)
        fake._write_control_file.assert_not_called()

    def test_arrival_silent_when_vless_over_vpn(self):
        dash, fake = self._fake_ui(vless_over_vpn=True)
        dash.BTopTui._on_vpn_arrived(fake)
        fake._write_control_file.assert_not_called()


if __name__ == "__main__":
    unittest.main()
"""Regression tests for the 1.0.35 UX + logic fixes.

Covers:
* the "[T] -> [S]" typo in the input-restored hint (T stops, S starts),
* the phantom console window (helper spawned WITHOUT CREATE_NEW_CONSOLE),
* the log panel resuming LIVE following when scrolled back to the bottom,
* the geo-via-VPN live re-apply keeping the VPN egress (the direct-only
  fallback chain used to clobber it with the physical NIC),
* the leak probe's multi-answer verdict (a geo-bypass-routed echo host is
  no longer a LEAK when the tunnel exit answered directly too).
"""
import argparse
import subprocess
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

from tuntop.ui import dashboard
from tuntop.network import leak_probe as L


def _leg(ip=None, err=None, ms=0):
    return {"ip": ip, "ips": [ip] if ip else [], "err": err, "ms": ms}


class TestInputRestoredHint(unittest.TestCase):
    def test_message_points_at_the_START_key(self):
        # [S] starts the tunnel; [T] STOPS it. The old text told the user to
        # "press [T] to start" - the exact typo class the footer pins.
        import inspect
        src = inspect.getsource(dashboard)
        self.assertIn(
            'press [S] to "\n'
            '                                      "start the tunnel again.',
            src)
        self.assertNotIn(
            'press [T] to "\n'
            '                                      "start the tunnel again.',
            src)


class TestHelperSpawnNoConsole(unittest.TestCase):
    def test_helper_spawned_without_create_new_console(self):
        # CREATE_NO_WINDOW is IGNORED when combined with CREATE_NEW_CONSOLE
        # (MSDN): the helper got its own fresh console that just sat there
        # EMPTY (its stdout is piped, so nothing was ever printed in it).
        # The spawn must pass CREATE_NO_WINDOW alone - the same pattern
        # every other TunTop child spawn already uses.
        import inspect
        src = inspect.getsource(dashboard.BTopTui.launch)
        self.assertIn("creationflags=subprocess.CREATE_NO_WINDOW)", src)
        self.assertNotIn("CREATE_NEW_CONSOLE |", src)
        self.assertNotIn("CREATE_NEW_PROCESS_GROUP", src)


class TestWatchdogSpawnNoConsole(unittest.TestCase):
    """The second black 'TunTop' window was the --watchdog-child process.

    Elevated window-monitor evidence (1.0.35 exe): at t+6.1s a second
    ConsoleWindowClass window appeared, owned by a TunTop.exe whose command
    line was 'TunTop.exe --watchdog-child ...' - spawned with
    DETACHED_PROCESS | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP.
    DETACHED_PROCESS only detaches the child from the PARENT console; it
    does not forbid the child from allocating its own - and PyInstaller 6's
    onefile bootloader is two processes, so the stub kept a visible console.
    The spawn must use CREATE_NO_WINDOW alone (plus the process-group flag).
    """

    def test_watchdog_spawned_without_detached_process(self):
        import inspect
        import re
        src = inspect.getsource(dashboard.main)
        # The creationflags EXPRESSION of the watchdog spawn must not use
        # DETACHED_PROCESS (comments mentioning the history are fine):
        m = re.search(r"creationflags=subprocess\.[^)]*\)", src)
        self.assertIsNotNone(m, "watchdog creationflags expression not found")
        flags = m.group(0)
        self.assertNotIn("DETACHED_PROCESS", flags)
        self.assertIn("CREATE_NO_WINDOW", flags)
        self.assertIn("CREATE_NEW_PROCESS_GROUP", flags)
        # Defense-in-depth child-side hide must survive refactors too.
        self.assertIn("_k32.ShowWindow(_hwnd, 0)", src)


class TestLogResumeAtBottom(unittest.TestCase):
    def _app(self):
        app = dashboard.BTopTui.__new__(dashboard.BTopTui)
        app.log_lines = [f"event {i}" for i in range(20)]
        app._log_snapshot = None
        app._log_scroll = 0
        return app

    def test_scrolling_back_to_bottom_resumes_live_following(self):
        app = self._app()
        app._scroll_log(5)                 # up: freezes the snapshot
        self.assertIsNotNone(app._log_snapshot)
        app._scroll_log(-5)                # all the way back down
        self.assertEqual(app._log_scroll, 0)
        # Bottom == LIVE again: the frozen snapshot is released, so new
        # lines appended after this point are followed automatically.
        self.assertIsNone(app._log_snapshot)
        app.log_lines.append("newest")
        self.assertEqual(app._log_entries()[-1], "newest")

    def test_partial_scroll_down_keeps_frozen_history(self):
        app = self._app()
        app._scroll_log(6)
        frozen = app._log_snapshot
        app._scroll_log(-2)                # not at the bottom yet
        self.assertIsNotNone(app._log_snapshot)
        self.assertIs(frozen, app._log_snapshot)


class TestGeoVpnEgressNotClobbered(unittest.TestCase):
    """The [R] live geo re-apply with target=winvpn must install via the
    VPN egress it just resolved - the direct-only fallback chain's `else`
    used to overwrite it with the physical NIC ("Installing geoip:ir
    bypass ... via Wi-Fi" right after "routed via connected Windows VPN")."""

    def _fake_app(self):
        app = dashboard.BTopTui.__new__(dashboard.BTopTui)
        app.ns = argparse.Namespace(
            geoip="C:\\geoip.dat", geoip_code="ir", vpn_interface=None,
            geoip_via_win_vpn=True, geoip_via_vpn=False, geoip_target=None,
            proxy2_port=None, proxy2_server=[], proxy2_bypass_ip=[])
        app._geo_reset_progress = mock.Mock()
        app._blog = mock.Mock()
        app._remove_geo_routes_for = mock.Mock()
        app._live_geo_added = []
        app._geo_applied_target = "direct"
        app._live_bypass_added = []
        app.endpoint_v4 = []
        app.endpoint_v6 = []
        app._get_vless_iface_gateway = mock.Mock(return_value=None)
        app._get_vless_iface_gateway_v6 = mock.Mock(return_value=None)
        app._protected_geo_prefixes = mock.Mock(return_value=[])
        return app

    def _run_worker(self, app, helper, target):
        with mock.patch.object(dashboard, "_get_vpn_ipv4_default",
                               return_value=("Shirazu-VPN", "10.8.0.1")), \
             mock.patch.object(dashboard, "_get_vpn_ipv6_default",
                               return_value=None), \
             mock.patch.object(dashboard, "_get_ipv4_default",
                               return_value=("Wi-Fi", "10.217.222.111")), \
             mock.patch.object(dashboard, "_get_ipv6_default",
                               return_value=None), \
             mock.patch.object(dashboard, "_GeoLogSink",
                               mock.Mock(return_value=mock.Mock())), \
             mock.patch.object(dashboard.sys, "stdout", mock.Mock()), \
             mock.patch.dict(dashboard.sys.modules,
                             {"tuntop.tunnel.helper": helper}):
            app._reapply_geo_bypass_worker("C:\\geoip.dat", "ir", target)

    def test_winvpn_target_installs_via_vpn_iface(self):
        app = self._fake_app()
        helper = mock.MagicMock()
        helper.parse_geoip.return_value = ["5.0.0.0/16"]
        helper.add_geoip_bypass.return_value = [("v4", "5.0.0.0/16",
                                                 "Shirazu-VPN", "10.8.0.1")]
        self._run_worker(app, helper, "winvpn")
        # The egress handed to the installer is the VPN - NOT Wi-Fi.
        self.assertEqual(helper.add_geoip_bypass.call_args.args[2],
                         "Shirazu-VPN")
        self.assertEqual(helper.add_geoip_bypass.call_args.args[3],
                         "10.8.0.1")

    def test_direct_target_still_resolves_physical(self):
        app = self._fake_app()
        app.ns.geoip_via_win_vpn = False
        helper = mock.MagicMock()
        helper.parse_geoip.return_value = ["5.0.0.0/16"]
        helper.add_geoip_bypass.return_value = []
        self._run_worker(app, helper, "direct")
        # Plain direct target: the physical adapter - with the fallback
        # chain gated direct-only, the connected VPN must NOT win here.
        self.assertEqual(helper.add_geoip_bypass.call_args.args[2], "Wi-Fi")


class TestLeakVerdictMultiAnswer(unittest.TestCase):
    """With a geo bypass active, an echo host inside the bypassed country
    exits via the GEO route; that divergent answer must not read as a LEAK
    when the tunnel exit answered directly too."""

    def test_geo_routed_echo_host_is_not_a_leak(self):
        direct = _leg("107.150.19.3")
        direct["ips"] = ["107.150.19.3", "107.175.209.186"]
        tunnel = _leg("107.175.209.186")
        status, msg = L._verdict(direct, tunnel, 10808)
        self.assertEqual(status, "same-exit")
        self.assertNotIn("LEAK", msg)
        self.assertIn("107.150.19.3", msg)

    def test_genuine_leak_with_single_answer_still_leak(self):
        status, _ = L._verdict(_leg("89.198.14.7"), _leg("45.12.33.9"), 10808)
        self.assertEqual(status, "leak")

    def test_single_answer_same_network_keeps_rotation_message(self):
        status, msg = L._verdict(
            _leg("2a09:bac5:465:c00::132:18"),
            _leg("2a09:bac5:5275:2864::406:48"), 10808)
        self.assertEqual(status, "same-exit")
        self.assertIn("SAME network", msg)

    def test_legs_collect_every_answer(self):
        def fake_fetch(scheme, host, path, timeout):
            return {"a": "1.1.1.1", "b": "8.8.8.8", "c": "1.1.1.1"}[host]
        with mock.patch.object(L, "_ECHO_ENDPOINTS",
                               [("https", "a", "/"), ("https", "b", "/"),
                                ("https", "c", "/")]):
            out = L._race_leg(fake_fetch, timeout=1)
        self.assertEqual(out["ip"], "1.1.1.1")
        self.assertEqual(out["ips"], ["1.1.1.1", "8.8.8.8"])

    def test_sequential_leg_collects_every_answer(self):
        def fake_fetch(scheme, host, path, timeout):
            return {"a": "1.1.1.1", "b": "8.8.8.8"}[host]
        with mock.patch.object(L, "_ECHO_ENDPOINTS",
                               [("https", "a", "/"), ("https", "b", "/")]):
            out = L._sequential_leg(fake_fetch, timeout=1)
        self.assertEqual(out["ips"], ["1.1.1.1", "8.8.8.8"])


if __name__ == "__main__":
    unittest.main()



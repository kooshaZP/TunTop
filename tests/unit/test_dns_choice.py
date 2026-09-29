"""Unit tests for the helper's DNS choice resolution (pure logic, no network,
no adapter changes). Covers the selection rules:

  * no input                     -> both defaults
  * v4-only choice               -> v4 only (no default v6 injected)
  * v6-only choice               -> v6 only
  * both chosen                  -> exactly those
  * legacy default-only pass     -> both defaults (backward compatibility)
"""
import json
import os
import tempfile
import time
import unittest
from unittest import mock

from tuntop.tunnel.helper import DNS4, DNS6, _resolve_dns_choice


class TestEffectiveDnsSingleSource(unittest.TestCase):
    """The leak, pinned at its source.

    Observed live: the tunnel up, wintun holding 8.8.8.8 + 2606:4700:4700::1111,
    the catch-all NRPT pin ABSENT, and the health panel reading "no DNS
    resolver is configured" for all four DNS rows - while a leak test showed
    the ISP's own resolvers (2.188.21.46, 2.189.44.x).

    `ns.dns4` is None whenever the user relies on the defaults, and the
    dashboard used to write those raw attributes into the live-reconfig
    control file. The helper reads a PRESENT-but-null key as "clear this
    family's DNS" - it has to, that is how an explicit [N] clear is expressed
    - so every server edit, bypass add/remove and [V]/[Y] toggle silently
    cleared the running resolver, and a guard with no resolvers would
    black-hole name resolution, so the helper removed the catch-all pin with
    it. One bypass addition put the machine back on the ISP's resolvers.
    """

    def test_no_choice_resolves_to_the_defaults(self):
        from tuntop.config import defaults as D
        self.assertEqual(D.resolve_dns_choice(None, None), (D.DNS4, D.DNS6))

    def test_a_choice_is_passed_through_exactly(self):
        from tuntop.config import defaults as D
        self.assertEqual(D.resolve_dns_choice("9.9.9.9", None), ("9.9.9.9", None))
        self.assertEqual(D.resolve_dns_choice(None, "2620:fe::fe"),
                         (None, "2620:fe::fe"))

    def test_legacy_default_v4_alone_still_means_both(self):
        from tuntop.config import defaults as D
        self.assertEqual(D.resolve_dns_choice(D.DNS4, None), (D.DNS4, D.DNS6))

    def test_helper_uses_the_shared_rule(self):
        """One implementation: two copies drifting apart is what allowed this
        bug in the first place."""
        from tuntop.config import defaults as D
        from tuntop.tunnel import helper
        for d4, d6 in ((None, None), ("9.9.9.9", None), (None, "2620:fe::fe"),
                       (D.DNS4, None), (" 1.1.1.1 ", "  ")):
            self.assertEqual(helper._resolve_dns_choice(d4, d6),
                             D.resolve_dns_choice(d4, d6))

    def test_control_file_carries_the_effective_pair(self):
        """The assertion that actually prevents the regression."""
        import argparse
        from tuntop.ui import dashboard
        app = dashboard.BTopTui.__new__(dashboard.BTopTui)
        app.ns = argparse.Namespace(dns4=None, dns6=None,
                                    dns_policy="availability")
        d = tempfile.mkdtemp()
        path = os.path.join(d, ".ctl.json")
        with mock.patch.object(dashboard, "_control_file_path",
                               return_value=path):
            app._write_control_file()
        with open(path, encoding="utf-8") as f:
            payload = json.load(f)
        self.assertEqual(payload["dns4"], dashboard._cfgdef.DNS4)
        self.assertEqual(payload["dns6"], dashboard._cfgdef.DNS6)

    def test_an_unchanged_pair_produces_no_helper_change(self):
        """End to end: the payload must be a NO-OP for a helper already
        running on the defaults - the whole point."""
        import argparse
        from tuntop.config import defaults as D
        from tuntop.tunnel import helper
        from tuntop.ui import dashboard
        app = dashboard.BTopTui.__new__(dashboard.BTopTui)
        app.ns = argparse.Namespace(dns4=None, dns6=None,
                                    dns_policy="availability")
        d = tempfile.mkdtemp()
        path = os.path.join(d, ".ctl.json")
        with mock.patch.object(dashboard, "_control_file_path",
                               return_value=path):
            app._write_control_file()
        saved = (helper.CONTROL_FILE, helper._ACTIVE_DNS4, helper._ACTIVE_DNS6,
                 helper._ACTIVE_DNS_POLICY, helper._control_mtime,
                 helper._dns_guard_state)
        try:
            helper.CONTROL_FILE = path
            helper._ACTIVE_DNS4, helper._ACTIVE_DNS6 = D.DNS4, D.DNS6
            helper._ACTIVE_DNS_POLICY = "availability"
            helper._control_mtime = 0.0
            helper._dns_guard_state = None
            self.assertFalse(
                helper.poll_control_file(),
                "a server edit / bypass add must not read as a DNS change")
            self.assertEqual(helper._ACTIVE_DNS4, D.DNS4)
            self.assertEqual(helper._ACTIVE_DNS6, D.DNS6)
        finally:
            (helper.CONTROL_FILE, helper._ACTIVE_DNS4, helper._ACTIVE_DNS6,
             helper._ACTIVE_DNS_POLICY, helper._control_mtime,
             helper._dns_guard_state) = saved

    def test_a_v4_only_choice_still_clears_v6(self):
        """The fix must not neuter a real choice: an explicit v4-only
        selection still means 'no IPv6 DNS', in both channels."""
        import argparse
        from tuntop.config import defaults as D
        from tuntop.tunnel import helper
        from tuntop.ui import dashboard
        app = dashboard.BTopTui.__new__(dashboard.BTopTui)
        app.ns = argparse.Namespace(dns4="9.9.9.9", dns6=None,
                                    dns_policy="availability")
        d = tempfile.mkdtemp()
        path = os.path.join(d, ".ctl.json")
        with mock.patch.object(dashboard, "_control_file_path",
                               return_value=path):
            app._write_control_file()
        with open(path, encoding="utf-8") as f:
            payload = json.load(f)
        self.assertEqual(payload["dns4"], "9.9.9.9")
        self.assertIsNone(payload["dns6"])
        saved = (helper.CONTROL_FILE, helper._ACTIVE_DNS4, helper._ACTIVE_DNS6,
                 helper._ACTIVE_DNS_POLICY, helper._control_mtime,
                 helper._dns_guard_state, helper.configure_tun,
                 helper._install_dns_guard)
        try:
            helper.CONTROL_FILE = path
            helper._ACTIVE_DNS4, helper._ACTIVE_DNS6 = D.DNS4, D.DNS6
            helper._ACTIVE_DNS_POLICY = "availability"
            helper._control_mtime = 0.0
            helper._dns_guard_state = None
            helper.configure_tun = lambda *a, **k: None
            helper._install_dns_guard = lambda *a, **k: True
            self.assertTrue(helper.poll_control_file())
            self.assertEqual(helper._ACTIVE_DNS4, "9.9.9.9")
            self.assertIsNone(helper._ACTIVE_DNS6)
        finally:
            (helper.CONTROL_FILE, helper._ACTIVE_DNS4, helper._ACTIVE_DNS6,
             helper._ACTIVE_DNS_POLICY, helper._control_mtime,
             helper._dns_guard_state, helper.configure_tun,
             helper._install_dns_guard) = saved

    def test_health_rows_receive_the_effective_pair(self):
        """The rows that read "no DNS resolver is configured" while the tunnel
        was up and the adapter really did hold 8.8.8.8."""
        import argparse
        import inspect
        from tuntop.ui import dashboard
        ns = argparse.Namespace(
            port=10808, server=["1.2.3.4"], dns4=None, dns6=None,
            endpoint_port=443, bypass_ip=[], vless_over_vpn=False, geoip=None,
            geoip_code="cn", geoip_target=None, proxy2_port=None,
            proxy2_server=[])
        row = [f for label, f in dashboard.build_checks(ns)
               if label == "DNS configuration (Wintun is selected source)"][0]
        cell = inspect.getclosurevars(row).nonlocals
        self.assertEqual(cell["dns_cfg"], dashboard._cfgdef.DNS4)
        self.assertEqual(cell["dns6_cfg"], dashboard._cfgdef.DNS6)


class TestResolveDnsChoice(unittest.TestCase):
    def test_no_input_uses_both_defaults(self):
        self.assertEqual(_resolve_dns_choice(None, None), (DNS4, DNS6))
        self.assertEqual(_resolve_dns_choice("", "   "), (DNS4, DNS6))

    def test_v4_only_choice_gets_no_default_v6(self):
        self.assertEqual(_resolve_dns_choice("9.9.9.9", None),
                         ("9.9.9.9", None))

    def test_v6_only_choice_gets_no_default_v4(self):
        self.assertEqual(_resolve_dns_choice(None, "2620:fe::fe"),
                         (None, "2620:fe::fe"))

    def test_both_chosen_used_as_is(self):
        self.assertEqual(
            _resolve_dns_choice("1.0.0.1", "2606:4700:4700::1001"),
            ("1.0.0.1", "2606:4700:4700::1001"))

    def test_legacy_default_only_pass_still_means_both_defaults(self):
        self.assertEqual(_resolve_dns_choice(DNS4, None), (DNS4, DNS6))

    def test_default_v4_with_explicit_v6_is_a_real_choice(self):
        self.assertEqual(_resolve_dns_choice(DNS4, "2620:fe::fe"),
                         (DNS4, "2620:fe::fe"))

    def test_whitespace_is_stripped(self):
        self.assertEqual(_resolve_dns_choice(" 9.9.9.9 ", None),
                         ("9.9.9.9", None))


class TestPollControlFileDns(unittest.TestCase):
    """The control-file channel must follow the same rules: a present-but-
    empty value CLEARS that family (v4-only pick), it does not keep the old
    default. configure_tun is stubbed out - no adapter access here."""

    def setUp(self):
        from tuntop.tunnel import helper
        self.helper = helper
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"dns4": "9.9.9.9", "dns6": None}, f)
        self.path = path
        self._saved = (helper.CONTROL_FILE, helper._ACTIVE_DNS4,
                       helper._ACTIVE_DNS6, helper._control_mtime,
                       helper.configure_tun, helper._install_dns_guard)
        helper.CONTROL_FILE = path
        helper._ACTIVE_DNS4 = DNS4
        helper._ACTIVE_DNS6 = DNS6
        helper._control_mtime = 0.0
        helper.configure_tun = lambda *a, **k: None
        # The DNS guard writes HKLM\...\DnsPolicyConfig (see
        # tuntop/network/dns_guard.py). An offline unit test must never reach
        # the real registry - on an ELEVATED test machine it would pin the
        # whole machine's DNS to a tunnel that does not exist. Stubbed, and
        # asserted on in TestPollControlFileReassertsTheGuard.
        helper._install_dns_guard = lambda *a, **k: True

    def tearDown(self):
        h = self.helper
        (h.CONTROL_FILE, h._ACTIVE_DNS4, h._ACTIVE_DNS6,
         h._control_mtime, h.configure_tun, h._install_dns_guard) = self._saved
        os.unlink(self.path)

    def test_v4_choice_clears_v6(self):
        self.assertTrue(self.helper.poll_control_file())
        self.assertEqual(self.helper._ACTIVE_DNS4, "9.9.9.9")
        self.assertIsNone(self.helper._ACTIVE_DNS6)

    def test_missing_keys_mean_no_change(self):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump({"other": 1}, f)
        self.assertFalse(self.helper.poll_control_file())
        self.assertEqual(self.helper._ACTIVE_DNS4, DNS4)
        self.assertEqual(self.helper._ACTIVE_DNS6, DNS6)

    def test_dns_change_reasserts_the_guard(self):
        """A live [N] DNS change must RE-PIN the catch-all rule to the new
        resolver: leaving the previous pin in place keeps sending every query
        to the old server while wintun's adapter list says otherwise."""
        calls = []
        self.helper._install_dns_guard = lambda *a, **k: (
            calls.append((self.helper._ACTIVE_DNS4, self.helper._ACTIVE_DNS6))
            or True)
        self.assertTrue(self.helper.poll_control_file())
        self.assertEqual(calls, [("9.9.9.9", None)])


class TestBaselineControlFile(unittest.TestCase):
    """A control file left over from a PREVIOUS session must not be applied
    to a fresh run: after _baseline_control_file() the stale content is
    ignored, and only a NEW write (mtime change) counts as a live change."""

    def setUp(self):
        from tuntop.tunnel import helper
        self.helper = helper
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"dns4": "1.1.1.1", "dns6": None}, f)
        self.path = path
        self._saved = (helper.CONTROL_FILE, helper._ACTIVE_DNS4,
                       helper._ACTIVE_DNS6, helper._control_mtime,
                       helper.configure_tun, helper._install_dns_guard)
        helper.CONTROL_FILE = path
        helper._ACTIVE_DNS4 = DNS4
        helper._ACTIVE_DNS6 = DNS6
        helper.configure_tun = lambda *a, **k: None
        # Never let an offline test reach the real NRPT registry (see
        # TestPollControlFileDns).
        helper._install_dns_guard = lambda *a, **k: True

    def tearDown(self):
        h = self.helper
        (h.CONTROL_FILE, h._ACTIVE_DNS4, h._ACTIVE_DNS6,
         h._control_mtime, h.configure_tun, h._install_dns_guard) = self._saved
        os.unlink(self.path)

    def test_stale_file_is_ignored_after_baseline(self):
        self.helper._control_mtime = 0.0
        self.helper._baseline_control_file()
        self.assertFalse(self.helper.poll_control_file())
        self.assertEqual(self.helper._ACTIVE_DNS4, DNS4)
        self.assertEqual(self.helper._ACTIVE_DNS6, DNS6)

    def test_new_write_after_baseline_is_applied(self):
        self.helper._control_mtime = 0.0
        self.helper._baseline_control_file()
        time.sleep(0.02)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump({"dns4": "9.9.9.9", "dns6": None}, f)
        self.assertTrue(self.helper.poll_control_file())
        self.assertEqual(self.helper._ACTIVE_DNS4, "9.9.9.9")
        self.assertIsNone(self.helper._ACTIVE_DNS6)


class TestDohPartialRegistration(unittest.TestCase):
    """configure_tun registers DoH per family. When only ONE registration
    succeeds, the old all-or-nothing gate reported a clean failure; the
    per-family version then installed BOTH resolvers on the adapter and
    printed only the success line - so the family that failed was silently
    downgraded to raw UDP/53, which is the path that dies inside a TUN whose
    SOCKS proxy has no UDP relay. The failure must be named explicitly."""

    def setUp(self):
        from tuntop.tunnel import helper
        self.helper = helper
        self._saved = (helper._register_doh_server,
                       helper._set_wintun_dns_servers,
                       helper._set_wintun_addresses_plain,
                       helper._disable_netbios_on_wintun,
                       helper._set_wintun_interface_metric,
                       helper._ACTIVE_DNS_MODE, helper._ACTIVE_DOH_TEMPLATE)
        self.set_list = []
        self.registrations = []
        helper._set_wintun_addresses_plain = lambda *a, **k: None
        helper._disable_netbios_on_wintun = lambda: None
        helper._set_wintun_interface_metric = lambda m: None
        helper._set_wintun_dns_servers = lambda s: (self.set_list.append(
            list(s or [])) or True)
        helper._ACTIVE_DNS_MODE = "doh"
        helper._ACTIVE_DOH_TEMPLATE = None

    def tearDown(self):
        (self.helper._register_doh_server,
         self.helper._set_wintun_dns_servers,
         self.helper._set_wintun_addresses_plain,
         self.helper._disable_netbios_on_wintun,
         self.helper._set_wintun_interface_metric,
         self.helper._ACTIVE_DNS_MODE,
         self.helper._ACTIVE_DOH_TEMPLATE) = self._saved

    def _register(self, ok_for):
        def _reg(ip, tpl):
            self.registrations.append((ip, tpl))
            return ok_for(ip)
        return _reg

    def _configure(self, dns4, dns6):
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.helper.configure_tun(dns4, dns6)
        return buf.getvalue()

    def test_the_failed_family_is_named(self):
        self.helper._register_doh_server = self._register(
            lambda ip: ip == "9.9.9.9")          # v6 only
        out = self._configure("1.1.1.1", "9.9.9.9")
        self.assertIn("DoH registration FAILED", out)
        self.assertIn("1.1.1.1", out.split("DoH registration FAILED", 1)[1])
        # The v6 success is still reported...
        self.assertIn("9.9.9.9", out)
        # ...and the adapter still gets both, so this is a reporting gap only.
        self.assertEqual(self.set_list, [["1.1.1.1", "9.9.9.9"]])

    def test_a_total_failure_still_reports_once(self):
        self.helper._register_doh_server = self._register(lambda ip: False)
        out = self._configure("1.1.1.1", "9.9.9.9")
        self.assertIn("DoH enable failed", out)
        self.assertIn("DoH registration FAILED", out)
        # No adapter list is written when nothing registered.
        self.assertEqual(self.set_list, [])

    def test_both_succeeding_reports_no_failure(self):
        self.helper._register_doh_server = self._register(lambda ip: True)
        out = self._configure("1.1.1.1", "9.9.9.9")
        self.assertNotIn("DoH registration FAILED", out)
        self.assertNotIn("DoH enable failed", out)
        self.assertIn("1.1.1.1", out)
        self.assertIn("9.9.9.9", out)

    def test_a_v6_only_choice_reports_a_v4_nothing_to_register(self):
        """dns4 None must not be collected as a 'failed registration' - there
        was nothing to register in the first place."""
        self.helper._register_doh_server = self._register(lambda ip: True)
        out = self._configure(None, "9.9.9.9")
        self.assertNotIn("DoH registration FAILED", out)
        self.assertEqual(self.set_list, [["9.9.9.9"]])


if __name__ == "__main__":
    unittest.main()

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

from tuntop.tunnel.helper import DNS4, DNS6, _resolve_dns_choice


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

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
                       helper.configure_tun)
        helper.CONTROL_FILE = path
        helper._ACTIVE_DNS4 = DNS4
        helper._ACTIVE_DNS6 = DNS6
        helper._control_mtime = 0.0
        helper.configure_tun = lambda *a, **k: None

    def tearDown(self):
        h = self.helper
        (h.CONTROL_FILE, h._ACTIVE_DNS4, h._ACTIVE_DNS6,
         h._control_mtime, h.configure_tun) = self._saved
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
                       helper.configure_tun)
        helper.CONTROL_FILE = path
        helper._ACTIVE_DNS4 = DNS4
        helper._ACTIVE_DNS6 = DNS6
        helper.configure_tun = lambda *a, **k: None

    def tearDown(self):
        h = self.helper
        (h.CONTROL_FILE, h._ACTIVE_DNS4, h._ACTIVE_DNS6,
         h._control_mtime, h.configure_tun) = self._saved
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


if __name__ == "__main__":
    unittest.main()

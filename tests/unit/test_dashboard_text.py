"""Unit-tier tests for the dashboard's pure text/layout helpers.

These render every panel line, so an off-by-one here is a garbled screen.
The helpers are pure string functions; `tuntop.dashboard` is imported
(which is safe headless - verified by CI) and nothing terminal-related is
touched.

Run:  python -m unittest discover -s tests -t . -v
"""
import unittest
from unittest import mock

from tuntop import dashboard


class TestSplitHostPort(unittest.TestCase):
    def test_host_port(self):
        self.assertEqual(dashboard._split_hostport("proxy.local:10808"),
                         ("proxy.local", "10808"))

    def test_bare_host_has_no_port(self):
        self.assertEqual(dashboard._split_hostport("example.com"),
                         ("example.com", ""))

    def test_bracketed_ipv6(self):
        self.assertEqual(dashboard._split_hostport("[2606:4700::1111]:443"),
                         ("2606:4700::1111", "443"))
        self.assertEqual(dashboard._split_hostport("[2606:4700::1111]"),
                         ("2606:4700::1111", ""))

    def test_colon_only_string(self):
        self.assertEqual(dashboard._split_hostport(":8080"), ("", "8080"))


class TestPad(unittest.TestCase):
    def test_pads_to_visible_width(self):
        self.assertEqual(dashboard._pad("ab", 5), "ab   ")

    def test_ansi_codes_do_not_count_as_columns(self):
        coloured = "\x1b[32mab\x1b[0m"
        out = dashboard._pad(coloured, 4)
        self.assertTrue(out.startswith(coloured))
        self.assertEqual(len(out), len(coloured) + 2)   # 2 visible, +2 pad

    def test_overlong_is_truncated_to_visible_width(self):
        out = dashboard._pad("abcdef", 3)
        self.assertEqual(out, "abc")

    def test_overlong_with_ansi_truncates_cleanly(self):
        out = dashboard._pad("\x1b[31mabcdef\x1b[0m", 3)
        self.assertEqual(out, "abc")   # codes stripped on the truncate path


class TestHslice(unittest.TestCase):
    def test_window_without_ansi(self):
        self.assertEqual(dashboard._hslice("abcdefgh", 2, 3), "cde")

    def test_ansi_state_is_preserved_across_the_cut(self):
        text = "\x1b[31mabcdef\x1b[0m"
        out = dashboard._hslice(text, 2, 2)
        # The leading colour code must survive so the window stays red.
        self.assertTrue(out.startswith("\x1b[31m"))
        self.assertEqual(out.replace("\x1b[31m", ""), "cd")

    def test_window_beyond_end_is_empty(self):
        self.assertEqual(dashboard._hslice("abc", 10, 3), "")


class TestHpad(unittest.TestCase):
    def test_short_text_right_padded(self):
        self.assertEqual(dashboard._hpad("ab", 5), "ab   ")

    def test_scroll_then_pad(self):
        out = dashboard._hpad("abcdefgh", 3, start=2)
        self.assertEqual(out, "cde")

    def test_no_scroll_needed_is_the_fast_path(self):
        self.assertEqual(dashboard._hpad("abc", 5, start=0), "abc  ")


class TestConsoleSafe(unittest.TestCase):
    def test_ascii_passes_through_when_unicode_off(self):
        with mock.patch.object(dashboard, "USE_UNICODE", False):
            self.assertEqual(dashboard._console_safe("ok [1] done"), "ok [1] done")

    def test_non_ascii_becomes_dots_when_unicode_off(self):
        with mock.patch.object(dashboard, "USE_UNICODE", False):
            # printable ASCII (incl. spaces) passes, everything else dots
            self.assertEqual(dashboard._console_safe("café ✓"), "caf. .")

    def test_unicode_mode_leaves_text_alone(self):
        with mock.patch.object(dashboard, "USE_UNICODE", True):
            self.assertEqual(dashboard._console_safe("café ✓"), "café ✓")


if __name__ == "__main__":
    unittest.main()

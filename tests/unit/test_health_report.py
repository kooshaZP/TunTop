"""Unit tests for tuntop.health_report - visual health reporting.

Pure stdlib, no Windows calls.
"""
import unittest

from tuntop.health_report import (
    overall_status, format_panel, format_compact, _suggest,
)


# Fake results in the format the dashboard uses: (index, name, ok, detail)
def _ok(name, detail="ok"):
    return (0, name, True, detail)


def _fail(name, detail="failed"):
    return (0, name, False, detail)


class TestOverallStatus(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(overall_status([]), "UNKNOWN")

    def test_all_pass(self):
        r = [_ok("A"), _ok("B"), _ok("C")]
        self.assertEqual(overall_status(r), "HEALTHY")

    def test_one_fail(self):
        r = [_ok("A"), _fail("B"), _ok("C")]
        self.assertEqual(overall_status(r), "DEGRADED")

    def test_most_fail(self):
        r = [_fail("A"), _fail("B"), _fail("C"), _ok("D")]
        self.assertEqual(overall_status(r), "DEGRADED")

    def test_all_fail(self):
        r = [_fail("A"), _fail("B")]
        self.assertEqual(overall_status(r), "UNHEALTHY")


class TestFormatPanel(unittest.TestCase):
    def test_empty(self):
        lines = format_panel([])
        self.assertEqual(len(lines), 1)
        self.assertIn("no health scan", lines[0])

    def test_healthy(self):
        lines = format_panel([_ok("VLESS"), _ok("SOCKS")])
        self.assertTrue(any("HEALTHY" in l for l in lines))
        self.assertTrue(any("VLESS" in l for l in lines))

    def test_unhealthy_shows_suggestion(self):
        lines = format_panel([_fail("DNS resolution", "timeout")])
        self.assertTrue(any("DNS" in l for l in lines))
        self.assertTrue(any("suggestion" in l.lower() or
                           "Press [N]" in l or "switch DNS" in l.lower()
                           for l in lines))

    def test_unicode_off(self):
        lines = format_panel([_ok("A")], use_unicode=False)
        self.assertTrue(any("OK" in l for l in lines))

    def test_detail_truncation(self):
        long_detail = "x" * 200
        lines = format_panel([_ok("Test", long_detail)], width=40)
        # Should not crash, detail should be truncated
        self.assertTrue(len(lines) > 0)


class TestFormatCompact(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(format_compact([]), "no scan")

    def test_healthy(self):
        r = [_ok("A"), _ok("B")]
        s = format_compact(r)
        self.assertIn("2/2", s)
        self.assertIn("HEALTHY", s)

    def test_degraded(self):
        r = [_ok("A"), _fail("B")]
        s = format_compact(r)
        self.assertIn("1/2", s)
        self.assertIn("DEGRADED", s)


class TestSuggest(unittest.TestCase):
    def test_dns_suggestion(self):
        s = _suggest("DNS resolution failed")
        self.assertIn("DNS", s.upper() if s else "")

    def test_vless_suggestion(self):
        s = _suggest("VLESS server unreachable")
        self.assertIn("v2rayN", s)

    def test_unknown_probe(self):
        s = _suggest("mystery probe xyz")
        self.assertEqual(s, "")


if __name__ == "__main__":
    unittest.main()

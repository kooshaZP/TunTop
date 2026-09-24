"""Offline tests for the fast |-delimited route-table dump parser.

The fast dump replaces ConvertTo-Json with a ForEach-Object pipeline that
emits ``dest|iface|nh`` (or ``dest|iface|nh|metric|store`` for the full dump).
These tests pin the pure-Python parser: string-in, dict-out, no Windows.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from tuntop.network.routing import (_parse_route_rows,
                                    _dump_route_table_ps,
                                    _dump_route_table_full_ps)


class TestParseRouteRows(unittest.TestCase):
    def test_empty_and_whitespace_input(self):
        self.assertEqual(_parse_route_rows(""), [])
        self.assertEqual(_parse_route_rows(None), [])
        self.assertEqual(_parse_route_rows("   \n  \n"), [])

    def test_garbage_without_delimiter_skipped(self):
        self.assertEqual(_parse_route_rows("hello world\nfoo bar"), [])

    def test_delimiter_only_lines_skipped(self):
        self.assertEqual(_parse_route_rows("|||\n|| "), [])

    def test_missing_dest_skipped(self):
        # dest|iface|nh with empty dest — must be filtered (the truthiness
        # filter the old ConvertTo-Json path applied via r.get("DestinationPrefix")).
        self.assertEqual(_parse_route_rows("||Wi-Fi|192.168.1.1"), [])

    def test_valid_lines_parsed_to_dicts(self):
        text = ("192.0.2.0/24|Wi-Fi|192.168.1.1\n"
                "203.0.113.0/24|wintun|10.0.0.1")
        rows = _parse_route_rows(text)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0], {"DestinationPrefix": "192.0.2.0/24",
                                   "InterfaceAlias": "Wi-Fi",
                                   "NextHop": "192.168.1.1"})
        self.assertEqual(rows[1], {"DestinationPrefix": "203.0.113.0/24",
                                   "InterfaceAlias": "wintun",
                                   "NextHop": "10.0.0.1"})

    def test_stray_quotes_stripped(self):
        text = "192.0.2.0/24|'Wi-Fi'|'192.168.1.1'"
        rows = _parse_route_rows(text)
        self.assertEqual(rows[0]["InterfaceAlias"], "Wi-Fi")
        self.assertEqual(rows[0]["NextHop"], "192.168.1.1")

    def test_on_link_next_hop_normalized_to_empty(self):
        text = ("192.0.2.0/24|Wi-Fi|0.0.0.0\n"
                "2001:db8::/64|Ethernet|::\n"
                "198.51.100.0/24|Wi-Fi|On-link")
        rows = _parse_route_rows(text)
        self.assertEqual(rows[0]["NextHop"], "")
        self.assertEqual(rows[1]["NextHop"], "")
        self.assertEqual(rows[2]["NextHop"], "")

    def test_full_dump_includes_metric_and_store(self):
        text = "192.0.2.0/24|Wi-Fi|192.168.1.1|25|ActiveStore"
        rows = _parse_route_rows(text, full=True)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["DestinationPrefix"], "192.0.2.0/24")
        self.assertEqual(row["InterfaceAlias"], "Wi-Fi")
        self.assertEqual(row["NextHop"], "192.168.1.1")
        self.assertEqual(row["RouteMetric"], 25)
        self.assertEqual(row["Store"], "ActiveStore")

    def test_full_dump_metric_as_string_converted_to_int(self):
        text = "192.0.2.0/24|Wi-Fi|192.168.1.1|0|PersistentStore"
        rows = _parse_route_rows(text, full=True)
        self.assertIsInstance(rows[0]["RouteMetric"], int)
        self.assertEqual(rows[0]["RouteMetric"], 0)

    def test_full_dump_missing_fields_skipped(self):
        # full=True requires 5 |-parts; a 3-part line is dropped.
        text = "192.0.2.0/24|Wi-Fi|192.168.1.1"
        rows = _parse_route_rows(text, full=True)
        self.assertEqual(rows, [])

    def test_non_full_ignores_metric_and_store(self):
        text = "192.0.2.0/24|Wi-Fi|192.168.1.1|25|ActiveStore"
        rows = _parse_route_rows(text, full=False)
        self.assertEqual(len(rows), 1)
        self.assertNotIn("RouteMetric", rows[0])
        self.assertNotIn("Store", rows[0])

    def test_ipv6_prefix(self):
        text = "2001:db8::/64|Ethernet|2001:db8::1"
        rows = _parse_route_rows(text)
        self.assertEqual(rows[0]["DestinationPrefix"], "2001:db8::/64")

    def test_blank_dest_in_full_skipped(self):
        text = "|Wi-Fi|192.168.1.1|25|ActiveStore"
        rows = _parse_route_rows(text, full=True)
        self.assertEqual(rows, [])

    def test_garbage_in_full_skipped(self):
        text = "not a route\n|||0|ActiveStore\n192.0.2.0/24|Wi-Fi|1.1.1.1|10|PersistentStore"
        rows = _parse_route_rows(text, full=True)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["DestinationPrefix"], "192.0.2.0/24")
        self.assertEqual(rows[0]["RouteMetric"], 10)


class TestDumpScripts(unittest.TestCase):
    def test_base_dump_uses_foreach_no_json(self):
        with mock.patch("tuntop.network.routing._ps",
                        return_value=(True, "")) as m:
            _dump_route_table_ps()
        script = m.call_args[0][0]
        self.assertIn("ForEach-Object", script)
        self.assertNotIn("ConvertTo-Json", script)
        self.assertIn("DestinationPrefix", script)
        self.assertIn("InterfaceAlias", script)
        self.assertIn("NextHop", script)

    def test_full_dump_uses_foreach_no_json(self):
        with mock.patch("tuntop.network.routing._ps",
                        return_value=(True, "")) as m:
            _dump_route_table_full_ps()
        script = m.call_args[0][0]
        self.assertIn("ForEach-Object", script)
        self.assertNotIn("ConvertTo-Json", script)
        self.assertIn("RouteMetric", script)
        self.assertIn("Store", script)

    def test_both_use_pipe_delimiter(self):
        for fn in (_dump_route_table_ps, _dump_route_table_full_ps):
            with mock.patch("tuntop.network.routing._ps",
                            return_value=(True, "")) as m:
                fn()
            script = m.call_args[0][0]
            self.assertIn("|", script)


if __name__ == "__main__":
    unittest.main()

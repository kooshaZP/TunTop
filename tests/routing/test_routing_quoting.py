"""Regression tests: PowerShell-literal quoting in the shared routing layer,
and the dashboard using it instead of shadowing it.

Two bugs in one lineage: (1) a Windows VPN connection name is free text
(Windows allows apostrophes - "Bob's VPN") and gets interpolated into a
single-quoted PowerShell literal, so without ps_quote() the apostrophe
closes the literal, the script fails to parse, _ps() reports failure and
the lookup silently returns None (bypass-vpn routes then never install);
(2) tuntop/ui/dashboard.py imported 14 routing helpers from
tuntop.network.routing and then re-defined 13 of them at module scope, so
the imports never ran and a quoting fix in the shared module never reached
the dashboard. These tests pin both.

Run:  python -m unittest discover -s tests -t . -v
"""
import json
import unittest
from unittest import mock

import tuntop.network.routing as routing


def _capturing_ps(seen):
    def fake_ps(script, timeout=8):
        seen.append(script)
        return True, json.dumps({"InterfaceAlias": "Bob", "NextHop": "10.0.0.1"})
    return fake_ps


class TestVpnInterfaceQuoting(unittest.TestCase):
    """Every free-text value interpolated into a PowerShell single-quoted
    literal in tuntop.network.routing must be ps_quote()-escaped."""

    def _script_for(self, fn, *args):
        seen = []
        with mock.patch.object(routing, "_ps", _capturing_ps(seen)):
            result = fn(*args)
        self.assertEqual(result, ("Bob", "10.0.0.1"))
        return seen[0]

    def test_vpn_v4_default_quotes_interface(self):
        script = self._script_for(routing._get_vpn_ipv4_default, "Bob's VPN")
        self.assertIn("-InterfaceAlias 'Bob''s VPN'", script)
        self.assertNotIn("Bob's VPN", script)

    def test_vpn_v6_default_quotes_interface(self):
        script = self._script_for(routing._get_vpn_ipv6_default, "Bob's VPN")
        self.assertIn("-InterfaceAlias 'Bob''s VPN'", script)
        self.assertNotIn("Bob's VPN", script)

    def test_ipv6_default_quotes_interface(self):
        script = self._script_for(routing._get_ipv6_default, "Bob's VPN")
        self.assertIn("-InterfaceAlias 'Bob''s VPN'", script)
        self.assertNotIn("Bob's VPN", script)

    def test_egress_for_quotes_ip(self):
        script = self._script_for(routing._get_egress_for, "1.2.3.4")
        self.assertIn("-RemoteIPAddress '1.2.3.4'", script)

    def test_hostile_name_cannot_break_out_of_literal(self):
        evil = "x' | Remove-NetRoute -Confirm:$false | echo '"
        script = self._script_for(routing._get_vpn_ipv4_default, evil)
        self.assertIn("-InterfaceAlias '%s'" % evil.replace("'", "''"), script)

    def test_plain_name_unchanged(self):
        script = self._script_for(routing._get_vpn_ipv4_default, "My VPN")
        self.assertIn("-InterfaceAlias 'My VPN'", script)


class TestDashboardBindsSharedRouting(unittest.TestCase):
    """The top-of-file import must not be shadowed by local redefinitions:
    every routing helper name the dashboard binds must BE the object from
    tuntop.network.routing, so a fix there is a fix everywhere."""

    def test_no_shadowing(self):
        import tuntop.ui.dashboard as dash
        for name in ("_ps", "_netsh", "_teardown_wintun",
                     "_add_route_v4", "_del_route_v4",
                     "_add_route_v6", "_del_route_v6",
                     "_route_exists_v4", "_route_exists_v6",
                     "_get_ipv4_default", "_get_ipv6_default",
                     "_get_egress_for", "_get_vpn_ipv4_default",
                     "_get_vpn_ipv6_default"):
            self.assertIs(getattr(dash, name), getattr(routing, name), name)


class TestHealthCheckScriptQuoting(unittest.TestCase):
    """build_checks() interpolates user-typed strings (--server values, [A]
    bypass entries, --dns4) into PowerShell single-quoted literals - the
    exact "Bob's VPN" class that was fixed for vpn_interface. Any apostrophe
    closes the literal, the script fails to PARSE, and the check row reports
    a nonsense parse error instead of its real verdict."""

    def _ns(self):
        import argparse
        return argparse.Namespace(
            port=10808, server=["Bob's server"], dns4="Bob's dns",
            endpoint_port=443, bypass_ip=["Bob's bypass"],
            vless_over_vpn=False, geoip=None, geoip_code="cn",
            geoip_target=None, proxy2_port=None, proxy2_server=[],
        )

    def _scripts(self, ns):
        """build_checks(ns) with every check executed against a stubbed
        Windows edge: _ps captures the generated script, the Python-side
        helpers (sockets/HTTP) are stubbed so nothing touches the network."""
        import tuntop.ui.dashboard as dash
        scripts = []

        def fake_ps(code, *a, **k):
            scripts.append(code)
            return True, ""

        def fake_resolve_cached(host):
            if host == "Bob's server":
                return ["1.2.3.4"], ["2606:4700::1111"]
            return [], []

        stubs = {name: (lambda *a, **k: (True, "stub"))
                 for name in ("_tcp", "_https", "_socks_greeting",
                              "_socks_connect_domain", "_socks_request",
                              "_socks_request_v6", "_check_udp_assoc",
                              "_leak_check", "_ipv6_tun_verdict")}
        with mock.patch.object(dash, "_ps", fake_ps), \
                mock.patch.object(dash, "_resolve_cached", fake_resolve_cached), \
                mock.patch.multiple(dash, **stubs):
            for _label, fn in dash.build_checks(ns):
                try:
                    fn()
                except Exception:
                    pass
        return scripts

    def test_no_raw_apostrophe_in_any_generated_script(self):
        for script in self._scripts(self._ns()):
            # _host_from_url lowercases, so check case-insensitively.
            self.assertNotIn("bob's", script.lower(), script)

    def test_bypass_unresolved_message_is_escaped(self):
        scripts = self._scripts(self._ns())
        hits = [s for s in scripts if "not resolved yet:" in s]
        self.assertTrue(hits)
        self.assertTrue(any("bob''s bypass" in s.lower() for s in hits))

    def test_server_route_lookup_uses_resolved_ips_not_hostname(self):
        scripts = self._scripts(self._ns())
        hits = [s for s in scripts
                if "$ips = @('1.2.3.4','2606:4700::1111')" in s]
        self.assertTrue(hits)
        for script in hits:
            self.assertIn("$ips = @('1.2.3.4','2606:4700::1111')", script)
            self.assertNotIn("Bob's server", script)
            self.assertNotIn("bob's server", script.lower())

    def test_udp_connect_and_ping_use_escaped_dns(self):
        scripts = self._scripts(self._ns())
        self.assertTrue(any("$u.Connect('Bob''s dns',53)" in s for s in scripts))
        self.assertTrue(any("ping.exe -n 1 -f -l 1200 'Bob''s dns'" in s
                            for s in scripts))

    def test_proxy_loop_check_flags_our_tunnel_by_alias(self):
        """1.0.33: the loop-detection check used to pass while the server
        route resolved through OUR OWN 'wintun' adapter (it only matched the
        adapter DESCRIPTION against 'Wintun', which our vendored tun2socks
        description does not contain). The generated script must treat our
        own aliases as a loop regardless of the description."""
        import tuntop.config.defaults as cfgdef
        scripts = self._scripts(self._ns())
        hits = [s for s in scripts if "Proxy loop detection" in s
                or "VLESS endpoint NOT bypassed" in s]
        self.assertTrue(hits)
        for s in hits:
            self.assertIn(f"@('{cfgdef.TUN}','{cfgdef.TUN2}')", s)
            self.assertIn("-contains $_.InterfaceAlias", s)

    def test_proxy_loop_check_uses_shared_tun_driver_regex(self):
        from tuntop.network import egress_scripts as es
        scripts = self._scripts(self._ns())
        hits = [s for s in scripts if "VLESS endpoint NOT bypassed" in s]
        self.assertTrue(hits)
        self.assertTrue(all(es.TUN_DRIVER_RE in s for s in hits))


if __name__ == "__main__":
    unittest.main()
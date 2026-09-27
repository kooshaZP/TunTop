"""Offline tests for the DNS leak guard (tuntop/network/dns_guard.py).

The guard is the fix for the real leak: Windows' Smart Multi-Homed Name
Resolution sends every query out over ALL connected adapters that have
resolvers and takes the first answer, so a DHCP-assigned physical resolver
(router/ISP) can answer even while the tunnel's own resolvers work fine -
which the in-app probes (TUN-only) could never see. A catch-all NRPT rule is
the only thing that stops it.

Everything here is text/state/logic: the PowerShell runner is INJECTED, so
these tests never touch the real registry (on an elevated machine a real
install would pin the whole system's name resolution).
"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))

from tuntop.network import dns_guard as G


def _runner(output, ok=True, calls=None):
    """A stand-in for routing._ps that records the scripts it was given."""
    def _run(script, timeout=8):
        if calls is not None:
            calls.append(script)
        return ok, output
    return _run


class TestRuleIdentity(unittest.TestCase):
    def test_every_key_carries_the_prefix(self):
        self.assertTrue(G.MATCH_KEY.startswith(G.GUARD_KEY_PREFIX))
        self.assertTrue(G.EXEMPT_LOCAL_KEY.startswith(G.GUARD_KEY_PREFIX))

    def test_catch_all_namespace_is_the_root_dot(self):
        self.assertEqual(G.CATCH_ALL_NAMESPACE, ".")

    def test_local_exemption_is_always_on(self):
        self.assertIn(G.LOCAL_NAMESPACE, G.DEFAULT_EXEMPT_NAMESPACES)

    def test_override_dns_option_bit(self):
        self.assertEqual(G.CONFIG_OPTIONS_OVERRIDE_DNS, 0x8)


class TestGuardResolvers(unittest.TestCase):
    def test_v4_then_v6_in_order(self):
        self.assertEqual(G.guard_resolvers("8.8.8.8", "2606:4700:4700::1111"),
                         ["8.8.8.8", "2606:4700:4700::1111"])

    def test_v4_only(self):
        self.assertEqual(G.guard_resolvers("9.9.9.9", None), ["9.9.9.9"])

    def test_v6_only(self):
        self.assertEqual(G.guard_resolvers(None, "2620:fe::fe"), ["2620:fe::fe"])

    def test_nothing_configured_is_empty(self):
        self.assertEqual(G.guard_resolvers(None, None), [])
        self.assertEqual(G.guard_resolvers("", "  "), [])

    def test_duplicates_are_collapsed(self):
        self.assertEqual(G.guard_resolvers("8.8.8.8", "8.8.8.8"), ["8.8.8.8"])

    def test_whitespace_is_stripped(self):
        self.assertEqual(G.guard_resolvers(" 1.1.1.1 ", None), ["1.1.1.1"])


class TestInstallScript(unittest.TestCase):
    def test_writes_both_rules_with_the_right_values(self):
        s = G.install_script(["8.8.8.8", "2606:4700:4700::1111"],
                             [G.LOCAL_NAMESPACE])
        self.assertIn("DnsPolicyConfig", s)
        self.assertIn(G.MATCH_KEY, s)
        self.assertIn(G.EXEMPT_LOCAL_KEY, s)
        self.assertIn("'Version'", s)
        self.assertIn("MultiString -Value @('.')", s)   # claims every name
        # Multiple override servers are joined with ';' (REG_SZ).
        self.assertIn("'8.8.8.8;2606:4700:4700::1111'", s)
        self.assertIn("-Value 8", s)                    # ConfigOptions 0x8
        self.assertIn("Clear-DnsClientCache", s)
        self.assertIn("DNS_GUARD_OK", s)

    def test_refresh_semantics_drop_stale_keys_first(self):
        s = G.install_script(["8.8.8.8"], [G.LOCAL_NAMESPACE])
        self.assertIn("Remove-Item -Recurse -Force", s)
        self.assertIn("'TunTop-*'", s)

    def test_exemption_value_is_present_and_empty(self):
        """Windows DISCARDS an NRPT rule whose GenericDNSServers value is
        missing, so the exemption would silently not apply and `.local` would
        go to 8.8.8.8 (RFC 6762 mDNS must not be sent to a unicast resolver).
        The value must therefore be written explicitly, and EMPTY."""
        s = G.install_script(["8.8.8.8"], [G.LOCAL_NAMESPACE])
        self.assertIn("New-ItemProperty -Path $ex -Name 'GenericDNSServers'"
                      " -PropertyType String -Value ''", s)

    def test_exemption_carries_every_namespace(self):
        # Namespaces are lower-cased (DNS is case-insensitive, and a
        # normalised value is what every other TunTop list stores).
        s = G.install_script(["8.8.8.8"], [".local", "Home.Example"])
        self.assertIn("@('.local','home.example')", s)

    def test_exemption_is_optional(self):
        s = G.install_script(["8.8.8.8"])
        self.assertNotIn(G.EXEMPT_LOCAL_KEY, s)

    def test_no_resolver_never_writes_a_black_hole(self):
        s = G.install_script([], [G.LOCAL_NAMESPACE])
        self.assertIn("DNS_GUARD_FAIL", s)
        self.assertNotIn("DNS_GUARD_OK", s)
        self.assertNotIn("New-ItemProperty", s)

    def test_quotes_in_a_namespace_cannot_break_out(self):
        s = G.install_script(["8.8.8.8"], ["evil'; Write-Output 'pwned"])
        # The embedded quote is doubled, so the whole thing stays ONE array
        # element instead of becoming a second PowerShell statement.
        self.assertIn("@('evil''; write-output ''pwned')", s)

    def test_comment_is_written(self):
        s = G.install_script(["8.8.8.8"])
        self.assertIn("-Name 'Comment'", s)
        self.assertIn("TunTop:", s)


class TestUninstallScript(unittest.TestCase):
    def test_removes_our_keys_and_flushes(self):
        s = G.uninstall_script()
        self.assertIn("'TunTop-*'", s)
        self.assertIn("Remove-Item -Recurse -Force", s)
        self.assertIn("Clear-DnsClientCache", s)
        self.assertIn("DNS_GUARD_REMOVED", s)

    def test_also_clears_a_cmdlet_made_rule(self):
        """A rule created through Add-DnsClientNrptRule is GUID-named, so the
        registry pass alone would miss it; the cmdlet pass matches on our
        display name / comment."""
        s = G.uninstall_script()
        self.assertIn("Get-DnsClientNrptRule", s)
        self.assertIn("Remove-DnsClientNrptRule", s)

    def test_never_touches_a_foreign_rule(self):
        s = G.uninstall_script()
        # The only broad delete is scoped to the TunTop- prefix.
        self.assertNotIn("-like '*'", s)


class TestDetectScript(unittest.TestCase):
    def test_asks_windows_for_the_effective_policy(self):
        s = G.detect_script()
        self.assertIn("Get-DnsClientNrptPolicy -Effective", s)
        self.assertIn("DNS_GUARD_STATE:", s)

    def test_parses_a_positive_result(self):
        state = G.parse_detect(
            "DNS_GUARD_STATE:keys=2;effective=true;servers=8.8.8.8")
        self.assertEqual(state["keys"], 2)
        self.assertTrue(state["effective"])
        self.assertEqual(state["servers"], "8.8.8.8")
        self.assertTrue(state["ok"])

    def test_key_without_effective_policy_is_not_ok(self):
        """A rule Windows silently dropped from its policy protects nothing."""
        state = G.parse_detect(
            "DNS_GUARD_STATE:keys=2;effective=false;servers=8.8.8.8")
        self.assertFalse(state["ok"])

    def test_absent_output_is_a_clean_default(self):
        for out in ("", None, "Get-ChildItem : denied"):
            state = G.parse_detect(out)
            self.assertEqual(state["keys"], 0)
            self.assertFalse(state["ok"])

    def test_garbage_keys_value_does_not_raise(self):
        state = G.parse_detect("DNS_GUARD_STATE:keys=abc;effective=true")
        self.assertEqual(state["keys"], 0)
        self.assertFalse(state["ok"])

    def test_finds_the_line_among_other_output(self):
        state = G.parse_detect(
            "some noise\nDNS_GUARD_STATE:keys=1;effective=true;servers=1.1.1.1\n"
            "more noise")
        self.assertTrue(state["ok"])
        self.assertEqual(state["servers"], "1.1.1.1")

    def test_the_catch_all_key_is_counted_separately(self):
        """`keys` counts EVERY TunTop-* key, including the .local exemption,
        which claims no namespace at all. A leftover exemption plus a foreign
        managed catch-all therefore read as 'fully protected' while our pin
        was long gone - the monitor loop would log 'DNS pinned' and the health
        row would go green on a dead guard."""
        state = G.parse_detect(
            "DNS_GUARD_STATE:keys=1;match=0;effective=true;servers=")
        self.assertEqual(state["keys"], 1)
        self.assertEqual(state["match"], 0)
        self.assertTrue(state["effective"])   # a foreign catch-all is in force
        self.assertFalse(state["ok"])         # but OURS is not

    def test_match_present_and_effective_is_ok(self):
        state = G.parse_detect(
            "DNS_GUARD_STATE:keys=2;match=1;effective=true;servers=8.8.8.8")
        self.assertTrue(state["ok"])
        self.assertEqual(state["match"], 1)

    def test_detect_script_reports_the_match_count(self):
        s = G.detect_script()
        self.assertIn(";match=", s)
        self.assertIn("PSChildName -eq", s)

    def test_a_line_without_the_match_field_still_parses(self):
        """Back-compat: parse_detect falls back to `keys` when `match` is
        absent, so an older cached/recorded line cannot read as a failure."""
        state = G.parse_detect(
            "DNS_GUARD_STATE:keys=2;effective=true;servers=8.8.8.8")
        self.assertIsNone(state["match"])
        self.assertTrue(state["ok"])


class TestStateRecord(unittest.TestCase):
    """The install record is what lets a LATER process (a different exe in
    the folder, the watchdog, the next launch) remove exactly what we
    created after a hard kill."""

    def setUp(self):
        self.path = os.path.join(self._tmpdir(), ".tuntop_dns_guard.json")

    def _tmpdir(self):
        d = tempfile.mkdtemp()
        self.addCleanup(_rmtree, d)
        return d

    def test_round_trip(self):
        self.assertTrue(G.save_state(["8.8.8.8"], [".local"], path=self.path))
        st = G.load_state(path=self.path)
        self.assertIsNotNone(st)
        self.assertEqual(st["resolvers"], ["8.8.8.8"])
        self.assertEqual(st["exempt"], [".local"])
        self.assertIn(G.MATCH_KEY, st["keys"])
        self.assertIn(G.EXEMPT_LOCAL_KEY, st["keys"])

    def test_missing_file_is_none(self):
        self.assertIsNone(G.load_state(path=self.path))

    def test_incomplete_record_is_ignored(self):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "installed": False}, f)
        self.assertIsNone(G.load_state(path=self.path))

    def test_unreadable_record_is_none(self):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("{not json")
        self.assertIsNone(G.load_state(path=self.path))

    def test_clear_is_idempotent(self):
        G.save_state(["8.8.8.8"], path=self.path)
        G.clear_state(path=self.path)
        G.clear_state(path=self.path)          # must not raise
        self.assertIsNone(G.load_state(path=self.path))


def _rmtree(d):
    import shutil
    shutil.rmtree(d, ignore_errors=True)


class TestInstall(unittest.TestCase):
    def test_success_records_the_state(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "state.json")
            ok, msg = G.install(["8.8.8.8"], ["8.8.8.8" and ".local"],
                                runner=_runner("DNS_GUARD_OK"),
                                path=path)
            self.assertTrue(ok)
            self.assertIn("8.8.8.8", msg)
            self.assertEqual(G.load_state(path=path)["resolvers"], ["8.8.8.8"])

    def test_reports_a_failure_and_records_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "state.json")
            ok, msg = G.install(["8.8.8.8"],
                                runner=_runner("DNS_GUARD_FAIL:access denied"),
                                path=path)
            self.assertFalse(ok)
            self.assertIn("access denied", msg)
            self.assertIsNone(G.load_state(path=path))

    def test_runner_exception_is_not_fatal(self):
        def boom(script, timeout=8):
            raise OSError("powershell missing")
        with tempfile.TemporaryDirectory() as d:
            ok, msg = G.install(["8.8.8.8"], runner=boom,
                                path=os.path.join(d, "s.json"))
        self.assertFalse(ok)
        self.assertIn("powershell missing", msg)

    def test_no_resolver_removes_instead_of_installing(self):
        """A rule with no override servers is a black hole, not protection."""
        with tempfile.TemporaryDirectory() as d:
            calls = []
            ok, _msg = G.install([], runner=_runner("DNS_GUARD_STATE:keys=1"
                                                   ";effective=true",
                                                   calls=calls),
                                 path=os.path.join(d, "s.json"))
            self.assertTrue(ok)
            # detect first, then the removal - never the install script.
            self.assertNotIn("DNS_GUARD_OK", calls[-1])
            self.assertIn("Remove-Item", calls[-1])

    def test_script_receives_both_families(self):
        calls = []
        G.install(["8.8.8.8", "2606:4700:4700::1111"],
                  runner=_runner("DNS_GUARD_OK", calls=calls),
                  path=os.path.join(tempfile.mkdtemp(), "s.json"))
        self.assertIn("8.8.8.8;2606:4700:4700::1111", calls[0])

    def test_an_unwritable_record_is_reported_not_swallowed(self):
        """The rule IS live when save_state fails (read-only install dir), so
        this is still a success - but the message must say the crash-safety
        record is missing instead of claiming a clean install."""
        missing = os.path.join(tempfile.mkdtemp(), "no", "such", "dir", "s.json")
        ok, msg = G.install(["8.8.8.8"],
                            runner=_runner("DNS_GUARD_OK"), path=missing)
        self.assertTrue(ok)
        self.assertIn("no install record", msg)


class TestUninstallAndEnsure(unittest.TestCase):
    def test_uninstall_clears_the_record(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.json")
            G.save_state(["8.8.8.8"], path=path)
            ok, _msg = G.uninstall(runner=_runner("DNS_GUARD_REMOVED"),
                                   path=path)
            self.assertTrue(ok)
            self.assertIsNone(G.load_state(path=path))

    def test_uninstall_reports_a_failure(self):
        ok, msg = G.uninstall(
            runner=_runner("DNS_GUARD_UNINSTALL_FAIL:locked"))
        self.assertFalse(ok)
        self.assertIn("locked", msg)

    def test_a_failed_runner_is_a_failure_not_a_silent_success(self):
        """routing._ps returns (False, <error>) when PowerShell is missing,
        times out, or exits non-zero - in every one of those cases NOTHING was
        removed. Reporting success there stranded a catch-all NRPT pin on the
        machine (every process resolving names through a dead tunnel) while
        telling the operator it was gone."""
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.json")
            G.save_state(["8.8.8.8"], path=path)
            for err in ("timed out after 8s", "access denied", ""):
                with self.subTest(err=err):
                    ok, msg = G.uninstall(
                        runner=_runner(err, ok=False), path=path)
                    self.assertFalse(ok)
                    self.assertIn("removal failed", msg)
                    # The crash-safety record MUST survive: it is the only
                    # thing the next launch's recovery can find.
                    self.assertIsNotNone(G.load_state(path=path),
                                         "record was destroyed on failure")

    def test_a_raising_runner_keeps_the_record(self):
        def boom(script, timeout=8):
            raise OSError("powershell missing")
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.json")
            G.save_state(["8.8.8.8"], path=path)
            ok, msg = G.uninstall(runner=boom, path=path)
            self.assertFalse(ok)
            self.assertIn("powershell missing", msg)
            self.assertIsNotNone(G.load_state(path=path))

    def test_ensure_removed_surfaces_a_failed_runner(self):
        """The path every teardown owner actually calls (helper cleanup, the
        dashboard sweep, startup recovery) goes through ensure_removed, so a
        failure has to survive that wrapper too - not just uninstall()."""
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.json")
            G.save_state(["8.8.8.8"], path=path)
            ok, _msg = G.ensure_removed(
                runner=_runner("timed out", ok=False), path=path)
            self.assertFalse(ok)
            self.assertIsNotNone(G.load_state(path=path))

    def test_removal_script_verifies_instead_of_assuming(self):
        """Remove-Item runs -ErrorAction SilentlyContinue (one unreadable key
        must not abort the sweep), so a DENIED removal leaves the rule behind
        while the old script still printed DNS_GUARD_REMOVED. The script must
        re-enumerate and report the survivors."""
        s = G.uninstall_script()
        self.assertIn("still present", s)
        # The verification re-read must come AFTER the removal pass.
        self.assertLess(s.index("Remove-Item"), s.index("still present"))
        self.assertIn("$left.Count -gt 0", s)

    def test_ensure_removed_skips_the_removal_when_nothing_exists(self):
        """A run with the guard off must not shell out to DELETE anything for
        nothing - only the cheap read-only probe runs."""
        calls = []
        with tempfile.TemporaryDirectory() as d:
            ok, msg = G.ensure_removed(
                runner=_runner("DNS_GUARD_STATE:keys=0;effective=false",
                               calls=calls),
                path=os.path.join(d, "s.json"))
        self.assertTrue(ok)
        self.assertIn("not installed", msg)
        self.assertEqual(len(calls), 1)
        self.assertIn("DNS_GUARD_STATE", calls[0])
        self.assertNotIn("Remove-Item", calls[0])

    def test_ensure_removed_shells_out_when_a_live_rule_exists(self):
        """The install record can be gone (deleted, or written by a crashed
        run) while the registry rule is not - the prefix probe is what catches
        that, and it must lead to a real removal."""
        with tempfile.TemporaryDirectory() as d:
            calls = []
            ok, _msg = G.ensure_removed(
                runner=_runner("DNS_GUARD_STATE:keys=2;effective=true",
                               calls=calls),
                path=os.path.join(d, "s.json"))
            self.assertTrue(ok)
            self.assertEqual(len(calls), 2)
            self.assertIn("Remove-Item", calls[1])

    def test_ensure_installed_picks_both_families(self):
        calls = []
        with tempfile.TemporaryDirectory() as d:
            G.ensure_installed("1.1.1.1", "2606:4700:4700::1001",
                                [".local"],
                                runner=_runner("DNS_GUARD_OK", calls=calls),
                                path=os.path.join(d, "s.json"))
        self.assertIn("1.1.1.1;2606:4700:4700::1001", calls[0])

    def test_ensure_installed_without_resolver_removes(self):
        calls = []
        with tempfile.TemporaryDirectory() as d:
            G.ensure_installed(None, None,
                               runner=_runner("DNS_GUARD_STATE:keys=0"
                                              ";effective=false", calls=calls),
                               path=os.path.join(d, "s.json"))
        self.assertEqual(len(calls), 1)
        self.assertNotIn("New-ItemProperty", calls[0])


class TestForeignResolvers(unittest.TestCase):
    """The check the in-app leak test was blind to: which NON-tunnel adapters
    still publish resolvers Windows could ask in parallel."""

    def test_script_excludes_the_tunnel_adapters(self):
        s = G.foreign_resolvers_script()
        self.assertIn("'wintun','wintun2'", s)
        self.assertIn("Get-DnsClientServerAddress", s)

    def test_tunnel_aliases_come_from_the_caller(self):
        """The adapter list is the shared TUNNEL_ALIASES constant in
        production, so a renamed TUN cannot be reported as a foreign
        resolver."""
        from tuntop.config.defaults import TUNNEL_ALIASES
        s = G.foreign_resolvers_script(TUNNEL_ALIASES)
        for alias in TUNNEL_ALIASES:
            self.assertIn(f"'{alias}'", s)
        # A quote in an alias cannot break out of the literal.
        self.assertIn("'ev''il'", G.foreign_resolvers_script(("ev'il",)))

    def test_parses_alias_and_servers(self):
        self.assertEqual(
            G.parse_foreign("Wi-Fi=192.168.1.1\nEthernet=10.0.0.1,8.8.8.8"),
            ["Wi-Fi=192.168.1.1", "Ethernet=10.0.0.1,8.8.8.8"])

    def test_only_CONNECTED_adapters_count(self):
        """Get-DnsClientServerAddress also reports DISCONNECTED adapters (an
        unplugged Ethernet port keeps a stale static resolver forever), and
        Windows never fans a query out to an adapter that is not connected.
        Without a status filter a machine with one dead NIC published a
        'dns-leak' verdict on a tunnel that was not leaking."""
        s = G.foreign_resolvers_script()
        self.assertIn("Get-NetAdapter", s)
        self.assertIn("$_.Status -eq 'Up'", s)
        self.assertIn("$up -contains $_.InterfaceAlias", s)
        # The Up-filter must be built BEFORE the server list is consulted.
        self.assertLess(s.index("Get-NetAdapter"),
                        s.index("Get-DnsClientServerAddress"))

    def test_loopback_is_dropped_per_address_not_per_adapter(self):
        """An adapter publishing 127.0.0.1 AND a real resolver is still a
        fan-out source; the old per-adapter -notcontains check hid it."""
        s = G.foreign_resolvers_script()
        self.assertIn("$_ -ne '127.0.0.1'", s)
        self.assertNotIn("$_.ServerAddresses -notcontains '127.0.0.1'", s)

    def test_ignores_powershell_noise(self):
        self.assertEqual(G.parse_foreign("No result\n\n#<something"), [])
        self.assertEqual(G.parse_foreign(""), [])

    def test_duplicates_are_collapsed(self):
        self.assertEqual(G.parse_foreign("Wi-Fi=1.1.1.1\nWi-Fi=1.1.1.1"),
                         ["Wi-Fi=1.1.1.1"])

    def test_probe_failure_is_empty_not_an_error(self):
        """An unreadable probe must never invent a leak verdict."""
        def boom(script, timeout=8):
            raise OSError("no powershell")
        self.assertEqual(G.foreign_resolvers(runner=boom), [])

    def test_failed_probe_is_empty(self):
        self.assertEqual(G.foreign_resolvers(runner=_runner("", ok=False)), [])

    def test_guard_in_force_follows_the_effective_policy(self):
        self.assertTrue(G.guard_in_force(
            runner=_runner("DNS_GUARD_STATE:keys=2;effective=true")))
        self.assertFalse(G.guard_in_force(
            runner=_runner("DNS_GUARD_STATE:keys=2;effective=false")))

    def test_guard_in_force_is_false_when_the_probe_breaks(self):
        def boom(script, timeout=8):
            raise OSError("nope")
        self.assertFalse(G.guard_in_force(runner=boom))


class TestHelperIntegration(unittest.TestCase):
    """The helper side: what the tunnel bring-up / live-DNS path actually
    calls, and that a disabled guard removes instead of installing.

    The module's PowerShell entry points are stubbed, so no registry write
    can happen from a test run."""

    def setUp(self):
        from tuntop.tunnel import helper
        self.helper = helper
        self.saved = (helper._ACTIVE_DNS4, helper._ACTIVE_DNS6,
                      helper._ACTIVE_DNS_GUARD, helper._ACTIVE_DNS_GUARD_EXEMPT,
                      helper._dns_guard_state, helper._dns_guard)
        helper._dns_guard_state = None
        self.calls = []
        self.state = {"detect": (True, {"keys": 0, "effective": False,
                                        "servers": "", "ok": False}),
                      "install": (True, "pinned to 8.8.8.8"),
                      "remove": (True, "removed")}
        # The REAL module with its PowerShell runner replaced: the pure
        # logic (resolver pick, exemption merge, script text) still runs, so
        # these tests cover the actual code path - and no registry write can
        # happen from a test run.
        helper._dns_guard = _FakeGuard(self.state, self.calls)

    def tearDown(self):
        h = self.helper
        (h._ACTIVE_DNS4, h._ACTIVE_DNS6, h._ACTIVE_DNS_GUARD,
         h._ACTIVE_DNS_GUARD_EXEMPT, h._dns_guard_state, h._dns_guard) = \
            self.saved

    def test_exemptions_merge_mdns_and_user_entries(self):
        h = self.helper
        h._ACTIVE_DNS_GUARD_EXEMPT = ["Home.Example", ".local", "home.example"]
        self.assertEqual(h._dns_guard_exempt(),
                         [".local", "home.example"])

    def test_install_passes_both_families_and_the_exemptions(self):
        h = self.helper
        h._ACTIVE_DNS4, h._ACTIVE_DNS6 = "8.8.8.8", "2606:4700:4700::1111"
        h._ACTIVE_DNS_GUARD = True
        h._ACTIVE_DNS_GUARD_EXEMPT = ["home.example"]
        self.assertTrue(h._install_dns_guard())
        self.assertEqual(self.calls[-1],
                         ("install", "8.8.8.8", "2606:4700:4700::1111",
                          [".local", "home.example"]))

    def test_disabled_guard_removes(self):
        h = self.helper
        h._ACTIVE_DNS_GUARD = False
        self.assertFalse(h._install_dns_guard())
        self.assertEqual(self.calls, [("remove",)])

    def test_no_resolver_removes_and_says_so(self):
        """A pin with no servers would black-hole resolution."""
        h = self.helper
        h._ACTIVE_DNS4, h._ACTIVE_DNS6 = None, None
        h._ACTIVE_DNS_GUARD = True
        self.assertFalse(h._install_dns_guard())
        self.assertEqual(self.calls, [("remove",)])

    def test_reassert_only_reinstalls_when_missing(self):
        h = self.helper
        h._ACTIVE_DNS_GUARD = True
        h._ACTIVE_DNS4, h._ACTIVE_DNS6 = "8.8.8.8", None
        self.state["detect"] = (True, {"keys": 2, "effective": True,
                                       "servers": "8.8.8.8", "ok": True})
        h._dns_guard_reassert()
        # Only the read-only probe: an intact rule costs nothing more.
        self.assertEqual(self.calls, [("detect",)])
        # A rule wiped mid-session (another VPN client's policy, a Group
        # Policy refresh) must be re-pinned, not left to leak silently.
        self.state["detect"] = (True, {"keys": 0, "effective": False,
                                       "servers": "", "ok": False})
        self.calls.clear()
        h._dns_guard_reassert()
        # Probe, then re-pin - the fix runs without a tunnel restart.
        self.assertEqual([c[0] for c in self.calls], ["detect", "install"])

    def test_reassert_is_a_noop_when_disabled(self):
        h = self.helper
        h._ACTIVE_DNS_GUARD = False
        h._dns_guard_reassert()
        self.assertEqual(self.calls, [])

    def test_remove_reports_failure_without_raising(self):
        h = self.helper
        self.state["remove"] = (False, "locked")
        self.assertFalse(h._remove_dns_guard())

    def test_cleanup_removes_the_guard_early(self):
        """A surviving rule outliving the tunnel pins every process on the
        machine to a dead proxy, so cleanup() must drop it before the long
        route sweeps (where the OS may kill us)."""
        src = open(self.helper.__file__, encoding="utf-8").read()
        body = src.split("def cleanup(", 1)[1]
        self.assertIn("_remove_dns_guard()", body)


class _FakeGuard:
    """The real dns_guard module with ONLY the PowerShell entry points
    replaced - everything else (resolver pick, exemption merge, script text)
    still comes from the module under test."""

    def __init__(self, state, calls):
        self._state = state
        self._calls = calls

    def __getattr__(self, name):
        return getattr(G, name)

    def detect(self, **kw):
        self._calls.append(("detect",))
        return self._state["detect"]

    def ensure_installed(self, d4, d6, exempt=(), **kw):
        self._calls.append(("install", d4, d6, list(exempt)))
        return self._state["install"]

    def ensure_removed(self, **kw):
        self._calls.append(("remove",))
        return self._state["remove"]


class TestDashboardHealthRow(unittest.TestCase):
    """The dashboard row that finally answers the question a browser-based
    leak test asks: can Windows ask anybody OTHER than the tunnel? The row
    beside it only proves the CONFIGURED resolvers ride the TUN - which is
    exactly what stayed green while the ISP answered."""

    def _run(self, state, wintun="UP", foreign=()):
        from tuntop.ui import dashboard
        scripts = []

        def _ps(code, *a, **k):
            scripts.append(code)
            if "DNS_GUARD_STATE:" in code:
                return True, state
            if "Get-NetAdapter -Name 'wintun'" in code:
                return True, wintun
            if "Get-DnsClientServerAddress" in code:
                return True, "\n".join(foreign)
            return True, ""

        with mock.patch.object(dashboard, "_ps", _ps):
            return dashboard._dns_guard_check("8.8.8.8", None), scripts

    def test_effective_rule_passes(self):
        (ok, msg), _scripts = self._run(
            "DNS_GUARD_STATE:keys=2;effective=true;servers=8.8.8.8",
            wintun="UP")
        self.assertTrue(ok)
        self.assertIn("8.8.8.8", msg)
        self.assertIn("cannot query a physical adapter", msg)

    def test_stale_rule_with_no_tunnel_fails(self):
        """A hard kill can leave the rule behind. With no tunnel it pins
        EVERY program on the machine to a dead proxy - that is a failure,
        not a pass, and the message must say how to clear it."""
        (ok, msg), _scripts = self._run(
            "DNS_GUARD_STATE:keys=2;effective=true;servers=8.8.8.8",
            wintun="DOWN")
        self.assertFalse(ok)
        self.assertIn("STALE", msg)
        self.assertIn("TunTop-Match", msg)

    def test_rule_present_but_not_effective_fails(self):
        """A registry key alone proves nothing - Windows can drop a
        malformed rule from its policy, and then nothing is pinned."""
        (ok, msg), _scripts = self._run(
            "DNS_GUARD_STATE:keys=2;effective=false;servers=8.8.8.8")
        self.assertFalse(ok)
        self.assertIn("NOT in force", msg)

    def test_no_rule_while_the_tunnel_is_up_fails(self):
        (ok, msg), _scripts = self._run(
            "DNS_GUARD_STATE:keys=0;effective=false;servers=", wintun="UP")
        self.assertFalse(ok)
        self.assertIn("NO DNS-guard rule", msg)
        self.assertIn("--no-dns-guard", msg)

    def test_no_rule_while_the_tunnel_is_down_passes(self):
        """The rule only exists while a tunnel is up, so its absence then is
        the CORRECT state, not a leak."""
        (ok, msg), _scripts = self._run(
            "DNS_GUARD_STATE:keys=0;effective=false;servers=", wintun="DOWN")
        self.assertTrue(ok)
        self.assertIn("correct while the tunnel is down", msg)

    def test_unreadable_probe_is_a_failure_not_a_pass(self):
        from tuntop.ui import dashboard

        def _boom(code, *a, **k):
            return False, "Get-ChildItem : access denied"

        with mock.patch.object(dashboard, "_ps", _boom):
            ok, msg = dashboard._dns_guard_check("8.8.8.8", None)
        self.assertFalse(ok)
        self.assertIn("could not be read", msg)

    def test_failure_names_the_adapters_still_publishing_resolvers(self):
        (ok, msg), _scripts = self._run(
            "DNS_GUARD_STATE:keys=0;effective=false;servers=", wintun="UP",
            foreign=["Wi-Fi=192.168.1.1", "Ethernet=10.0.0.1"])
        self.assertFalse(ok)
        self.assertIn("Wi-Fi=192.168.1.1", msg)
        self.assertIn("Ethernet=10.0.0.1", msg)

    def test_pass_case_also_names_them(self):
        (ok, msg), _scripts = self._run(
            "DNS_GUARD_STATE:keys=2;effective=true;servers=8.8.8.8",
            wintun="UP", foreign=["Wi-Fi=192.168.1.1"])
        self.assertTrue(ok)
        self.assertIn("192.168.1.1", msg)

    def test_uses_the_dashboard_ps_edge_only(self):
        """Every probe must go through the dashboard's own _ps: an offline
        test that stubs _ps must never reach PowerShell or the registry."""
        _result, scripts = self._run(
            "DNS_GUARD_STATE:keys=2;effective=true;servers=8.8.8.8",
            wintun="UP", foreign=["Wi-Fi=192.168.1.1"])
        self.assertTrue(any("DNS_GUARD_STATE:" in s for s in scripts))
        self.assertTrue(any("Get-DnsClientServerAddress" in s
                            for s in scripts))

    def _run_enabled(self, enabled, state, wintun="UP", foreign=()):
        from tuntop.ui import dashboard
        scripts = []

        def _ps(code, *a, **k):
            scripts.append(code)
            if "DNS_GUARD_STATE:" in code:
                return True, state
            if "Get-NetAdapter -Name" in code:
                return True, wintun
            if "Get-DnsClientServerAddress" in code:
                return True, "\n".join(foreign)
            return True, ""

        with mock.patch.object(dashboard, "_ps", _ps):
            return dashboard._dns_guard_check("8.8.8.8", None,
                                              enabled=enabled), scripts

    def test_a_deliberate_opt_out_is_not_a_failure(self):
        """--no-dns-guard is a user CHOICE. Without the setting reaching this
        check, opting out produced the same red row and the same
        '--no-dns-guard is active, or the install failed' message as a genuine
        install failure - unfixable and indistinguishable from a fault."""
        (ok, msg), _scripts = self._run_enabled(
            False, "DNS_GUARD_STATE:keys=0;effective=false;servers=",
            wintun="UP")
        self.assertTrue(ok)
        self.assertIn("DISABLED by choice", msg)
        # Still honest about the consequence, and still names the adapters.
        self.assertIn("may query a physical adapter's resolver", msg)

    def test_the_opt_out_row_still_names_the_foreign_adapters(self):
        (ok, msg), _scripts = self._run_enabled(
            False, "DNS_GUARD_STATE:keys=0;effective=false;servers=",
            wintun="UP", foreign=["Wi-Fi=192.168.1.1"])
        self.assertTrue(ok)
        self.assertIn("192.168.1.1", msg)

    def test_the_guard_enabled_row_still_fails(self):
        """The opt-out path must not swallow a real failure."""
        (ok, msg), _scripts = self._run_enabled(
            True, "DNS_GUARD_STATE:keys=0;effective=false;servers=",
            wintun="UP")
        self.assertFalse(ok)
        self.assertIn("NO DNS-guard rule", msg)

    def test_the_row_takes_the_setting_from_the_namespace(self):
        """build_checks must thread ns.dns_guard in, or the opt-out branch is
        unreachable in the real app no matter what the user passed."""
        import argparse
        from tuntop.ui import dashboard
        ns = argparse.Namespace(
            port=10808, server=["1.2.3.4"], dns4="8.8.8.8", dns6=None,
            endpoint_port=443, bypass_ip=[], geoip=None,
            geoip_code="cn", geoip_target=None, proxy2_port=None,
            proxy2_server=[], vpn_bypass_ip=[], proxy2_bypass_ip=[],
            vless_over_vpn=False, no_vpn_bypass=False)
        ns.dns_guard = False
        row = [fn for name, fn in dashboard.build_checks(ns)
               if name.startswith("DNS leak protection")]
        self.assertEqual(len(row), 1)
        with mock.patch.object(dashboard, "_ps",
                               lambda code, *a, **k: (True, "")):
            ok, msg = row[0]()
        self.assertTrue(ok)
        self.assertIn("DISABLED by choice", msg)

    def test_wintun_up_uses_the_shared_tun_constant(self):
        """_wintun_up drives half the verdict (tunnel up vs a STALE rule), so
        it must read the same TUN name every other probe uses - a hardcoded
        literal silently disagreed with the rest of the module, and an
        adapter name with a space or quote has to be escaped, not pasted in."""
        from tuntop.ui import dashboard
        seen = []

        def _ps(code, *a, **k):
            seen.append(code)
            return True, "UP"

        with mock.patch.object(dashboard, "_ps", _ps):
            with mock.patch.object(dashboard, "TUN", "My Tunnel's Name"):
                self.assertTrue(dashboard._wintun_up())
        self.assertIn("Get-NetAdapter -Name 'My Tunnel''s Name'", seen[0])

        seen.clear()
        with mock.patch.object(dashboard, "_ps", _ps), \
             mock.patch.object(dashboard, "TUN", "wintun"):
            self.assertTrue(dashboard._wintun_up())
        self.assertIn("Get-NetAdapter -Name 'wintun'", seen[0])


class TestDashboardRowWiring(unittest.TestCase):
    def test_build_checks_has_the_guard_row(self):
        import argparse
        from tuntop.ui import dashboard
        ns = argparse.Namespace(
            port=10808, server=["1.2.3.4"], dns4="8.8.8.8", dns6=None,
            endpoint_port=443, bypass_ip=[], vless_over_vpn=False, geoip=None,
            geoip_code="cn", geoip_target=None, proxy2_port=None,
            proxy2_server=[])
        labels = [label for label, _fn in dashboard.build_checks(ns)]
        self.assertIn("DNS configuration (Wintun is selected source)", labels)
        self.assertIn("DNS leak protection (catch-all NRPT rule)", labels)

    def test_stop_sweep_removes_the_guard(self):
        """The shutdown checklist must take the rule down even when the
        helper was force-killed and never ran its own cleanup."""
        from tuntop.ui import dashboard
        src = open(dashboard.__file__, encoding="utf-8").read()
        self.assertIn("Removing the DNS leak-guard rule", src)
        self.assertIn("self._sweep_dns_guard", src)

    def test_sweep_is_best_effort(self):
        from tuntop.ui import dashboard
        app = dashboard.BTopTui.__new__(dashboard.BTopTui)
        with mock.patch.object(dashboard, "_dns_guard") as g:
            g.ensure_removed.side_effect = OSError("no powershell")
            self.assertFalse(app._sweep_dns_guard())
        with mock.patch.object(dashboard, "_dns_guard") as g:
            g.ensure_removed.return_value = (True, "removed")
            self.assertTrue(app._sweep_dns_guard())

    def test_diagnostics_carry_the_guard_state(self):
        """"My DNS still leaks" is a property of the OS resolver's policy, so
        the [D] export has to carry it - a report without these is
        unanswerable."""
        import argparse
        from tuntop.ui import dashboard
        app = dashboard.BTopTui.__new__(dashboard.BTopTui)
        app.ns = argparse.Namespace(dns_guard=False,
                                    dns_guard_exempt=["home.example"])

        def _ps(code, *a, **k):
            if "DNS_GUARD_STATE:" in code:
                return True, "DNS_GUARD_STATE:keys=1;effective=false;servers="
            if "Get-NetAdapter -Name 'wintun'" in code:
                return True, "UP"
            if "Get-DnsClientServerAddress" in code:
                return True, "Wi-Fi=192.168.1.1"
            return True, ""

        with mock.patch.object(dashboard, "_ps", _ps), \
                mock.patch.object(dashboard._dns_guard, "load_state",
                                  return_value=None):
            text = app._dns_guard_diagnostics()
        self.assertIn("dns_guard=False", text)
        self.assertIn("home.example", text)
        self.assertIn("wintun up: True", text)
        self.assertIn("effective=False", text)
        self.assertIn("Wi-Fi=192.168.1.1", text)

    def test_diagnostics_survive_a_broken_probe(self):
        import argparse
        from tuntop.ui import dashboard
        app = dashboard.BTopTui.__new__(dashboard.BTopTui)
        app.ns = argparse.Namespace(dns_guard=True, dns_guard_exempt=[])

        def _ps(code, *a, **k):
            if "DNS_GUARD_STATE:" in code:
                return False, "access denied"
            return True, ""

        with mock.patch.object(dashboard, "_ps", _ps), \
                mock.patch.object(dashboard._dns_guard, "load_state",
                                  side_effect=OSError("locked")):
            text = app._dns_guard_diagnostics()
        # A failed probe must SAY so, not read as a clean system.
        self.assertIn("unreadable", text)
        self.assertIn("NRPT probe failed", text)


class TestDnsConfigurationCheckUnknown(unittest.TestCase):
    """_dns_configuration_check used to fold "could not verify" into "not
    pinned" - presenting a broken probe as a leak."""

    def _run(self, results):
        from tuntop.ui import dashboard
        with mock.patch.object(dashboard, "_dns_enforcement_check",
                               side_effect=results):
            return dashboard._dns_configuration_check("8.8.8.8", None)

    def test_unknown_is_reported_as_unknown(self):
        ok, msg = self._run([(None, "8.8.8.8: no route to it right now")])
        self.assertFalse(ok)
        self.assertIn("could not be verified", msg)
        self.assertIn("8.8.8.8", msg)
        self.assertNotIn("NOT pinned", msg)

    def test_all_pinned_still_passes(self):
        ok, msg = self._run([(True, "8.8.8.8 rides the TUN (IPv4)")])
        self.assertTrue(ok)
        self.assertIn("selected DNS source", msg)

    def test_real_misrouting_still_fails(self):
        ok, msg = self._run([(False, "reachable OUTSIDE the tunnel")])
        self.assertFalse(ok)
        self.assertIn("NOT pinned", msg)


if __name__ == "__main__":
    unittest.main()

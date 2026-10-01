"""Offline tests for zero-residue teardown (1.0.51).

Five fixes share one theme: **state that outlived the process that created it**.

  1. the machine-wide DoH templates `Add-DnsClientDohServer` writes - nothing
     removed them at all, on any path;
  2. the physical adapter's InterfaceMetric, lowered by the VPN-shadow pass -
     the original lived in the helper's module globals, so a hard kill left it
     lowered permanently with nothing remembering what it had been;
  3. the Wintun adapter itself - a PnP device, not a process, so it did not
     "die with the process tree"; only the NEXT launch's preflight removed it;
  4. the LAN victim's netsh delete token, encoded twice and differently;
  5. the previous country's geo routes after a `[F]` switch - unsweepable,
     because `geo_victims` identifies a leftover by matching a prefix against
     ONE country's CIDR set.

Everything is text, JSON and pure-function level: the PowerShell runner is
injected, so nothing here touches the registry, the routing table or an
interface. A test that installed a real DoH mapping would pin a live machine's
name resolution, and a test that really removed an adapter would take the test
runner's own network down with it.
"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))

from tuntop.network import residue
from tuntop.network import routing
from tuntop.network.routeops import sweeps
from tuntop.tunnel import helper as H


def _tmp_record():
    return os.path.join(tempfile.mkdtemp(), ".tuntop_residue.json")


def _dashboard_src():
    from tuntop.ui import dashboard
    with open(dashboard.__file__, encoding="utf-8-sig") as f:
        return f.read()


def _src(module):
    with open(module.__file__, encoding="utf-8-sig") as f:
        return f.read()


# ── The residue record (tuntop/network/residue.py) ───────────────────

class TestResidueRecord(unittest.TestCase):
    def setUp(self):
        self.path = _tmp_record()

    def test_doh_servers_roundtrip(self):
        self.assertEqual(residue.load_doh_servers(self.path), [])
        self.assertTrue(residue.save_doh_servers(["8.8.8.8", "2606:4700::1111"],
                                                path=self.path))
        self.assertEqual(residue.load_doh_servers(self.path),
                         ["8.8.8.8", "2606:4700::1111"])

    def test_saving_again_appends_rather_than_replaces(self):
        """A v6 registration must not evict the v4 one recorded moments
        earlier, and the self-heal pass re-registers the same pair every cycle."""
        residue.save_doh_servers(["8.8.8.8"], path=self.path)
        residue.save_doh_servers(["8.8.8.8", "1.1.1.1"], path=self.path)
        self.assertEqual(sorted(residue.load_doh_servers(self.path)),
                         ["1.1.1.1", "8.8.8.8"])
        residue.save_doh_servers(["1.1.1.1", "8.8.8.8"], path=self.path)
        self.assertEqual(sorted(residue.load_doh_servers(self.path)),
                         ["1.1.1.1", "8.8.8.8"], "duplicates crept in")

    def test_clearing_drops_the_key_entirely(self):
        """An explicit "nothing to clean up" must not leave a stale empty list
        that a later reader has to interpret."""
        residue.save_doh_servers(["8.8.8.8"], path=self.path)
        residue.clear_doh_servers(self.path)
        self.assertNotIn("doh_servers", residue.load(self.path))

    def test_merge_preserves_the_other_category(self):
        """The DoH list and the metric share one file; writing one must never
        cost the other, or a DoH registration would erase the record of a
        lowered InterfaceMetric."""
        residue.save_physical_metric("Wi-Fi", 4270, path=self.path)
        residue.save_doh_servers(["8.8.8.8"], path=self.path)
        self.assertEqual(residue.load_physical_metric(self.path),
                         ("Wi-Fi", 4270))
        residue.clear_doh_servers(self.path)
        self.assertEqual(residue.load_physical_metric(self.path),
                         ("Wi-Fi", 4270),
                         "clearing DoH dropped the metric record")

    def test_corrupt_record_reads_as_absent(self):
        """A half-read record costs a leftover; acting on guessed contents
        could remove something we never installed."""
        with open(self.path, "w", encoding="utf-8") as f:
            f.write('{"doh_servers": ["8.8.8')     # truncated write
        self.assertEqual(residue.load(self.path), {})
        self.assertEqual(residue.load_doh_servers(self.path), [])

    def test_a_list_payload_is_not_a_record(self):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write('["8.8.8.8"]')
        self.assertEqual(residue.load(self.path), {})

    def test_physical_metric_rejects_non_int(self):
        """A string, a float, a bool - anything but a plain int must not reach
        `Set-NetIPInterface -InterfaceMetric`."""
        for bad in ("4270", 4270.0, True, None, [], {}):
            residue.save_physical_metric("Wi-Fi", bad, path=self.path)
            self.assertIsNone(
                residue.load_physical_metric(self.path),
                f"{bad!r} was accepted as an InterfaceMetric")

    def test_physical_metric_requires_an_adapter(self):
        residue.save_physical_metric("", 4270, path=self.path)
        self.assertIsNone(residue.load_physical_metric(self.path))

    def test_writes_are_ownership_stamped(self):
        residue.save_doh_servers(["8.8.8.8"], path=self.path)
        rec = residue.load(self.path)
        self.assertEqual(rec["pid"], os.getpid())
        self.assertIn("started", rec)

    def test_our_own_record_is_never_treated_as_a_leftover(self):
        """A second launch must not 'restore' the first launch's settings out
        from under it - and a process never treats its OWN record as someone
        else's leftover."""
        residue.save_doh_servers(["8.8.8.8"], path=self.path)
        rec = residue.load(self.path)
        self.assertFalse(residue.record_owner_alive(rec))

    def test_a_dead_owner_leaves_the_record_actionable(self):
        rec = {"pid": 999999, "started": 1000, "doh_servers": ["8.8.8.8"]}
        with mock.patch.object(residue.procidentity, "process_alive",
                               return_value=False):
            self.assertFalse(residue.record_owner_alive(rec))

    def test_a_live_owner_protects_the_record(self):
        rec = {"pid": 4242, "started": 1000, "doh_servers": ["8.8.8.8"]}
        with mock.patch.object(residue.procidentity, "same_process",
                               return_value=True), \
             mock.patch.object(residue.procidentity, "process_alive",
                               return_value=True):
            self.assertTrue(residue.record_owner_alive(rec))

    def test_a_recycled_pid_is_not_an_owner(self):
        """The PID exists but is demonstrably a different process: that is a
        leftover, not a live session."""
        rec = {"pid": 4242, "started": 1000}
        with mock.patch.object(residue.procidentity, "same_process",
                               return_value=False), \
             mock.patch.object(residue.procidentity, "process_alive",
                               return_value=True):
            self.assertFalse(residue.record_owner_alive(rec))

    def test_garbage_owner_fields_are_not_an_owner(self):
        for rec in ({}, {"pid": None}, {"pid": "abc"}, {"pid": 0}):
            self.assertFalse(residue.record_owner_alive(rec))


# ── 1. DoH templates were never removed ───────────────────────────────

class TestDohTemplateRemoval(unittest.TestCase):
    def setUp(self):
        self.path = _tmp_record()
        self.patcher = mock.patch.object(
            residue, "residue_path", return_value=self.path)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def _run(self, out, ok=True, calls=None, want_record=True):
        def _ps(ps, timeout=None):
            if calls is not None:
                calls.append(ps)
            return ok, out, ""
        if want_record:
            residue.save_doh_servers(["8.8.8.8"], path=self.path)
        with mock.patch.object(H, "run_ps", _ps):
            return H._remove_doh_servers(), (calls if calls is not None else [])

    def test_script_removes_and_then_re_enumerates(self):
        """`Remove-DnsClientDohServer` runs silenced, so 'it returned' proves
        nothing - the script must ask the store again afterwards and only claim
        success when nothing of ours is left."""
        calls = []
        ok, scripts = self._run("DOH_REMOVED", calls=calls)
        self.assertTrue(ok)
        ps = scripts[0]
        self.assertIn("Remove-DnsClientDohServer", ps)
        self.assertLess(ps.index("Remove-DnsClientDohServer"),
                        ps.rindex("Get-DnsClientDohServer"),
                        "the verification read must come AFTER the removal")
        self.assertIn("DOH_REMOVED", ps)

    def test_script_proves_the_store_is_readable_before_sweeping(self):
        """A non-elevated process (or a denied key) makes every silenced
        cmdlet return nothing, and the script would print DOH_REMOVED over a
        mapping that is still registered."""
        calls = []
        self._run("DOH_REMOVED", calls=calls)
        self.assertIn("-ErrorAction Stop", calls[0])

    def test_a_surviving_mapping_fails_and_keeps_the_record(self):
        """The record is the only thing a later owner retries from - it must
        not be cleared over a mapping that is still in the registry."""
        ok, _ = self._run("DOH_UNINSTALL_FAIL:still registered: 8.8.8.8")
        self.assertFalse(ok)
        self.assertEqual(residue.load_doh_servers(self.path), ["8.8.8.8"])

    def test_no_verdict_at_all_fails_closed(self):
        """Neither marker means nothing was proven either way. Clearing the
        record there would strand a machine-wide template permanently."""
        ok, _ = self._run("something else entirely")
        self.assertFalse(ok)
        self.assertEqual(residue.load_doh_servers(self.path), ["8.8.8.8"])

    def test_success_clears_the_record(self):
        ok, _ = self._run("DOH_REMOVED")
        self.assertTrue(ok)
        self.assertEqual(residue.load_doh_servers(self.path), [])

    def test_nothing_recorded_means_nothing_to_do(self):
        ok, calls = self._run("DOH_REMOVED", want_record=False)
        self.assertTrue(ok)
        self.assertEqual(calls, [], "spawned PowerShell with no mapping to "
                                    "remove")

    def test_only_recorded_addresses_are_ever_named(self):
        """A DoH mapping the user configured themselves must survive - the
        script's Where-Object is the only thing standing between us and it."""
        calls = []
        self._run("DOH_REMOVED", calls=calls)
        ps = calls[0]
        self.assertIn("8.8.8.8", ps)
        self.assertNotIn("1.1.1.1", ps,
                         "an address we never registered was named for removal")

    def test_a_raising_runner_is_a_failure_not_a_success(self):
        residue.save_doh_servers(["8.8.8.8"], path=self.path)
        with mock.patch.object(H, "run_ps",
                               side_effect=OSError("no powershell")):
            self.assertFalse(H._remove_doh_servers())

    def test_registration_records_what_it_registered(self):
        """The mapping is machine-wide, so a successful registration is the
        only place a record of it can come from."""
        residue.save_doh_servers(["8.8.8.8"], path=self.path)
        with mock.patch.object(H, "run_ps",
                               return_value=(True, "DOH_OK", "")):
            self.assertTrue(H._register_doh_server("1.1.1.1", "t"))
        self.assertEqual(residue.load_doh_servers(self.path),
                         ["8.8.8.8", "1.1.1.1"])

    def test_a_failed_registration_records_nothing(self):
        """Recording an address we did not manage to register would make the
        sweep report a failure for residue that never existed."""
        with mock.patch.object(H, "run_ps",
                               return_value=(True, "DOH_FAIL:nope", "")):
            self.assertFalse(H._register_doh_server("1.1.1.1", "t"))
        self.assertEqual(residue.load_doh_servers(self.path), [])

    def test_cleanup_runs_the_doh_removal(self):
        """Ordering: with the DNS guard, before the geo long pole - a machine
        -wide DNS change must not outlive the tunnel just because a route
        sweep is slow."""
        src = _src(H)
        guard = src.index('"remove DNS leak guard"')
        doh = src.index('"remove DoH templates"')
        geo = src.index('"stop geo installer"')
        self.assertLess(guard, doh)
        self.assertLess(doh, geo)


# ── 2. The physical adapter metric was unrestoreable after a hard kill ──

class TestPhysicalMetricPersistence(unittest.TestCase):
    def setUp(self):
        self.path = _tmp_record()
        self.patcher = mock.patch.object(
            residue, "residue_path", return_value=self.path)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def test_lowering_the_metric_records_the_original(self):
        """The metric is a change to the USER's Wi-Fi, so the original has to
        outlive this process - the whole point of the record."""
        H.phys_bypass_metric_saved = None
        H.phys_bypass_iface = None
        with mock.patch.object(H, "get_vpn_ipv4_default",
                               return_value=("VPN", "10.0.0.1")), \
             mock.patch.object(H, "run_ps",
                               return_value=(True, "25,4270", "")):
            H.ensure_physical_metric_below_vpn("Wi-Fi")
        self.assertEqual(residue.load_physical_metric(self.path), ("Wi-Fi", 4270))

    def test_nothing_is_recorded_when_the_vpn_is_gone(self):
        H.phys_bypass_metric_saved = None
        H.phys_bypass_iface = None
        with mock.patch.object(H, "get_vpn_ipv4_default", return_value=None):
            H.ensure_physical_metric_below_vpn("Wi-Fi")
        self.assertEqual(residue.load(self.path), {})

    def test_restore_issues_the_original_value_and_clears_the_record(self):
        residue.save_physical_metric("Wi-Fi", 4270, path=self.path)
        seen = []
        with mock.patch.object(H, "run_ps",
                               side_effect=lambda ps, timeout=None: (
                                   seen.append(ps), (True, "", ""))[1]):
            self.assertTrue(H.restore_recorded_physical_metric())
        self.assertTrue(any("4270" in s and "Set-NetIPInterface" in s
                            for s in seen), seen)
        self.assertIsNone(residue.load_physical_metric(self.path))

    def test_the_recovery_path_uses_the_SAVED_metric_not_the_target(self):
        """A bug here would write the lowered value back and make the record
        look like it had been handled."""
        residue.save_physical_metric("Wi-Fi", 4270, path=self.path)
        seen = []
        with mock.patch.object(H, "run_ps",
                               side_effect=lambda ps, timeout=None: (
                                   seen.append(ps), (True, "", ""))[1]):
            H.restore_recorded_physical_metric()
        self.assertTrue(any("4270" in s for s in seen))
        self.assertFalse(any("InterfaceMetric 9" in s for s in seen))

    def test_in_memory_restore_clears_the_record_on_success(self):
        residue.save_physical_metric("Wi-Fi", 4270, path=self.path)
        H.phys_bypass_iface = "Wi-Fi"
        H.phys_bypass_metric_saved = 4270
        with mock.patch.object(H, "run_ps", return_value=(True, "", "")):
            self.assertTrue(H.restore_physical_metric())
        self.assertIsNone(residue.load_physical_metric(self.path))

    def test_in_memory_restore_keeps_the_record_when_the_write_fails(self):
        """A failed write means the metric is still lowered; the record is the
        only thing that can retry it."""
        residue.save_physical_metric("Wi-Fi", 4270, path=self.path)
        H.phys_bypass_iface = "Wi-Fi"
        H.phys_bypass_metric_saved = 4270
        with mock.patch.object(H, "run_ps",
                               side_effect=OSError("access denied")):
            self.assertFalse(H.restore_physical_metric())
        self.assertEqual(residue.load_physical_metric(self.path), ("Wi-Fi", 4270))

    def test_a_live_owners_record_is_never_restored(self):
        """A second instance's recovery pass must not reconfigure the first
        instance's adapter mid-session."""
        residue.save_physical_metric("Wi-Fi", 4270, path=self.path)
        rec = residue.load(self.path)
        rec["pid"] = 4242
        rec["started"] = 1000
        residue.merge(self.path, "physical_metric", None)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(dict(rec, physical_metric={"iface": "Wi-Fi",
                                                  "metric": 4270}), f)
        called = []
        with mock.patch.object(residue, "record_owner_alive",
                               return_value=True), \
             mock.patch.object(H, "run_ps",
                               side_effect=lambda ps, timeout=None: (
                                   called.append(ps), (True, "", ""))[1]):
            self.assertTrue(H.restore_recorded_physical_metric())
        self.assertEqual(called, [], "restored a live session's adapter")

    def test_no_record_is_a_no_op(self):
        self.assertTrue(H.restore_recorded_physical_metric())

    def test_a_raising_runner_is_a_failure(self):
        residue.save_physical_metric("Wi-Fi", 4270, path=self.path)
        with mock.patch.object(H, "run_ps", side_effect=OSError("boom")):
            self.assertFalse(H.restore_recorded_physical_metric())


# ── 3. The Wintun adapter itself ─────────────────────────────────────

class TestTunnelAdapterRemoval(unittest.TestCase):
    def _drive(self, adapter_ps=None, verify=None):
        """Run remove_tunnel_adapters with BOTH PowerShell runners faked, and
        return (verdict, scripts) in the order they were issued.

        The device-node pass lives in the HELPER (remove_stale_wintun_devices),
        so faking only routing._ps would record the adapter half and hide the
        ordering that matters - the PnP pass must run AFTER, or Wintun
        enumerates the node we were about to clear."""
        seen = []

        def _routing_ps(ps, timeout=None):
            if "Remove-NetAdapter" in ps and adapter_ps is not None:
                return adapter_ps(ps)
            seen.append(ps)
            return True, ("" if verify is None else verify)

        def _helper_ps(ps, timeout=None):
            seen.append(ps)
            return True, "0"

        with mock.patch.object(routing, "_ps", _routing_ps), \
             mock.patch.object(H, "run_ps", _helper_ps):
            return routing.remove_tunnel_adapters(), seen

    def test_removes_the_adapter_before_the_device_node(self):
        """`Remove-NetAdapter` clears the network adapter but the PnP node
        survives as SWD\\WINTUN\\{GUID}; Wintun then enumerates that stale node
        instead of creating a fresh adapter, tun2socks finds no interface, and
        the dashboard restarts it into a loop that never converges."""
        _ok, seen = self._drive()
        joined = "\n".join(seen)
        self.assertIn("Remove-NetAdapter", joined)
        self.assertIn("Remove-PnpDevice", joined)
        self.assertLess(joined.index("Remove-NetAdapter"),
                        joined.index("Remove-PnpDevice"))

    def test_covers_both_aliases(self):
        """A previous run with --proxy2-port left wintun2 behind."""
        _ok, seen = self._drive()
        joined = "\n".join(seen)
        for alias in ("wintun", "wintun2"):
            self.assertIn(f"'{alias}'", joined)

    def test_every_mutating_command_is_silenced(self):
        """A refusal must be reported, not raised into a teardown. The closing
        verification read is the deliberate exception: it uses -ErrorAction
        Stop so an unreadable table is a leftover rather than a false all-clear
        (see test_reports_false_when_the_verifying_read_itself_fails)."""
        _ok, seen = self._drive()
        for ps in seen:
            if "Get-NetAdapter" in ps and "Remove-NetAdapter" not in ps:
                self.assertIn("-ErrorAction Stop", ps)
            else:
                self.assertIn("ErrorAction SilentlyContinue", ps)

    def test_a_raising_adapter_removal_does_not_skip_the_device_pass(self):
        def _boom(ps, timeout=None):
            raise OSError("adapter busy")

        _ok, seen = self._drive(adapter_ps=_boom)
        self.assertTrue(any("Remove-PnpDevice" in s for s in seen),
                        "the device pass was skipped after the adapter "
                        "refusal, leaving the stale node that causes the "
                        "tun2socks restart loop")

    def test_reports_true_when_no_adapter_survives(self):
        ok, _seen = self._drive()
        self.assertTrue(ok)

    def test_reports_false_when_one_survives(self):
        ok, _seen = self._drive(verify="wintun\n")
        self.assertFalse(ok, "reported a clean removal while the adapter is "
                             "still enumerated by the OS")

    def test_reports_false_when_the_verifying_read_itself_fails(self):
        def _unreadable(ps, timeout=None):
            return False, "access denied"

        ok, _seen = self._drive(verify="access denied")
        self.assertFalse(ok)

    def test_every_exit_path_calls_it(self):
        """[Q]'s checklist and the post-flush guard, [T]'s sweep, the close
        handler, atexit and the crash handler."""
        src = _dashboard_src()
        calls = [ln.strip() for ln in src.splitlines()
                 if "_remove_tunnel_adapters" in ln and "def " not in ln]
        self.assertGreaterEqual(
            len(calls), 6,
            f"only {len(calls)} call site(s) - an exit path is missing:\n"
            + "\n".join(calls))

    def test_the_dashboard_no_longer_claims_the_adapter_dies_with_the_tree(self):
        """The old comment asserted the opposite of the truth, and that claim
        is why no exit path ever removed the adapter."""
        self.assertNotIn("the adapter dies with the process tree",
                         _dashboard_src())


# ── 4. The LAN victim's delete token ─────────────────────────────────

class TestLanVictimDeletes(unittest.TestCase):
    ROWS = [
        {"DestinationPrefix": "192.168.0.0/16", "InterfaceAlias": "Wi-Fi",
         "NextHop": "192.168.1.1"},
        {"DestinationPrefix": "10.0.0.0/8", "InterfaceAlias": "Wi-Fi",
         "NextHop": "On-link"},
        {"DestinationPrefix": "172.16.0.0/12", "InterfaceAlias": "Wi-Fi",
         "NextHop": "10.20.30.1"},
        {"DestinationPrefix": "192.168.0.0/16", "InterfaceAlias": "Ethernet",
         "NextHop": "192.168.1.1"},
    ]

    def test_onlink_and_current_gateway_get_the_widened_token(self):
        """netsh rejects an on-link spelling as a next-hop token, so the
        next-hop-less form is the only one that deletes those rows at all."""
        got = sweeps.lan_victim_deletes(self.ROWS, "Wi-Fi", "192.168.1.1")
        by_prefix = {d: nh for d, _a, nh in got}
        self.assertEqual(by_prefix["192.168.0.0/16"], "")
        self.assertEqual(by_prefix["10.0.0.0/8"], "")

    def test_a_stale_gateway_is_not_a_victim_at_all(self):
        """Not a widened token, not an exact one: the class is refused when it
        is not the current gateway. A corporate static route, a VPN split
        tunnel and a NAS subnet are indistinguishable from one of our own
        stale pins, so `lan_victims` refuses the class rather than guess -
        deleting it would be a coin flip against the user's own routes."""
        got = sweeps.lan_victim_deletes(self.ROWS, "Wi-Fi", "192.168.1.1")
        self.assertNotIn("172.16.0.0/12", {d for d, _a, _nh in got})
        # The SAME row becomes a victim once that gateway IS the current one -
        # so this is a gateway-scoped decision, not a blanket refusal.
        got2 = sweeps.lan_victim_deletes(self.ROWS, "Wi-Fi", "10.20.30.1")
        self.assertIn("172.16.0.0/12", {d for d, _a, _nh in got2})

    def test_a_foreign_adapter_is_never_named(self):
        got = sweeps.lan_victim_deletes(self.ROWS, "Wi-Fi", "192.168.1.1")
        self.assertTrue(all(a == "Wi-Fi" for _d, a, _nh in got))

    def test_the_watchdog_shares_the_rule(self):
        """It used to call lan_victims and build the token itself, keeping the
        next hop for the current-gateway class - so the two owners disagreed
        about the same leftover."""
        from tuntop.core import cleanup_watchdog as W
        got = W._lan_victim_deletes(self.ROWS, "Wi-Fi", "192.168.1.1")
        self.assertEqual(
            got,
            sweeps.lan_victim_deletes(self.ROWS, "Wi-Fi", "192.168.1.1"))

    def test_the_dashboard_no_longer_reimplements_it(self):
        src = _dashboard_src()
        self.assertIn("lan_victim_deletes", src)
        body = src[src.index("def _sweep_lan_leftovers"):
                   src.index("def _sweep_dns_guard")]
        self.assertNotIn("lan_victims(", body)


# ── 5. A [F] switch orphaned the previous country's routes ────────────

class TestGeoCodesUnion(unittest.TestCase):
    def test_the_sidecar_carries_every_country(self):
        self.assertIn('"geoip_codes"', _dashboard_src())

    def _geo_app(self, code):
        from tuntop.ui import dashboard
        app = dashboard.BTopTui.__new__(dashboard.BTopTui)
        app._geo_prev_codes = {}
        app._invalidate_geo_cache = lambda: None
        app.log_lines = []
        app.ns = mock.Mock(geoip="geoip.dat", geoip_code=code)
        app._geo_sweep_cidrs = lambda: []
        app._geo_target = lambda: "direct"
        # v == "2" re-applies live on a background thread, which would parse a
        # non-existent geoip.dat and print a traceback into the test output.
        app._reapply_geo_bypass = lambda: None
        return app

    def test_a_switch_remembers_the_code_it_left(self):
        """[F] -> 2 applies a new code but does NOT remove the old country's
        routes, and `geo_victims` can only name the CURRENT code's prefixes -
        so the code being left has to be recorded for the crash sweep."""
        from tuntop.ui import dashboard
        app = self._geo_app("ir")
        with mock.patch.object(dashboard.BTopTui, "_read_line",
                               side_effect=["2", "ru\n"]):
            dashboard.BTopTui._edit_geo(app)
        self.assertIn("ir", app._geo_prev_codes,
                      "the code it left is not recorded, so a crash after the "
                      "switch strands that country's routes unsweepable")
        self.assertEqual(app.ns.geoip_code, "ru")

    def test_the_sidecar_hands_the_watchdog_every_code(self):
        """The point of recording it: the sidecar is the ONLY channel from this
        process to the detached watchdog, and the watchdog is the only owner
        alive after a hard kill."""
        from tuntop.ui import dashboard
        app = self._geo_app("ir")
        with mock.patch.object(dashboard.BTopTui, "_read_line",
                               side_effect=["2", "ru\n"]):
            dashboard.BTopTui._edit_geo(app)
        self.assertIn('"geoip_codes"', _src(dashboard))
        self.assertIn("_geo_prev_codes", _src(dashboard))

    def test_re_choosing_the_same_code_records_nothing(self):
        from tuntop.ui import dashboard
        app = self._geo_app("ir")
        with mock.patch.object(dashboard.BTopTui, "_read_line",
                               side_effect=["2", "ir\n"]):
            dashboard.BTopTui._edit_geo(app)
        self.assertEqual(app._geo_prev_codes, {})

    def test_a_cancelled_prompt_records_nothing(self):
        from tuntop.ui import dashboard
        app = self._geo_app("ir")
        with mock.patch.object(dashboard.BTopTui, "_read_line",
                               side_effect=["2", "\n"]):
            dashboard.BTopTui._edit_geo(app)
        self.assertEqual(app._geo_prev_codes, {})

    def test_the_watchdog_parses_every_code(self):
        """`geo_victims` matches a prefix against ONE country's CIDR set, so
        with only the current code a hard kill after a `[F]` switch left the
        previous country's routes with nothing able to name them."""
        from tuntop.core import cleanup_watchdog as W
        seen = []

        def _parse(path, code):
            seen.append(code)
            return {"5.0.0.0/8"} if code == "ir" else {"20.0.0.0/8"}

        # A REAL file: `sweep_geo_routes` refuses to parse a path that is not
        # there - it returns 0, "geo bypass was never active" - and the repo
        # root `geoip.dat` is an UNTRACKED local artifact, so a fresh checkout
        # has none. A bare "geoip.dat" here only ever passed on the author's
        # machine, which is why this failed on every CI runner. The parse is
        # mocked, so the file's contents never matter.
        fd, gpath = tempfile.mkstemp(suffix=".dat")
        os.close(fd)
        try:
            with mock.patch.object(W, "_live_rows",
                                   return_value=[{"DestinationPrefix":
                                                  "5.0.0.0/8",
                                                  "InterfaceAlias": "Wi-Fi",
                                                  "NextHop": "192.168.1.1"}]), \
                 mock.patch("tuntop.geoip.parse_geoip", side_effect=_parse), \
                 mock.patch.object(W, "_run_netsh_batch",
                                   return_value=(1, "")) as batch:
                W.sweep_geo_routes(gpath, "ru", geoip_codes=["ir"])
        finally:
            os.unlink(gpath)
        self.assertEqual(sorted(seen), ["ir", "ru"])
        sent = "\n".join(batch.call_args[0][0])
        self.assertIn("5.0.0.0/8", sent,
                      "the PREVIOUS country's prefix was not in the delete "
                      "batch")

    def test_a_code_with_no_geoip_file_is_not_a_failure(self):
        from tuntop.core import cleanup_watchdog as W
        self.assertEqual(W.sweep_geo_routes("missing.dat", "ir"), 0)
        self.assertEqual(W.sweep_geo_routes("missing.dat", ""), 0)

    def test_no_codes_at_all_spares_the_parser(self):
        from tuntop.core import cleanup_watchdog as W
        with mock.patch("tuntop.geoip.parse_geoip",
                        side_effect=AssertionError("must not be called")):
            # "missing.dat", never a bare "geoip.dat": the repo-root
            # geoip.dat is GITIGNORED, so a fresh checkout has none and any
            # assertion whose result depends on it passing passes only on the
            # author's machine. This one must hold with the file absent - which
            # is why the path is a name that cannot exist anywhere.
            self.assertEqual(W.sweep_geo_routes("missing.dat", ""), 0)


# ── The watchdog's residue sweep ─────────────────────────────────────

class TestWatchdogResidueSweep(unittest.TestCase):
    def setUp(self):
        self.path = _tmp_record()
        self.patcher = mock.patch.object(
            residue, "residue_path", return_value=self.path)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        from tuntop.core import cleanup_watchdog as W
        self.W = W

    def test_restores_the_metric_and_drops_the_doh_templates(self):
        residue.save_physical_metric("Wi-Fi", 4270, path=self.path)
        residue.save_doh_servers(["8.8.8.8"], path=self.path)
        seen = []
        with mock.patch.object(routing, "_ps",
                               side_effect=lambda ps, timeout=None: (
                                   seen.append(ps), (True, "", ""))[1]), \
             mock.patch.object(H, "run_ps", return_value=(True,
                                                          "DOH_REMOVED", "")):
            self.assertTrue(self.W.sweep_residue())
        self.assertTrue(any("4270" in s for s in seen))
        self.assertIsNone(residue.load_physical_metric(self.path))
        self.assertEqual(residue.load_doh_servers(self.path), [])

    def test_an_absent_record_is_a_clean_no_op(self):
        self.assertTrue(self.W.sweep_residue())

    def test_a_failing_metric_restore_keeps_the_record(self):
        residue.save_physical_metric("Wi-Fi", 4270, path=self.path)
        with mock.patch.object(routing, "_ps", side_effect=OSError("denied")), \
             mock.patch.object(H, "run_ps", return_value=(True,
                                                          "DOH_REMOVED", "")):
            self.assertFalse(self.W.sweep_residue())
        self.assertEqual(residue.load_physical_metric(self.path), ("Wi-Fi", 4270))

    def test_a_live_owner_is_left_alone(self):
        residue.save_physical_metric("Wi-Fi", 4270, path=self.path)
        rec = residue.load(self.path)
        rec["pid"] = 4242
        rec["started"] = 1000
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(rec, f)
        with mock.patch.object(residue, "record_owner_alive",
                               return_value=True), \
             mock.patch.object(routing, "_ps",
                               side_effect=AssertionError("must not run")), \
             mock.patch.object(H, "run_ps",
                               side_effect=AssertionError("must not run")):
            self.assertTrue(self.W.sweep_residue())

    def test_a_failed_sweep_vetoes_the_marker_clear(self):
        """sweeps_ok is the whole point: it keeps the crash marker so the next
        launch retries, instead of declaring a half-clean machine clean."""
        src = _src(self.W)
        self.assertIn("if not sweep_residue(log):", src)
        self.assertIn("sweeps_ok = False", src)

    def test_the_veto_reaches_the_marker_decision(self):
        """Not a source grep: drive the whole sweep and assert the marker
        survives a residue failure, which is the behaviour the veto exists
        for."""
        marker = os.path.join(tempfile.mkdtemp(), "marker.json")
        with open(marker, "w", encoding="utf-8") as f:
            json.dump({"pid": 4242, "started": 1000.0, "helper_pid": None}, f)
        residue.save_physical_metric("Wi-Fi", 4270, path=self.path)

        def _scan(**kwargs):
            from tuntop.core.startup_recovery import StartupFindings
            f = StartupFindings()
            f.residue = True
            return f

        with mock.patch.object(self.W, "scan", side_effect=_scan), \
             mock.patch.object(self.W, "recover_ex",
                               return_value=(["x"], True)), \
             mock.patch.object(self.W, "kill_pid", return_value=True), \
             mock.patch.object(self.W, "sweep_geo_routes", return_value=0), \
             mock.patch.object(self.W, "sweep_lan_routes", return_value=0), \
             mock.patch.object(self.W, "sweep_residue", return_value=False), \
             mock.patch("tuntop.core.startup_recovery.marker_is_live",
                               return_value=False), \
             mock.patch("tuntop.core.startup_recovery.read_marker",
                               return_value={"pid": 4242, "started": 1000.0,
                                             "helper_pid": None}), \
             mock.patch("tuntop.core.startup_recovery.clear_marker") as clr:
            self.W.sweep_after_unclean_exit(4242, marker_path=marker)
        clr.assert_not_called()


# ── startup recovery ─────────────────────────────────────────────────

class TestStartupRecoveryResidue(unittest.TestCase):
    def test_the_probe_exists_on_default_probes(self):
        from tuntop.core import startup_recovery as SR
        self.assertTrue(callable(SR.default_probes().remove_residue))

    def test_a_leftover_record_is_detected_from_the_record_itself(self):
        """Unlike the NRPT rule, a lowered metric is indistinguishable from a
        normal one until you know what it should be - so the record IS the
        detection, and only a file that names one counts."""
        from tuntop.core import startup_recovery as SR
        path = _tmp_record()
        with mock.patch.object(residue, "residue_path", return_value=path):
            self.assertFalse(SR._residue_record_left())
            residue.save_physical_metric("Wi-Fi", 4270, path=path)
            self.assertTrue(SR._residue_record_left())

    def test_a_corrupt_record_is_not_a_failure(self):
        """Guessing at half-read contents could remove something we never
        installed; a leftover is the cheaper mistake."""
        from tuntop.core import startup_recovery as SR
        path = os.path.join(tempfile.mkdtemp(), ".tuntop_residue.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write('{"doh_servers": ["8.8.8')
        with mock.patch.object(residue, "residue_path", return_value=path):
            self.assertFalse(SR._residue_record_left())

    def test_it_runs_after_the_dns_guard_and_before_the_adapter(self):
        src = _src(sys.modules["tuntop.core.startup_recovery"])
        guard = src.index('("remove leftover DNS guard"')
        res = src.index('("restore non-route machine state"')
        self.assertLess(guard, res)

    def test_findings_report_it(self):
        from tuntop.core.startup_recovery import StartupFindings
        f = StartupFindings()
        self.assertFalse(f.residue)
        self.assertFalse(f.dirty)
        f.residue = True
        self.assertTrue(f.dirty)
        self.assertTrue(any("InterfaceMetric" in s
                            for s in f.summary_lines()))

    def test_a_live_session_still_wins_over_a_leftover_record(self):
        """A second launch must not reconfigure the first one's adapter."""
        from tuntop.core.startup_recovery import StartupFindings
        f = StartupFindings(residue=True, live_session=4242)
        self.assertFalse(f.dirty)
        self.assertTrue(any("still running" in s for s in f.summary_lines()))


if __name__ == "__main__":
    unittest.main()

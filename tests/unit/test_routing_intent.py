"""Offline tests for the routing-intent defects fixed in 1.0.51, part 2.

The first batch (tests/unit/test_residue_teardown.py) was about *teardown*.
This one is about **intent**: eleven places where TunTop did something other
than what the user asked for, most of them silently and most of them only
visible on an ordinary setup.

Grouped by the failure, because that is what a reader needs to check:

  on-link next hops     the geo installer and the dashboard's route re-add both
                        emitted a literal 0.0.0.0 token, which netsh rejects, so
                        every route in those batches silently failed
  ledger vs lists       [X] left the row in the live ledger, so the next gateway
                        change re-added a bypass the user had deleted
  shadow vs geo         override_vpn_routes read geoip_added before the geo
                        thread had parsed anything, so the VPN shadow captured
                        the country ranges
  install accounting    a wholly refused netsh batch was scored as a total
                        success and every planned prefix stayed in the ledger
  geo egress            "via proxy2" was live-only; [R] destroyed a working
                        bypass before discovering the egress was unusable
  honesty               the panels reported configured intent, not effective
                        state, in three separate places
  port collision        proxy2_port == port killed the PRIMARY tunnel

Everything is text, pure functions and injected runners: no registry, no
routing table, no interface. A test that really installed a route or really
removed an adapter would be a test that changes the machine it runs on.
"""
import ipaddress
import os
import sys
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))

from tuntop.config import defaults as C
from tuntop.network import egress_scripts as ES
from tuntop.network import routing
from tuntop.network.routeops import sweeps
from tuntop.tunnel import helper as H
from tuntop.ui import dashboard


def _src(mod):
    with open(mod.__file__, encoding="utf-8-sig") as f:
        return f.read()


# ── On-link next hops: the shared normaliser ─────────────────────────

class TestOnLinkNormalisation(unittest.TestCase):
    """netsh REJECTS a literal 0.0.0.0 next hop ("The filename, directory name,
    or volume label syntax is incorrect"). A PPP/PPTP VPN has no gateway and
    reports NextHop 0.0.0.0 - the form this project calls the normal case. The
    IPv6 half was normalised in 1.0.30; every IPv4 writer that grew later
    copied the wrong half, and the geo installer was the worst of them."""

    def test_norm_next_hop_canonicalises_every_spelling(self):
        for raw in ("0.0.0.0", "::", "0", "", " 0.0.0.0 ", "On-link",
                    "on-link", None):
            self.assertEqual(ES.norm_next_hop(raw), "",
                             f"{raw!r} was not recognised as on-link")
        self.assertEqual(ES.norm_next_hop("192.168.1.1"), "192.168.1.1")
        self.assertEqual(ES.norm_next_hop("fe80::1"), "fe80::1")

    def test_netsh_gw_token_omits_the_token_entirely(self):
        """Not a bare double-space: netsh rejects that too."""
        for raw in ("0.0.0.0", "::", "", None):
            self.assertEqual(ES.netsh_gw_token(raw), "")
        self.assertEqual(ES.netsh_gw_token("10.0.0.1"), " 10.0.0.1")

    def test_the_helper_uses_the_shared_implementation(self):
        """`_norm_v4_gw` was the ORIGINAL IPv4 fix. Three copies of this
        predicate is how the geo installer ended up the one place still
        emitting 0.0.0.0, so it is now an alias."""
        self.assertEqual(H._norm_v4_gw("0.0.0.0"), "")
        self.assertEqual(H._norm_v4_gw("::"), "")
        self.assertEqual(H._norm_v4_gw(" 1.2.3.4 "), "1.2.3.4")

    def test_the_geo_installer_never_emits_a_literal_onlink_hop(self):
        """THE bug: `gw_part = (" " + str(gw)) if gw else ""` - and "0.0.0.0"
        is truthy, so it went verbatim. On any on-link-default VPN every
        country CIDR failed and geo-via-VPN installed nothing at all."""
        src = _src(H)
        self.assertIn("gw_part = _es.netsh_gw_token(gw)", src)
        self.assertNotIn('gw_part = (" " + str(gw)) if gw else ""', src)

    def test_the_geo_installer_normalises_even_if_given_the_raw_value(self):
        """Defence in depth: the token is built by the shared helper, so a
        caller that hands it a raw 0.0.0.0 still cannot leak one."""
        self.assertEqual(ES.netsh_gw_token("0.0.0.0"), "")

    def test_the_vpn_default_lookups_normalise_at_the_source(self):
        """helper.get_vpn_ipv4_default returned the raw NextHop; the IPv6 twin
        had normalised '::' since 1.0.30."""
        src = _src(H)
        self.assertIn('return d["InterfaceAlias"], _norm_v4_gw(d["NextHop"]), '
                      'int(d["InterfaceIndex"])', src)
        rsrc = _src(routing)
        self.assertEqual(rsrc.count("egress_scripts.norm_next_hop(d[\"NextHop\"])"),
                         2, "both the default and the VPN IPv4 twin must "
                            "normalise at the source")

    def test_the_dashboard_adds_normalise_too(self):
        """`_batch_delete_routes` normalised; `_batch_add_routes` - the twin
        three functions away - did not. So a row read from the table with
        NextHop 0.0.0.0 could be DELETED by the snapshot restore but never
        re-ADDED by it, and the restore reported the VPN's routes back while
        silently dropping the on-link ones."""
        app = dashboard.BTopTui.__new__(dashboard.BTopTui)
        app._SWEEP_CHUNK = 250
        seen = []
        with mock.patch.object(dashboard, "_netsh_batch_result",
                               return_value=(0, True)) as batch, \
             mock.patch("tuntop.ui.dashboard.time.sleep"):
            app._batch_add_routes([("10.0.0.0/8", "Corp-VPN", "0.0.0.0", 1, 1),
                                   ("10.0.0.0/8", "Corp-VPN", "10.20.30.1",
                                    1, 1)])
        seen = list(batch.call_args[0][0]) if batch.call_args else []
        for script in seen:
            for line in script.splitlines():
                self.assertNotIn(" 0.0.0.0", line, line)
        self.assertTrue(any("10.20.30.1" in s for s in seen), seen)

    def test_an_on_link_add_omits_the_hop_and_a_routed_one_keeps_it(self):
        app = dashboard.BTopTui.__new__(dashboard.BTopTui)
        app._SWEEP_CHUNK = 250
        lines = []
        with mock.patch.object(dashboard, "_netsh_batch_result",
                               side_effect=lambda s, **k: (
                                   lines.extend(s) or (len(s), True))), \
             mock.patch("tuntop.ui.dashboard.time.sleep"):
            app._batch_add_routes([("10.0.0.0/8", "Corp-VPN", "0.0.0.0", 1, 1)])
        self.assertIn('route 10.0.0.0/8 "Corp-VPN" metric=1', lines[0])
        self.assertNotIn("0.0.0.0 metric", lines[0])


# ── #1 the live ledger outliving the [X] that deleted the entry ─────

class TestBypassLedgerMembership(unittest.TestCase):
    def _app(self, dests):
        app = dashboard.BTopTui.__new__(dashboard.BTopTui)
        app.ns = types.SimpleNamespace(vless_over_vpn=False, vpn_interface=None,
                                       bypass_ip=[], proxy2_bypass_ip=[],
                                       vpn_bypass_ip=[], bypass_list=[])
        app._vpn_res_state = {}
        app._vpn_res_cache = {}
        app._proxy2_res_state = {}
        app._proxy2_res_cache = {}
        app._bypass_res_cache = {}
        app._bypass_res_lock = __import__("threading").Lock()
        app._bypass_res_state = (
            {"a.test": {"status": "ok", "ips": list(dests)}} if dests else {})
        app.log_lines = []
        app.checks = None
        # The re-point runs on a background thread whose exceptions are logged
        # through _blog -> event_log; without it the worker dies before the
        # membership filter is reached and the assertion below would pass for
        # the wrong reason (nothing re-pointed at all).
        app.event_log = mock.MagicMock()
        return app

    def test_dest_comes_from_the_state_and_from_the_cache(self):
        app = self._app(["1.2.3.4"])
        app._bypass_res_cache = {"b.test": (["5.6.7.8"], ["2001:db8::1"])}
        app._proxy2_res_state = {"c.test": {"ips": ["9.9.9.9"]}}
        self.assertEqual(
            app._live_bypass_dests(),
            {"v4": {"1.2.3.4/32", "5.6.7.8/32", "9.9.9.9/32"},
             "v6": {"2001:db8::1/128"}})

    def test_a_malformed_cache_value_is_skipped_not_fatal(self):
        app = self._app([])
        app._bypass_res_cache = {"d.test": "not a pair", "e.test": (["1.1.1.1"],)}
        self.assertEqual(app._live_bypass_dests()["v4"], set())

    def test_removing_an_entry_prunes_its_ledger_rows(self):
        app = self._app(["1.2.3.4"])
        app.ns.bypass_ip = ["a.test"]
        app._write_watchdog_state = lambda *a, **k: {}
        app._remove_bypass_routes_async = lambda *a, **k: None
        app._live_bypass_added = [("v4", "1.2.3.4/32", "Wi-Fi", "192.168.1.1"),
                                  ("v4", "5.6.7.8/32", "Wi-Fi", "192.168.1.1")]
        with mock.patch.object(dashboard, "build_checks", return_value=[]):
            app._remove_bypass_ip("a.test", target="direct")
        self.assertEqual(app._live_bypass_added,
                         [("v4", "5.6.7.8/32", "Wi-Fi", "192.168.1.1")],
                         "the deleted entry's row stayed in the ledger, so the "
                         "next gateway change would re-add the bypass")

    def test_the_repoint_drops_rows_nothing_authorises(self):
        """THE resurrection bug: _reroute_own_bypass_live rebuilt rows purely
        from the ledger with no membership check, so the next [GATEWAY] event
        or [V]/[Y] toggle re-added a bypass the user had deleted - and then
        rewrote its tracking to the new gateway, so nothing repaired it."""
        app = self._app(["5.6.7.8"])
        app._live_bypass_added = [("v4", "1.2.3.4/32", "Wi-Fi", "192.168.1.1"),
                                  ("v4", "5.6.7.8/32", "Wi-Fi", "192.168.1.1")]
        app._SWEEP_CHUNK, app._SWEEP_WORKERS = 250, 6
        with mock.patch("tuntop.ui.dashboard._get_ipv4_default",
                        return_value=("Ethernet", "10.0.0.1")), \
             mock.patch("tuntop.ui.dashboard._get_ipv6_default",
                        return_value=None), \
             mock.patch("tuntop.ui.dashboard._netsh_batch_result",
                        return_value=(250, True)), \
             mock.patch("tuntop.ui.dashboard._del_route_scoped"), \
             mock.patch.object(dashboard, "RouteTransaction"):
            app._reroute_own_bypass_live()
            import time
            deadline = time.time() + 5
            while (app._live_bypass_added
                   and app._live_bypass_added[0][2] == "Wi-Fi"
                   and time.time() < deadline):
                time.sleep(0.01)
        dests = [r[1] for r in app._live_bypass_added]
        self.assertIn("5.6.7.8/32", dests,
                      "the authorised row was dropped, so the re-point did "
                      "not run at all")
        self.assertNotIn("1.2.3.4/32", dests,
                         "a bypass the user deleted was re-pointed, not "
                         "dropped")

    def test_a_dead_socket_pair_in_the_cache_still_authorises(self):
        """The resolver state is replaced on every cycle and popped on removal,
        but a cache entry is a pure DNS record with no lifecycle - a row must
        not be dropped merely because its state row was replaced."""
        app = self._app([])
        app._bypass_res_cache = {"a.test": (["1.2.3.4"], [])}
        self.assertEqual(app._live_bypass_dests()["v4"], {"1.2.3.4/32"})


# ── #10 the VPN shadow capturing the geo ranges ──────────────────────

class TestUnshadowGeoPrefixes(unittest.TestCase):
    def setUp(self):
        H.geoip_added.clear()
        H.vpn_override_routes.clear()
        H.vpn_saved_routes[:] = []
        self.addCleanup(lambda: (H.geoip_added.clear(),
                                 H.vpn_override_routes.clear(),
                                 H.vpn_saved_routes.clear()))

    def _seed(self):
        H.vpn_override_routes.extend(
            [("v4", "5.0.0.0/8", "wintun", "192.168.123.1"),
             ("v4", "8.8.8.0/24", "wintun", "192.168.123.1")])
        H.vpn_saved_routes.extend(
            [("v4", "5.0.0.0/8", "Corp-VPN", "10.20.30.1", 1),
             ("v4", "8.8.8.0/24", "Corp-VPN", "10.20.30.1", 1)])

    def test_a_geo_prefix_loses_its_shadow_and_the_vpn_route_comes_back(self):
        self._seed()
        removed, added = [], []
        with mock.patch.object(H, "remove_route",
                               side_effect=lambda r: removed.append(r)), \
             mock.patch.object(H, "_raw_add_route",
                               side_effect=lambda *a, **k: added.append(
                                   (a, k))):
            n = H.unshadow_geo_prefixes({"5.0.0.0/8"}, "ir")
        self.assertEqual(n, 1)
        self.assertEqual(removed, [("v4", "5.0.0.0/8", "wintun", "192.168.123.1")])
        self.assertEqual(added[0][0][:5], ("v4", "5.0.0.0/8", "Corp-VPN",
                                          "10.20.30.1", 1))
        self.assertEqual(added[0][1], {"store": "persistent"},
                         "the VPN's OWN route must return to its own store, "
                         "not to the active store the shadows use")
        self.assertEqual(H.vpn_saved_routes,
                         [("v4", "8.8.8.0/24", "Corp-VPN", "10.20.30.1", 1)])
        self.assertEqual(list(H.vpn_override_routes),
                         [("v4", "8.8.8.0/24", "wintun", "192.168.123.1")])

    def test_a_non_geo_prefix_keeps_its_shadow(self):
        self._seed()
        with mock.patch.object(H, "remove_route",
                               side_effect=AssertionError("must not run")), \
             mock.patch.object(H, "_raw_add_route"):
            self.assertEqual(H.unshadow_geo_prefixes({"20.0.0.0/8"}, "ir"), 0)
        self.assertEqual(len(H.vpn_saved_routes), 2)

    def test_no_geo_prefixes_is_a_no_op(self):
        self._seed()
        with mock.patch.object(H, "remove_route",
                               side_effect=AssertionError("must not run")):
            self.assertEqual(H.unshadow_geo_prefixes(set(), "ir"), 0)

    def test_a_protected_prefix_stays_shadowed(self):
        """geoip_added is the authoritative set, not the parsed CIDR list: a
        protected prefix (the server, the VPN endpoint, a user bypass) is never
        installed as a geo route and MUST stay inside the tunnel."""
        self._seed()
        with mock.patch.object(H, "remove_route"), \
             mock.patch.object(H, "_raw_add_route"):
            # 8.8.8.0/24 is the VPN's own split tunnel, not a geo range.
            H.unshadow_geo_prefixes({"5.0.0.0/8"}, "ir")
        self.assertIn(("v4", "8.8.8.0/24", "Corp-VPN", "10.20.30.1", 1),
                      H.vpn_saved_routes)

    def test_the_shadow_pass_still_reads_the_ledger(self):
        """The ledger is empty when the pass runs; that is the whole reason
        the reconciliation exists, and it must not be 'fixed' by making the
        shadow synchronous."""
        self.assertIn("geo_dests = {r[1] for r in geoip_added}",
                      _src(H))

    def test_the_geo_thread_calls_the_reconciliation(self):
        src = _src(H)
        self.assertIn("unshadow_geo_prefixes({r[1] for r in geoip_added}, code)",
                      src)


# ── #9 the install ledger must not claim routes netsh refused ────────

class TestGeoInstallAccounting(unittest.TestCase):
    def setUp(self):
        # geoip_added is a RouteLedger, not a list - it has no __eq__, so
        # assertions go through len()/list() rather than comparing to [].
        H.geoip_added.clear()
        self.addCleanup(H.geoip_added.clear)
        # Teardown arms this from other tests (a stop() sets it so an in-flight
        # install stops adding routes). _install_sub returns None immediately
        # when it is set, so a leaked value would make every sub-batch look
        # "wholly refused" and the accounting tests would pass or fail depending
        # on suite order. It is an Event, not a boolean.
        H._geo_install_cancel.clear()
        self.addCleanup(H._geo_install_cancel.clear)

    def _install(self, netsh_rc, netsh_out, cidrs=("5.0.0.0/8",),
                 iface="Wi-Fi", gw="192.168.1.1"):
        def _run(argv, timeout=None):
            if argv and argv[0] == "netsh":
                return netsh_rc, netsh_out, ""
            return 0, "", ""
        with mock.patch.object(H, "run", _run), \
             mock.patch.object(H, "get_vpn_ipv4_default", return_value=None), \
             mock.patch.object(H, "ensure_physical_metric_below_vpn"), \
             mock.patch.object(H, "_geo_remove_conflicts"), \
             mock.patch.object(H, "ps_json", return_value=None), \
             mock.patch.object(H, "get_existing_v4_routes", return_value=[]):
            return list(H.add_geoip_bypass("ir", list(cidrs), iface, gw))

    def test_a_wholly_refused_batch_registers_nothing(self):
        """THE bug: registration was UPFRONT and that list was also the return
        value, so a total netsh failure returned the full planned list. The
        dashboard put it in _live_geo_added and announced "re-applied live
        (3000 routes)", and the ledger then held thousands of prefixes that
        were never in the table."""
        rc, out = 1, ("The filename, directory name, or volume label syntax "
                      "is incorrect")
        self.assertEqual(self._install(rc, out), [])
        self.assertEqual(len(H.geoip_added), 0,
                         "the ledger still claims routes netsh refused")

    def test_a_partially_refused_batch_keeps_its_rows(self):
        """For teardown, "might exist" is the safe direction: an untracked route
        that really is installed is the failure that matters. We cannot map
        netsh's per-line output back to prefixes on a localised build."""
        out = "Ok.\nThe parameter is incorrect.\n"
        installed = self._install(0, out)
        self.assertEqual(installed, [("v4", "5.0.0.0/8", "Wi-Fi", "192.168.1.1")])
        self.assertEqual(len(H.geoip_added), 1)

    def test_a_total_failure_with_exit_zero_is_not_a_success(self):
        """`if done == 0 and rc == 0: done = len(grp)` - and `netsh -f`
        reports every per-line failure in its OUTPUT while still exiting 0, so
        a wholly refused batch scored as a total success and the warning never
        printed. Only genuinely EMPTY output may be read as success."""
        out = "The parameter is incorrect.\nThe parameter is incorrect.\n"
        self.assertEqual(self._install(0, out), [])
        self.assertEqual(len(H.geoip_added), 0)

    def test_empty_output_still_counts_as_success(self):
        """A non-English netsh prints no 'Ok.' lines at all; that is the only
        honest 'no per-line report' case."""
        installed = self._install(0, "")
        self.assertEqual(installed, [("v4", "5.0.0.0/8", "Wi-Fi", "192.168.1.1")])

    def test_already_exists_counts_as_installed(self):
        out = "The object already exists.\n"
        self.assertEqual(len(self._install(0, out)), 1)


# ── #5 geo via proxy2 must survive a restart ────────────────────────

class TestGeoViaProxy2SurvivesRestart(unittest.TestCase):
    def test_the_helper_has_a_proxy2_branch(self):
        src = _src(H)
        self.assertIn('elif getattr(args, "geoip_via_proxy2", False) and '
                      'tun2_proc is not None:', src)
        self.assertIn("g_iface, g_gw = TUN2, TUN2_IP4", src)

    def test_the_helper_flag_exists(self):
        self.assertIn('ap.add_argument("--geoip-via-proxy2"',
                      _src(H))

    def test_the_launch_builder_passes_it(self):
        self.assertIn('self._geo_target() == "proxy2"', _src(dashboard))
        self.assertIn('cmd.append("--geoip-via-proxy2")', _src(dashboard))

    def test_configured_is_not_up(self):
        """If the second SOCKS5 was not listening the pipe was skipped, and
        installing onto wintun2 would fail every route while the bypass
        silently did nothing."""
        src = _src(H)
        self.assertIn("tun2_proc is not None:", src)
        self.assertIn("listening on 127.0.0.1:", src)


# ── #6 the geo sweep must not run before the egress is proven ───────

class TestGeoSweepOrdering(unittest.TestCase):
    def _app(self, target):
        app = dashboard.BTopTui.__new__(dashboard.BTopTui)
        app.ns = types.SimpleNamespace(geoip="geoip.dat", geoip_code="ir",
                                       proxy2_port=10809, vpn_interface=None,
                                       vless_over_vpn=False,
                                       geoip_via_vpn=False,
                                       geoip_via_win_vpn=False)
        app._geo_target = lambda: target
        app._proxy2_active = False
        app._live_geo_added = [("v4", "5.0.0.0/8", "Wi-Fi", "192.168.1.1")]
        app._geo_applied_target = "direct"
        app.logs = __import__("queue").Queue()
        app._blog = lambda m, **k: app.logs.put(m)
        app._remove_geo_routes_for = mock.Mock()
        app._geo_reset_progress = lambda: None
        app._update_geo_progress = lambda *a, **k: None
        app._protected_geo_prefixes = lambda: []
        app._get_vless_iface_gateway = lambda: None
        app._get_vless_iface_gateway_v6 = lambda: None
        app.endpoint_v4, app.endpoint_v6 = [], []
        app._bypass_res_state, app._bypass_res_cache = {}, {}
        app._proxy2_res_state, app._proxy2_res_cache = {}, {}
        app._vpn_res_state, app._vpn_res_cache = {}, {}
        app._live_bypass_added = []
        return app

    def _run(self, app, target, v4d):
        # parse_geoip reads a real multi-megabyte .dat; stub it to one CIDR so
        # the worker reaches the egress branches under test.
        with mock.patch.object(dashboard, "time",
                               mock.MagicMock(sleep=lambda *a: None)), \
             mock.patch("tuntop.tunnel.helper.parse_geoip",
                        return_value=["5.0.0.0/8"]), \
             mock.patch("tuntop.tunnel.helper.collect_protected_geo_prefixes",
                        return_value=[]), \
             mock.patch("tuntop.tunnel.helper.add_geoip_bypass",
                        return_value=[("v4", "5.0.0.0/8", "Wi-Fi",
                                       "192.168.1.1")]), \
             mock.patch("tuntop.ui.dashboard._get_ipv4_default",
                        return_value=v4d), \
             mock.patch("tuntop.ui.dashboard._get_ipv6_default",
                        return_value=None), \
             mock.patch("tuntop.ui.dashboard._get_vpn_ipv4_default",
                        return_value=None), \
             mock.patch("tuntop.ui.dashboard._get_vpn_ipv6_default",
                        return_value=None), \
             mock.patch("tuntop.ui.dashboard._netsh_batch_result",
                        return_value=(250, True)):
            app._reapply_geo_bypass_worker_inner("geoip.dat", "ir", target)

    def test_a_dead_proxy2_with_no_physical_egress_never_touches_the_table(self):
        """THE bug: the proxy2 branch checked ns.proxy2_port (CONFIGURED) and
        ignored _proxy2_active, and the sweep had already run - so with
        proxy2's SOCKS5 closed the working bypass was deleted, the install
        targeted an adapter that was not there, and every add failed. The user
        ended up with neither egress."""
        app = self._app("proxy2")
        self._run(app, "proxy2", None)      # no physical IPv4 egress either
        app._remove_geo_routes_for.assert_not_called()
        self.assertEqual(app._live_geo_added,
                         [("v4", "5.0.0.0/8", "Wi-Fi", "192.168.1.1")],
                         "the working bypass was destroyed for an install that "
                         "could not happen")

    def test_a_dead_proxy2_degrades_to_direct_and_keeps_the_bypass(self):
        """With a usable physical egress the fallback is not a loss: the
        country still leaves directly, and the panel says so."""
        app = self._app("proxy2")
        self._run(app, "proxy2", ("Wi-Fi", "192.168.1.1"))
        self.assertEqual(app._live_geo_added,
                         [("v4", "5.0.0.0/8", "Wi-Fi", "192.168.1.1")],
                         "the country fell into the TUN instead of falling back "
                         "to the direct egress")

    def test_no_physical_gateway_never_touches_the_table_either(self):
        app = self._app("direct")
        self._run(app, "direct", None)
        app._remove_geo_routes_for.assert_not_called()

    def test_a_usable_egress_sweeps_then_installs(self):
        app = self._app("direct")
        self._run(app, "direct", ("Wi-Fi", "192.168.1.1"))
        self.assertTrue(app._remove_geo_routes_for.called,
                        "the old egress must be swept once the new one is "
                        "proven usable")

    def test_the_working_path_uses_the_physical_egress(self):
        app = self._app("direct")
        self._run(app, "direct", ("Wi-Fi", "192.168.1.1"))
        self.assertEqual(app._live_geo_added,
                         [("v4", "5.0.0.0/8", "Wi-Fi", "192.168.1.1")])

    def test_the_sweep_runs_after_the_egress_branch_not_before_it(self):
        """Structural: the removal must not appear before the branch chain,
        or a future edit re-introduces remove-before-install."""
        src = _src(dashboard)
        body = src[src.index("def _reapply_geo_bypass_worker_inner"):]
        body = body[:body.index("def _reapply_geo_bypass_worker_inner"
                                .replace("inner", ""))] \
            if "def _reapply_geo_bypass_worker_inner\n" in body else body
        sweep = body.index("self._remove_geo_routes_for(cidrs)")
        proxy2 = body.index('elif target == "proxy2"')
        self.assertLess(proxy2, sweep,
                        "the sweep still runs before the egress is resolved")


# ── #4 the DNS panel claimed a resolver that had just been cleared ──

class TestDnsPanelHonesty(unittest.TestCase):
    def test_a_v6_only_choice_leaves_no_v4_resolver(self):
        self.assertEqual(C.resolve_dns_choice(None, "2001:4860:4860::8888"),
                         (None, "2001:4860:4860::8888"))
        self.assertEqual(C.resolve_dns_choice(None, "8.8.8.8"),
                         (None, "8.8.8.8"))

    def test_the_config_row_never_claims_a_default_v4_that_was_cleared(self):
        """The row rendered
            f"{GRAY}(default {_cfgdef.DNS4}){_R} / {CYAN}{_d6}{_R}"
        for a v6-only configuration - i.e. it advertised 8.8.8.8 at the exact
        moment [N] had cleared it, one panel above a health row that said the
        truth.

        Checked against the executable lines only: the fixed code quotes that
        old f-string in a comment (that is where the "what it used to do"
        explanation lives), so a raw substring scan would pass on the comment
        alone."""
        code = [ln for ln in _src(dashboard).splitlines()
                if not ln.lstrip().startswith("#")]
        live = "\n".join(code)
        self.assertNotIn("(default {_cfgdef.DNS4})", live)
        self.assertIn("no v4 resolver", live)

    def test_the_config_row_resolves_the_effective_pair(self):
        src = _src(dashboard)
        self.assertIn("elif _eff6:", src)
        self.assertIn("_cfgdef.resolve_dns_choice(", src)

    def test_the_prompt_reports_the_cleared_family_too(self):
        src = _src(dashboard)
        self.assertNotIn('_cur4 = getattr(self.ns, "dns4", None) or '
                         '(_cfgdef.DNS4 + " (default)")', src)
        self.assertIn("none (IPv4 resolver CLEARED)", src)

    def test_the_live_apply_names_the_shared_adapter(self):
        """Every other DNS path uses the shared TUN constant precisely so a
        renamed tunnel cannot diverge. This one was the exception."""
        src = _src(dashboard)
        self.assertIn("-InterfaceAlias '{ps_quote(TUN)}'", src)
        self.assertNotIn("Set-DnsClientServerAddress -InterfaceAlias 'wintun'",
                         src)

    def test_the_live_apply_verifies_before_claiming_success(self):
        """-ErrorAction SilentlyContinue with a discarded result logged
        "Wintun DNS4 set to ... (live)" when nothing had been applied - e.g.
        with the tunnel stopped."""
        src = _src(dashboard)
        self.assertIn("Set-DnsClientServerAddress", src)
        self.assertIn("-ErrorAction Stop", src)

    def test_the_apply_says_which_family_it_cleared(self):
        """[N] with a v6 address CLEARS IPv4 (resolve_dns_choice injects no
        default v4 for a v6-only choice, and the helper honours a
        present-but-null key as 'clear this family'). The user is entitled to
        know that before the next lookup fails.

        The closure is invoked INSIDE both patches on purpose. Calling it after
        the `_ps` patch expires runs the real PowerShell against the real
        wintun adapter - a live DNS change on the machine running the tests."""
        app = dashboard.BTopTui.__new__(dashboard.BTopTui)
        app.ns = types.SimpleNamespace(dns4=None, dns6="2001:4860::8888",
                                       dns_policy="availability")
        app._blog = mock.Mock()
        app.log_lines = []
        app.checks = None
        app._write_control_file = lambda *a, **k: {}
        holder = {}
        with mock.patch("tuntop.ui.dashboard._ps",
                        return_value=(True, "")) as ps, \
             mock.patch("tuntop.ui.dashboard.threading.Thread",
                        side_effect=lambda target=None, **k:
                        (holder.setdefault("t", target), mock.MagicMock())[1]):
            app._change_dns("2001:4860:4860::8888")
            self.assertIn("t", holder, "[N] never reached the apply closure")
            holder["t"]()
        self.assertTrue(ps.called)
        self.assertIn("IPv4 resolver is now UNSET",
                      app._blog.call_args_list[-1][0][0])
        self.assertIn("-ErrorAction Stop", ps.call_args[0][0])


# ── #8 proxy2_port == port killed the primary tunnel ─────────────────

class TestProxy2PortCollision(unittest.TestCase):
    def _app(self):
        app = dashboard.BTopTui.__new__(dashboard.BTopTui)
        app.ns = types.SimpleNamespace(port=10808, proxy2_port=10810)
        app.log_lines = []
        app.checks = None
        app._apply_launch_change = mock.Mock()
        # The accepted path spawns _port_restart on a thread, which calls the
        # real stop() and _managed_start(). Run it inline instead, with both
        # stubbed: these tests are about the collision refusal, and a real
        # stop() in a unit test tears down the test machine's tunnel state.
        app.stop = mock.Mock()
        app._managed_start = mock.Mock()
        app._blog = lambda m, **k: app.log_lines.append(m)
        import collections
        app.speed_hist = collections.deque(maxlen=120)
        app.rx_hist = collections.deque(maxlen=120)
        app.tx_hist = collections.deque(maxlen=120)
        app.ping_samples = collections.deque(maxlen=8)
        app.baseline_bytes = [None]
        app._last_raw_rx = None
        app._last_raw_tx = None
        return app

    def _change(self, app, value):
        holder = {}
        with mock.patch("tuntop.ui.dashboard.threading.Thread",
                        side_effect=lambda target=None, **k:
                        (holder.setdefault("t", target), mock.MagicMock())[1]):
            app._change_port(value)
        if holder.get("t"):
            holder["t"]()
        return holder.get("t") is not None

    def test_the_primary_port_refuses_the_proxy2_port(self):
        """THE bug: neither entry point checked, so the dashboard logged
        "restarting the tunnel in the background" and the helper sys.exit()ed
        on the next launch - the user got a FAILED tunnel and an explanation
        buried in helper stdout."""
        app = self._app()
        ran = self._change(app, "10810")
        self.assertFalse(ran, "a restart the user did not ask for, for a "
                              "value that will be refused anyway")
        self.assertFalse(app._managed_start.called)
        self.assertEqual(app.ns.port, 10808, "the primary port was changed")
        self.assertTrue(any("PROXY2 port" in s for s in app.log_lines),
                        app.log_lines)

    def test_a_different_primary_port_is_accepted(self):
        app = self._app()
        self.assertTrue(self._change(app, "10811"))
        self.assertTrue(app._managed_start.called)
        self.assertEqual(app.ns.port, 10811)

    def test_re_choosing_the_current_port_is_a_no_op(self):
        app = self._app()
        self.assertFalse(self._change(app, "10808"))
        self.assertTrue(any("Already using" in s for s in app.log_lines))

    def test_proxy2_refuses_the_primary_port(self):
        app = self._app()
        app._read_line = lambda *a, **k: ""
        app._proxy2_set_port("10808")
        self.assertEqual(app.ns.proxy2_port, 10810, "the stored proxy2 port "
                                                    "was overwritten")
        self.assertFalse(app._apply_launch_change.called)

    def test_proxy2_still_accepts_a_different_port(self):
        app = self._app()
        app._read_line = lambda *a, **k: ""
        app._proxy2_set_port("10812")
        self.assertEqual(app.ns.proxy2_port, 10812)
        self.assertTrue(app._apply_launch_change.called)

    def test_the_helper_degrades_instead_of_exiting(self):
        """Every OTHER proxy2 misconfiguration here is non-fatal by design, so
        a second-hop mistake cannot cost the user their primary tunnel. This
        one used to sys.exit() - AFTER the dashboard had already restarted."""
        src = _src(H)
        self.assertNotIn('sys.exit(f"[!] --proxy2-port {args.proxy2_port} '
                         'equals the primary ', src)
        self.assertIn("Skipping the second hop - the ", src)

    def test_the_helper_clears_the_port_so_nothing_targets_wintun2(self):
        src = _src(H)
        self.assertIn("args.proxy2_port = None", src)


# ── #7 the status bar reported configured intent, not egress ─────────

class TestGeoRowHonesty(unittest.TestCase):
    def _app(self, target, port, active):
        app = dashboard.BTopTui.__new__(dashboard.BTopTui)
        app.ns = types.SimpleNamespace(geoip="geoip.dat", geoip_code="ir",
                                       proxy2_port=port)
        app._geo_target = lambda: target
        app._proxy2_active = active
        return app

    def test_the_row_is_green_only_when_proxy2_is_both_set_and_up(self):
        src = _src(dashboard)
        self.assertIn('if _gt == "proxy2" and not getattr('
                      'self.ns, "proxy2_port", None):', src)
        self.assertIn('elif _gt == "proxy2" and not getattr(self, '
                      '"_proxy2_active", False):', src)
        self.assertIn('"proxy2 selected but NOT configured "', src)
        self.assertIn('"proxy2 configured but NOT running "', src)

    def test_a_profile_with_no_proxy2_port_cannot_claim_a_green_dot(self):
        """profiles.py saves geoip_target and proxy2_port independently, so a
        profile can carry target 'proxy2' with the port absent. The [F] menu
        blocks choosing it and the worker degrades - but the row rendered a
        green dot either way."""
        app = self._app("proxy2", None, False)
        self.assertFalse(app.ns.proxy2_port)


# ── #7 the geo sweep deleted TunTop's own CGNAT LAN bypass ──────────

class TestSpecialPurposeIsVersionIndependent(unittest.TestCase):
    """`is_private` learned 100.64.0.0/10 in CPython 3.13. A routing decision
    whose answer depends on the interpreter version is not a decision."""

    def test_cgnat_is_special_purpose_on_every_supported_python(self):
        for raw in ("100.64.0.0/10", "100.127.255.255/10"):
            net = ipaddress.ip_network(raw, strict=False)
            self.assertTrue(ES.is_special_purpose(net),
                            f"{raw}: is_private says {net.is_private} on this "
                            f"interpreter - the answer must not vary")

    def test_the_install_and_sweep_boundaries_are_the_same_predicate(self):
        self.assertFalse(H._is_routable_bypass_cidr("100.64.0.0/10"))
        self.assertFalse(sweeps.is_sweepable_geo_cidr("100.64.0.0/10"))

    def test_the_whole_registry_is_refused_by_both_boundaries(self):
        for raw in ES.SPECIAL_PURPOSE_V4:
            self.assertFalse(H._is_routable_bypass_cidr(raw), raw)
            self.assertFalse(sweeps.is_sweepable_geo_cidr(raw), raw)
        for raw in ES.SPECIAL_PURPOSE_V6:
            self.assertFalse(H._is_routable_bypass_cidr(raw), raw)
            self.assertFalse(sweeps.is_sweepable_geo_cidr(raw), raw)

    def test_public_ranges_are_still_accepted_by_both(self):
        for raw in ("5.0.0.0/8", "1.1.1.0/24", "2606:4700::/32",
                    "2001:4860::/32"):
            self.assertTrue(H._is_routable_bypass_cidr(raw), raw)
            self.assertTrue(sweeps.is_sweepable_geo_cidr(raw), raw)

    def test_an_unparseable_cidr_is_refused_by_both(self):
        self.assertFalse(H._is_routable_bypass_cidr("not-a-cidr"))
        self.assertFalse(sweeps.is_sweepable_geo_cidr("not-a-cidr"))

    def test_the_prefix_floor_is_still_the_caller_s_concern(self):
        """The two boundaries agree on ROUTABILITY; the floor differs, so it
        stays applied by each caller rather than being folded in."""
        self.assertTrue(ES.is_globally_routable("0.0.0.0/4"))
        self.assertFalse(sweeps.is_sweepable_geo_cidr("0.0.0.0/4"))
        self.assertFalse(H._is_routable_bypass_cidr("0.0.0.0/4"))


# ── #3 [A] on a working entry claimed a re-apply that never ran ──────

class TestBypassReapplyIsReal(unittest.TestCase):
    def _app(self, status):
        app = dashboard.BTopTui.__new__(dashboard.BTopTui)
        app.ns = types.SimpleNamespace(bypass_ip=[], proxy2_bypass_ip=[],
                                       vpn_bypass_ip=[], bypass_list=[])
        app.log_lines = []
        app.checks = None
        app._bypass_res_lock = __import__("threading").Lock()
        app._bypass_res_state = {}
        app._bypass_res_cache = {}
        app._proxy2_res_state = {}
        app._proxy2_res_cache = {}
        app._vpn_res_state = {}
        app._vpn_res_cache = {}
        app._bypass_new_state = dashboard.BTopTui._bypass_new_state.__get__(
            app) if hasattr(dashboard.BTopTui, "_bypass_new_state") else None
        if app._bypass_new_state is None:
            app._bypass_new_state = lambda: {"status": "new", "next": 0.0}
        if status is not None:
            app._bypass_res_state["a.test"] = {
                "status": "ok", "ips": ["1.2.3.4"],
                "next": __import__("time").time() + 300}
        app._write_watchdog_state = lambda *a, **k: {}
        app._ensure_bypass_resolver = lambda *a, **k: None
        return app

    def test_pressing_a_on_a_working_entry_makes_it_due_now(self):
        app = self._app("ok")
        with mock.patch.object(dashboard, "build_checks", return_value=[]):
            app._add_bypass_ip("a.test", target="direct")
        self.assertEqual(app._bypass_res_state["a.test"]["next"], 0.0,
                         "the entry stayed scheduled 300 s out, so the two "
                         "log lines below it announced work that never ran - "
                         "and [A] is how a user forces a repair after a "
                         "foreign TUN stripped the route")

    def test_a_fresh_entry_is_due_now_too(self):
        app = self._app(None)
        with mock.patch.object(dashboard, "build_checks", return_value=[]):
            app._add_bypass_ip("a.test", target="direct")
        self.assertEqual(app._bypass_res_state["a.test"]["next"], 0.0)


# ── the second hop's subnets ────────────────────────────────────────

class TestTun2SubnetComment(unittest.TestCase):
    def test_the_comment_no_longer_overstates_its_protection(self):
        self.assertNotIn("shadow the tunnel's own next-hop and break every "
                         "Wintun route add.\n_WINTUN4_NET",
                         _src(H))
        self.assertIn("these cover the PRIMARY adapter only", _src(H))

    def test_the_unreachability_is_still_true(self):
        """Both second-hop subnets are private, so net.is_private rejects them
        first - which is why the coverage gap is a comment problem only."""
        self.assertFalse(ipaddress.ip_network(C.TUN2_IP4 + "/32").is_private
                         is False)
        for tun2 in (C.TUN2_IP4, C.TUN2_IP6):
            net = ipaddress.ip_network(f"{tun2}/32"
                                       if ":" not in tun2
                                       else f"{tun2}/128")
            self.assertTrue(ES.is_special_purpose(net), tun2)


if __name__ == "__main__":
    unittest.main()

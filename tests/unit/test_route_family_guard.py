"""Offline tests for the route-family and egress invariants.

These are the bugs that turned a routine network event (a Wi-Fi roam, a DHCP
renewal, a full-tunnel VPN reconnect) into a blackholed tunnel:

* the physical-IPv4-default lookup could answer with an **IPv6** gateway on a
  dual-stack NIC, and the gateway monitor treated that as a real egress
  change - re-pointing every route we own onto it and caching the broken
  value, so nothing could be re-installed afterwards;
* a PPP/PPTP Windows VPN reports NextHop ``0.0.0.0``, which netsh rejects, so
  the VLESS transport pin and the VPN endpoint /32 both failed to install -
  leaving the proxy server with no bypass, its traffic falling into the TUN;
* the cached "physical" egress could hold a **VPN** adapter (the last-resort
  lookup clause is allowed to return one), so a VPN endpoint's bypass route
  got installed ON the VPN - a self-referential route.

No Windows calls: the routing-table and shell layers are mocked, so this runs
anywhere without Administrator rights.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from tuntop.network import egress_scripts as _es
from tuntop.tunnel import helper


class TestTunNextHopCountsAsTheSameRoute(unittest.TestCase):
    """Every route through the TUN is installed with the adapter's OWN address
    as the next hop (TUN4 / TUN6). Windows does not keep it: a next hop that is
    the outgoing interface's own address reads back as on-link ('0.0.0.0' /
    '::'). Comparing the wanted next hop against the reported one literally
    therefore made every single TUN route look STALE on every add.

    The visible symptom was the self-heal firing "though nothing happened": it
    deleted and re-added 0.0.0.0/1, 128.0.0.0/1, ::/0, ::/1 and 8000::/1 on
    every cycle, on routes that were already exactly right. Each of those
    cycles is several PowerShell and netsh processes, so it was also a large
    slice of the start-to-RUNNING latency.
    """

    def test_own_v4_address_matches_the_on_link_report(self):
        self.assertTrue(helper._gw_matches(helper.TUN, helper.TUN4, "", "v4"))

    def test_own_v6_address_matches_the_on_link_report(self):
        self.assertTrue(helper._gw_matches(helper.TUN, helper.TUN6, "", "v6"))

    def test_secondary_pipe_addresses_too(self):
        self.assertTrue(helper._gw_matches(helper.TUN2, helper.TUN2_IP4,
                                          "", "v4"))
        self.assertTrue(helper._gw_matches(helper.TUN2, helper.TUN2_IP6,
                                          "", "v6"))

    def test_a_real_gateway_is_unaffected(self):
        # A physical next hop is never the tunnel's own address, so ordinary
        # route comparison (and stale-route cleanup) behaves exactly as before.
        self.assertTrue(helper._gw_matches("Wi-Fi", "192.168.1.1",
                                          "192.168.1.1", "v4"))
        self.assertFalse(helper._gw_matches("Wi-Fi", "192.168.1.1",
                                           "10.0.0.1", "v4"))

    def test_the_wrong_family_own_address_does_not_match(self):
        self.assertFalse(helper._gw_matches(helper.TUN, helper.TUN6, "", "v4"))

    def test_a_physical_adapter_never_claims_the_tun_address(self):
        """The exemption belongs to the TUN only. If it leaked to another
        interface, a physical route pinned to 192.168.123.1 would compare equal
        to an on-link row and a real stale copy would be left in place."""
        self.assertFalse(helper._gw_matches("Wi-Fi", helper.TUN4, "", "v4"))

    def test_on_link_never_matches_a_real_next_hop(self):
        # The reverse direction must stay false: an on-link install does not
        # become "already correct" because some other row has a gateway.
        self.assertFalse(helper._gw_matches(helper.TUN, "", helper.TUN4, "v4"))

    def test_the_post_add_identity_check_agrees_with_add_v4(self):
        """_route_identity_present verifies an add that just succeeded, so it
        must recognise exactly the same routes add_v4 considers correct.

        It used to normalise on-link to '0.0.0.0' while add_v4 normalises it
        to ''. Routing the wanted next hop through the SAME helper makes the
        two agree, so a TUN route (own address installed, reported on-link) is
        found here too - otherwise a successful TUN install of a /32 would be
        reported as having vanished."""
        rows = [{"InterfaceAlias": helper.TUN, "NextHop": "0.0.0.0",
                 "RouteMetric": 1}]
        self.assertTrue(helper._route_identity_present(
            rows, "v4", helper.TUN, helper.TUN4, metric=1))
        rows6 = [{"InterfaceAlias": helper.TUN, "NextHop": "::",
                  "RouteMetric": 1}]
        self.assertTrue(helper._route_identity_present(
            rows6, "v6", helper.TUN, helper.TUN6, metric=1))
        # An on-link install must still match an on-link report.
        self.assertTrue(helper._route_identity_present(
            rows, "v4", helper.TUN, "", metric=1))
        # And a genuinely different gateway must still NOT match.
        self.assertFalse(helper._route_identity_present(
            rows, "v4", "Wi-Fi", "192.168.1.1", metric=1))


class TestTunRouteIsNotRewritten(unittest.TestCase):
    """add_v4/add_v6 must treat an already-correct TUN route as correct, not as
    stale. This is the end-to-end version of TestTunNextHopCountsAsTheSameRoute:
    the unit test proves the comparison, this one proves the comparison is
    actually the one add_v4 uses (a wrong wiring would pass the unit test and
    still churn the table on every self-heal)."""

    def setUp(self):
        # The ledger decides whether the persistent->active conversion runs, so
        # it must be empty here: these tests decide the ledger state themselves.
        # RouteLedger iterates 4-tuples (fam, dest, iface, gw) - the same shape
        # append() takes - so restoring is a straight re-append. (Unpacking each
        # entry into `item, metric` does not work: the entry IS the 4-tuple.)
        self._saved = list(helper.added_routes)
        helper.added_routes.clear()

    def tearDown(self):
        helper.added_routes.clear()
        for item in self._saved:
            helper.added_routes.append(item)

    def _row(self, alias, nexthop):
        return {"InterfaceAlias": alias, "NextHop": nexthop, "RouteMetric": 1}

    @staticmethod
    def _fake_run(calls):
        """Stand in for the shell layer: record the command, report success."""
        def _run(cmd, *a, **k):
            calls.append(list(cmd))
            return (0, "", "")
        return _run

    def _add(self, family, tracked):
        """Run one TUN route add with a correct existing row; return
        (shell commands, printed output)."""
        import io
        from contextlib import redirect_stdout
        calls, buf = [], io.StringIO()
        dest, gw = (("0.0.0.0/1", helper.TUN4) if family == "v4"
                    else ("::/1", helper.TUN6))
        if tracked:
            # Pretend this process installed it earlier: active store, nothing
            # to convert.
            helper.added_routes.append(
                (family, dest, helper.TUN, gw), metric=1)
        try:
            with mock.patch.object(helper, "get_existing_v4_routes",
                                   return_value=[self._row(helper.TUN,
                                                           "0.0.0.0")]), \
                    mock.patch.object(helper, "get_existing_v6_routes",
                                      return_value=[self._row(helper.TUN,
                                                              "::")]), \
                    mock.patch.object(helper, "run", self._fake_run(calls)), \
                    redirect_stdout(buf):
                if family == "v4":
                    helper.add_v4(dest, helper.TUN, gw, metric=1)
                else:
                    helper.add_v6(dest, helper.TUN, gw, metric=1)
        finally:
            helper.added_routes.clear()
        return calls, buf.getvalue()

    def test_existing_tun_split_route_is_not_replaced(self):
        calls, out = self._add("v4", tracked=True)
        self.assertNotIn("Replacing stale route", out,
                         "a correct TUN route was judged stale and rewritten")
        self.assertIn("already exists and is correct", out)
        self.assertEqual([c for c in calls if "delete" in c], [],
                         "our own active-store route was deleted and re-added")

    def test_existing_tun_v6_default_is_not_replaced(self):
        calls, out = self._add("v6", tracked=True)
        self.assertNotIn("Replacing stale route", out,
                         "a correct TUN IPv6 route was judged stale and rewritten")
        self.assertIn("already exists and is correct", out)
        self.assertEqual([c for c in calls if "delete" in c], [],
                         "our own active-store route was deleted and re-added")

    def test_a_legacy_persistent_leftover_is_still_converted(self):
        """The conversion must survive for a route we did NOT install - that is
        the case it exists for (a pre-store=active build left it in the
        registry, where it survives a reboot)."""
        calls, out = self._add("v4", tracked=False)
        self.assertNotIn("Replacing stale route", out,
                         "the route is correct, not stale")
        self.assertTrue([c for c in calls if "delete" in c],
                        "a legacy persistent leftover was left in the registry")

    def test_a_genuinely_stale_copy_is_still_replaced(self):
        """The fix must not disable stale-route cleanup: a drifted copy on a
        different interface is exactly what this code exists to remove."""
        calls = []
        with mock.patch.object(helper, "get_existing_v4_routes",
                               return_value=[self._row("Wi-Fi", "192.168.1.1")]), \
                mock.patch.object(helper, "run", self._fake_run(calls)):
            helper.add_v4("0.0.0.0/1", helper.TUN, helper.TUN4, metric=1)
        self.assertTrue([c for c in calls if "delete" in c],
                        "a drifted same-prefix copy survived")


class TestNormV4Gw(unittest.TestCase):
    """0.0.0.0 and :: are the on-link spellings. netsh must be given NO
    next-hop token for them - a literal 0.0.0.0 is rejected with "The
    filename, directory name, or volume label syntax is incorrect"."""

    def test_on_link_spellings_normalise_to_empty(self):
        for gw in ("0.0.0.0", "::", "0", "", None, " 0.0.0.0 "):
            self.assertEqual(helper._norm_v4_gw(gw), "", repr(gw))

    def test_real_gateways_are_preserved(self):
        self.assertEqual(helper._norm_v4_gw("192.168.1.1"), "192.168.1.1")
        self.assertEqual(helper._norm_v4_gw(" fe80::1 "), "fe80::1")


class TestWrongFamilyGw(unittest.TestCase):
    def test_ipv6_next_hop_is_rejected_for_ipv4(self):
        for gw in ("fe80::e43e:d3ff:fe7f:e3d", "2001:db8::1", "::ffff:1.2.3.4"):
            self.assertTrue(helper._wrong_family_gw(gw, 4), gw)

    def test_ipv4_next_hop_is_rejected_for_ipv6(self):
        self.assertTrue(helper._wrong_family_gw("192.168.1.1", 6))

    def test_matching_family_and_on_link_are_accepted(self):
        self.assertFalse(helper._wrong_family_gw("192.168.1.1", 4))
        self.assertFalse(helper._wrong_family_gw("fe80::1", 6))
        self.assertFalse(helper._wrong_family_gw("", 4))
        self.assertFalse(helper._wrong_family_gw(None, 6))
        self.assertFalse(helper._wrong_family_gw("0.0.0.0", 4))


class TestPhysicalEgress(unittest.TestCase):
    """The cache is validated on EVERY read: a value labelled "physical" that
    is not physical must never reach a route install."""

    def test_accepts_a_real_physical_adapter(self):
        self.assertEqual(
            helper.physical_egress(("Wi-Fi", "192.168.1.1")),
            ("Wi-Fi", "192.168.1.1"))

    def test_on_link_gateway_is_normalised(self):
        self.assertEqual(helper.physical_egress(("Wi-Fi", "0.0.0.0")),
                         ("Wi-Fi", ""))

    def test_rejects_a_vpn_adapter(self):
        # The last-resort lookup clause may return the VPN; a full-tunnel VPN
        # reconnect produced exactly this and every bypass was pinned onto it.
        self.assertIsNone(helper.physical_egress(("Shirazu-VPN", "0.0.0.0")))
        self.assertIsNone(helper.physical_egress(("WAN Miniport (IKEv2)", "10.8.0.1")))

    def test_rejects_a_tunnel_adapter(self):
        self.assertIsNone(helper.physical_egress(("Wintun", "192.168.123.1")))

    def test_rejects_a_wrong_family_gateway(self):
        self.assertIsNone(
            helper.physical_egress(("Wi-Fi", "fe80::e43e:d3ff:fe7f:e3d")))

    def test_rejects_empty(self):
        for bad in (None, (), ("", "192.168.1.1"), (None, "192.168.1.1")):
            self.assertIsNone(helper.physical_egress(bad), repr(bad))

    def test_falls_back_to_the_live_cache(self):
        with mock.patch.dict(helper._live_mode,
                             {"phys": ("Ethernet", "10.0.0.1")}, clear=False):
            self.assertEqual(helper.physical_egress(),
                             ("Ethernet", "10.0.0.1"))


class TestDirectBypassEgress(unittest.TestCase):
    """A route that must not ride a tunnel or VPN: the proxy server's /32, a
    user bypass, and above all a connected Windows VPN's own server address."""

    def test_uses_the_per_ip_egress_when_it_is_physical(self):
        with mock.patch.object(helper, "get_egress_for",
                               return_value=("Wi-Fi", "192.168.1.1")):
            self.assertEqual(helper._direct_bypass_egress("203.0.113.7"),
                             ("Wi-Fi", "192.168.1.1"))

    def test_falls_back_to_physical_when_the_resolver_says_none(self):
        with mock.patch.object(helper, "get_egress_for", return_value=None):
            self.assertEqual(
                helper._direct_bypass_egress("203.0.113.7", ("Wi-Fi", "1.2.3.4")),
                ("Wi-Fi", "1.2.3.4"))

    def test_never_returns_a_vpn_interface(self):
        # Even if the resolver hands one back (split-tunnel confusion), the
        # result must not be the VPN: that is a self-referential route.
        with mock.patch.object(helper, "get_egress_for",
                               return_value=("Shirazu-VPN", "0.0.0.0")), \
                mock.patch.dict(helper._live_mode,
                                {"phys": ("Wi-Fi", "192.168.1.1")},
                                clear=False):
            self.assertEqual(helper._direct_bypass_egress("185.64.178.62"),
                             ("Wi-Fi", "192.168.1.1"))

    def test_never_returns_a_tunnel_interface(self):
        with mock.patch.object(helper, "get_egress_for",
                               return_value=("Wintun", "192.168.123.1")), \
                mock.patch.dict(helper._live_mode,
                                {"phys": ("Wi-Fi", "192.168.1.1")},
                                clear=False):
            self.assertEqual(helper._direct_bypass_egress("185.64.178.62"),
                             ("Wi-Fi", "192.168.1.1"))

    def test_returns_none_rather_than_a_bad_answer(self):
        """No physical egress anywhere -> say so. A visible, reported
        omission beats a silently broken transport."""
        with mock.patch.object(helper, "get_egress_for", return_value=None), \
                mock.patch.dict(helper._live_mode, {"phys": None}, clear=False):
            self.assertIsNone(helper._direct_bypass_egress("185.64.178.62"))

    def test_rejects_a_wrong_family_resolver_answer(self):
        with mock.patch.object(helper, "get_egress_for",
                               return_value=("Wi-Fi", "fe80::1")), \
                mock.patch.dict(helper._live_mode,
                                {"phys": ("Wi-Fi", "192.168.1.1")},
                                clear=False):
            self.assertEqual(helper._direct_bypass_egress("203.0.113.7"),
                             ("Wi-Fi", "192.168.1.1"))


class TestAddV4NetshArguments(unittest.TestCase):
    """What actually reaches netsh."""

    def _add(self, gateway, existing=None, rc=0):
        calls = []

        def _run(cmd, *a, **kw):
            calls.append(list(cmd))
            return rc, "", ""

        with mock.patch.object(helper, "run", side_effect=_run), \
                mock.patch.object(helper, "get_existing_v4_routes",
                                  return_value=list(existing or [])), \
                mock.patch.object(helper, "get_existing_v6_routes",
                                  return_value=[]):
            helper.add_v4("188.114.97.6/32", "Shirazu-VPN", gateway, metric=1)
        return calls

    def test_on_link_gateway_omits_the_token(self):
        calls = self._add("0.0.0.0")
        add = [c for c in calls if c[3] == "add"]
        self.assertTrue(add)
        # dest, iface, metric, store - and NO "0.0.0.0" in between.
        self.assertEqual(add[0][:4],
                         ["netsh", "interface", "ipv4", "add"])
        self.assertNotIn("0.0.0.0", add[0])
        self.assertIn("188.114.97.6/32", add[0])
        self.assertIn("Shirazu-VPN", add[0])

    def test_real_gateway_is_passed_through(self):
        calls = self._add("10.99.205.162")
        add = [c for c in calls if c[3] == "add"]
        self.assertIn("10.99.205.162", add[0])

    def test_wrong_family_gateway_is_refused_before_any_netsh(self):
        # Defence in depth: even if a bad value reaches add_v4, it must not
        # become a netsh invocation (and a misleading Windows error).
        calls = self._add("fe80::e43e:d3ff:fe7f:e3d")
        self.assertEqual(calls, [])

    def test_an_on_link_route_already_in_the_table_is_recognised(self):
        """A correct on-link install must COMPARE EQUAL, or add_v4 treats it
        as stale, tears it down and re-adds on every single call - the
        endless '[HEAL] ... re-install FAILED - retrying next cycle'."""
        existing = [{"InterfaceAlias": "Shirazu-VPN", "NextHop": "0.0.0.0",
                     "DestinationPrefix": "188.114.97.6/32",
                     "RouteMetric": 1, "Store": "ActiveStore"}]
        calls = self._add("0.0.0.0", existing=existing)
        # Not recognised -> it would have been "replaced" as stale first.
        self.assertNotIn("delete", [c[3] for c in calls if c[2] == "interface"])
        # Recognised -> at most the deliberate persistent->active conversion
        # delete + one re-add, and never a second add on top.
        adds = [c for c in calls if c[3] == "add"]
        self.assertLessEqual(len(adds), 1)
        self.assertNotIn("0.0.0.0", adds[0]) if adds else None


class TestAddV6NetshArguments(unittest.TestCase):
    def test_on_link_gateway_is_omitted(self):
        calls = []

        def _run(cmd, *a, **kw):
            calls.append(list(cmd))
            return 0, "", ""

        with mock.patch.object(helper, "run", side_effect=_run), \
                mock.patch.object(helper, "get_existing_v6_routes",
                                  return_value=[]), \
                mock.patch.object(helper, "get_existing_v4_routes",
                                  return_value=[]):
            helper.add_v6("2001:db8::/128", "Wi-Fi", "::", metric=1)
        add = [c for c in calls if c[3] == "add"]
        self.assertTrue(add)
        self.assertNotIn("::", add[0])

    def test_wrong_family_is_refused(self):
        with mock.patch.object(helper, "run") as run, \
                mock.patch.object(helper, "get_existing_v6_routes",
                                  return_value=[]):
            self.assertFalse(helper.add_v6("2001:db8::/128", "Wi-Fi",
                                           "192.168.1.1", metric=1))
            run.assert_not_called()


class TestPhysicalDefaultLookupExcludesIPv6Gateways(unittest.TestCase):
    """Win32_NetworkAdapterConfiguration.DefaultIPGateway is an array holding
    the adapter's IPv4 *and* IPv6 gateways. The fallback used to take the
    first element that was neither 0.0.0.0 nor :: - which on a dual-stack NIC
    is the IPv6 gateway, returned from a script whose job is to answer for
    IPv4."""

    def test_cim_fallback_filters_out_ipv6(self):
        ps = _es.ipv4_default_ps()
        self.assertIn("DefaultIPGateway", ps)
        # The filter must reject anything containing a colon (every IPv6
        # literal, including IPv4-mapped forms) rather than only '::'.
        self.assertIn("$_ -notmatch ':'", ps)
        # ...and must no longer be the old colon-blind predicate.
        self.assertNotIn("$_ -ne '::'", ps)


class TestDnsGuardGlobalIsDeclared(unittest.TestCase):
    """Regression: _install_dns_guard ASSIGNED _dns_guard_state without
    declaring it global, so Python compiled it as a local and the READ in the
    resolver-less branch raised UnboundLocalError. That unwound out of
    self_heal_tunnel and skipped every Wintun address, the default and
    split-default routes, the whole IPv6 stack and the LAN bypass re-apply -
    a cosmetic bookkeeping bug silently disabled self-healing entirely."""

    def test_no_unboundlocal_when_no_resolver_is_configured(self):
        with mock.patch.object(helper, "_dns_guard") as guard, \
                mock.patch.object(helper, "_ACTIVE_DNS_GUARD", True), \
                mock.patch.object(helper, "_ACTIVE_DNS4", []), \
                mock.patch.object(helper, "_ACTIVE_DNS6", []), \
                mock.patch.dict(helper.__dict__, {"_dns_guard_state": None}):
            guard.guard_resolvers.return_value = []
            # Must not raise UnboundLocalError.
            self.assertFalse(helper._install_dns_guard(verbose=True))
            # Read INSIDE the patch: patch.dict restores the original on exit.
            self.assertEqual(helper._dns_guard_state, "none")

    def test_no_unboundlocal_when_the_guard_is_disabled(self):
        with mock.patch.object(helper, "_dns_guard") as guard, \
                mock.patch.object(helper, "_ACTIVE_DNS_GUARD", False), \
                mock.patch.dict(helper.__dict__, {"_dns_guard_state": None}):
            guard.ensure_removed.return_value = (True, "")
            self.assertFalse(helper._install_dns_guard(verbose=True))
            self.assertEqual(helper._dns_guard_state, "off")

    def test_a_healthy_install_still_reports_and_records(self):
        with mock.patch.object(helper, "_dns_guard") as guard, \
                mock.patch.object(helper, "_ACTIVE_DNS_GUARD", True), \
                mock.patch.object(helper, "_ACTIVE_DNS4", ["1.1.1.1"]), \
                mock.patch.object(helper, "_ACTIVE_DNS6", []), \
                mock.patch.dict(helper.__dict__, {"_dns_guard_state": None}), \
                mock.patch.object(helper, "_dns_guard_exempt", return_value=[]):
            guard.guard_resolvers.return_value = ["1.1.1.1"]
            guard.ensure_installed.return_value = (True, "1.1.1.1")
            self.assertTrue(helper._install_dns_guard(verbose=True))
            self.assertEqual(helper._dns_guard_state, "on")

    def test_self_heal_contains_a_dns_guard_failure(self):
        """The self-heal must not let a DNS-guard problem take the route
        re-apply down with it - its own docstring promises every step is
        individually guarded, and the UnboundLocalError proved it did not."""
        with mock.patch.object(helper, "wait_for_tun", return_value=True), \
                mock.patch.object(helper, "configure_tun"), \
                mock.patch.object(helper, "_install_dns_guard",
                                  side_effect=UnboundLocalError("boom")), \
                mock.patch.object(helper, "ensure_wintun_ipv4") as v4, \
                mock.patch.object(helper, "ensure_wintun_ipv6") as v6, \
                mock.patch.object(helper, "add_v4", return_value=True) as a4, \
                mock.patch.object(helper, "add_v6", return_value=True) as a6, \
                mock.patch.object(helper, "_add_lan_bypass") as lan, \
                mock.patch.object(helper, "get_ipv4_default",
                                  return_value=("Wi-Fi", "192.168.1.1", 7)):
            # Reports through its marker (returns None), so assert the work.
            helper.self_heal_tunnel("1.1.1.1", None)
        v4.assert_called()
        v6.assert_called()
        self.assertTrue(a4.called, "default/split routes were never re-applied")
        self.assertTrue(a6.called, "IPv6 routes were never re-applied")
        lan.assert_called()


class TestGatewayMonitorRefusesNonPhysicalCandidates(unittest.TestCase):
    def _check(self, cur):
        """Run the monitor against a live-table reading; return
        (repoint_mock, phys_after) with phys_after sampled INSIDE the patch
        (mock.patch.dict restores the real _live_mode on exit)."""
        holder = {}

        def _rp(*a, **kw):
            holder["called"] = True
            return 1

        with mock.patch.dict(helper._live_mode,
                             {"phys": ("Wi-Fi", "192.168.1.1"),
                              "phys6": None, "v4": [], "vpn_routes": []},
                             clear=False), \
                mock.patch.object(helper, "get_ipv4_default",
                                  return_value=cur), \
                mock.patch.object(helper, "get_ipv6_default",
                                  return_value=None), \
                mock.patch.object(helper, "_repoint_pinned_routes",
                                  side_effect=_rp) as rp, \
                mock.patch.object(helper, "restore_physical_metric"), \
                mock.patch.object(helper, "ensure_physical_metric_below_vpn"):
            helper._check_gateway_change()
            holder["phys"] = helper._live_mode["phys"]
        return rp, holder

    def _confirm_candidate(self, cur):
        """The monitor is debounced: a candidate must be seen twice, >=2s
        apart, before anything moves. Pre-seed it as already-confirmed."""
        import time as _time
        with mock.patch.dict(helper.__dict__,
                             {"_gw_pending": cur,
                              "_gw_pending_since": _time.time() - 30.0}):
            return self._check(cur)

    def test_a_wrong_family_next_hop_is_ignored(self):
        rp, _h = self._check(("Wi-Fi", "fe80::e43e:d3ff:fe7f:e3d"))
        rp.assert_not_called()

    def test_a_vpn_adapter_is_ignored(self):
        rp, _h = self._check(("Shirazu-VPN", "0.0.0.0"))
        rp.assert_not_called()

    def test_a_tunnel_adapter_is_ignored(self):
        rp, _h = self._check(("Wintun", "192.168.123.1"))
        rp.assert_not_called()

    def test_a_real_gateway_change_still_proceeds(self):
        # Must not become so strict that a genuine Wi-Fi roam is ignored -
        # that would leave every bypass pinned to a dead gateway forever.
        rp, holder = self._confirm_candidate(("Ethernet", "10.0.0.1"))
        rp.assert_called_once()
        self.assertEqual(holder["phys"], ("Ethernet", "10.0.0.1"))

    def test_a_refused_candidate_leaves_the_cache_alone(self):
        """The re-point COMMITS the new egress, so a refused candidate must
        not touch _live_mode['phys'] either - a poisoned cache outlives the
        call and every later bypass is built from it."""
        for cur in (("Shirazu-VPN", "0.0.0.0"),
                    ("Wi-Fi", "fe80::e43e:d3ff:fe7f:e3d"),
                    ("Wintun", "192.168.123.1")):
            with self.subTest(candidate=cur):
                rp, holder = self._confirm_candidate(cur)
                rp.assert_not_called()
                self.assertEqual(holder["phys"], ("Wi-Fi", "192.168.1.1"))


if __name__ == "__main__":
    unittest.main()

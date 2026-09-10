"""Regression tests: the route-delete fallback must never be prefix-wide.

Bug lineage: when netsh delete failed with parameter drift, the shared
routing layer fell back to `Remove-NetRoute -DestinationPrefix <p>` with NO
-InterfaceAlias - deleting every route with that prefix on EVERY interface,
including static routes the user or a corporate VPN client installed on
adapters TunTop never touched. The fallback is now interface-scoped (tunnel
adapters + the interface the route was installed on), and any same-prefix
route that survives on a foreign interface is reported back instead of
being silently destroyed.

Run:  python -m unittest discover -s tests -t . -v
"""
import unittest
from unittest import mock

import tuntop.network.routing as routing


def _ps_replying(leftover_aliases):
    """Fake routing._ps: records every script; answers the final
    'which interfaces still hold this prefix' probe with the given
    aliases ('|'-joined answer expected by _del_route_scoped)."""
    seen = []

    def fake(script, timeout=8):
        seen.append(script)
        if "Get-NetRoute -DestinationPrefix" in script:
            if leftover_aliases:
                return True, "|".join(leftover_aliases)
            return True, "none"
        return True, ""

    return fake, seen


class TestScopedDelete(unittest.TestCase):
    DEST = "1.2.3.4/32"

    def _run_scoped(self, leftover, known=("Ethernet 2",)):
        fake, seen = _ps_replying(leftover)
        with mock.patch.object(routing, "_ps", fake):
            result = routing._del_route_scoped(
                self.DEST, "v4", list(known))
        return result, seen

    def test_every_remove_has_interface_alias(self):
        # THE regression: no Remove-NetRoute may be issued without an
        # -InterfaceAlias qualifier.
        _, seen = self._run_scoped([])
        removes = [s for s in seen if "Remove-NetRoute" in s]
        self.assertTrue(removes)
        for s in removes:
            self.assertIn("-InterfaceAlias", s)

    def test_candidates_are_tunnel_adapters_plus_known(self):
        _, seen = self._run_scoped([])
        removes = " ".join(s for s in seen if "Remove-NetRoute" in s)
        self.assertIn("-InterfaceAlias 'wintun'", removes)
        self.assertIn("-InterfaceAlias 'wintun2'", removes)
        self.assertIn("-InterfaceAlias 'Ethernet 2'", removes)

    def test_clean_removal_reports_no_foreign(self):
        (removed, foreign), _ = self._run_scoped([])
        self.assertTrue(removed)
        self.assertFalse(foreign)

    def test_foreign_survivor_is_reported_not_deleted(self):
        # A same-prefix route on an interface outside our scope must come
        # back as foreign=True - the caller warns, the route survives.
        (removed, foreign), _ = self._run_scoped(["Ethernet"])
        self.assertFalse(removed)
        self.assertTrue(foreign)

    def test_survivor_on_tunnel_adapter_is_ours_not_foreign(self):
        (removed, foreign), _ = self._run_scoped(["wintun"])
        self.assertFalse(removed)
        self.assertFalse(foreign)

    def test_hostile_alias_cannot_break_out_of_literal(self):
        evil = "x' | Remove-NetRoute -Confirm:$false | echo '"
        fake, seen = _ps_replying([])
        with mock.patch.object(routing, "_ps", fake):
            routing._del_route_scoped(self.DEST, "v4", [evil])
        removes = " ".join(s for s in seen if "Remove-NetRoute" in s)
        self.assertIn("-InterfaceAlias '%s'" % evil.replace("'", "''"), removes)

    def test_del_route_v4_netsh_success_never_falls_back(self):
        with mock.patch.object(routing, "_netsh",
                               return_value=(True, "")) as netsh, \
             mock.patch.object(routing, "_ps") as ps:
            removed, foreign = routing._del_route_v4(
                self.DEST, "Ethernet 2", "10.0.0.1")
        self.assertTrue(removed)
        self.assertFalse(foreign)
        self.assertFalse(ps.called)
        self.assertTrue(netsh.called)

    def test_del_route_v4_drift_falls_back_scoped(self):
        # 'element not found' with the route still alive = parameter drift;
        # the fallback deletes on OUR interfaces only.
        with mock.patch.object(routing, "_netsh",
                               return_value=(False, "The element was not found")), \
             mock.patch.object(routing, "_ps",
                               side_effect=[(True, "yes"),   # _route_exists_v4
                                            (True, ""),      # Remove wintun..
                                            (True, ""),      # Remove wintun2..
                                            (True, ""),      # Remove Ethernet 2..
                                            (True, "none")]):  # leftover probe
            removed, foreign = routing._del_route_v4(
                self.DEST, "Ethernet 2", "10.0.0.1")
        self.assertTrue(removed)
        self.assertFalse(foreign)

    def test_del_route_v6_same_contract(self):
        with mock.patch.object(routing, "_netsh",
                               return_value=(False, "element not found")), \
             mock.patch.object(routing, "_ps",
                               side_effect=[(True, "yes"),
                                            (True, ""),
                                            (True, ""),
                                            (True, ""),
                                            (True, "VpnAdapter")]):
            removed, foreign = routing._del_route_v6(
                "::ffff:1.2.3.4/128", "Ethernet 2", None)
        self.assertFalse(removed)
        self.assertTrue(foreign)


class TestDashboardBindsScopedDelete(unittest.TestCase):
    def test_no_shadowing(self):
        import tuntop.ui.dashboard as dash
        self.assertIs(dash._del_route_scoped, routing._del_route_scoped)


if __name__ == "__main__":
    unittest.main()

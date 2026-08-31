"""Unit tier: proxy2 (second SOCKS5 hop) configuration schema.

Covers the data model only - no Windows, no processes:

* Profile round-trips the three new proxy2 keys (to_snapshot/from_snapshot).
* Legacy profile JSON files WITHOUT proxy2 keys still load (defaults kept) -
  the exact backward-compatibility promise the feature made.
* snapshot_from_args() captures proxy2 state from the argparse namespace.
* apply_to_args() restores it (with host normalisation, mirroring bypass_ip).

Run:  python -m unittest discover -s tests -t . -v
"""
import unittest

from tuntop.config.models import Profile
from tuntop.config.profiles import apply_to_args, snapshot_from_args


class _FakeArgs:
    """Mirrors the argparse namespace attributes apply_to_args reads."""

    def __init__(self, **kw):
        self.server = kw.get("server", ["1.1.1.1"])
        self.port = kw.get("port", 10808)
        self.dns4 = kw.get("dns4", "8.8.8.8")
        self.endpoint_port = kw.get("endpoint_port", 443)
        self.geoip = kw.get("geoip", None)
        self.geoip_code = kw.get("geoip_code", "cn")
        self.vpn_interface = kw.get("vpn_interface", None)
        self.bypass_ip = kw.get("bypass_ip", [])
        self.proxy2_bypass_ip = kw.get("proxy2_bypass_ip", [])
        self.proxy2_port = kw.get("proxy2_port", None)
        self.proxy2_server = kw.get("proxy2_server", [])
        self.vless_over_vpn = kw.get("vless_over_vpn", False)
        self.no_vpn_bypass = kw.get("no_vpn_bypass", False)


class TestProfileRoundTrip(unittest.TestCase):
    def test_proxy2_keys_round_trip(self):
        p = Profile(name="two-hop", proxy2_port=10809,
                    proxy2_server=["5.5.5.5"],
                    proxy2_bypass_ip=["discord.com"])
        snap = p.to_snapshot()
        self.assertEqual(snap["proxy2_port"], 10809)
        self.assertEqual(snap["proxy2_server"], ["5.5.5.5"])
        self.assertEqual(snap["proxy2_bypass_ip"], ["discord.com"])
        p2 = Profile.from_snapshot("two-hop", snap)
        self.assertEqual(p2.proxy2_port, 10809)
        self.assertEqual(p2.proxy2_server, ["5.5.5.5"])
        self.assertEqual(p2.proxy2_bypass_ip, ["discord.com"])

    def test_legacy_profile_without_proxy2_keys_still_loads(self):
        # An old profiles.json has no proxy2_* keys at all: from_snapshot must
        # keep the dataclass defaults (feature off), never raise.
        legacy = {"server": ["1.2.3.4"], "port": 10808, "bypass_ip": ["x.com"]}
        p = Profile.from_snapshot("old", legacy)
        self.assertIsNone(p.proxy2_port)
        self.assertEqual(p.proxy2_bypass_ip, [])
        self.assertEqual(p.proxy2_server, [])
        self.assertEqual(p.bypass_ip, ["x.com"])

    def test_disabled_proxy2_snapshots_as_null_port(self):
        snap = Profile().to_snapshot()
        self.assertIsNone(snap["proxy2_port"])
        self.assertEqual(snap["proxy2_bypass_ip"], [])


class TestSnapshotFromArgs(unittest.TestCase):
    def test_proxy2_state_captured(self):
        ns = _FakeArgs(proxy2_port=10809, proxy2_server=["5.5.5.5"],
                       proxy2_bypass_ip=["discord.com"])
        snap = snapshot_from_args(ns)
        self.assertEqual(snap["proxy2_port"], 10809)
        self.assertEqual(snap["proxy2_server"], ["5.5.5.5"])
        self.assertEqual(snap["proxy2_bypass_ip"], ["discord.com"])

    def test_missing_proxy2_attrs_default_cleanly(self):
        # A namespace built before the feature (no proxy2 attributes at all)
        # must still snapshot without raising.
        ns = _FakeArgs()
        del ns.__dict__["proxy2_port"]
        del ns.__dict__["proxy2_server"]
        del ns.__dict__["proxy2_bypass_ip"]
        snap = snapshot_from_args(ns)
        self.assertIsNone(snap["proxy2_port"])
        self.assertEqual(snap["proxy2_server"], [])


class TestApplyToArgs(unittest.TestCase):
    def test_proxy2_entries_normalised_like_direct_ones(self):
        ns = _FakeArgs()
        snap = {"proxy2_port": 10809,
                "proxy2_server": ["5.5.5.5"],
                "proxy2_bypass_ip": ["https://discord.com/", "1.2.3.4"]}
        apply_to_args(ns, snap,
                      normalise_host=lambda u: u.split("://")[-1].split("/")[0])
        self.assertEqual(ns.proxy2_port, 10809)
        self.assertEqual(ns.proxy2_server, ["5.5.5.5"])
        self.assertEqual(ns.proxy2_bypass_ip, ["discord.com", "1.2.3.4"])

    def test_proxy2_port_absent_keeps_namespace_value(self):
        ns = _FakeArgs(proxy2_port=10809)
        apply_to_args(ns, {"server": ["1.1.1.1"]})
        self.assertEqual(ns.proxy2_port, 10809)   # untouched, not reset to None

    def test_direct_list_unaffected_by_proxy2_entries(self):
        ns = _FakeArgs()
        apply_to_args(ns, {"bypass_ip": ["a.com"],
                           "proxy2_bypass_ip": ["b.com"]})
        self.assertEqual(ns.bypass_ip, ["a.com"])
        self.assertEqual(ns.proxy2_bypass_ip, ["b.com"])


if __name__ == "__main__":
    unittest.main()

"""Regression tests for the 1.0.48 correctness pass.

Each class here pins ONE invariant that was previously false, and each names
the failure it prevents. They are grouped by the area that regressed rather
than by the function, because the failure modes cluster there.

No Windows calls, no admin, no real routes: every PowerShell/netsh boundary
is mocked. Run:

    python -m unittest tests.unit.test_correctness_pass -v
"""
import ipaddress
import os
import unittest
from unittest import mock

from tuntop.geo import geoip
from tuntop.network import dns_guard
from tuntop.psshell import ps_quote
from tuntop.tunnel import helper as H


# ═══════════════════════════════════════════════════════════════════════
# 1.4  Geoip is DATA, and a country range is never a default route
# ═══════════════════════════════════════════════════════════════════════

def _varint(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _wire_entry(country, cidrs):
    """Hand-encode one GeoIPList entry - the v2ray .dat wire format, with no
    google.protobuf anywhere.

    The pure fallback is the ONLY decoder that runs on a host where protobuf is
    missing, so a regression in it is invisible to every test that builds its
    input through the protobuf descriptors: such a test would need protobuf
    installed AND would only ever exercise the fast path. The layout here is
    exactly what `_geoip_parse_entry` reads: entry field 1 = country_code,
    entry field 2 = CIDR{country field 1 = ip bytes, field 2 = prefix}; a
    prefix of None OMITS field 2 from the wire entirely.
    """
    inner = _varint((1 << 3) | 2) + _varint(len(country)) + country.encode()
    for ip, prefix in cidrs:
        body = _varint((1 << 3) | 2) + _varint(len(ip)) + ip
        if prefix is not None:
            body += _varint((2 << 3) | 0) + _varint(prefix)
        inner += _varint((2 << 3) | 2) + _varint(len(body)) + body
    return _varint((1 << 3) | 2) + _varint(len(inner)) + inner


class TestGeoPrefixFloor(unittest.TestCase):
    """`/0` rejection was six hardcoded strings; a range this broad installs at
    metric=1 and is more specific than the tunnel's own split-defaults, so it
    captures ALL traffic outside the tunnel. 2000::/3 is the whole IPv6 global
    unicast space and used to sail straight through."""

    def test_v6_default_and_beyond_are_refused(self):
        for cidr in ("2000::/3", "::/0", "::/1", "::/2", "4000::/2",
                     "8000::/1", "::/16", "fc00::/7"):
            with self.subTest(cidr=cidr):
                self.assertFalse(H._is_routable_bypass_cidr(cidr),
                                 f"{cidr} must not be installable as a bypass")

    def test_v4_default_and_beyond_are_refused(self):
        for cidr in ("0.0.0.0/0", "0.0.0.0/1", "1.0.0.0/1", "2.0.0.0/2",
                     "8.0.0.0/3", "16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2",
                     "0.0.0.0/8"):
            with self.subTest(cidr=cidr):
                self.assertFalse(H._is_routable_bypass_cidr(cidr),
                                 f"{cidr} must not be installable as a bypass")

    def test_ordinary_country_ranges_still_install(self):
        # The floor must not eat real data. NOTE: 2001:db8::/32 is NOT a
        # usable example - it is the RFC 3849 documentation range, so
        # is_reserved rejects it for an unrelated (correct) reason.
        for cidr in ("1.0.1.0/24", "5.255.255.0/24", "8.8.8.0/24",
                     "114.114.114.0/24", "2400:3200::/32", "2a00:1450::/32"):
            with self.subTest(cidr=cidr):
                self.assertTrue(H._is_routable_bypass_cidr(cidr))

    def test_garbage_is_refused(self):
        for cidr in ("", "not-a-cidr", "1.2.3.4.5/24", "999.0.0.0/8", None):
            with self.subTest(cidr=cidr):
                self.assertFalse(H._is_routable_bypass_cidr(cidr))

    def test_pure_decoder_enforces_the_v4_floor(self):
        """The pure-fallback .dat parser emitted a /0 and a /1 verbatim, so on a
        host WITHOUT `google.protobuf` (the only configuration that runs this
        decoder) `0.0.0.0/1` and `128.0.0.0/1` - TunTop's OWN split-defaults -
        reached the sweep. Install drops them, but `dashboard._remove_geo_
        routes_for` / `_sweep_geo_leftovers` and `cleanup_watchdog.
        sweep_geo_routes` delete on exact-prefix match with no allow-list, so
        `[R]` or exiting removed half the tunnel's default set and the traffic
        silently fell back to the physical NIC. /8 is the floor and must
        survive: the check must not eat real data."""
        raw = _wire_entry("cn", [(b"\x00\x00\x00\x00", 0), (b"\x00\x00\x00\x00", 1),
                                 (b"\x80\x00\x00\x00", 1), (b"\x01\x00\x00\x00", 7),
                                 (b"\x01\x02\x03\x00", 24), (b"\x0a\x00\x00\x00", 8)])
        self.assertEqual(geoip._geoip_decode_pure(raw, "cn")["cn"],
                         ["1.2.3.0/24", "10.0.0.0/8"])

    def test_pure_decoder_enforces_the_v6_floor(self):
        """`8000::/1` is the other half of TunTop's IPv6 split-default
        (::/0 + ::/1 + 8000::/1), so the same sweep exposure applies with
        `_MIN_PREFIXLEN[6] == 16` as the boundary: ::/1 and 8000::/1 out,
        2400::/16 - genuinely a single country - in."""
        raw = _wire_entry("cn", [(b"\x00" * 16, 0), (b"\x80\x00" + b"\x00" * 14, 1),
                                 (b"\x00" * 16, 15),
                                 (b"\x24\x00" + b"\x00" * 14, 16),
                                 (b"\x20\x01\x0d\xb8" + b"\x00" * 12, 32)])
        self.assertEqual(geoip._geoip_decode_pure(raw, "cn")["cn"],
                         ["2400::/16", "2001:db8::/32"])

    def test_pure_decoder_and_normalise_cidr_agree_on_every_prefix(self):
        """The floor must live in BOTH decoders, not one. Which validation a
        .dat gets must not depend on whether `google.protobuf` happens to import
        on the user's machine - that is a security decision varying by
        environment. `_geoip_cidr_to_str` is the pure path's gate and used to
        apply no floor at all; this walks both gates over every in-range prefix
        length so the two cannot drift apart again. (/32 itself is excluded: this
        decoder requires plen < maxlen, so it is stricter there than
        `_normalise_cidr`, which accepts a /32 - unrelated to the floor.)"""
        for plen in range(0, 32):
            with self.subTest(prefix=plen):
                cidr = geoip._geoip_cidr_to_str(b"\x01\x02\x03\x04", plen)
                text = f"1.2.3.4/{plen}"
                if plen < geoip._MIN_PREFIXLEN[4]:
                    self.assertIsNone(cidr, f"pure decoder kept {text}")
                    self.assertIsNone(geoip._normalise_cidr(text), text)
                else:
                    self.assertEqual(cidr, geoip._normalise_cidr(text), text)


class TestGeoJsonDecodeIsValidated(unittest.TestCase):
    """`_geoip_decode_json` handed every string in entry["ip"] to the installer
    with no ip_network parse and no /0 rejection, while the binary decoder
    beside it had rejected /0 since 1.0.41."""

    @staticmethod
    def _doc(ips):
        import json
        return json.dumps({"country": [{"code": "cn", "ip": ips}]})

    def test_over_broad_ranges_are_dropped(self):
        out = geoip._geoip_decode_json(self._doc(
            ["2000::/3", "0.0.0.0/0", "::/0"]), "cn")
        self.assertEqual(out.get("cn"), [])

    def test_real_ranges_survive_and_are_canonicalised(self):
        out = geoip._geoip_decode_json(self._doc(
            ["1.0.1.0/24", "2001:0DB8::/32"]), "cn")
        # Canonical form matters: Get-NetRoute reports the compressed string,
        # so a non-canonical input installed fine and then failed every
        # identity comparison against the live table forever (CHANGELOG 1.0.41).
        self.assertEqual(out["cn"], ["1.0.1.0/24", "2001:db8::/32"])

    def test_malformed_entries_do_not_raise(self):
        out = geoip._geoip_decode_json(
            self._doc(["1.0.1.0/24", "garbage", "1.2.3.4/33", 7, None]), "cn")
        self.assertEqual(out["cn"], ["1.0.1.0/24"])


class TestGeoDiskCacheIsRevalidated(unittest.TestCase):
    """`_geo_disk_load` only checked dict[str, list[str]] and returned the file
    STRAIGHT INTO THE CACHE. The file is user-writable and read by the
    ELEVATED helper, so {"cn": ["2000::/3"]} there routed the entire IPv6
    address space outside the tunnel on the next [S], with no error and a
    green dashboard."""

    def setUp(self):
        import hashlib
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self._src = os.path.join(self.tmp, "geoip.dat")
        with open(self._src, "wb") as f:
            f.write(b"x")
        self._real_dir = geoip._GEO_DISK_CACHE_DIR
        self._real_key = geoip._geo_cache_key
        d = os.path.join(self.tmp, "cache")
        os.makedirs(d, exist_ok=True)
        geoip._GEO_DISK_CACHE_DIR = d
        self._cache_path = os.path.join(
            d, hashlib.sha256(
                self._real_key(self._src, "cn").encode("utf-8")).hexdigest()
            + ".json")

    def tearDown(self):
        geoip._GEO_DISK_CACHE_DIR = self._real_dir
        geoip._geo_cache_key = self._real_key

    def _write(self, payload):
        import json
        with open(self._cache_path, "w", encoding="utf-8") as f:
            json.dump(payload, f)

    def test_over_broad_cidr_in_cache_is_dropped(self):
        self._write({"cn": ["2000::/3", "0.0.0.0/0"]})
        self.assertEqual(geoip._geo_disk_load(self._src, "cn"), {"cn": []})

    def test_real_cidr_in_cache_survives(self):
        self._write({"cn": ["1.0.1.0/24"]})
        self.assertEqual(geoip._geo_disk_load(self._src, "cn"),
                         {"cn": ["1.0.1.0/24"]})

    def test_wrong_shape_still_rejected(self):
        for payload in ({"cn": "1.0.1.0/24"}, {"cn": [1, 2]}, ["a"], "x", 5):
            with self.subTest(payload=payload):
                self._write(payload)
                self.assertIsNone(geoip._geo_disk_load(self._src, "cn"))


class TestGeoProtoDecodeIsValidated(unittest.TestCase):
    """`_geoip_decode_proto` is the ONE decoder that appended `"%s/%d" % (addr,
    cd.prefix)` with no `_normalise_cidr` call, so it skipped the prefix floor
    and the canonicalisation every other decoder in the file is gated by.

    Why this branch needs its own class: it only runs when
    `google.protobuf` imports, i.e. exactly the PRODUCTION configuration. The
    pure fallback this file's other geoip tests exercise was never the code
    that was broken, and on a machine without protobuf the fast path is dead
    code - so without these tests the hole is invisible on any dev box that
    has not installed protobuf, and live on every real one.

    The failure it pins: `prefix` is LABEL_OPTIONAL, so a .dat entry with the
    field OMITTED decodes to 0. Install is protected by
    `helper._is_routable_bypass_cidr`, but the SWEEP is not -
    `dashboard._remove_geo_routes_for` / `_sweep_geo_leftovers` and
    `cleanup_watchdog.sweep_geo_routes` canonicalise with
    `ip_network(strict=False)` and pass the result to `_batch_delete_routes`,
    so `[R]` or quitting ran `netsh interface ipv4 delete route 0.0.0.0/0` and
    dropped the machine's default route on every interface, with no error.
    `--geoip` takes a user file and hand-edited / merged v2rayN databases are
    normal, so one omitted field was enough."""

    @staticmethod
    def _cls():
        """The real v2fly descriptor, or None when protobuf is unavailable."""
        try:
            return geoip._build_v2fly_descriptors()
        except Exception:
            return None

    def _build(self, cidrs, code="CN"):
        """Serialise a minimal GeoIPList. `cidrs` is [(ip_bytes, prefix)] where
        prefix=None means the field is OMITTED from the wire entirely."""
        cls = self._cls()
        if cls is None:
            self.skipTest("google.protobuf is not importable, so the protobuf "
                          "fast path cannot be constructed on this host")
        msg = cls()
        entry = msg.entry.add()
        entry.country_code = code
        for ip, prefix in cidrs:
            c = entry.cidr.add()
            c.ip = ip
            if prefix is not None:
                c.prefix = prefix
        return msg.SerializeToString()

    def _decode(self, cidrs, code="CN"):
        return geoip._geoip_decode_proto(self._build(cidrs, code), self._cls(), "cn")

    def test_prefix_less_cidr_is_dropped_not_turned_into_slash_zero(self):
        # The exact repro: a CIDR message carrying no `prefix` at all. Before
        # the fix this appended "5.6.7.8/0", which every consumer then
        # canonicalised to 0.0.0.0/0 and deleted.
        out = self._decode([(b"\x01\x02\x03\x00", 24), (b"\x05\x06\x07\x08", None)])
        self.assertEqual(out.get("cn"), ["1.2.3.0/24"])
        for cidr in out.get("cn", []):
            self.assertNotEqual(ipaddress.ip_network(cidr, strict=False).prefixlen, 0,
                                 f"{cidr} canonicalised to a default route")

    def test_v6_prefix_less_cidr_is_dropped_not_turned_into_slash_zero(self):
        # The 16-byte form of the same hole: the pure fallback rejects it too,
        # but a ::/0 that slipped through deletes the IPv6 default route.
        v6 = b"\x20\x01\x0d\xb8" + b"\x00" * 12
        out = self._decode([(v6, None)])
        self.assertNotIn("::/0", out.get("cn", []))
        self.assertEqual(out.get("cn"), [])

    def test_v4_wider_than_the_prefix_floor_is_dropped(self):
        # /1 and /7 are below _MIN_PREFIXLEN[4] == 8. 0.0.0.0/1 and 128.0.0.1
        # are TunTop's OWN split-defaults: an entry this broad in a .dat makes
        # the sweep delete half the tunnel's default set.
        for prefix in (0, 1, 2, 3, 7):
            with self.subTest(prefix=prefix):
                out = self._decode([(b"\x00\x00\x00\x00", prefix)])
                self.assertEqual(out.get("cn"), [])

    def test_v6_wider_than_the_prefix_floor_is_dropped(self):
        # 8000::/1 is the other half of TunTop's IPv6 split-default; the
        # floor for v6 is /16.
        for prefix in (0, 1, 2, 3, 15):
            with self.subTest(prefix=prefix):
                out = self._decode([(b"\x20\x00" + b"\x00" * 14, prefix)])
                self.assertEqual(out.get("cn"), [])

    def test_ordinary_ranges_survive_and_are_canonicalised(self):
        # Canonicalisation matters as much as the floor: Get-NetRoute reports
        # the compressed string, so a non-canonical "1.2.3.4/24" installed as
        # 1.2.3.0/24 and then failed every identity comparison against the
        # live route table forever - surviving every sweep (CHANGELOG 1.0.41).
        v6 = bytes.fromhex("20010db8" + "00" * 12)
        out = self._decode([(b"\x01\x02\x03\x04", 24), (v6, 32)])
        self.assertEqual(out["cn"], ["1.2.3.0/24", "2001:db8::/32"])

    def test_fast_path_agrees_with_the_pure_fallback(self):
        """Two decoders, one policy: the same bytes must decode identically
        through both, whichever one this host happens to run.

        The real-world failure this pins: `_geoip_decode_pure`'s gate was
        `_geoip_cidr_to_str`, which rejected plen == 0 and out-of-range but
        applied no per-family floor, so for the same bytes it emitted
        `0.0.0.0/1` where the fast path emitted nothing. Which validation a .dat
        got therefore depended on whether `google.protobuf` imported - a
        security-relevant decision varying by environment. On a host without
        protobuf, `0.0.0.0/1` and `128.0.0.0/1` (TunTop's OWN split-defaults,
        which `dashboard._remove_geo_routes_for` / `_sweep_geo_leftovers` and
        `cleanup_watchdog.sweep_geo_routes` delete on exact-prefix match with no
        allow-list) were removed on `[R]` or on exit, and the tunnel's traffic
        silently fell back to the physical NIC. The `/1` and `/7` cases below
        are that regression; they used to be excluded here because the two
        paths provably diverged."""
        if self._cls() is None:
            self.skipTest("google.protobuf is not importable, so the protobuf "
                          "fast path cannot be constructed on this host")
        v6 = bytes.fromhex("20010db8" + "00" * 12)
        cases = [
            ("prefix-less v4", [(b"\x01\x02\x03\x00", 24), (b"\x05\x06\x07\x08", None)],
             ["1.2.3.0/24"]),
            ("prefix-less v6", [(v6, None), (v6, 32)], ["2001:db8::/32"]),
            ("ordinary", [(b"\x01\x02\x03\x04", 24), (v6, 32)],
             ["1.2.3.0/24", "2001:db8::/32"]),
            # 0.0.0.0/1 + 128.0.0.0/1 are the split-defaults; below the /8 floor.
            ("v4 /1 beside a real range",
             [(b"\x00\x00\x00\x00", 1), (b"\x80\x00\x00\x00", 1),
              (b"\x01\x02\x03\x04", 24)], ["1.2.3.0/24"]),
            ("v4 /7 beside a real range",
             [(b"\x01\x00\x00\x00", 7), (b"\x01\x02\x03\x04", 24)], ["1.2.3.0/24"]),
            # 8000::/1 is the IPv6 half; the v6 floor is /16.
            ("v6 /1 beside a real range",
             [(b"\x80\x00" + b"\x00" * 14, 1), (v6, 32)], ["2001:db8::/32"]),
        ]
        for label, cidrs, expected in cases:
            with self.subTest(case=label):
                raw = self._build(cidrs)
                fast = geoip._geoip_decode_proto(raw, self._cls(), "cn")
                pure = geoip._geoip_decode_pure(raw, "cn")
                self.assertEqual(fast.get("cn", []), expected)
                self.assertEqual(pure.get("cn", []), expected)
                self.assertEqual(fast, pure)


class TestGeoFloorIsPinnedInBothLayers(unittest.TestCase):
    """The floor is deliberately duplicated at the install boundary and in the
    parser. This test is what stops the two from drifting apart - the exact
    failure mode of every other 'single source of truth' comment in this repo."""

    def test_helper_and_parser_agree(self):
        for cidr in ("0.0.0.0/0", "::/0", "2000::/3", "8.0.0.0/3"):
            self.assertIsNone(geoip._normalise_cidr(cidr), cidr)
            self.assertFalse(H._is_routable_bypass_cidr(cidr), cidr)
        for cidr in ("1.0.1.0/24", "2400:3200::/32"):
            self.assertIsNotNone(geoip._normalise_cidr(cidr), cidr)
            self.assertTrue(H._is_routable_bypass_cidr(cidr), cidr)


# ═══════════════════════════════════════════════════════════════════════
# 1.6  PowerShell: no '//' comments, and one quoting implementation
# ═══════════════════════════════════════════════════════════════════════

class TestNoDoubleSlashInEmbeddedPowerShell(unittest.TestCase):
    """PowerShell has NO '//' comment. A '//' line is a PARSE ERROR, and a
    parse error kills the WHOLE script - so the function silently returned
    nothing at all while its code looked entirely correct.

    `_get_ipv6_default` shipped with seven '//' lines, which made every IPv6
    bypass and geo route in the dashboard a silent no-op."""

    def _assert_no_slash_comments(self, script, label):
        for ln, line in enumerate(script.splitlines(), 1):
            if line.strip().startswith("//"):
                self.fail(f"{label} line {ln}: '//' is not a PowerShell "
                          f"comment: {line.strip()!r}")

    def test_routing_get_ipv6_default_script_parses_as_powershell(self):
        from tuntop.network import routing
        scripts = []

        def _capture(script, timeout=8):
            scripts.append(script)
            return True, ""

        with mock.patch.object(routing, "_ps", side_effect=_capture):
            try:
                routing._get_ipv6_default()
            except Exception:
                pass
        self.assertTrue(scripts, "no PowerShell was generated at all")
        for s in scripts:
            self._assert_no_slash_comments(s, "routing._get_ipv6_default")

    def test_helper_get_ipv6_default_script_parses_as_powershell(self):
        scripts = []

        def _capture(ps, timeout=15):
            scripts.append(ps)
            return None

        with mock.patch.object(H, "ps_json", side_effect=_capture):
            try:
                H.get_ipv6_default()
            except Exception:
                pass
        self.assertTrue(scripts, "no PowerShell was generated at all")
        for s in scripts:
            self._assert_no_slash_comments(s, "helper.get_ipv6_default")

    def test_ipv6_fallback_still_excludes_a_vpn(self):
        """Because the hardened block was unreachable, helper's copy became
        the only live one - and it dropped the VPN clause, so on a box with no
        native v6 default the corporate adapter was the first candidate."""
        scripts = []

        def _capture(ps, timeout=15):
            scripts.append(ps)
            return None

        with mock.patch.object(H, "ps_json", side_effect=_capture):
            try:
                H.get_ipv6_default()
            except Exception:
                pass
        joined = "\n".join(scripts)
        self.assertIn("$vpnAliases", joined,
                      "the IPv6 fallback lost its VPN exclusion")

    def test_dns_guard_scripts_carry_no_slash_comments(self):
        """Every PowerShell the DNS guard emits, including the 1.0.51 boot-task
        scripts. The boot arm script in particular is a single long line per
        statement, which is exactly the shape that invites a `//` to be typed
        by mistake - and a parse error there is invisible until the machine
        boots and the rule survives the crash it was meant to clear."""
        scripts = {
            "install": dns_guard.install_script(["8.8.8.8"], [".local"]),
            "uninstall": dns_guard.uninstall_script(),
            "detect": dns_guard.detect_script(),
            "arm_boot_cleanup": dns_guard.arm_boot_cleanup_script(),
            "disarm_boot_cleanup": dns_guard.disarm_boot_cleanup_script(),
            "boot_cleanup_action": dns_guard.boot_cleanup_action(),
            "foreign_resolvers": dns_guard.foreign_resolvers_script(),
        }
        for label, s in scripts.items():
            self._assert_no_slash_comments(s, f"dns_guard.{label}")


class TestPsQuoteIsSingleSourced(unittest.TestCase):
    """psshell's own docstring promises a quoting fix 'can never land in one
    copy and silently miss the other' - while dns_guard kept a third copy."""

    def test_dns_guard_delegates_to_psshell(self):
        # The wrapper stays (only this one quotes as well as escapes); the
        # ESCAPE must come from the shared leaf.
        self.assertEqual(dns_guard._ps_quote("a'b"), "'a''b'")
        for raw in ("x\u2019y", "x\u2018y", "x\u201ay", "x\u201by"):
            with self.subTest(raw=raw):
                self.assertEqual(dns_guard._ps_quote(raw),
                                 "'" + ps_quote(raw) + "'")

    def test_ps_quote_escapes_unicode_quote_lookalikes(self):
        # PowerShell's tokenizer accepts these as delimiters too, so doubling
        # only the ASCII apostrophe left four ways out of a string literal.
        for q in ("\u2018", "\u2019", "\u201a", "\u201b"):
            with self.subTest(q=q):
                self.assertEqual(ps_quote(f"a{q}b"), f"a{q}{q}b")

    def test_ps_quote_is_idempotent_on_ascii(self):
        self.assertEqual(ps_quote("Bob's VPN"), "Bob''s VPN")

    def test_no_module_defines_its_own_escape(self):
        # A second `def _ps_quote` or a bare `replace("'", "''")` in a module
        # that builds PowerShell is the drift this guards against.
        import pathlib
        root = pathlib.Path(dns_guard.__file__).resolve().parents[2]
        offenders = []
        for p in root.glob("tuntop/**/*.py"):
            text = p.read_text(encoding="utf-8", errors="replace")
            if "def _ps_quote" in text and p.name != "dns_guard.py":
                offenders.append(f"{p.name}: duplicate _ps_quote")
            if "replace(\"'\", \"''\")" in text and p.name not in (
                    "psshell.py", "dns_guard.py"):
                offenders.append(f"{p.name}: hand-rolled quote doubling")
        self.assertEqual(offenders, [])


class TestHostFromUrlIsSingleSourced(unittest.TestCase):
    """helper.py carried a second, weaker _host_from_url that used
    split("@", 1)[-1] where the shared one uses rsplit("@", 1) - so
    "user:p@ss@host.com" became "ss@host.com" - and it kept :port and IPv6
    brackets, which socket.getaddrinfo cannot parse."""

    def test_helper_delegates(self):
        for raw in ("https://user:p@ss@example.com:443/x",
                    "[2001:db8::1]:8443",
                    "example.com.",
                    "https://api.ipify.org/"):
            with self.subTest(raw=raw):
                self.assertEqual(H._host_from_url(raw),
                                 H._shared_host_from_url(raw))

    def test_credential_with_at_sign_keeps_the_host(self):
        self.assertEqual(H._host_from_url("user:p@ss@host.com"), "host.com")

    def test_port_and_brackets_are_stripped(self):
        self.assertEqual(H._host_from_url("example.com:443"), "example.com")
        self.assertEqual(H._host_from_url("[2001:db8::1]:8443"),
                         "2001:db8::1")


# ═══════════════════════════════════════════════════════════════════════
# 1.1  _live_switch_vless must never delete the endpoint /32 it cannot replace
# ═══════════════════════════════════════════════════════════════════════

class TestLiveSwitchVlessKeepsTheRouteItCannotReplace(unittest.TestCase):
    """The old pre-clean deleted EVERY /32 for the endpoint BEFORE resolving
    an egress, then logged 'route left as-is' when it had none. Server traffic
    then fell into the Wintun /1 splits and the tunnel swallowed its own
    upstream - a full blackout with a log claiming all was well."""

    def _run(self, egress):
        removed = []
        added = []
        with mock.patch.dict(H._live_mode, {"v4": ["203.0.113.7"], "v6": [],
                                            "over": None,
                                            "vless_over_vpn": False,
                                            "args": None}, clear=False), \
             mock.patch.object(H, "_direct_bypass_egress",
                               return_value=egress), \
             mock.patch.object(H, "_remove_host_routes_v4",
                               side_effect=lambda p: removed.append(p)), \
             mock.patch.object(H, "add_v4",
                               side_effect=lambda p, i, g, metric=1: (
                                   added.append(p) or True)), \
             mock.patch.object(H, "get_ipv6_default", return_value=None):
            ok, lines = H._live_switch_vless(False)
        return ok, lines, removed, added

    def test_no_egress_never_deletes_the_endpoint_route(self):
        ok, lines, removed, added = self._run(None)
        self.assertEqual(removed, [],
                         "the /32 was deleted but could not be re-added")
        self.assertEqual(added, [])
        self.assertFalse(ok)

    def test_successful_switch_adds_without_a_destructive_pre_clean(self):
        ok, lines, removed, added = self._run(("Wi-Fi", "192.168.1.1"))
        self.assertTrue(ok)
        self.assertEqual(removed, [],
                         "add_v4 replaces a drifted same-prefix copy, so a "
                         "pre-clean is unnecessary AND destructive")
        self.assertEqual(added, ["203.0.113.7/32"])

    def test_message_no_longer_claims_the_route_was_left_alone(self):
        _ok, lines, _removed, _added = self._run(None)
        joined = " ".join(lines)
        self.assertNotIn("left as-is", joined)
        self.assertIn("left untouched", joined)


# ═══════════════════════════════════════════════════════════════════════
# 1.5  The geo ledger must be written BEFORE the routes are installed
# ═══════════════════════════════════════════════════════════════════════

class TestGeoRepointLedgerOrdering(unittest.TestCase):
    """The rewrite sat at the END of _repoint_geo_routes - after the install
    and after the delete - leaving a multi-second window in which thousands of
    live routes were in NO ledger. A teardown arriving there cleared the
    ledger and no sweep could ever find them again."""

    def setUp(self):
        H.geoip_added.clear()

    def tearDown(self):
        H.geoip_added.clear()

    def test_rows_are_tracked_before_the_batch_runs(self):
        H.geoip_added.append(("v4", "203.0.113.0/24", "Wi-Fi", "192.168.1.1"))
        seen = {}

        def _batch(rows):
            seen["rows"] = list(H.geoip_added)
            return len(rows)

        with mock.patch.object(H, "_repoint_geo_batch", side_effect=_batch), \
             mock.patch.object(H, "_remove_routes_bulk"), \
             mock.patch.object(H, "get_ipv6_default", return_value=None):
            H._repoint_geo_routes("Wi-Fi", "Wi-Fi", "10.0.0.1")

        # At the moment the install ran, the NEW row must already be tracked.
        self.assertTrue(any(r[1] == "203.0.113.0/24" and r[3] == "10.0.0.1"
                            for r in seen.get("rows", [])),
                        f"new route was not tracked before install: "
                        f"{seen.get('rows')}")

    def test_partial_failure_rolls_back_and_keeps_the_originals(self):
        rows = [("v4", "203.0.113.0/24", "Wi-Fi", "192.168.1.1")]
        H.geoip_added.extend(rows)
        with mock.patch.object(H, "_repoint_geo_batch", return_value=0), \
             mock.patch.object(H, "_remove_routes_bulk") as rm, \
             mock.patch.object(H, "get_ipv6_default", return_value=None):
            moved = H._repoint_geo_routes("Wi-Fi", "Wi-Fi", "10.0.0.1")
        self.assertEqual(moved, 0)
        rm.assert_not_called()
        # The ORIGINAL row must remain tracked, so cleanup and the next
        # check can still see it.
        self.assertIn(rows[0], list(H.geoip_added))

    def test_v6_rows_survive_when_there_is_no_v6_egress(self):
        """With no usable IPv6 egress new_rows is v4-only; the old code still
        deleted every v6 row, so country IPv6 silently re-entered the tunnel
        and the ledger forgot it could ever be there."""
        rows = [("v4", "203.0.113.0/24", "Wi-Fi", "192.168.1.1"),
                ("v6", "2001:db8::/32", "Wi-Fi", "")]
        H.geoip_added.extend(rows)
        with mock.patch.object(H, "_repoint_geo_batch", return_value=1), \
             mock.patch.object(H, "_remove_routes_bulk") as rm, \
             mock.patch.object(H, "get_ipv6_default", return_value=None):
            H._repoint_geo_routes("Wi-Fi", "Wi-Fi", "10.0.0.1")
        deleted = [r[0][0] for r in rm.call_args_list]
        self.assertNotIn("v6", deleted,
                         "v6 rows were deleted with no v6 replacement")
        self.assertIn(rows[1], list(H.geoip_added),
                      "the untouched v6 row must stay tracked")


# ═══════════════════════════════════════════════════════════════════════
# 1.7  Control-file addresses reach netsh; they must be validated first
# ═══════════════════════════════════════════════════════════════════════

class TestLiveApplyServersValidatesAddresses(unittest.TestCase):
    """The control file is user-writable and read by the ELEVATED helper, and
    its endpoint IPs went into f"{ip}/32" with no validation - while DNS values
    on the same channel had gone through _validated_dns() all along."""

    def _run(self, endpoints):
        added = []
        with mock.patch.dict(H._live_mode, {
                "hosts": ["a.example"],
                "v4": [], "v6": [], "vpn_routes": [], "vpn_pending": [],
                "vless_over_vpn": False, "no_vpn_bypass": True,
                "over": None, "args": None, "phys": ("Wi-Fi", "192.168.1.1"),
                "phys6": None}, clear=False), \
             mock.patch.object(H, "_direct_bypass_egress",
                               return_value=("Wi-Fi", "192.168.1.1")), \
             mock.patch.object(H, "add_v4", side_effect=(
                 lambda p, i, g, metric=1: (added.append(p) or True))), \
             mock.patch.object(H, "_remove_host_routes_v4"), \
             mock.patch.object(H, "_live_set_vpn_shadow", return_value=False), \
             mock.patch.object(H, "get_ipv6_default", return_value=None):
            lines = H._live_apply_servers(["a.example"], endpoints)
        return added, lines

    def test_injected_shell_metacharacters_never_reach_a_route(self):
        added, lines = self._run({"a.example": {
            "v4": ["1.2.3.4; start-process calc.exe"],
            "v6": []}})
        # The value IS named in the log - reporting a rejected address is the
        # point. What must never happen is it reaching a netsh command.
        self.assertEqual(added, [])
        self.assertTrue(any("invalid" in ln for ln in lines))

    def test_wrong_family_is_rejected(self):
        added, lines = self._run({"a.example": {
            "v4": ["not-an-ip"],
            "v6": ["1.2.3.4"]}})          # v4 literal in the v6 list
        self.assertEqual(added, [],
                         "a wrong-family or unparseable address was installed")
        self.assertTrue(any("invalid" in ln for ln in lines))

    def test_valid_addresses_still_pass_through(self):
        added, _lines = self._run({"a.example": {
            "v4": ["1.2.3.4"],
            "v6": ["2001:db8::1"]}})
        self.assertIn("1.2.3.4/32", added)

    def test_non_string_values_cannot_explode(self):
        added, lines = self._run({"a.example": {
            "v4": [7, None, {"x": 1}], "v6": []}})
        self.assertEqual(added, [])

    def test_malformed_input_is_reported_rather_than_silently_dropped(self):
        _added, lines = self._run({"a.example": {
            "v4": ["1.2.3.4", "evil'; Write-Output 'pwned"], "v6": []}})
        self.assertTrue(any("invalid" in ln for ln in lines),
                        "a rejected address must be visible in the log")


# ═══════════════════════════════════════════════════════════════════════
# 2.1 / 2.2  _raw_add_route: store=active, and a normalised on-link next hop
# ═══════════════════════════════════════════════════════════════════════

class TestRawAddRoute(unittest.TestCase):
    def _cmd(self, **kw):
        with mock.patch.object(H, "run", return_value=(0, "", "")) as r:
            H._raw_add_route(**kw)
        return r.call_args[0][0]

    def test_store_is_active_by_default(self):
        """netsh add route DEFAULTS TO PERSISTENT. The Wintun override shadows
        therefore survived a reboot as registry rows pointing at an adapter
        that no longer existed, and no generic sweep covers them."""
        cmd = self._cmd(fam="v4", dest="10.0.0.0/8", iface="wintun",
                        gateway="192.168.1.1", metric=1)
        self.assertIn("store=active", cmd)

    def test_restore_path_uses_persistent(self):
        cmd = self._cmd(fam="v4", dest="10.0.0.0/8", iface="Shirazu-VPN",
                        gateway="10.99.0.1", metric=1, store="persistent")
        self.assertIn("store=persistent", cmd)

    def test_on_link_next_hop_is_normalised_away(self):
        """vpn_saved_routes stores the RAW Get-NetRoute NextHop, which for an
        IKEv2/L2TP VPN is '0.0.0.0' or '::'. netsh rejects that as a token, so
        the restore silently failed and the user's VPN lost its routes."""
        for raw in ("0.0.0.0", "::", "", None):
            with self.subTest(raw=raw):
                cmd = self._cmd(fam="v4", dest="10.0.0.0/8",
                                iface="Shirazu-VPN", gateway=raw, metric=1)
                self.assertNotIn("0.0.0.0", cmd[7:],
                                 f"on-link {raw!r} reached netsh verbatim")

    def test_real_gateway_is_preserved(self):
        cmd = self._cmd(fam="v4", dest="10.0.0.0/8", iface="Shirazu-VPN",
                        gateway="10.99.205.162", metric=1)
        self.assertIn("10.99.205.162", cmd)


# ═══════════════════════════════════════════════════════════════════════
# 2.3  Endpoint checks must be family-correct
# ═══════════════════════════════════════════════════════════════════════

class TestEndpointFamilyCorrectness(unittest.TestCase):
    """verify_endpoints_off_tun hardcoded f"{ip}/32" + get_existing_v4_routes,
    so an IPv6 endpoint built '2001:db8::1/32' and asked about it in IPv4 -
    always empty, always a reported problem, and the heal could not fix it.
    Any machine whose VPN ServerAddress is IPv6 showed a permanent false
    "TUNNEL DEGRADED"."""

    def test_prefix_and_lookup_match_the_family(self):
        prefix, lookup = H._endpoint_prefix_and_lookup("2001:db8::1")
        self.assertEqual(prefix, "2001:db8::1/128")
        self.assertIs(lookup, H.get_existing_v6_routes)
        prefix, lookup = H._endpoint_prefix_and_lookup("1.2.3.4")
        self.assertEqual(prefix, "1.2.3.4/32")
        self.assertIs(lookup, H.get_existing_v4_routes)

    def test_v6_endpoints_are_tracked_at_all(self):
        with mock.patch.dict(H._live_mode, {
                "v4": ["203.0.113.7"], "v6": ["2001:db8::1"],
                "vpn_routes": [], "vpn_pending": []}, clear=False):
            ips = H._tracked_endpoint_ips()
        self.assertIn("2001:db8::1", ips)
        self.assertIn("203.0.113.7", ips)

    def test_pending_endpoints_are_visible_to_the_loop_guard(self):
        with mock.patch.dict(H._live_mode, {
                "v4": [], "v6": [], "vpn_routes": [],
                "vpn_pending": [("v4", "185.64.178.62/32")]}, clear=False):
            self.assertIn("185.64.178.62", H._tracked_endpoint_ips())


# ═══════════════════════════════════════════════════════════════════════
# 2.4  The gateway monitor must normalise the on-link next hop
# ═══════════════════════════════════════════════════════════════════════

class TestGatewayChangeNormalisation(unittest.TestCase):
    """get_ipv4_default() returns NextHop verbatim, and for a DHCP-less/static
    adapter that is literally '0.0.0.0'. Everything downstream normalises
    through _norm_v4_gw, so the monitor saw a change where there was none -
    and then COMMITTED the unnormalised value, so the next real change matched
    no row and the endpoint /32 was never re-pointed."""

    def test_on_link_default_does_not_look_like_a_change(self):
        with mock.patch.object(H, "get_ipv4_default",
                               return_value=("Wi-Fi", "0.0.0.0")), \
             mock.patch.dict(H._live_mode, {"phys": ("Wi-Fi", "")}, clear=False), \
             mock.patch.object(H, "_repoint_pinned_routes") as pp, \
             mock.patch.object(H, "_repoint_geo_routes") as _geo, \
             mock.patch.object(H, "get_ipv6_default", return_value=None), \
             mock.patch.object(H, "_gw_pending", None), \
             mock.patch.object(H, "_gw_pending_since", 0.0):
            # First call only arms the debounce.
            H._check_gateway_change()
            pp.assert_not_called()
            _geo.assert_not_called()
            # The committed value must be the NORMALISED one, or the NEXT
            # real change matches no row and the endpoint /32 is never
            # re-pointed. Read INSIDE the patch.dict block.
            self.assertEqual(H._live_mode.get("phys"), ("Wi-Fi", ""))


# ═══════════════════════════════════════════════════════════════════════
# 2.5  A bounded probe must actually be bounded
# ═══════════════════════════════════════════════════════════════════════

class TestProbeMultiIsActuallyBounded(unittest.TestCase):
    """`with ThreadPoolExecutor(...)` calls shutdown(wait=True) on __exit__,
    which blocks until EVERY worker finishes - so the documented timeout+5
    bought nothing. With plain UDP/53 unable to cross the tunnel (the normal
    state for a SOCKS5 client with no UDP relay) one wedged resolver froze the
    entire monitor loop: no heal, no gateway re-point, no recovery."""

    def test_wedged_worker_does_not_stall_the_call(self):
        import threading
        release = threading.Event()

        def _wedged(_url, timeout=1):
            release.wait(30)          # never answers within the bound
            return False, "never"

        try:
            with mock.patch.object(H, "_probe_tunnel_once", side_effect=_wedged):
                t = threading.Thread(
                    target=H._probe_tunnel_multi,
                    args=(1, ["http://a/", "http://b/"]))
                t.daemon = True
                t.start()
                t.join(timeout=8)
                self.assertFalse(t.is_alive(),
                                 "_probe_tunnel_multi blocked past its own "
                                 "timeout - the 'with' block voided it")
        finally:
            release.set()

    def test_a_fast_success_is_still_reported(self):
        with mock.patch.object(H, "_probe_tunnel_once",
                               return_value=(True, "")):
            ok, msg = H._probe_tunnel_multi(2, ["http://a/"])
        self.assertTrue(ok)


# ═══════════════════════════════════════════════════════════════════════
# 2.6  DoH registration must be verified, not assumed
# ═══════════════════════════════════════════════════════════════════════

class TestDohRegistrationIsVerified(unittest.TestCase):
    """-ErrorAction SilentlyContinue made the ordinary failures
    NON-TERMINATING, so execution fell through to DOH_OK and the catch could
    never fire. The caller then reported "Wintun DNS set to DoH" while
    resolution was still raw UDP/53 into a TUN with no UDP relay."""

    def _register(self, ps_output):
        # run_ps returns (code, out, err) - out is the SECOND element.
        with mock.patch.object(H, "run_ps", return_value=(0, ps_output, "")):
            return H._register_doh_server("1.1.1.1",
                                          "https://cloudflare-dns.com/dns-query")

    def test_not_registered_is_a_failure(self):
        self.assertFalse(self._register("DOH_FAIL:not registered: 1.1.1.1"))

    def test_registered_is_a_success(self):
        self.assertTrue(self._register("DOH_OK"))

    def test_the_script_asks_the_os_rather_than_trusting_the_call(self):
        with mock.patch.object(H, "run_ps",
                               return_value=(0, "DOH_OK", "")) as r:
            H._register_doh_server("1.1.1.1", "https://x/dns-query")
        script = r.call_args[0][0]
        self.assertIn("Get-DnsClientDohServer", script,
                      "the verdict must come from the OS, not the exit code "
                      "of a cmdlet told to stay quiet")


# ═══════════════════════════════════════════════════════════════════════
# 2.10  A teardown must not be abortable
# ═══════════════════════════════════════════════════════════════════════

class TestTeardownIsIndivisible(unittest.TestCase):
    def test_step_contains_keyboardinterrupt(self):
        """except Exception does not catch KeyboardInterrupt or SystemExit,
        and both are documented live in this module - so an interrupt during
        any teardown step skipped every remaining one, and the casualty is
        specifically the DNS guard (the metric restore runs first)."""
        ran = []
        for exc in (KeyboardInterrupt, SystemExit, ValueError):
            with self.subTest(exc=exc.__name__):
                H._step("t", lambda e=exc: (_ for _ in ()).throw(e("x")))
                ran.append(exc)
        self.assertEqual(len(ran), 3)

    def test_cleanup_latches_against_re_entrance(self):
        """The guard lived in _on_signal only, so `atexit.register(cleanup)` -
        a second entry point with no guard - could re-enter, and the repeat
        Ctrl+C then os._exit(0)'d out of the OUTER pass mid-sweep."""
        seen = []
        H.cleaned = False
        H._cleanup_in_progress = False
        H.tun_proc = None
        H.tun2_proc = None
        H.wintun_saved_metric = None
        H.vpn_saved_routes[:] = []
        H.vpn_override_routes[:] = []
        H.added_routes[:] = []
        H.geoip_added[:] = []
        with mock.patch.object(H, "remove_route", side_effect=lambda i: None), \
             mock.patch.object(H, "_remove_routes_bulk",
                               side_effect=lambda rows: seen.append(list(rows))), \
             mock.patch.object(H, "_raw_add_route"), \
             mock.patch.object(H, "restore_physical_metric"), \
             mock.patch.object(H, "_remove_dns_guard"), \
             mock.patch.object(H, "_stop_geo_installer"), \
             mock.patch.object(H, "_drop_control_file"):
            H.cleanup()
            bulk_after_first = len(seen)
            H.cleanup()          # must be a no-op
        self.assertEqual(len(seen), bulk_after_first,
                         "a second cleanup() re-ran the whole sweep")
        H.cleaned = False
        H._cleanup_in_progress = False

    def test_latch_is_released_so_a_later_run_is_possible(self):
        """The latch blocks CONCURRENT/recursive entry, not future calls -
        `cleaned` is what makes a finished teardown redundant. Leaving it set
        would also strand it on if the pass raised."""
        H.cleaned = False
        H._cleanup_in_progress = True
        try:
            H.cleanup()          # must return immediately, not hang
        finally:
            H.cleaned = False
            H._cleanup_in_progress = False


# ═══════════════════════════════════════════════════════════════════════
# 2.15  HTTP 204 has no body - that is the success case
# ═══════════════════════════════════════════════════════════════════════

class TestGenerate204IsASuccess(unittest.TestCase):
    """connectivitycheck.gstatic.com/generate_204 answers 204 No Content by
    design, and urlopen does not raise for it. It is the FIRST entry in
    _VERIFY_URLS precisely because it is fast - scoring it as a failure meant
    the most reliable endpoint could never succeed, burning the whole round
    and returning DEGRADED on a tunnel that was carrying packets."""

    class _Resp:
        def __init__(self, status):
            self.status = status
            self.headers = {}

        def read(self, _n):
            return b""

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def test_204_with_no_body_passes(self):
        with mock.patch("socket.getaddrinfo", return_value=[
                (2, 1, 6, "", ("1.2.3.4", 443))]), \
             mock.patch("urllib.request.urlopen",
                        return_value=self._Resp(204)):
            ok, msg = H._probe_tunnel_once(
                "http://connectivitycheck.gstatic.com/generate_204", timeout=2)
        self.assertTrue(ok, msg)

    def test_200_with_a_real_body_passes(self):
        class _Body:
            status = 200
            headers = {}

            def read(self, _n):
                return b" 203.0.113.9 "

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        with mock.patch("socket.getaddrinfo", return_value=[
                (2, 1, 6, "", ("1.2.3.4", 443))]), \
             mock.patch("urllib.request.urlopen", return_value=_Body()):
            ok, msg = H._probe_tunnel_once("https://api.ipify.org/", timeout=2)
        self.assertTrue(ok, msg)
        self.assertIn("203.0.113.9", msg)

    def test_empty_body_on_a_body_expecting_endpoint_still_fails(self):
        with mock.patch("socket.getaddrinfo", return_value=[
                (2, 1, 6, "", ("1.2.3.4", 443))]), \
             mock.patch("urllib.request.urlopen",
                        return_value=self._Resp(200)):
            ok, msg = H._probe_tunnel_once("https://api.ipify.org/", timeout=2)
        self.assertFalse(ok)
        self.assertIn("empty body", msg)


# ═══════════════════════════════════════════════════════════════════════
# 2.11  --live-bypass must validate the egress it pins to
# ═══════════════════════════════════════════════════════════════════════

class TestLiveBypassValidatesEgress(unittest.TestCase):
    """It took get_ipv4_default() RAW, whose last-resort clause can
    legitimately return the VPN - so a user who asked for a DIRECT bypass got
    one pinned onto their corporate VPN, logged as a success. main() wraps the
    same call in physical_egress() and refuses it."""

    def test_refuses_when_no_physical_egress_can_be_validated(self):
        with mock.patch.object(H, "is_admin", return_value=True), \
             mock.patch.object(H, "wait_for_tun", return_value=True), \
             mock.patch.object(H, "physical_egress", return_value=None), \
             mock.patch.object(H, "add_v4") as add:
            with self.assertRaises(SystemExit):
                H.do_live_bypass(mock.Mock(
                    bypass_ip=["1.2.3.4"], server=[], vless_over_vpn=False))
        add.assert_not_called()

    def test_vpn_exclusion_follows_the_mode_flag(self):
        args = mock.Mock(bypass_ip=["1.2.3.4"], server=[],
                         vless_over_vpn=False)
        with mock.patch.object(H, "is_admin", return_value=True), \
             mock.patch.object(H, "wait_for_tun", return_value=True), \
             mock.patch.object(H, "physical_egress",
                               return_value=("Wi-Fi", "192.168.1.1")), \
             mock.patch.object(H, "resolve_all_safe",
                               return_value=(["1.2.3.4"], None)), \
             mock.patch.object(H, "get_ipv6_default", return_value=None), \
             mock.patch.object(H, "add_v4", return_value=True), \
             mock.patch.object(H, "get_egress_for",
                               return_value=("Wi-Fi", "192.168.1.1")) as eg:
            H.do_live_bypass(args)
        eg.assert_called()
        self.assertTrue(eg.call_args[1].get("exclude_vpn", False),
                        "DIRECT mode must refuse to pin onto the VPN")


# ═══════════════════════════════════════════════════════════════════════
# 3a  The geo downloader must be as strict as the updater
# ═══════════════════════════════════════════════════════════════════════

class _Payload:
    """A successful (small) geoip download response."""

    def __init__(self, url="https://github.com/x/y.dat", data=b"geo"):
        self.headers = {"Content-Length": str(len(data))}
        self.url = url
        self._d = data
        self._done = False

    def read(self, n):
        if self._done:
            return b""
        self._done = True
        return self._d

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestGeoDownloaderTransport(unittest.TestCase):
    """It used bare urlopen - no TLS floor, no redirect allow-list, no size
    cap - while the updater in the same project has had all three."""

    def setUp(self):
        import tempfile
        self.dir = tempfile.mkdtemp()

    def _dest(self, name="g.dat"):
        return os.path.join(self.dir, name)

    def test_off_host_url_is_refused_before_any_socket(self):
        with mock.patch.object(geoip._GEO_OPENER, "open") as op:
            with self.assertRaises(ValueError):
                geoip.download_geoip(self._dest(),
                                     url="http://evil.example/g.dat",
                                     sha_url=None)
        op.assert_not_called()

    def test_redirect_landing_off_host_is_refused(self):
        with mock.patch.object(geoip._GEO_OPENER, "open",
                               return_value=_Payload(
                                   url="https://evil.example/g.dat")):
            with self.assertRaises(ValueError):
                geoip.download_geoip(self._dest(), sha_url=None)

    def test_unusable_checksum_fails_closed_by_default(self):
        """A geo CIDR decides what leaves the machine unencrypted, so an
        unverifiable database must not be installed. It used to fail OPEN."""
        dest = self._dest()

        def _open(req, timeout=30):
            if req.full_url.endswith(".sha256sum"):
                return _Payload(url=req.full_url, data=b"not-a-digest")
            return _Payload(url=req.full_url)

        with mock.patch.object(geoip._GEO_OPENER, "open", side_effect=_open):
            with self.assertRaises(ValueError):
                geoip.download_geoip(dest)
        self.assertFalse(os.path.exists(dest),
                         "an unverifiable database was installed anyway")

    def test_strict_checksum_can_be_relaxed_deliberately(self):
        dest = self._dest("relaxed.dat")

        def _open(req, timeout=30):
            if req.full_url.endswith(".sha256sum"):
                return _Payload(url=req.full_url, data=b"not-a-digest")
            return _Payload(url=req.full_url)

        with mock.patch.object(geoip._GEO_OPENER, "open", side_effect=_open):
            size = geoip.download_geoip(dest, strict_checksum=False)
        self.assertTrue(os.path.exists(dest))
        self.assertEqual(size, 3)

    def test_a_matching_checksum_installs(self):
        import hashlib
        dest = self._dest("good.dat")
        digest = hashlib.sha256(b"geo").hexdigest()

        def _open(req, timeout=30):
            if req.full_url.endswith(".sha256sum"):
                return _Payload(url=req.full_url,
                                data=f"{digest}  geoip.dat\n".encode())
            return _Payload(url=req.full_url)

        with mock.patch.object(geoip._GEO_OPENER, "open", side_effect=_open):
            geoip.download_geoip(dest)
        self.assertTrue(os.path.exists(dest))

    def test_a_mismatched_checksum_is_fatal(self):
        dest = self._dest("bad.dat")

        def _open(req, timeout=30):
            if req.full_url.endswith(".sha256sum"):
                return _Payload(url=req.full_url,
                                data=("0" * 64 + "\n").encode())
            return _Payload(url=req.full_url)

        with mock.patch.object(geoip._GEO_OPENER, "open", side_effect=_open):
            with self.assertRaises(ValueError):
                geoip.download_geoip(dest)
        self.assertFalse(os.path.exists(dest))

    def test_oversized_content_is_refused(self):
        dest = self._dest("huge.dat")
        big = _Payload()
        big.headers = {"Content-Length": str(geoip.GEO_MAX_BYTES + 1)}
        with mock.patch.object(geoip._GEO_OPENER, "open", return_value=big):
            with self.assertRaises(ValueError):
                geoip.download_geoip(dest, sha_url=None)
        self.assertFalse(os.path.exists(dest))


# ═══════════════════════════════════════════════════════════════════════
# 3b  The live catch-all rule must never be deleted, not even briefly
# ═══════════════════════════════════════════════════════════════════════

class TestGuardWritesBeforeItDeletes(unittest.TestCase):
    """install_script must keep a catch-all rule installed CONTINUOUSLY.

    Two implementations got this wrong, in order:

    1. It deleted every TunTop-* key FIRST and only then wrote the
       replacement, so on every self-heal, [N] DNS change and VPN-shadow pass
       there was a window with no rule at all - i.e. exactly the leak the guard
       exists to close, reopened on a schedule the tunnel itself drives.
    2. It staged the replacement under `TunTop-Match.new` and then did
       `Remove-Item` on the LIVE key followed by `Move-Item`. That narrowed
       the window to the two statements between them and nothing more - the
       delete was load-bearing for the swap, because `Move-Item -Force`
       cannot overwrite an existing directory - so the gap survived the fix
       and the README row claiming it was "verified" was untrue.

    The current script writes the five values IN PLACE onto `TunTop-Match`,
    which `New-Item -Force` opens whether or not it exists. The rule is
    therefore never absent, only ever refreshed.
    """

    def test_the_live_catch_all_key_is_never_removed(self):
        s = dns_guard.install_script(["8.8.8.8"], [".local"])
        for gone in ("Remove-Item -Path $k",
                     "Move-Item -Path $matchNew",
                     "$matchNew",
                     "TunTop-Match.new"):
            self.assertNotIn(gone, s,
                             f"the swap-based install is back ({gone!r}): the "
                             "live catch-all is deleted before its "
                             "replacement exists, which is a leak window on "
                             "every re-assert")

    def test_values_are_written_in_place_onto_the_live_key(self):
        s = dns_guard.install_script(["8.8.8.8"], [".local"])
        self.assertIn(f"$k = Join-Path $root '{dns_guard.MATCH_KEY}'", s)
        self.assertIn("New-Item -Path $k -Force", s)
        for name in ("Version", "Name", "GenericDNSServers",
                     "ConfigOptions", "Comment"):
            self.assertIn(f"New-ItemProperty -Path $k -Name '{name}'", s,
                          f"the {name} value is no longer written in place")

    def test_the_stale_sweep_never_candidates_the_live_key(self):
        """The sweep is retained - it is what deletes a stale exemption key,
        and what clears a .new left by a pre-1.0.51 run - but it must exclude
        the rule that was just written, or a refresh deletes its own pin."""
        s = dns_guard.install_script(["8.8.8.8"], [".local"])
        sweep = s.split("Get-ChildItem -Path $root", 1)[1]
        self.assertIn(f"-ne '{dns_guard.MATCH_KEY}'", sweep)
        self.assertIn(f"-ne '{dns_guard.EXEMPT_LOCAL_KEY}'", sweep)
        self.assertLess(s.find("New-ItemProperty -Path $k"),
                        s.find("Get-ChildItem -Path $root"),
                        "the sweep still runs before the rule is refreshed")

    def test_a_refresh_keeps_the_exemption_key_continuous_too(self):
        s = dns_guard.install_script(["8.8.8.8"], [".local"])
        self.assertIn(f"$ex = Join-Path $root '{dns_guard.EXEMPT_LOCAL_KEY}'",
                      s)
        self.assertIn("New-Item -Path $ex -Force", s)


# ═══════════════════════════════════════════════════════════════════════
# 3c  Foreign-TUN detection must use the shared classifier
# ═══════════════════════════════════════════════════════════════════════

class TestForeignTunDetectionUsesSharedPattern(unittest.TestCase):
    """One script still filtered on -match 'Wintun' while every other
    classifier had moved to TUN_DRIVER_RE - so it missed every competing TUN
    not built on the Wintun driver and let start proceed. That is the 'Throne's
    sing-tun Tunnel owned 176.0.0.0/4 and the dashboard never saw it' class of
    bug the shared pattern was introduced to close."""

    def test_script_carries_the_shared_driver_regex(self):
        with mock.patch.object(H, "ps_json", return_value=[]) as pj:
            H.get_foreign_tun_adapters()
        script = pj.call_args[0][0]
        self.assertNotIn("-match 'Wintun'", script,
                         "the hardcoded Wintun-only filter is back")
        self.assertIn("sing-tun", script, "TUN_DRIVER_RE is not in the script")
        self.assertIn("InterfaceType -eq 131", script,
                      "the IfType 131 fallback is missing too")


# ═══════════════════════════════════════════════════════════════════════
# Source-level guards for the two 10k/5k-line files
# ═══════════════════════════════════════════════════════════════════════

def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


class TestSourceLevelGuards(unittest.TestCase):
    def test_dashboard_quashes_the_resolver_before_the_clear_check(self):
        """[Q] never set _stopping, so the bypass resolver kept installing
        /32s during the teardown, and the verify loop only counts routes on the
        WINTUN adapter - so a direct /32 on the physical NIC was invisible to
        it and the panel said "Routes cleared - safe to quit"."""
        import tuntop.ui.dashboard as D
        src = _read(D.__file__)
        start = src.find("def _shutdown_with_progress")
        self.assertGreater(start, 0)
        end = src.find("\n    def ", start + 10)
        body = src[start:end if end > 0 else start + 20000]
        quiesce = body.find("self._stopping.set()")
        check = body.find("verified clear")
        self.assertGreater(quiesce, 0,
                           "the teardown never quiesces its writers")
        self.assertGreater(check, quiesce,
                           "the writers must be quiesced BEFORE the clear "
                           "check, not after it")

    def test_ctrl_c_cannot_abort_a_teardown_step(self):
        """The console handler returns False, so the default action still
        raises KeyboardInterrupt on the teardown thread. `except Exception`
        did not catch it, so it unwound out of the loop, skipped every
        remaining step, and main() printed 'cleaned up' having swept nothing."""
        import tuntop.ui.dashboard as D
        src = _read(D.__file__)
        start = src.find("def _shutdown_with_progress")
        end = src.find("\n    def ", start + 10)
        body = src[start:end if end > 0 else start + 20000]
        self.assertIn("except KeyboardInterrupt", body)

    def test_start_never_launches_a_second_helper(self):
        """_managed_start concluded the machine was 'stranded' and
        force-reset it WITHOUT checking self.proc, so a recovery-thread race
        with [S] produced two tun2socks, two adapters, and an orphan that
        self.proc no longer pointed at - so nothing could ever kill it."""
        import tuntop.ui.dashboard as D
        src = _read(D.__file__)
        start = src.find("def _managed_start")
        self.assertGreater(start, 0)
        end = src.find("\n    def ", start + 10)
        body = src[start:end if end > 0 else start + 8000]
        gate = body.find("self.proc is not None")
        reset = body.find("self.tunnel.reset")
        self.assertGreater(gate, 0, "_managed_start must check self.proc")
        self.assertGreater(reset, 0, "the force-reset is gone")
        self.assertLess(gate, reset,
                        "the liveness gate must come before the force-reset")

    def test_bypass_health_check_fails_when_the_route_is_absent(self):
        """Get-NetRoute piped into % {'routed'} emits nothing when there is no
        such route, PowerShell exits 0, and routing._ps turns empty output
        into (True, 'No result') - so the one row that proves traffic goes
        AROUND the tunnel was permanently green."""
        import tuntop.ui.dashboard as D
        src = _read(D.__file__)
        self.assertNotIn(
            "-DestinationPrefix '{prefix}' -ErrorAction SilentlyContinue | % "
            "{'routed'}", src)
        self.assertIn("no route for {prefix}", src)

    def test_vpn_bypass_hosts_are_in_the_startup_sweep(self):
        """vpn_bypass_ip was swept by the hard-kill watchdog and the [Q]
        cleanup but MISSING from _startup_hosts - the one host-route class no
        startup recovery could ever match."""
        import tuntop.ui.dashboard as D
        src = _read(D.__file__)
        start = src.find("_startup_hosts = list")
        self.assertGreater(start, 0)
        body = src[start:start + 1200]
        self.assertIn("vpn_bypass_ip", body)


# ═══════════════════════════════════════════════════════════════════════
# 2.16  urlopen() accepts ANY scheme - these three paths accept http(s) only
# ═══════════════════════════════════════════════════════════════════════

class TestUrlOpenSchemeGuards(unittest.TestCase):
    """B310 is the one class of bandit finding NOT skipped in bandit.yaml,
    because each of its three call sites can say what it accepts. urlopen
    resolves file:, ftp: and data: as readily as https:, and two of the three
    URLs are assembled from configuration (the DoH endpoint, the download
    target), so the guard IS the audit and the inline B310 suppression points
    back at it. Every test here asserts the opener is NEVER reached - a guard
    that still calls urlopen has audited nothing."""

    NON_HTTP = ("file:///C:/Windows/win.ini", "ftp://example.com/x",
                "data:text/plain,hello", "//example.com/x", "")

    class _Resp:
        def __init__(self, status):
            self.status = status
            self.headers = {}

        def read(self, _n):
            return b""

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def test_probe_refuses_a_non_http_url(self):
        for url in self.NON_HTTP:
            with self.subTest(url=url), \
                 mock.patch("urllib.request.urlopen") as opener:
                ok, msg = H._probe_tunnel_once(url, timeout=1)
            self.assertFalse(ok)
            self.assertIn("not http(s)", msg)
            opener.assert_not_called()

    def test_probe_still_accepts_http_and_https(self):
        # The guard must not cost the 204 endpoint its success case.
        for url in ("https://api.ipify.org/",
                    "http://connectivitycheck.gstatic.com/generate_204"):
            with self.subTest(url=url), \
                 mock.patch("socket.getaddrinfo", return_value=[
                     (2, 1, 6, "", ("1.2.3.4", 443))]), \
                 mock.patch("urllib.request.urlopen",
                            return_value=self._Resp(204)):
                ok, msg = H._probe_tunnel_once(url, timeout=2)
            self.assertTrue(ok, msg)

    def test_doh_query_refuses_a_non_http_endpoint(self):
        import tuntop.network.dns as D
        for endpoint in self.NON_HTTP:
            with self.subTest(endpoint=endpoint), \
                 mock.patch("urllib.request.urlopen") as opener:
                self.assertEqual(
                    D._dns_query_doh("example.com", 1, endpoint), [])
            opener.assert_not_called()

    def test_download_to_refuses_a_non_http_url(self):
        import tuntop.ui.dashboard as D
        dest = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "never-written.bin")
        for url in self.NON_HTTP:
            with self.subTest(url=url), \
                 mock.patch("urllib.request.urlopen") as opener:
                with self.assertRaises(ValueError):
                    D._download_to(url, dest)
            opener.assert_not_called()
        self.assertFalse(os.path.exists(dest),
                         "the refusal happened after the file was opened")


if __name__ == "__main__":
    unittest.main()

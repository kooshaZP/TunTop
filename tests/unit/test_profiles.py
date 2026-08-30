"""Unit tests for tuntop.profiles - profile persistence, export, import.

Pure stdlib, no Windows calls.
"""
import json
import os
import tempfile
import unittest

from tuntop.profiles import (
    profile_file, snapshot_from_args, load_store, save_snapshot,
    apply_to_args, export_profile, import_profile, secret_store,
    SecretStoreError, PROFILE_FILENAME,
)


class _FakeArgs:
    """Minimal argparse-like namespace for testing."""
    def __init__(self, **kw):
        self.server = kw.get("server", ["1.2.3.4"])
        self.port = kw.get("port", 10808)
        self.dns4 = kw.get("dns4", "8.8.8.8")
        self.endpoint_port = kw.get("endpoint_port", 443)
        self.bypass_ip = kw.get("bypass_ip", [])
        self.geoip = kw.get("geoip", None)
        self.geoip_code = kw.get("geoip_code", "cn")
        self.vless_over_vpn = kw.get("vless_over_vpn", False)
        self.no_vpn_bypass = kw.get("no_vpn_bypass", False)
        self.vpn_interface = kw.get("vpn_interface", None)


class TestProfileFile(unittest.TestCase):
    def test_path(self):
        self.assertEqual(profile_file("/pkg"),
                         os.path.join("/pkg", PROFILE_FILENAME))

    def test_default_filename_is_branded(self):
        self.assertEqual(PROFILE_FILENAME, "MyTunTopProfile.json")


class TestSnapshotFromArgs(unittest.TestCase):
    def test_basic(self):
        ns = _FakeArgs(server=["1.1.1.1"], port=9999)
        snap = snapshot_from_args(ns)
        self.assertEqual(snap["server"], ["1.1.1.1"])
        self.assertEqual(snap["port"], 9999)
        self.assertIn("dns4", snap)
        self.assertIn("geoip_code", snap)

    def test_empty_server(self):
        ns = _FakeArgs(server=[])
        snap = snapshot_from_args(ns)
        self.assertEqual(snap["server"], [])


class TestLoadStore(unittest.TestCase):
    def test_missing(self):
        data, err = load_store("/nonexistent/path.json")
        self.assertEqual(data, {})
        self.assertEqual(err, "missing")

    def test_valid(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                         delete=False) as f:
            json.dump({"home": {"port": 9999}}, f)
            path = f.name
        try:
            data, err = load_store(path)
            self.assertIsNone(err)
            self.assertEqual(data["home"]["port"], 9999)
        finally:
            os.unlink(path)


class TestSaveSnapshot(unittest.TestCase):
    def test_save_and_load(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "profiles.json")
        snap = {"server": ["1.1.1.1"], "port": 5000}
        ok, msg = save_snapshot(path, "test", snap)
        self.assertTrue(ok)
        self.assertIn("saved", msg)
        data, err = load_store(path)
        self.assertIsNone(err)
        self.assertEqual(data["test"]["port"], 5000)
        os.unlink(path)
        os.rmdir(d)

    def test_empty_name(self):
        ok, msg = save_snapshot("/tmp/x.json", "", {})
        self.assertFalse(ok)
        self.assertIn("Empty", msg)


class TestApplyToArgs(unittest.TestCase):
    def test_basic(self):
        ns = _FakeArgs()
        snap = {"port": 7777, "dns4": "1.1.1.1", "server": ["5.5.5.5"]}
        applied = apply_to_args(ns, snap)
        self.assertEqual(ns.port, 7777)
        self.assertEqual(ns.dns4, "1.1.1.1")
        self.assertEqual(ns.server, ["5.5.5.5"])
        self.assertIn("port", applied)


class TestExportProfile(unittest.TestCase):
    def test_export_and_import(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "my_profile.json")
        snap = {"server": ["8.8.8.8"], "port": 10808}

        ok, msg = export_profile(path, "work", snap)
        self.assertTrue(ok)
        self.assertIn("exported", msg)

        name, loaded, err = import_profile(path)
        self.assertIsNone(err)
        self.assertEqual(name, "work")
        self.assertEqual(loaded["server"], ["8.8.8.8"])

        os.unlink(path)
        os.rmdir(d)

    def test_export_empty_name(self):
        ok, msg = export_profile("/tmp/x.json", "", {})
        self.assertFalse(ok)
        self.assertIn("Empty", msg)


class TestImportProfile(unittest.TestCase):
    def test_missing_file(self):
        name, snap, err = import_profile("/nonexistent/profile.json")
        self.assertIsNone(name)
        self.assertIsNone(snap)
        self.assertIn("not found", err.lower())

    def test_corrupt_file(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "bad.json")
        with open(path, "w") as f:
            f.write("not json")
        name, snap, err = import_profile(path)
        self.assertIsNone(name)
        self.assertIsNotNone(err)
        os.unlink(path)
        os.rmdir(d)

    def test_valid_envelope(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "ok.json")
        envelope = {"name": "home", "snapshot": {"port": 8080}}
        with open(path, "w") as f:
            json.dump(envelope, f)
        name, snap, err = import_profile(path)
        self.assertIsNone(err)
        self.assertEqual(name, "home")
        self.assertEqual(snap["port"], 8080)
        os.unlink(path)
        os.rmdir(d)

    def test_missing_name_field(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "noname.json")
        with open(path, "w") as f:
            json.dump({"snapshot": {"port": 1}}, f)
        name, snap, err = import_profile(path)
        self.assertIsNone(name)
        self.assertIsNotNone(err)
        self.assertIn("name", err.lower())
        os.unlink(path)
        os.rmdir(d)

    def test_missing_snapshot_field(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "nosnap.json")
        with open(path, "w") as f:
            json.dump({"name": "x"}, f)
        name, snap, err = import_profile(path)
        self.assertIsNone(name)
        self.assertIsNotNone(err)
        self.assertIn("snapshot", err.lower())
        os.unlink(path)
        os.rmdir(d)


class TestSecretStore(unittest.TestCase):
    """Secrets must never be written to the shareable JSON profile. On a
    platform without a protected store (e.g. CI / non-Windows) any attempt
    to persist a secret must fail loudly rather than fall back to plaintext.
    """

    def test_unavailable_store_refuses_to_persist(self):
        if secret_store.available():
            self.skipTest("protected store present on this platform")
        with self.assertRaises(SecretStoreError):
            secret_store.put("vless-key", "super-secret-uuid")

    def test_unavailable_store_reports_unavailable(self):
        self.assertEqual(secret_store.available(),
                         os.name == "nt" and
                         __import__("tuntop.profiles", fromlist=["_HAS_WINCRED"])
                         ._HAS_WINCRED)


if __name__ == "__main__":
    unittest.main()

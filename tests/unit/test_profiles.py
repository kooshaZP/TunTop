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
    DEFAULT_KEY, delete_profile, set_default_profile, get_default_profile,
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

class TestDefaultAndDelete(unittest.TestCase):
    """The default (auto-load) profile marker and profile deletion -
    v1.0.17: profiles can be deleted from the [I] picker and one profile
    can be marked DEFAULT so it auto-loads on every start."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = profile_file(self.dir)

    def _save(self, name, server="1.2.3.4"):
        ok, _ = save_snapshot(self.path, name, {"server": [server],
                                                "port": 10808})
        self.assertTrue(ok)

    def test_no_default_initially(self):
        self._save("home")
        self.assertIsNone(get_default_profile(self.path))

    def test_set_and_clear_default(self):
        self._save("home")
        ok, _ = set_default_profile(self.path, "home")
        self.assertTrue(ok)
        self.assertEqual(get_default_profile(self.path), "home")
        ok, msg = set_default_profile(self.path, None)
        self.assertTrue(ok)
        self.assertIsNone(get_default_profile(self.path))
        self.assertIn("cleared", msg)

    def test_default_must_exist(self):
        ok, msg = set_default_profile(self.path, "ghost")
        self.assertFalse(ok)
        self.assertIn("does not exist", msg)

    def test_default_survives_other_saves(self):
        self._save("home")
        set_default_profile(self.path, "home")
        self._save("work", "5.6.7.8")
        self.assertEqual(get_default_profile(self.path), "home")

    def test_delete_removes_profile(self):
        self._save("home")
        self._save("work", "5.6.7.8")
        ok, _ = delete_profile(self.path, "home")
        self.assertTrue(ok)
        data, err = load_store(self.path)
        self.assertIsNone(err)
        self.assertNotIn("home", data)
        self.assertIn("work", data)

    def test_delete_missing_is_a_noop(self):
        ok, msg = delete_profile(self.path, "ghost")
        self.assertFalse(ok)
        self.assertIn("does not exist", msg)

    def test_deleting_default_clears_auto_load(self):
        self._save("home")
        set_default_profile(self.path, "home")
        ok, msg = delete_profile(self.path, "home")
        self.assertTrue(ok)
        self.assertIn("was the default", msg)
        self.assertIsNone(get_default_profile(self.path))

    def test_default_key_is_reserved(self):
        ok, msg = save_snapshot(self.path, DEFAULT_KEY, {"server": []})
        self.assertFalse(ok)
        self.assertIn("reserved", msg)
        # ...and can never be deleted/set as a "profile".
        ok, _ = delete_profile(self.path, DEFAULT_KEY)
        self.assertFalse(ok)
        ok, _ = set_default_profile(self.path, DEFAULT_KEY)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()

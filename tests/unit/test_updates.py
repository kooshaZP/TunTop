"""Offline regression tests for tuntop.config.updates (GitHub release
auto-update, 1.0.33).

No network: every fetch is intercepted at urllib.request.urlopen, so the
verification pipeline (version gating, asset selection, checksum parse,
SHA-256 match, PE header, staging semantics) is exercised in isolation.

Run:  python -m unittest tests.unit.test_updates -v
"""
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

import urllib.error

from tuntop.config import updates


def _exe_blob():
    # Minimal but real x64 PE: 'MZ' + e_lfanew at 0x3C -> 'PE\0\0' + machine
    # 0x8664 at offset+4.
    blob = bytearray(b"MZ" + b"\x00" * 0x3A)
    blob += (0x40).to_bytes(4, "little")
    blob += b"PE\0\0" + (0x8664).to_bytes(2, "little") + b"\x00" * 8
    return bytes(blob)


def _release(version="9.9.9"):
    tag = "v" + version
    return {
        "tag_name": tag,
        "draft": False,
        "prerelease": False,
        "assets": [
            {"name": "TunTop.exe",
             "browser_download_url": "https://github.com/kooshaZP/TunTop/"
                                     f"releases/download/{tag}/TunTop.exe"},
            {"name": "checksums.txt",
             "browser_download_url": "https://github.com/kooshaZP/TunTop/"
                                     f"releases/download/{tag}/checksums.txt"},
        ],
    }


def _checksums(blob):
    # The EXACT line format build_release.write_checksums emits:
    # "<sha256>  <name>  (<size> bytes)"
    return (f"{hashlib.sha256(blob).hexdigest()}  TunTop.exe  "
            f"({len(blob):,} bytes)\n").encode()


class _FakeResp:
    def __init__(self, payload, status=200):
        self._buf = io.BytesIO(payload)
        self.status = status

    def read(self, n=-1):
        return self._buf.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestCheckLatest(unittest.TestCase):
    def test_newer_release_reports_update(self):
        rel = _release("9.9.9")
        body = json.dumps(rel).encode()

        def fake_urlopen(req, timeout=None):
            if "api.github.com" in req.full_url:
                return _FakeResp(body)
            raise AssertionError("unexpected fetch " + req.full_url)

        with mock.patch.object(updates.urllib.request, "urlopen", fake_urlopen):
            info = updates.check_latest("1.0.32")
        self.assertTrue(info["update_available"])
        self.assertEqual(info["version"], "9.9.9")
        self.assertTrue(info["exe_url"].endswith("/TunTop.exe"))

    def test_same_or_older_version_is_no_update(self):
        body = json.dumps(_release("1.0.32")).encode()
        with mock.patch.object(updates.urllib.request, "urlopen",
                               lambda req, timeout=None: _FakeResp(body)):
            info = updates.check_latest("1.0.32")
        self.assertFalse(info["update_available"])
        self.assertEqual(info["version"], "1.0.32")

    def test_v_prefixed_tag_is_accepted(self):
        body = json.dumps(_release("2.0.1")).encode()
        with mock.patch.object(updates.urllib.request, "urlopen",
                               lambda req, timeout=None: _FakeResp(body)):
            info = updates.check_latest("1.0.32")
        self.assertEqual(info["version"], "2.0.1")

    def test_prerelease_is_rejected(self):
        rel = _release("9.9.9")
        rel["prerelease"] = True
        body = json.dumps(rel).encode()
        with mock.patch.object(updates.urllib.request, "urlopen",
                               lambda req, timeout=None: _FakeResp(body)):
            self.assertRaises(updates.UpdateError, updates.check_latest, "1.0.32")

    def test_missing_checksum_asset_is_rejected(self):
        rel = _release()
        rel["assets"] = rel["assets"][:1]
        body = json.dumps(rel).encode()
        with mock.patch.object(updates.urllib.request, "urlopen",
                               lambda req, timeout=None: _FakeResp(body)):
            self.assertRaises(updates.UpdateError, updates.check_latest, "1.0.32")

    def test_bad_current_version_is_rejected(self):
        self.assertRaises(updates.UpdateError, updates.check_latest, "abc")


class TestDownloadRelease(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="tuntop_upd_test_")
        self.blob = _exe_blob()
        self.addCleanup(os.rmdir_guard if False else self._cleanup)

    def _cleanup(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _install(self, blob=None, sums=None):
        blob = self.blob if blob is None else blob
        sums = _checksums(blob) if sums is None else sums
        rel = _release("9.9.9")

        def fake_urlopen(req, timeout=None):
            url = req.full_url
            if url.endswith("releases/latest"):
                return _FakeResp(json.dumps(rel).encode())
            if url.endswith("/TunTop.exe"):
                return _FakeResp(blob)
            if url.endswith("/checksums.txt"):
                return _FakeResp(sums)
            raise AssertionError("unexpected fetch " + url)

        return fake_urlopen

    def test_stages_verified_versioned_exe(self):
        with mock.patch.object(updates.urllib.request, "urlopen",
                               self._install()):
            staged = updates.prepare_update("1.0.32", self.tmp)
        self.assertIsNotNone(staged)
        self.assertEqual(staged.version, "9.9.9")
        name = os.path.basename(staged.path)
        self.assertTrue(name.startswith("TunTop-9.9.9"))
        self.assertTrue(name.endswith(".exe"))
        self.assertEqual(os.path.dirname(os.path.abspath(staged.path)),
                         os.path.abspath(self.tmp))
        with open(staged.path, "rb") as f:
            self.assertEqual(hashlib.sha256(f.read()).hexdigest(), staged.sha256)
        self.assertEqual([n for n in os.listdir(self.tmp)
                          if n.startswith("tuntop_upd_")], [])

    def test_up_to_date_returns_none(self):
        rel = _release("1.0.32")
        body = json.dumps(rel).encode()
        with mock.patch.object(updates.urllib.request, "urlopen",
                               lambda req, timeout=None: _FakeResp(body)):
            self.assertIsNone(updates.prepare_update("1.0.32", self.tmp))

    def test_checksum_mismatch_leaves_nothing_behind(self):
        bad_sums = f"TunTop.exe  {'0' * 64}\n".encode()
        with mock.patch.object(updates.urllib.request, "urlopen",
                               self._install(sums=bad_sums)):
            self.assertRaises(updates.UpdateError,
                              updates.prepare_update, "1.0.32", self.tmp)
        self.assertEqual([n for n in os.listdir(self.tmp)
                          if not n.startswith("tuntop_upd_")], [])

    def test_not_a_pe_is_rejected(self):
        with mock.patch.object(updates.urllib.request, "urlopen",
                               self._install(blob=b"not an executable")):
            self.assertRaises(updates.UpdateError,
                              updates.prepare_update, "1.0.32", self.tmp)

    def test_32bit_pe_is_rejected(self):
        blob = bytearray(_exe_blob())
        off = int.from_bytes(blob[0x3C:0x40], "little")
        blob[off + 4:off + 6] = (0x014C).to_bytes(2, "little")
        with mock.patch.object(updates.urllib.request, "urlopen",
                               self._install(blob=bytes(blob))):
            self.assertRaises(updates.UpdateError,
                              updates.prepare_update, "1.0.32", self.tmp)

    def test_oversized_exe_is_rejected(self):
        with mock.patch.object(updates, "_MAX_EXE_BYTES", 16):
            with mock.patch.object(updates.urllib.request, "urlopen",
                                   self._install()):
                self.assertRaises(updates.UpdateError,
                                  updates.prepare_update, "1.0.32", self.tmp)

    def test_existing_identical_stage_is_reused(self):
        with mock.patch.object(updates.urllib.request, "urlopen",
                               self._install()):
            first = updates.prepare_update("1.0.32", self.tmp)
            second = updates.prepare_update("1.0.32", self.tmp)
        self.assertEqual(first.path, second.path)

    def test_existing_conflicting_stage_is_rejected(self):
        with mock.patch.object(updates.urllib.request, "urlopen",
                               self._install()):
            updates.prepare_update("1.0.32", self.tmp)
        other = bytearray(_exe_blob())
        other[-1] ^= 0xFF
        with mock.patch.object(updates.urllib.request, "urlopen",
                               self._install(blob=bytes(other))):
            self.assertRaises(updates.UpdateError,
                              updates.prepare_update, "1.0.32", self.tmp)

    def test_offline_returns_none(self):
        def offline(req, timeout=None):
            raise urllib.error.URLError("no network")

        with mock.patch.object(updates.urllib.request, "urlopen", offline):
            self.assertIsNone(updates.prepare_update("1.0.32", self.tmp))


if __name__ == "__main__":
    unittest.main()

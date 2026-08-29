"""Unit-tier tests for tuntop.integrity - binary SHA-256 pinning.

Temp-file based (deterministic) plus one repo-integrity test that fails
loudly if the vendored binaries and their pins ever drift apart.

Run:  python -m unittest discover -s tests -t . -v
"""
import hashlib
import os
import shutil
import tempfile
import unittest
from unittest import mock

from tuntop import integrity
from tuntop.integrity import (
    PINNED_BINARIES, STATUS_MISSING, STATUS_MISMATCH, STATUS_OK,
    locate_wintun, sha256_of, verify_file, verify_for_launch,
)


def write_temp(content: bytes, suffix: str = "") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as f:
        f.write(content)
    return path


GOOD = b"definitely the real tun2socks binary"
GOOD_SHA = hashlib.sha256(GOOD).hexdigest()
EVIL = b"definitely not the real tun2socks binary"


def make_exe(directory: str, content: bytes = GOOD,
             name: str = "tun2socks.exe") -> str:
    """A binary with a REAL name inside `directory` (pin keys match
    basenames, so 'tmpabc123.exe' would never match a pin)."""
    path = os.path.join(directory, name)
    with open(path, "wb") as f:
        f.write(content)
    return path


class TestSha256(unittest.TestCase):
    def test_known_content(self):
        path = write_temp(GOOD)
        try:
            self.assertEqual(sha256_of(path), GOOD_SHA)
        finally:
            os.unlink(path)

    def test_chunked_reading_matches_whole_file(self):
        path = write_temp(GOOD * 1000)      # > 1 MiB: exercises chunks
        try:
            self.assertEqual(sha256_of(path, chunk_size=64 * 1024),
                             hashlib.sha256(GOOD * 1000).hexdigest())
        finally:
            os.unlink(path)


class TestVerifyFile(unittest.TestCase):
    def test_ok(self):
        path = write_temp(GOOD)
        try:
            r = verify_file(path, GOOD_SHA.upper())   # case-insensitive
            self.assertEqual(r.status, STATUS_OK)
            self.assertTrue(r.ok)
            self.assertEqual(r.size, len(GOOD))
        finally:
            os.unlink(path)

    def test_mismatch(self):
        path = write_temp(EVIL)
        try:
            r = verify_file(path, GOOD_SHA)
            self.assertEqual(r.status, STATUS_MISMATCH)
            self.assertFalse(r.ok)
            self.assertEqual(r.actual, hashlib.sha256(EVIL).hexdigest())
        finally:
            os.unlink(path)

    def test_missing(self):
        r = verify_file(os.path.join(tempfile.mkdtemp(), "nope.exe"),
                        GOOD_SHA)
        self.assertEqual(r.status, STATUS_MISSING)
        self.assertFalse(r.ok)


class TestLocateWintun(unittest.TestCase):
    def test_prefers_next_to_tun2socks(self):
        d = tempfile.mkdtemp()
        dll = os.path.join(d, "wintun.dll")
        with open(dll, "wb") as f:
            f.write(b"dll")
        exe = make_exe(d)     # same dir -> candidate 1 must win...
        # ...even though the CWD (repo root) ALSO has a wintun.dll.
        try:
            self.assertEqual(locate_wintun(exe), dll)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_none_when_nowhere(self):
        empty = tempfile.mkdtemp()
        exe = make_exe(empty)
        with mock.patch.object(integrity, "__file__",
                               os.path.join(empty, "integrity.py")), \
             mock.patch("os.getcwd", return_value=empty):
            self.assertIsNone(locate_wintun(exe))


class TestVerifyForLaunch(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.exe = make_exe(self.dir)                       # tun2socks.exe
        self.dll = os.path.join(self.dir, "wintun.dll")
        with open(self.dll, "wb") as f:
            f.write(b"dll-bytes")
        self.expected = {
            "tun2socks.exe": GOOD_SHA,
            "wintun.dll": hashlib.sha256(b"dll-bytes").hexdigest(),
        }

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_ok_when_both_match(self):
        ok, reports, msgs = verify_for_launch(
            self.exe, wintun_path=self.dll, expected=self.expected)
        self.assertTrue(ok)
        self.assertTrue(all(r.status == STATUS_OK for r in reports))
        self.assertTrue(any("verified" in m for m in msgs))

    def test_mismatch_refuses_with_detail(self):
        self.expected["tun2socks.exe"] = "0" * 64
        ok, reports, msgs = verify_for_launch(
            self.exe, wintun_path=self.dll, expected=self.expected)
        self.assertFalse(ok)
        self.assertEqual(reports[0].status, STATUS_MISMATCH)
        self.assertTrue(any("MISMATCH" in m for m in msgs))
        self.assertTrue(any("Refusing" in m for m in msgs))

    def test_missing_refuses(self):
        ghost_dir = tempfile.mkdtemp()
        ok, reports, msgs = verify_for_launch(
            os.path.join(ghost_dir, "tun2socks.exe"),
            wintun_path=self.dll, expected=self.expected)
        self.assertFalse(ok)
        self.assertEqual(reports[0].status, STATUS_MISSING)

    def test_trust_bypasses_but_admits_it(self):
        self.expected["wintun.dll"] = "f" * 64
        ok, reports, msgs = verify_for_launch(
            self.exe, wintun_path=self.dll, trust=True,
            expected=self.expected)
        self.assertTrue(ok)
        self.assertEqual(reports[1].status, STATUS_MISMATCH)  # still reported
        self.assertTrue(any("UNVERIFIED" in m for m in msgs))

    def test_wintun_located_automatically(self):
        # wintun.dll sits next to tun2socks.exe (setUp put it there): the
        # default lookup must find and verify it without being told.
        ok, reports, _ = verify_for_launch(self.exe, expected=self.expected)
        self.assertTrue(ok)
        self.assertEqual(reports[1].path, self.dll)


class TestRepoPins(unittest.TestCase):
    def test_vendored_binaries_match_their_pins(self):
        # Repo root = the package's parent directory. If someone swaps a
        # vendored binary without updating PINNED_BINARIES, THIS fails.
        repo_root = os.path.dirname(os.path.dirname(
            os.path.abspath(integrity.__file__)))
        for name, pin in PINNED_BINARIES.items():
            path = os.path.join(repo_root, name)
            if not os.path.isfile(path):
                continue        # binaries not vendored in this checkout
            self.assertEqual(sha256_of(path), pin.lower(),
                             f"{name} does not match its pin - update "
                             f"PINNED_BINARIES in tuntop/integrity.py")


if __name__ == "__main__":
    unittest.main()


"""Offline tests for the AV-resilience logic in build_release.py.

Defender routinely quarantines a freshly-written unsigned onefile exe
within seconds - and verdicts land 5-30 s AFTER the write, so the old
12 s single-copy guard lost races. The new logic:
  * mirrors BOTH protected copies the moment the exe lands;
  * restores ANY vanished copy from whichever survives, repeatedly;
  * returns the best surviving artifact instead of a bare None.

All filesystem access is redirected to a temp dir; no PyInstaller, no
PowerShell, no real AV involved.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from unittest import mock

_BUILD = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "build_release.py")

_spec = importlib.util.spec_from_file_location("build_release_under_test",
                                               _BUILD)
br = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("build_release_under_test", br)
_spec.loader.exec_module(br)


class TestMirrorAndRestore(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name

    def _p(self, name):
        return os.path.join(self.root, name)

    def _write(self, name, data=b"hello"):
        p = self._p(name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def test_mirror_copies_the_file(self):
        src = self._write("src.bin")
        dst = self._p("dst.bin")
        self.assertTrue(br._mirror(src, dst))
        self.assertTrue(os.path.isfile(dst))

    def test_mirror_skips_when_dst_is_current(self):
        src = self._write("src.bin")
        dst = self._write("dst.bin")
        with mock.patch.object(br.shutil, "copy2",
                               side_effect=AssertionError("no re-copy")):
            self.assertTrue(br._mirror(src, dst))

    def test_mirror_tolerates_a_locked_dst(self):
        src = self._write("src.bin")
        dst = self._p("dst.bin")
        calls = []

        def real_copy(s, d):
            calls.append(d)
            if len(calls) < 3:
                raise PermissionError(32, "in use by AV")
            with open(d, "wb") as f:
                f.write(b"hello")
        with mock.patch.object(br.shutil, "copy2", real_copy), \
                mock.patch.object(br.time, "sleep"):
            self.assertTrue(br._mirror(src, dst))
        self.assertTrue(os.path.isfile(dst))

    def test_first_surviving_prefers_earlier_entries(self):
        gone = self._p("gone.bin")
        alive = self._write("alive.bin")
        self.assertEqual(br._first_surviving([None, gone, alive]), alive)
        self.assertIsNone(br._first_surviving([None, gone]))

    def test_restore_all_recreates_every_missing_copy(self):
        src = self._write("survivor.bin")
        gone1 = self._p("gone1.bin")
        gone2 = self._p("gone2.bin")
        n = br._restore_all([gone1, gone2], [src])
        self.assertEqual(n, 2)
        self.assertTrue(os.path.isfile(gone1) and os.path.isfile(gone2))

    def test_restore_all_with_no_source_is_a_noop(self):
        gone = self._p("gone.bin")
        self.assertEqual(br._restore_all([gone], [self._p("nope.bin")]), 0)
        self.assertFalse(os.path.isfile(gone))

    def test_restore_all_never_treats_source_as_target(self):
        src = self._write("s.bin")
        gone = self._p("gone.bin")
        n = br._restore_all([src, gone], [src])
        self.assertEqual(n, 1)          # only the genuinely missing copy


class TestGuardExeSurvivesQuarantine(unittest.TestCase):
    """_guard_exe against a simulated AV that deletes the original twice."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name
        self.old_cwd = os.getcwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, self.old_cwd)
        # _guard_exe reads the module-level DIST/ROOT constants - point them
        # at the temp dir so the test can never touch (or create files in)
        # the real repo's dist/ or root.
        os.makedirs(os.path.join(self.root, "dist"), exist_ok=True)
        self._p_d = mock.patch.object(br, "DIST", os.path.join(self.root, "dist"))
        self._p_r = mock.patch.object(br, "ROOT", self.root)
        self._p_d.start()
        self._p_r.start()
        self.addCleanup(self._p_d.stop)
        self.addCleanup(self._p_r.stop)

    def _paths(self, version="9.9.9"):
        exe = os.path.join(self.root, "dist", "TunTop.exe")
        keep = os.path.join(self.root, "dist", f"TunTop-{version}.exe")
        fall = os.path.join(self.root, f"TunTop-{version}.standalone.exe")
        return exe, keep, fall

    def _av(self, paths, kills_left):
        """Side effect: delete the FIRST existing path while kills remain."""
        def kill(*a, **k):
            if kills_left[0] <= 0:
                return
            for p in paths:
                if os.path.isfile(p):
                    os.unlink(p)
                    kills_left[0] -= 1
                    return
        return kill

    def test_all_copies_survive_a_transient_av(self):
        exe, keep, fall = self._paths()
        os.makedirs(os.path.dirname(exe), exist_ok=True)
        for p in (exe, keep, fall):
            with open(p, "wb") as f:
                f.write(b"payload")
        # AV eats the ORIGINAL after the first settle window.
        with mock.patch.object(br.time, "sleep", self._av([exe], [1])):
            result = br._guard_exe(exe, "9.9.9", timeout=3.0)
        self.assertEqual(result, exe)
        # ...and the guard restored it from a protected copy.
        self.assertTrue(os.path.isfile(exe))

    def test_returns_protected_copy_when_original_stays_dead(self):
        exe, keep, fall = self._paths()
        os.makedirs(os.path.dirname(exe), exist_ok=True)
        for p in (keep, fall):
            with open(p, "wb") as f:
                f.write(b"payload")
        # AV keeps deleting the dist/ copies; the fallback survives.
        with mock.patch.object(br.time, "sleep",
                               self._av([exe, keep], [10**6])):
            result = br._guard_exe(exe, "9.9.9", timeout=2.0)
        self.assertIsNotNone(result)
        self.assertTrue(os.path.isfile(result))

    def test_none_only_when_every_copy_is_gone(self):
        exe, keep, fall = self._paths()
        os.makedirs(os.path.dirname(exe), exist_ok=True)
        with mock.patch.object(br.time, "sleep", self._av([exe], [0])), \
                mock.patch.object(br, "_AV_HELP", ""):
            self.assertIsNone(br._guard_exe(exe, "9.9.9", timeout=1.0))


if __name__ == "__main__":
    unittest.main()


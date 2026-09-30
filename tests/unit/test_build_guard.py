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
import inspect
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


class TestOnedirIsTheDefault(unittest.TestCase):
    """1.0.51: the self-extracting onefile is no longer the default.

    The bootloader unpacks an unsigned payload to a temp dir on every start -
    the profile Defender's ML model keys on. A local 1.0.50 build was
    quarantined as Trojan:Win32/Bearfoos.A!ml mid-session, parent and four
    children, which turned a documented risk into a reproducible one.
    """

    def _parse(self, argv):
        return br.build_parser().parse_args(argv)

    def test_build_exe_defaults_to_onedir(self):
        sig = inspect.signature(br.build_exe)
        self.assertIs(sig.parameters["onedir"].default, True,
                      "build_exe() still defaults to the onefile layout that "
                      "gets quarantined")

    def test_no_flag_means_onedir(self):
        self.assertFalse(self._parse([]).onefile)

    def test_onefile_is_an_explicit_opt_out(self):
        self.assertTrue(self._parse(["--onefile"]).onefile)

    def test_contradictory_flags_are_rejected_not_silently_resolved(self):
        """--onefile --onedir has no correct interpretation. Picking one
        quietly is how a user ends up shipping the layout they were trying to
        avoid."""
        with self.assertRaises(SystemExit):
            self._parse(["--onefile", "--onedir"])

    def test_onedir_flag_still_parses_so_old_instructions_work(self):
        """--onedir was documented in the README, FAQ and release notes for
        1.0.50. It must remain a valid no-op rather than start erroring."""
        args = self._parse(["--onedir"])
        self.assertTrue(args.onedir)

    def test_the_spec_reads_onedir_through_the_env_var_not_a_cli_flag(self):
        """--onedir/--onefile are MAKESPEC options; PyInstaller rejects them
        next to a .spec file, so the choice has to travel in the environment.
        A regression here is a build that silently produces the wrong layout.
        """
        src = inspect.getsource(br.build_exe)
        self.assertIn('env["TUNTOP_SPEC_ONEDIR"] = "1"', src)
        self.assertIn('cmd.append(spec)', src)


class TestOnedirArtifactIsPublishable(unittest.TestCase):
    """The onedir artifact is a DIRECTORY. A directory is not a release asset
    and `certutil -hashfile` cannot hash a folder name - so it has to be zipped
    for download AND digested for checksums, or the one claim users are told to
    verify silently vanishes for exactly the artifact that replaced the
    quarantined exe."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name
        self._p_d = mock.patch.object(br, "DIST", os.path.join(self.root, "dist"))
        self._p_d.start()
        self.addCleanup(self._p_d.stop)

    def _tree(self):
        base = os.path.join(self.root, "dist", "TunTop")
        os.makedirs(os.path.join(base, "_internal"), exist_ok=True)
        for rel, data in (("TunTop.exe", b"exe"),
                          ("_internal/python312.dll", b"dll"),
                          ("_internal/__pycache__/m.pyc", b"pyc")):
            p = os.path.join(base, rel.replace("/", os.sep))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(data)
        return base

    def test_build_exe_returns_a_FILE_not_the_onedir_directory(self):
        """A regression found by actually running the build, not by the unit
        tests: build_exe() was made to return the onedir FOLDER, and
        main() passed that straight to _guard_exe(), which tests each copy
        with os.path.isfile(). Every copy read as missing, so a perfectly
        healthy onedir build printed the AV-quarantine help and exited 1.
        _guard_exe watches ONE file, so this must be a file."""
        src = inspect.getsource(br.build_exe)
        self.assertIn('print("  * onedir artifact: " + exe)', src)
        self.assertIn("return exe", src)
        self.assertNotIn("return os.path.dirname(exe)", src)

    def test_a_built_onedir_exe_survives_the_guard(self):
        """End of the regression above: _guard_exe on a real onedir exe must
        return it, not the quarantine message."""
        with tempfile.TemporaryDirectory() as d:
            dist = os.path.join(d, "dist")
            exe = os.path.join(dist, "TunTop", "TunTop.exe")
            os.makedirs(os.path.dirname(exe))
            with open(exe, "wb") as f:
                f.write(b"payload")
            with mock.patch.object(br, "DIST", dist), \
                    mock.patch.object(br, "ROOT", d), \
                    mock.patch.object(br.time, "sleep"):
                got = br._guard_exe(exe, "9.9.9", timeout=2.0, protect=False)
        self.assertEqual(got, exe)

    def test_the_zip_keeps_the_top_level_folder(self):
        """Users extract and run TunTop/TunTop.exe. Flattening the tree would
        scatter _internal/ across the extraction dir and the app would not
        start."""
        import zipfile
        base = self._tree()
        z = br.zip_onedir(base, "1.0.51")
        self.assertTrue(os.path.isfile(z))
        with zipfile.ZipFile(z) as zf:
            names = zf.namelist()
        self.assertIn("TunTop/TunTop.exe", names)
        self.assertIn("TunTop/_internal/python312.dll", names)

    def test_the_zip_keeps_pycache_that_the_app_requires(self):
        """EXCLUDE_PATTERNS is SOURCE-tree hygiene and must NOT be applied to
        PyInstaller output: _internal/ legitimately contains __pycache__ and
        compiled modules, and filtering them yields a zip that installs and
        then fails to start."""
        import zipfile
        base = self._tree()
        z = br.zip_onedir(base, "1.0.51")
        with zipfile.ZipFile(z) as zf:
            self.assertTrue(any("__pycache__" in n for n in zf.namelist()))

    def test_a_missing_folder_yields_no_artifact_rather_than_an_empty_zip(self):
        self.assertIsNone(br.zip_onedir(os.path.join(self.root, "nope"),
                                        "1.0.51"))

    def test_dir_digest_is_stable_and_order_independent(self):
        base = self._tree()
        first = br.dir_digest(base)
        second = br.dir_digest(base)
        self.assertEqual(first, second)
        self.assertEqual(first[2], 3)          # three files
        self.assertEqual(first[1], len(b"exe") + len(b"dll") + len(b"pyc"))

    def test_dir_digest_changes_when_any_file_changes(self):
        base = self._tree()
        before = br.dir_digest(base)
        with open(os.path.join(base, "_internal", "python312.dll"), "wb") as f:
            f.write(b"tampered")
        self.assertNotEqual(before, br.dir_digest(base))

    def test_dir_digest_changes_when_a_file_is_added(self):
        base = self._tree()
        before = br.dir_digest(base)
        with open(os.path.join(base, "leftover.pyc"), "wb") as f:
            f.write(b"stale")
        self.assertNotEqual(before, br.dir_digest(base),
                            "a stale file from a previous build would ship "
                            "inside the published hash")

    def test_a_directory_artifact_gets_a_checksum_line(self):
        """The regression this whole class exists for: write_checksums gated
        on os.path.isfile, so the onedir tree was skipped SILENTLY and
        checksums.txt promised less than the release page offered."""
        base = self._tree()
        cs = br.write_checksums("1.0.51", [base])
        text = open(cs, encoding="utf-8").read()
        self.assertIn("TunTop/", text)
        self.assertIn("3 files", text)
        digest = br.dir_digest(base)[0]
        self.assertIn(digest, text)

    def test_the_checksum_line_says_the_zip_is_what_to_hash(self):
        base = self._tree()
        text = open(br.write_checksums("1.0.51", [base]), encoding="utf-8").read()
        self.assertIn("zip", text.lower())


class TestExclusionIsNarrowedAndDeprioritised(unittest.TestCase):
    def test_the_repo_root_is_not_excluded_by_default(self):
        """A root exclusion tells Defender to stop watching every file ever
        written in the working tree. dist/ is the only path a build writes.

        Compared as QUOTED paths, not substrings: DIST is ROOT + '\\dist', so
        a plain substring test passes no matter which one is passed.
        """
        with mock.patch.object(br.subprocess, "run",
                               return_value=mock.Mock(stdout="")) as r:
            br.try_defender_exclusion()
        ps = r.call_args[0][0][-1]
        self.assertIn(f"'{br.DIST}'", ps)
        self.assertNotIn(f"'{br.ROOT}'", ps,
                         "the repo root is excluded - Defender will now ignore "
                         "every future file written in the working tree")

    def test_the_av_help_leads_with_the_layout_fix(self):
        """The recovery text used to recommend an AV exclusion FIRST, before
        the option that needs no AV configuration at all."""
        self.assertLess(br._AV_HELP.index("BEST FIX"),
                        br._AV_HELP.index("LAST RESORT"))
        self.assertIn("--onefile", br._AV_HELP)


class TestStaleArtifactsNeverShip(unittest.TestCase):
    """dist/ accumulates artifacts from every previous build. Two of them are
    actively dangerous to leave next to a fresh release."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name
        self.dist = os.path.join(self.root, "dist")
        os.makedirs(self.dist, exist_ok=True)
        self._p_d = mock.patch.object(br, "DIST", self.dist)
        self._p_d.start()
        self.addCleanup(self._p_d.stop)

    def _onefile_cleanup(self):
        """The cleanup branch of build_exe, without running PyInstaller."""
        return br._clean_onedir_output()

    def test_a_stale_onefile_is_removed(self):
        """A previous release's self-extracting dist/TunTop.exe is the exact
        artifact that gets quarantined, it is the larger of the two files
        called TunTop.exe, and nothing in dist/ says which belongs to the
        current release. A user grabbing the wrong one gets the problem this
        change exists to remove."""
        stale = os.path.join(self.dist, "TunTop.exe")
        with open(stale, "wb") as f:
            f.write(b"onefile from a previous release")
        self._onefile_cleanup()
        self.assertFalse(os.path.isfile(stale))

    def test_a_stale_onedir_tree_is_removed(self):
        """PyInstaller's COLLECT merges into an existing directory, so a file
        dropped from the spec survives into the new build - and the whole
        directory is digested as part of the release artifact, so it would ship
        INSIDE the published hash with no way to tell it was not in the
        build."""
        tree = os.path.join(self.dist, "TunTop", "_internal")
        os.makedirs(tree)
        with open(os.path.join(tree, "leftover.pyd"), "wb") as f:
            f.write(b"stale")
        self._onefile_cleanup()
        self.assertFalse(os.path.isdir(os.path.join(self.dist, "TunTop")))

    def test_the_onefile_opt_out_keeps_its_own_artifact(self):
        """--onefile rebuilds dist/TunTop.exe, so the cleanup must be scoped to
        the onedir path. Deleting it unconditionally would make the opt-out
        layout unbuildable."""
        stale = os.path.join(self.dist, "TunTop.exe")
        with open(stale, "wb") as f:
            f.write(b"current onefile")
        br._clean_onedir_output(onedir=False)
        self.assertTrue(os.path.isfile(stale))

    def test_a_locked_stale_file_does_not_fail_the_build(self):
        stale = os.path.join(self.dist, "TunTop.exe")
        with open(stale, "wb") as f:
            f.write(b"locked")
        with mock.patch.object(br.os, "remove", side_effect=PermissionError(32)):
            self._onefile_cleanup()   # must not raise
        self.assertTrue(os.path.isfile(stale))


if __name__ == "__main__":
    unittest.main()


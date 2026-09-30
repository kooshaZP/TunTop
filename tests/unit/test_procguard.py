"""Regression tests: ownership-scoped tun2socks process control.

Bug lineage: every cleanup path (helper preflight, routing._teardown_wintun,
startup recovery probes, the dashboard's teardown loop and its "tun2socks
process" health check) killed or counted BY PROCESS NAME
(`Get-Process | ? ProcessName -like 'tun2socks*'`). tun2socks is a generic
open-source tool other software legitimately runs, so TunTop's
cleanup/watchdog could terminate a foreign tun2socks.exe it never started.

tuntop.network.procguard replaces all of those with identity checks:
recorded PIDs, the exact configured --tun2socks path, or the distinctive
vendored binary name FROM a directory TunTop put it in. These tests pin the
filter's decisions - including that a generic tun2socks.exe from another
tool, and an upstream-named tun2socks-windows-amd64-v3.exe installed
elsewhere, are NEVER selected.

Run:  python -m unittest discover -s tests -t . -v
"""
import unittest
from unittest import mock

from tuntop.network import procguard


def row(pid, name="tun2socks.exe", exe=None, cmd=None):
    return {"pid": pid, "name": name, "exe": exe or "", "cmd": cmd or ""}


class TestSelectOwn(unittest.TestCase):
    """The pure ownership filter - the decisions that keep foreign
    processes alive."""

    def test_recorded_pid_is_owned(self):
        rows = [row(4242)]
        self.assertEqual([r["pid"] for r in procguard.select_own(
            rows, recorded=[4242])], [4242])

    def test_exact_configured_path_is_owned(self):
        rows = [row(11, exe="C:\\Tools\\TunTop\\tun2socks-windows-amd64-v3.exe")]
        got = procguard.select_own(
            rows, tun2socks_path="c:\\tools\\tuntop\\TUN2SOCKS-WINDOWS-AMD64-V3.EXE")
        self.assertEqual([r["pid"] for r in got], [11])

    def test_vendored_name_is_owned_regardless_of_dir(self):
        # Frozen onefile crash recovery: the child ran from a throwaway
        # extraction dir that no longer exists, so the path differs - the
        # distinctive FILE NAME still identifies it as ours.
        rows = [row(12, exe="C:\\Users\\x\\AppData\\Local\\Temp\\"
                         "_MEI123456\\tun2socks-windows-amd64-v3.exe")]
        got = procguard.select_own(rows, tun2socks_path=None)
        self.assertEqual([r["pid"] for r in got], [12])

    def test_vendored_name_outside_a_tuntop_dir_is_NOT_owned(self):
        # The vendored name is the UPSTREAM xjasonlyu/tun2socks v2.7.0
        # release asset name, so a user who installed tun2socks from its own
        # release (or a tool vendoring the same build) has a process with
        # this exact basename. Matching the name anywhere made every TunTop
        # teardown / startup recovery / watchdog sweep taskkill that
        # foreign proxy. The name only counts from a TunTop-controlled dir.
        rows = [row(14, exe="C:\\Users\\x\\Downloads\\"
                          "tun2socks-windows-amd64-v3.exe")]
        self.assertEqual(procguard.select_own(rows, tun2socks_path=None), [])

    def test_vendored_name_next_to_the_package_is_owned(self):
        # A source checkout: the binary sits next to tuntop/network/.
        import os
        import tuntop.network as _pkg
        rows = [row(15, exe=os.path.join(
            os.path.dirname(os.path.dirname(_pkg.__file__)),
            "tun2socks-windows-amd64-v3.exe"))]
        self.assertEqual([r["pid"] for r in procguard.select_own(
            rows, tun2socks_path=None)], [15])

    def test_generic_foreign_tun2socks_is_never_owned(self):
        # THE regression: another tool's plain tun2socks.exe. Not recorded,
        # not our path, not the vendored name -> must stay alive.
        rows = [row(99, exe="D:\\OtherTool\\tun2socks.exe")]
        self.assertEqual(procguard.select_own(
            rows, tun2socks_path="C:\\TunTop\\tun2socks-windows-amd64-v3.exe"), [])
        self.assertEqual(procguard.select_own(rows, recorded=[4242]), [])

    def test_unrelated_process_ignored_even_if_pid_recorded(self):
        # A recorded PID that has since been reused by a non-tun2socks
        # image must not be killed (the name gate runs first).
        rows = [row(4242, name="notepad.exe", exe="C:\\Windows\\notepad.exe")]
        self.assertEqual(procguard.select_own(rows, recorded=[4242]), [])

    def test_no_path_is_never_owned_without_a_recorded_pid(self):
        """An unreadable path proves NOTHING about location, so it is not ours.

        The old body of this test asserted the opposite - that a
        pathless vendored-named process IS selected - which is precisely the
        bug: CIM reports an empty ExecutablePath exactly when it cannot open
        the process (another user, elevated), so that clause selected the
        processes whose identity could not be established, and killed a
        foreign upstream proxy on every teardown. The inline comment it
        implemented said "recorded PIDs only" while the code matched any
        name; rule 1 already claims recorded PIDs and `continue`s, so a
        pathless row can only ever be ours via a recorded PID.
        """
        rows = [row(13, name="tun2socks-windows-amd64-v3.exe", exe="")]
        self.assertEqual(procguard.select_own(rows), [])
        # ...and a generic pathless name was never ours either.
        rows2 = [row(14, name="tun2socks.exe", exe="")]
        self.assertEqual(procguard.select_own(rows2), [])
        # Rule 1 still rescues it: this PID came from our own Popen handle.
        self.assertEqual([r["pid"] for r in
                          procguard.select_own(rows, recorded=[13])], [13])

    def test_a_path_normalized_to_empty_is_not_owned(self):
        """A path that exists but cannot be normalized must not become
        '' and thereby satisfy the old `not exe_norm` escape hatch."""
        rows = [row(21, name="tun2socks-windows-amd64-v3.exe",
                    exe="C:\\TunTop\\tun2socks-windows-amd64-v3.exe")]
        with mock.patch.object(procguard, "_norm", return_value=""):
            self.assertEqual(procguard.select_own(rows), [])
            # ...still ours via a recorded PID, since rule 1 runs first.
            self.assertEqual([r["pid"] for r in
                              procguard.select_own(rows, recorded=[21])], [21])

    def test_temp_and_cwd_are_not_tuntop_owned_locations(self):
        """%TEMP% and the launch directory are user-controlled, not
        TunTop-controlled.

        %TEMP% is shared with every other application (v2rayN/xray/nekoray
        unpack their vendored copies into temp dirs by design), and the
        working directory is wherever the user happened to be - also the
        most common place to drop a downloaded tool. Both used to be in
        _tuntop_owned_locations, so a foreign upstream-named tun2socks
        sitting in either was treated as TunTop's and killed. The frozen
        case those entries were meant to cover is matched exactly by
        _MEI_RE instead.
        """
        import os
        locs = procguard._tuntop_owned_locations()
        for env in ("TEMP", "TMP"):
            tmp = os.environ.get(env)
            if tmp:
                self.assertNotIn(tmp.replace("\\", "/").rstrip("/").lower(),
                                 locs)
        # The CWD is no longer consulted at all. Running the tests from the
        # repo root would otherwise pass trivially, because that root is a
        # genuine owned location via app_root - so point the CWD somewhere
        # unrelated and require that it still confers no ownership.
        unrelated = os.path.join(os.sep, "Users", "someone", "Downloads")
        with mock.patch.object(procguard.os, "getcwd", return_value=unrelated):
            self.assertNotIn(procguard._norm_dir(unrelated),
                             procguard._tuntop_owned_locations())
        # A foreign upstream-named tun2socks in the launch directory is not
        # ours - this is the case that used to be selected for killing.
        rows = [row(41, exe=os.path.join(
            unrelated, "tun2socks-windows-amd64-v3.exe"))]
        with mock.patch.object(procguard.os, "getcwd", return_value=unrelated):
            self.assertEqual(procguard.select_own(rows), [])

    def test_app_root_is_an_owned_location(self):
        """The coverage the CWD entry used to provide is now structural:
        a git checkout keeps its binaries at the repo root, one level above
        the package, and that root is derived from __file__ - not from
        whatever directory the launcher happened to Set-Location into."""
        import os
        import tuntop.network as _pkg
        repo_root = os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.abspath(_pkg.__file__))))
        self.assertIn(procguard._norm_dir(repo_root),
                      procguard._tuntop_owned_locations())
        rows = [row(31, exe=os.path.join(
            repo_root, "tun2socks-windows-amd64-v3.exe"))]
        self.assertEqual([r["pid"] for r in
                          procguard.select_own(rows)], [31])

    def test_empty_rows(self):
        self.assertEqual(procguard.select_own([]), [])
        self.assertEqual(procguard.select_own(None), [])

    def test_absolute_windows_paths_normalize_the_same_on_every_host(self):
        """A drive-qualified path is already absolute, so it must NOT be
        resolved against the process's working directory.

        `os.path.abspath` leaves it alone on Windows but prepends the CWD on
        POSIX, which made the location test's verdict depend on the test
        runner's working directory - untestable off Windows, and untestable
        honestly anywhere. This asserts the cross-host property the
        docstring claims, from two different working directories.
        """
        import os
        p = r"C:\v2rayN\bin\tun2socks-windows-amd64-v3.exe"
        results = []
        for cwd in (r"C:\somewhere", "/tmp", os.getcwd()):
            with mock.patch.object(procguard.os, "getcwd", return_value=cwd):
                results.append(procguard._norm(p))
        self.assertEqual(len(set(results)), 1, results)
        self.assertEqual(results[0],
                         "c:/v2rayn/bin/tun2socks-windows-amd64-v3.exe")

    def test_a_foreign_absolute_windows_path_is_not_owned(self):
        # Now assertable directly on Linux, which is the point of the above.
        rows = [row(51, exe=r"D:\v2rayN\bin\tun2socks-windows-amd64-v3.exe")]
        self.assertEqual(procguard.select_own(rows), [])


class TestCountAndKill(unittest.TestCase):
    def test_count_own_uses_filter(self):
        # Our vendored binary sitting in a PyInstaller extraction dir is
        # ours; the foreign one in D:\foreign is not.
        rows = [row(1, exe="C:\\Users\\x\\AppData\\Local\\Temp\\_MEI1234\\"
                          "tun2socks-windows-amd64-v3.exe"),
                row(2, exe="D:\\foreign\\tun2socks.exe")]
        with mock.patch.object(procguard, "enumerate_tun2socks",
                               return_value=rows):
            self.assertEqual(procguard.count_own(), 1)

    def test_count_ignores_upstream_binary_in_a_download_dir(self):
        rows = [row(1, exe="C:\\Users\\x\\Downloads\\"
                          "tun2socks-windows-amd64-v3.exe")]
        with mock.patch.object(procguard, "enumerate_tun2socks",
                               return_value=rows):
            self.assertEqual(procguard.count_own(), 0)

    def test_kill_own_targets_only_owned(self):
        rows = [row(1, exe="C:\\Users\\x\\AppData\\Local\\Temp\\_MEI1234\\"
                          "tun2socks-windows-amd64-v3.exe"),
                row(2, exe="D:\\foreign\\tun2socks.exe")]
        calls = []
        with mock.patch.object(procguard, "enumerate_tun2socks",
                               return_value=rows), \
             mock.patch.object(procguard.subprocess, "call",
                               side_effect=lambda argv, **k:
                               calls.append(argv) or 0):
            n = procguard.kill_own(log=lambda m: None)
        self.assertEqual(n, 1)
        # Exactly one victim (our vendored exe), and it is the owned PID -
        # never the foreign tun2socks.exe in the same enumeration.
        self.assertEqual(calls, [["taskkill", "/F", "/T", "/PID", "1"]])


class TestTeardownDelegates(unittest.TestCase):
    """routing._teardown_wintun must kill through procguard - never by
    process name again."""

    def test_teardown_wintun_uses_kill_own(self):
        import tuntop.network.routing as routing
        with mock.patch.object(procguard, "kill_own",
                               return_value=2) as ko, \
             mock.patch.object(routing, "_ps", return_value=(True, "")):
            routing._teardown_wintun()
        self.assertTrue(ko.called)

    def test_no_name_based_kill_left_in_sources(self):
        # Source hygiene: the literal name-based kill/count patterns must
        # not reappear anywhere under tuntop/ (the `$_.ProcessName` form is
        # the CODE shape; procguard's docstring quotes the console alias
        # form and is deliberately not matched).
        import os
        root = os.path.join(os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__)))), "tuntop")
        bad = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d != "__pycache__"]
            for fn in filenames:
                if not fn.endswith(".py"):
                    continue
                with open(os.path.join(dirpath, fn), encoding="utf-8") as f:
                    src = f.read()
                if "$_.ProcessName -like 'tun2socks" in src.replace('"', "'"):
                    bad.append(os.path.join(dirpath, fn))
        self.assertEqual(
            bad, [],
            "name-based tun2socks kill crept back in: %r" % bad)


if __name__ == "__main__":
    unittest.main()


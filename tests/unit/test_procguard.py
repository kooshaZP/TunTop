"""Regression tests: ownership-scoped tun2socks process control.

Bug lineage: every cleanup path (helper preflight, routing._teardown_wintun,
startup recovery probes, the dashboard's teardown loop and its "tun2socks
process" health check) killed or counted BY PROCESS NAME
(`Get-Process | ? ProcessName -like 'tun2socks*'`). tun2socks is a generic
open-source tool other software legitimately runs, so TunTop's
cleanup/watchdog could terminate a foreign tun2socks.exe it never started.

tuntop.network.procguard replaces all of those with identity checks:
recorded PIDs, the exact configured --tun2socks path, or the distinctive
vendored binary name. These tests pin the filter's decisions - including
that a generic tun2socks.exe from another tool is NEVER selected.

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

    def test_no_path_falls_back_to_image_name(self):
        rows = [row(13, name="tun2socks-windows-amd64-v3.exe", exe="")]
        self.assertEqual([r["pid"] for r in procguard.select_own(rows)], [13])
        rows2 = [row(14, name="tun2socks.exe", exe="")]
        self.assertEqual(procguard.select_own(rows2), [])

    def test_empty_rows(self):
        self.assertEqual(procguard.select_own([]), [])
        self.assertEqual(procguard.select_own(None), [])


class TestCountAndKill(unittest.TestCase):
    def test_count_own_uses_filter(self):
        rows = [row(1, exe="C:\\t\\tun2socks-windows-amd64-v3.exe"),
                row(2, exe="D:\\foreign\\tun2socks.exe")]
        with mock.patch.object(procguard, "enumerate_tun2socks",
                               return_value=rows):
            self.assertEqual(procguard.count_own(), 1)

    def test_kill_own_targets_only_owned(self):
        rows = [row(1, exe="C:\\t\\tun2socks-windows-amd64-v3.exe"),
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


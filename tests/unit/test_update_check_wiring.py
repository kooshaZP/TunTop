"""Offline tests for the dashboard's update-check wiring (1.0.33, relocated in
1.0.40).

The check used to start from BTopTui.loop() as a silent background thread, so
a new release was only visible if the user scrolled the log panel. It now runs
ONCE in main()'s initial startup block - right after the binary-integrity
lines - and prints its verdict inline; only the download + SHA-256
verification continues in the background.

Asserted here: the gating (source run / BTOP_NO_UPDATE / --no-update-check),
the inline verdict per outcome, that staging really happens off-thread and is
reported with version + path + SHA-256, that the short startup timeout is the
one that reaches the network call, and that lines produced before the
dashboard exists are replayed into the log panel exactly once. No network: the
updater module is mocked.
"""
import os
import queue
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))

from tuntop.ui import dashboard
from tuntop.config.updates import StagedUpdate


class _Recorder:
    """A _StartupLogSink-compatible sink that just collects the lines."""

    def __init__(self):
        self.lines = []

    def __call__(self, msg):
        self.lines.append(msg)

    def joined(self):
        return "\n".join(self.lines)


def _args(no_update_check=False):
    return mock.Mock(no_update_check=no_update_check)


def _app():
    app = dashboard.BTopTui.__new__(dashboard.BTopTui)
    app.logs = queue.Queue()
    return app


def _drain(q):
    out = []
    while not q.empty():
        out.append(q.get_nowait())
    return out


def _info(current, version, available):
    return {"version": version, "current": current,
            "update_available": available}


class TestStartupUpdateCheckGating(unittest.TestCase):
    """Every opt-out path returns None and never touches the network."""

    def setUp(self):
        self.env = {k: v for k, v in os.environ.items()
                    if k != "BTOP_NO_UPDATE"}

    def _frozen(self):
        patcher = mock.patch("tuntop.ui.dashboard._sys")
        msys = patcher.start()
        self.addCleanup(patcher.stop)
        msys.frozen = True
        msys.executable = sys.executable
        return msys

    def test_source_run_is_skipped(self):
        """Only the packaged exe can stage an update next to itself, so a
        source run must not even ask the release feed."""
        with mock.patch("tuntop.ui.dashboard._sys") as msys:
            msys.frozen = False
            with mock.patch("tuntop.config.updates.check_latest") as chk:
                self.assertIsNone(dashboard._startup_update_check(
                    _args(), sink=_Recorder()))
        chk.assert_not_called()

    def test_frozen_run_does_check(self):
        self._frozen()
        with mock.patch.dict(os.environ, self.env, clear=True), \
                mock.patch("tuntop.config.updates.check_latest") as chk:
            chk.return_value = _info("1.0.0", "1.0.0", False)
            self.assertIsNone(dashboard._startup_update_check(
                _args(), sink=_Recorder()))
        chk.assert_called_once()

    def test_env_opt_out_is_skipped(self):
        self._frozen()
        env = dict(self.env, BTOP_NO_UPDATE="1")
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch("tuntop.config.updates.check_latest") as chk:
            self.assertIsNone(dashboard._startup_update_check(
                _args(), sink=_Recorder()))
        chk.assert_not_called()

    def test_flag_opt_out_is_skipped(self):
        self._frozen()
        with mock.patch.dict(os.environ, self.env, clear=True), \
                mock.patch("tuntop.config.updates.check_latest") as chk:
            self.assertIsNone(dashboard._startup_update_check(
                _args(no_update_check=True), sink=_Recorder()))
        chk.assert_not_called()

    def test_every_skip_says_why(self):
        """A silent skip is the old failure mode: the user must be able to
        tell that the check was skipped ON PURPOSE."""
        with mock.patch("tuntop.ui.dashboard._sys") as msys:
            msys.frozen = False
            rec = _Recorder()
            dashboard._startup_update_check(_args(), sink=rec)
        self.assertIn("skipped", rec.joined())
        self.assertIn("packaged", rec.joined())

    def test_network_failure_never_raises(self):
        """An update check must not be able to stop the launch."""
        self._frozen()
        with mock.patch.dict(os.environ, self.env, clear=True), \
                mock.patch("tuntop.config.updates.check_latest",
                           side_effect=RuntimeError("boom")):
            rec = _Recorder()
            self.assertIsNone(dashboard._startup_update_check(
                _args(), sink=rec))
        self.assertIn("boom", rec.joined())


class TestStartupUpdateCheckVerdicts(unittest.TestCase):
    def setUp(self):
        self.env = {k: v for k, v in os.environ.items()
                    if k != "BTOP_NO_UPDATE"}
        patcher = mock.patch("tuntop.ui.dashboard._sys")
        self.msys = patcher.start()
        self.addCleanup(patcher.stop)
        self.msys.frozen = True
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.msys.executable = os.path.join(self._tmp.name, "TunTop.exe")

    def _run(self, check, sink):
        with mock.patch.dict(os.environ, self.env, clear=True), \
                mock.patch("tuntop.config.updates.check_latest", check):
            return dashboard._startup_update_check(_args(), sink=sink)

    def test_up_to_date_names_the_running_version(self):
        import tuntop
        rec = _Recorder()
        with mock.patch("tuntop.config.updates.download_release") as dl:
            self.assertIsNone(self._run(
                lambda cur, timeout=None: _info(cur, cur, False), rec))
            dl.assert_not_called()
        joined = rec.joined()
        self.assertIn("newest release", joined)
        self.assertIn(tuntop.__version__, joined)

    def test_available_update_stages_off_thread(self):
        staged = StagedUpdate("9.9.9", os.path.join(self._tmp.name,
                                                    "TunTop-9.9.9.exe"),
                              "ab" * 32)
        rec = _Recorder()
        with mock.patch("tuntop.config.updates.download_release",
                        return_value=staged) as dl:
            th = self._run(
                lambda cur, timeout=None: _info(cur, "9.9.9", True), rec)
            self.assertIsNotNone(th)
            # Background: daemon thread, and the caller returns without
            # waiting for the download.
            self.assertTrue(th.daemon)
            th.join(timeout=10)
            dl.assert_called_once()
        joined = rec.joined()
        # Verdict inline, completion announced with the verifiable details.
        self.assertIn("Update 9.9.9 available", joined)
        self.assertIn("TunTop-9.9.9.exe", joined)
        self.assertIn("SHA-256", joined)
        self.assertIn("9.9.9", joined)

    def test_download_failure_is_reported_not_raised(self):
        rec = _Recorder()
        with mock.patch("tuntop.config.updates.download_release",
                        side_effect=OSError("disk gone")):
            th = self._run(
                lambda cur, timeout=None: _info(cur, "9.9.9", True), rec)
            th.join(timeout=10)
        self.assertIn("disk gone", rec.joined())

    def test_check_timeout_is_bounded_and_passed_through(self):
        seen = {}

        def _check(cur, timeout=None):
            seen["timeout"] = timeout
            return _info(cur, cur, False)

        self._run(_check, _Recorder())
        self.assertEqual(seen.get("timeout"),
                         dashboard._STARTUP_UPDATE_TIMEOUT)
        # The check runs INLINE, in front of the user: it must be bounded far
        # below the updater module's own 20 s default.
        self.assertLess(dashboard._STARTUP_UPDATE_TIMEOUT, 20)


class TestStartupLogSink(unittest.TestCase):
    """The sink bridges "the check already ran" and "the log panel now
    exists" without losing or doubling a line."""

    def setUp(self):
        self.sink = dashboard._StartupLogSink()
        # Silence the console: the sink's job here is the buffer/plumbing.
        patcher = mock.patch("builtins.print")
        self.addCleanup(patcher.stop)
        patcher.start()

    def test_lines_before_attach_are_replayed_once(self):
        self.sink("before the UI exists")
        app = _app()
        self.sink.attach(app)
        self.assertEqual(_drain(app.logs), ["before the UI exists"])
        # A second attach must not replay the buffer again.
        self.sink.attach(_app())
        self.assertEqual(_drain(app.logs), [])

    def test_lines_after_attach_go_straight_to_the_panel(self):
        app = _app()
        self.sink.attach(app)
        self.sink("after the UI exists")
        self.assertEqual(_drain(app.logs), ["after the UI exists"])

    def test_attach_is_none_safe(self):
        self.sink.attach(None)          # no dashboard - must not raise
        self.sink.attach(_app())
        self.sink("x")
        self.assertEqual(_drain(self.sink._app.logs), ["x"])

    def test_main_binds_the_shared_sink_to_the_dashboard(self):
        """The staging thread writes through the MODULE-level sink, and main()
        is what binds that same sink to the freshly built dashboard - if
        either side changed, a finished download would be invisible in the UI.
        """
        dashboard._UPDATE_SINK.reset()
        self.addCleanup(dashboard._UPDATE_SINK.reset)
        app = _app()
        dashboard._UPDATE_SINK.attach(app)
        dashboard._UPDATE_SINK("staged in the background")
        self.assertEqual(_drain(app.logs), ["staged in the background"])

    def test_a_line_racing_attach_is_never_lost(self):
        """The staging thread writes from another thread while main() is
        calling attach(). Unlocked, a producer could observe _app is None,
        then have attach() drain the buffer, then append to the
        already-drained list - and that line reached neither the console panel
        nor the replay. Drive real threads to prove none is dropped."""
        import threading
        for _ in range(40):
            sink = dashboard._StartupLogSink()
            app = _app()
            produced = []
            start = threading.Barrier(2)

            def produce():
                start.wait()
                for i in range(20):
                    msg = f"line-{i}"
                    produced.append(msg)
                    sink(msg)

            def attach():
                start.wait()
                sink.attach(app)

            t1 = threading.Thread(target=produce)
            t2 = threading.Thread(target=attach)
            t1.start()
            t2.start()
            t1.join()
            t2.join()
            got = _drain(app.logs)
            self.assertEqual(sorted(got), sorted(produced),
                             "a line produced across attach() was lost")
            self.assertEqual(len(got), len(set(got)), "a line was doubled")

    def test_a_failing_panel_does_not_kill_the_staging_thread(self):
        """The staging thread is a daemon doing the only thing that reports
        an update result; a raising log panel must not take it down."""
        class _Broken:
            class logs:
                @staticmethod
                def put(_msg):
                    raise RuntimeError("panel gone")

        self.sink.attach(_Broken())
        self.sink("survives a broken panel")   # must not raise


if __name__ == "__main__":
    unittest.main()

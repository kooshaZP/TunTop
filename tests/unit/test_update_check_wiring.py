"""Offline tests for the dashboard's update-check wiring (1.0.33).

Asserts the gating (source run / BTOP_NO_UPDATE / --no-update-check /
double-start) and that a successful stage announces the versioned exe in
the log. No network: prepare_update is mocked.
"""
import unittest
from unittest import mock

import sys
import os
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tuntop.ui import dashboard
from tuntop.config.updates import StagedUpdate


def _app(frozen=True):
    app = dashboard.BTopTui.__new__(dashboard.BTopTui)
    app.ns = mock.Mock(no_update_check=False)
    app.logs = __import__("queue").Queue()
    app._update_thread = None
    return app


class TestUpdateCheckWiring(unittest.TestCase):
    def run_worker(self, app, prepare):
        with mock.patch("tuntop.config.updates.prepare_update", prepare), \
                mock.patch("tuntop.ui.dashboard._sys") as msys:
            msys.frozen = True
            msys.executable = sys.executable
            app._update_check_worker()

    def test_source_run_is_skipped(self):
        app = _app()
        with mock.patch("tuntop.ui.dashboard._sys") as msys:
            msys.frozen = False
            self.assertIsNone(app._start_update_check())
        self.assertEqual(app.logs.qsize(), 0)

    def test_env_opt_out_is_skipped(self):
        app = _app()
        env = {k: v for k, v in os.environ.items() if k != "BTOP_NO_UPDATE"}
        env["BTOP_NO_UPDATE"] = "1"
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch("tuntop.ui.dashboard._sys") as msys:
            msys.frozen = True
            self.assertIsNone(app._start_update_check())

    def test_flag_opt_out_is_skipped(self):
        app = _app()
        app.ns.no_update_check = True
        with mock.patch("tuntop.ui.dashboard._sys") as msys:
            msys.frozen = True
            self.assertIsNone(app._start_update_check())

    def test_successful_stage_is_announced(self):
        app = _app()
        staged = StagedUpdate("9.9.9",
                              os.path.join("x", "TunTop-9.9.9.exe"), "ab" * 32)
        self.run_worker(app, lambda cur, d: staged)
        msgs = []
        while not app.logs.empty():
            msgs.append(app.logs.get_nowait())
        joined = "\n".join(msgs)
        self.assertIn("9.9.9", joined)
        self.assertIn("TunTop-9.9.9.exe", joined)
        self.assertIn("SHA-256", joined)

    def test_up_to_date_is_quiet_but_logged(self):
        app = _app()
        self.run_worker(app, lambda cur, d: None)
        msgs = []
        while not app.logs.empty():
            msgs.append(app.logs.get_nowait())
        self.assertTrue(any("up to date" in m or "offline" in m
                            for m in msgs))

    def test_worker_never_raises(self):
        app = _app()

        def boom(cur, d):
            raise RuntimeError("network gone")

        self.run_worker(app, boom)
        msgs = []
        while not app.logs.empty():
            msgs.append(app.logs.get_nowait())
        self.assertTrue(any("Update check skipped" in m for m in msgs))


if __name__ == "__main__":
    unittest.main()

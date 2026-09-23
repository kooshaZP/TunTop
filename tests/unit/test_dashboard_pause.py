import unittest

from tuntop.ui import dashboard


def _app():
    app = dashboard.BTopTui.__new__(dashboard.BTopTui)
    app.log_lines = [f"event {i}" for i in range(20)]
    app._log_snapshot = None
    app._log_scroll = 0
    app._log_hscroll = 0
    app._checks_scroll = 0
    app._checks_hscroll = 0
    app._mouse_hovered = False
    app._active_panel = "checks"
    app._hidden = set()
    app.results = []
    return app


class TestDashboardPause(unittest.TestCase):
    def test_frozen_scroll_clamps_to_history(self):
        app = _app()
        app._pause_log()
        frozen = tuple(app.log_lines)
        app.log_lines = ["replacement"]
        app._scroll_log(100)
        self.assertEqual(app._log_scroll, len(frozen) - 1)
        self.assertEqual(app._log_entries(), frozen)
        # Scrolling all the way back DOWN to the newest entry RESUMES live
        # following (bottom == live) - the 1.0.35 fix; the frozen snapshot
        # from the pause is released together with the scroll offset.
        app._scroll_log(-100)
        self.assertEqual(app._log_scroll, 0)
        self.assertIsNone(app._log_snapshot)
        self.assertEqual(app._log_entries(), app.log_lines)

    def test_up_freezes_history_before_new_logs_and_pruning(self):
        app = _app()
        original = tuple(app.log_lines)
        self.assertTrue(app._handle_key_action("up"))
        self.assertEqual(app._log_scroll, 1)
        app.log_lines.extend(f"new {i}" for i in range(300))
        app.log_lines = app.log_lines[-200:]
        self.assertEqual(app._log_entries(), original)
        self.assertEqual(app._log_scroll, 1)

    def test_k_scrolls_frozen_log_back(self):
        app = _app()
        app._mouse_hovered = True
        app._active_panel = "log"
        self.assertTrue(app._handle_key_action("k"))
        self.assertEqual(app._log_scroll, 5)
        self.assertEqual(len(app._log_entries()), 20)
        app.log_lines = ["pruned"]
        self.assertEqual(app._log_entries()[0], "event 0")

    def test_space_toggles_pause_over_live_log(self):
        app = _app()
        app._handle_key_action(" ")
        self.assertIsNotNone(app._log_snapshot)
        frozen = tuple(app.log_lines)
        app.log_lines = ["pruned"]
        self.assertEqual(app._log_entries(), frozen)
        app._handle_key_action(" ")
        self.assertIsNone(app._log_snapshot)
        self.assertEqual(app._log_scroll, 0)
        self.assertEqual(app._log_entries(), ["pruned"])

    def test_end_resumes_live_and_follows_newest(self):
        app = _app()
        app._pause_log()
        app._log_scroll = 4
        self.assertTrue(app._handle_key_action("end"))
        self.assertIsNone(app._log_snapshot)
        self.assertEqual(app._log_scroll, 0)
        app.log_lines.append("newest")
        self.assertEqual(app._log_entries()[-1], "newest")
        self.assertEqual(app._log_entries(), app.log_lines)

    def test_j_follows_newest_only_when_live(self):
        app = _app()
        self.assertTrue(app._handle_key_action("j"))
        self.assertEqual(app._log_scroll, 0)
        self.assertEqual(app._log_entries(), app.log_lines)

    def test_home_freezes_at_oldest_frozen_row(self):
        app = _app()
        self.assertTrue(app._handle_key_action("home"))
        self.assertIsNotNone(app._log_snapshot)
        self.assertEqual(app._log_scroll, len(app._log_entries()) - 1)
        app.log_lines = ["pruned"]
        self.assertEqual(app._log_entries()[0], "event 0")

    def test_scroll_log_zero_keeps_live_following(self):
        app = _app()
        app._scroll_log(0)
        self.assertIsNone(app._log_snapshot)
        self.assertEqual(app._log_entries(), app.log_lines)


if __name__ == "__main__":
    unittest.main()

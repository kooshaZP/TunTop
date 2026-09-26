"""Offline regression tests for Wintun throughput sampling."""
import json
import unittest
from unittest import mock

from tuntop.ui import dashboard


class TestWintunSpeed(unittest.TestCase):
    def _sample(self, state_ref, rx, tx, when):
        payload = json.dumps({"ReceivedBytes": rx, "SentBytes": tx})
        with mock.patch.object(dashboard, "_ps", return_value=(True, payload)), \
             mock.patch.object(dashboard.time, "time", return_value=when):
            return dashboard.get_wintun_speed(state_ref)

    def test_first_sample_establishes_baseline(self):
        state = [None]
        rx, tx, total_rx, total_tx = self._sample(state, 100, 200, 10.0)
        self.assertEqual((rx, tx, total_rx, total_tx), (0.0, 0.0, 100, 200))
        self.assertEqual(state[0], (100, 200, 10.0))

    def test_normal_delta_is_reported(self):
        state = [None]
        self._sample(state, 100, 200, 10.0)
        rx, tx, total_rx, total_tx = self._sample(state, 1100, 2200, 10.1)
        self.assertEqual(rx, 9.766)
        self.assertEqual(tx, 19.531)
        self.assertEqual((total_rx, total_tx), (1100, 2200))

    def test_implausible_positive_jump_is_discarded_and_rebaselined(self):
        state = [None]
        self._sample(state, 100, 200, 10.0)
        jump = dashboard._WINTUN_MAX_SAMPLE_DELTA + 1
        rx, tx, total_rx, total_tx = self._sample(
            state, 100 + jump, 200, 10.1)
        self.assertEqual((rx, tx, total_rx, total_tx), (0.0, 0.0, None, None))
        self.assertEqual(state[0], (100 + jump, 200, 10.1))


if __name__ == "__main__":
    unittest.main()

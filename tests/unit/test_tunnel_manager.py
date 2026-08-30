"""Unit tests for tuntop.core.tunnel_manager - the Core lifecycle facade.

Exercises the UI-facing lifecycle (start sequence, stop, startup recovery,
binary verification) with injected fakes, so no Windows / Administrator /
Wintun is required. This is the seam the dashboard must drive instead of
calling Windows internals directly (Phase 1 layering rule).

Pure stdlib, no Windows calls.
"""
import unittest
from unittest import mock

from tuntop.core.state import TunnelState, TunnelStateMachine
from tuntop.core.tunnel_manager import TunnelManager


class TestLifecycle(unittest.TestCase):
    def test_start_runs_sequence_and_verifies(self):
        calls = []
        m = TunnelStateMachine(initial=TunnelState.STOPPED)
        tm = TunnelManager(
            machine=m,
            launch=lambda: calls.append("launch"),
            teardown=lambda: calls.append("teardown"),
        )
        self.assertTrue(tm.request_start())
        # STARTING -> VERIFYING on launch; then monitors verify.
        self.assertIn(TunnelState.VERIFYING, (m.current,))
        tm.mark_verified(True)
        self.assertIs(m.current, TunnelState.RUNNING)
        self.assertEqual(calls, ["launch"])

    def test_stop_only_from_operational_or_transitioning(self):
        m = TunnelStateMachine(initial=TunnelState.RUNNING)
        tore = []
        tm = TunnelManager(machine=m, teardown=lambda: tore.append(1))
        self.assertTrue(tm.request_stop())
        self.assertIs(m.current, TunnelState.STOPPED)
        self.assertEqual(tore, [1])

    def test_start_rejected_when_already_running(self):
        m = TunnelStateMachine(initial=TunnelState.RUNNING)
        tm = TunnelManager(machine=m)
        self.assertFalse(tm.request_start())

    def test_startup_recovery_invokes_hook(self):
        ran = []
        tm = TunnelManager(startup_recover=lambda: ran.append(1))
        tm.startup_recovery()
        self.assertEqual(ran, [1])

    def test_binary_verification_gate(self):
        tm = TunnelManager(verify_binaries=lambda: False)
        self.assertFalse(tm.verify_binaries())
        tm2 = TunnelManager(verify_binaries=lambda: True)
        self.assertTrue(tm2.verify_binaries())

    def test_degraded_on_failed_verify(self):
        m = TunnelStateMachine(initial=TunnelState.VERIFYING)
        tm = TunnelManager(machine=m)
        tm.mark_verified(False, "dns unreachable")
        self.assertIs(m.current, TunnelState.DEGRADED)


if __name__ == "__main__":
    unittest.main()

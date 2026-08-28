"""Recovery tier: the crash storyline, told end to end.

Not a single-engine unit test - this walks the exact sequence a user
lives through when a machine is unstable: tunnel keeps dying, recovery
keeps restarting it with backoff, eventually the crash-loop protection
kicks in and demands a human, and a manual restart re-arms everything.

Run:  python -m unittest discover -s tests -t . -v
"""
import time
import unittest

from tunmood.recovery import FailureKind, RecoveryAction, RecoveryEngine
from tunmood.state import TunnelState, TunnelStateMachine


def wait_for(predicate, timeout=3.0, what="condition"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.005)
    raise AssertionError(f"timed out waiting for {what}")


class TestCrashLoopStoryline(unittest.TestCase):
    def setUp(self):
        self.m = TunnelStateMachine()
        self.restarts = 0
        eng = RecoveryEngine(self.m, log=self.log_append,
                             max_attempts=2, give_up_after=3,
                             delay_scale=0.0)
        self.eng = eng
        self.lines = []

    def log_append(self, line):
        self.lines.append(line)

    def crash(self):
        """The helper dying unexpectedly (the reader-thread path)."""
        self.m.try_transition(TunnelState.STOPPING, "helper process exited")
        self.m.try_transition(TunnelState.STOPPED, "helper process exited")

    def test_full_crash_loop_storyline(self):
        m, eng = self.m, self.eng

        def doomed_restart():
            """Every restart dies before it can be verified."""
            self.restarts += 1
            m.try_transition(TunnelState.STARTING, "helper relaunched")
            m.try_transition(TunnelState.STOPPED, "start failed")
            return False

        eng.register(FailureKind.PROCESS, [RecoveryAction(
            "restart the tunnel helper", repair=doomed_restart,
            verify=lambda: False)])
        eng.start()
        try:
            # --- the good old days: the tunnel actually works once ---
            m.try_transition(TunnelState.STARTING, "helper launched")
            m.try_transition(TunnelState.VERIFYING, "routes installed")
            m.try_transition(TunnelState.RUNNING, "stable")

            # --- crash #1: one verified recovery keeps faith ---
            self.crash()
            wait_for(lambda: eng.stats()["incidents"] == 1,
                     what="first incident opened")

            # --- the tunnel turns unstable: every restart dies ---
            # crash #2 -> incident 2 exhausts its 2 attempts
            self.crash()
            wait_for(lambda: eng.stats()["give_ups"] == 1,
                     what="incident 2 exhausted")
            # crash #3 -> incident 3 exhausts -> streak of 3 -> give up
            self.crash()
            wait_for(lambda: eng.gave_up, what="crash-loop protection")

            # Between give-up and now, NOTHING restarts any more.
            before = self.restarts
            self.crash()
            time.sleep(0.05)
            self.assertEqual(self.restarts, before)
            self.assertTrue(self.m.current.is_terminal)

            # The user was TOLD, clearly, what happened and what to do.
            self.assertTrue(any("DISABLED" in ln for ln in self.lines))
            self.assertTrue(any("manual intervention" in ln
                                for ln in self.lines))

            # --- the human restarts manually: engine re-arms ---
            self.m.reset("manual restart")
            self.eng.resume()
            self.assertFalse(self.eng.gave_up)
            self.m.try_transition(TunnelState.STARTING, "helper launched")
            self.m.try_transition(TunnelState.VERIFYING, "routes installed")
            self.m.try_transition(TunnelState.RUNNING, "stable")
        finally:
            eng.shutdown()

    def test_backoff_gaps_grow_across_attempts(self):
        # Drive attempts through the internal path so no real sleeping
        # happens, but keep the schedule observable in the log: the retry
        # wait after attempt N is BACKOFF_SCHEDULE[N] (2s, then 4s).
        m = TunnelStateMachine(initial=TunnelState.DEGRADED)
        lines = []
        eng = RecoveryEngine(m, log=lines.append, max_attempts=3,
                             delay_scale=1.0)
        eng.register(FailureKind.DNS, [RecoveryAction(
            "futile fix", repair=lambda: False)])
        from tunmood.recovery import _Incident
        incident = _Incident(kind=FailureKind.DNS)
        eng._in_attempt = True
        eng._incident = incident
        for _ in range(2):                    # attempts 1 and 2
            eng._run_attempt(incident)
        eng.shutdown()
        retries = [ln for ln in lines if "retrying as attempt" in ln]
        self.assertEqual(len(retries), 2)
        self.assertIn("attempt 2 in 2s", retries[0])
        self.assertIn("attempt 3 in 4s", retries[1])


if __name__ == "__main__":
    unittest.main()

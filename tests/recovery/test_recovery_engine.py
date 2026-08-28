"""Unit tests for tunmood.recovery - the recovery engine.

Deterministic: engines run with delay_scale=0.0 so backoff waits vanish,
and a poll helper absorbs worker-thread scheduling jitter. Pure stdlib.

Run:  python -m unittest discover -s tests -v
"""
import threading
import time
import unittest

from tunmood.recovery import FailureKind, RecoveryAction, RecoveryEngine
from tunmood.state import TunnelState, TunnelStateMachine


def wait_for(predicate, timeout=3.0, what="condition"):
    """Poll until predicate() is true (worker-thread jitter absorption)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.005)
    raise AssertionError(f"timed out waiting for {what}")


def make_engine(machine, **kw):
    """A started, instant (zero-delay) engine wired to a fresh machine."""
    eng = RecoveryEngine(machine, delay_scale=0.0, **kw)
    eng.start()
    return eng


class TestBackoffSchedule(unittest.TestCase):
    def test_schedule_climbs_and_caps(self):
        delays = [RecoveryEngine.delay_for_attempt(n) for n in range(1, 9)]
        self.assertEqual(delays[:6], [1, 2, 4, 8, 16, 30])
        self.assertEqual(delays[6], 30)   # capped, not exploded
        self.assertEqual(delays[7], 30)

    def test_attempt_zero_and_negative_clamp_to_first(self):
        self.assertEqual(RecoveryEngine.delay_for_attempt(0), 1)
        self.assertEqual(RecoveryEngine.delay_for_attempt(-3), 1)


class TestHappyRecovery(unittest.TestCase):
    def test_repair_success_returns_machine_to_running(self):
        m = TunnelStateMachine(initial=TunnelState.DEGRADED)
        calls = []
        eng = make_engine(m)
        eng.register(FailureKind.DNS, [RecoveryAction(
            "flush dns", repair=lambda: calls.append(1) or True)])
        try:
            eng.report_failure(FailureKind.DNS, "probe timed out")
            wait_for(lambda: m.current is TunnelState.RUNNING,
                     what="verified RUNNING")
            self.assertEqual(calls, [1])
        finally:
            eng.shutdown()

    def test_recovering_entered_during_attempt(self):
        m = TunnelStateMachine(initial=TunnelState.RUNNING)
        gate = threading.Event()
        seen_state = []

        def slow_repair():
            seen_state.append(m.current)
            gate.set()
            return True

        eng = make_engine(m)
        eng.register(FailureKind.PROCESS,
                     [RecoveryAction("restart", repair=slow_repair)])
        try:
            eng.report_failure(FailureKind.PROCESS, "helper died")
            gate.wait(3.0)
            self.assertIs(seen_state[0], TunnelState.RECOVERING)
            wait_for(lambda: m.current is TunnelState.RUNNING,
                     what="back to RUNNING")
        finally:
            eng.shutdown()

    def test_verify_rejects_bogus_repair(self):
        m = TunnelStateMachine(initial=TunnelState.DEGRADED)
        eng = make_engine(m, max_attempts=1)
        eng.register(FailureKind.DNS, [RecoveryAction(
            "lie", repair=lambda: True, verify=lambda: False)])
        try:
            eng.report_failure(FailureKind.DNS)
            # max_attempts=1: the rejected repair must end in a give-up.
            wait_for(lambda: eng.stats()["give_ups"] == 1,
                     what="give-up after failed verify")
            self.assertIs(m.current, TunnelState.DEGRADED)
        finally:
            eng.shutdown()

    def test_repair_exception_counts_as_failure(self):
        m = TunnelStateMachine(initial=TunnelState.DEGRADED)
        eng = make_engine(m, max_attempts=1)
        eng.register(FailureKind.ROUTES, [RecoveryAction(
            "boom", repair=lambda: 1 / 0)])
        try:
            eng.report_failure(FailureKind.ROUTES)
            wait_for(lambda: eng.stats()["repairs_failed"] == 1,
                     what="failure stat")
        finally:
            eng.shutdown()


class TestBackoffAndEscalation(unittest.TestCase):
    def test_failed_repair_retries_and_escalates_ladder(self):
        m = TunnelStateMachine(initial=TunnelState.DEGRADED)
        done = []
        eng = make_engine(m, max_attempts=3)
        eng.register(FailureKind.DNS, [
            RecoveryAction("light touch", repair=lambda: False),
            RecoveryAction("heavy hammer",
                           repair=lambda: done.append("hammer") or True),
        ])
        try:
            eng.report_failure(FailureKind.DNS)
            wait_for(lambda: m.current is TunnelState.RUNNING,
                     what="escalated recovery success")
            self.assertEqual(done, ["hammer"])  # rung 2 after rung 1 failed
            self.assertEqual(eng.stats()["repairs_failed"], 1)
            self.assertEqual(eng.stats()["repairs_ok"], 1)
        finally:
            eng.shutdown()

    def test_max_attempts_then_give_up_and_stay_down(self):
        m = TunnelStateMachine(initial=TunnelState.DEGRADED)
        attempts = []
        eng = make_engine(m, max_attempts=2)
        eng.register(FailureKind.DNS, [RecoveryAction(
            "futile", repair=lambda: attempts.append(1) or False)])
        try:
            eng.report_failure(FailureKind.DNS)
            wait_for(lambda: eng.stats()["give_ups"] == 1, what="give-up")
            self.assertEqual(len(attempts), 2)   # bounded, not infinite
            time.sleep(0.05)
            self.assertEqual(len(attempts), 2)   # nothing further fires
            self.assertIs(m.current, TunnelState.DEGRADED)  # stays degraded
        finally:
            eng.shutdown()

    def test_report_flood_does_not_accelerate_or_duplicate(self):
        m = TunnelStateMachine(initial=TunnelState.DEGRADED)
        attempts = []
        started = threading.Event()

        def repair():
            attempts.append(1)
            started.set()
            time.sleep(0.1)          # repair in flight while reports flood
            return True

        eng = make_engine(m)
        eng.register(FailureKind.DNS,
                     [RecoveryAction("fix", repair=repair)])
        try:
            for _ in range(50):      # scream 50 times in a tight loop
                eng.report_failure(FailureKind.DNS)
            started.wait(3.0)
            wait_for(lambda: eng.stats()["repairs_ok"] == 1,
                     what="single repair success")
            time.sleep(0.05)
            # Exactly ONE repair for the whole flood: no acceleration.
            self.assertEqual(len(attempts), 1)
        finally:
            eng.shutdown()


class TestPauseAndGiveUp(unittest.TestCase):
    def test_pause_blocks_reports(self):
        m = TunnelStateMachine(initial=TunnelState.DEGRADED)
        calls = []
        eng = make_engine(m)
        eng.register(FailureKind.DNS, [RecoveryAction(
            "fix", repair=lambda: calls.append(1) or True)])
        try:
            eng.pause("user stop")
            eng.report_failure(FailureKind.DNS)
            time.sleep(0.05)
            self.assertEqual(calls, [])
            self.assertTrue(eng.paused)
        finally:
            eng.shutdown()

    def test_resume_rearms(self):
        m = TunnelStateMachine(initial=TunnelState.DEGRADED)
        calls = []
        eng = make_engine(m)
        eng.register(FailureKind.DNS, [RecoveryAction(
            "fix", repair=lambda: calls.append(1) or True)])
        try:
            eng.pause()
            eng.resume()
            self.assertFalse(eng.paused)
            eng.report_failure(FailureKind.DNS)
            wait_for(lambda: len(calls) == 1, what="post-resume repair")
        finally:
            eng.shutdown()

    def test_crash_loop_protection_gives_up_after_streak(self):
        m = TunnelStateMachine(initial=TunnelState.STOPPED)
        eng = make_engine(m, max_attempts=1, give_up_after=2)
        calls = []
        eng.register(FailureKind.PROCESS, [RecoveryAction(
            "restart", repair=lambda: calls.append(1) or False)])
        try:
            # Incident 1: fails its single attempt.
            eng.report_failure(FailureKind.PROCESS, "crash 1")
            wait_for(lambda: eng.stats()["give_ups"] == 1,
                     what="incident 1 give-up")
            # Incident 2: also fails -> streak of 2 -> engine disables itself.
            eng.report_failure(FailureKind.PROCESS, "crash 2")
            wait_for(lambda: eng.gave_up, what="engine gave up")
            time.sleep(0.05)
            self.assertEqual(len(calls), 2)
            # A third report is ignored: no more attempts, ever.
            eng.report_failure(FailureKind.PROCESS, "crash 3")
            time.sleep(0.05)
            self.assertEqual(len(calls), 2)
        finally:
            eng.shutdown()

    def test_success_resets_consecutive_failure_streak(self):
        m = TunnelStateMachine(initial=TunnelState.STOPPED)
        eng = make_engine(m, max_attempts=1, give_up_after=2)
        eng.register(FailureKind.PROCESS, [RecoveryAction(
            "restart", repair=lambda: False)])
        try:
            eng.report_failure(FailureKind.PROCESS, "crash 1")
            wait_for(lambda: eng.stats()["give_ups"] == 1,
                     what="first failed incident")
            eng.report_success()             # tunnel got healthy
            # A new streak of 1 must NOT trip the give-up (needs 2).
            eng.report_failure(FailureKind.PROCESS, "crash 2")
            wait_for(lambda: eng.stats()["give_ups"] == 2,
                     what="second failed incident")
            self.assertFalse(eng.gave_up)    # streak was reset in between
        finally:
            eng.shutdown()


class TestValidation(unittest.TestCase):
    def test_unregistered_kind_is_ignored_with_log(self):
        m = TunnelStateMachine(initial=TunnelState.DEGRADED)
        lines = []
        eng = RecoveryEngine(m, log=lines.append, delay_scale=0.0)
        eng.start()
        try:
            eng.report_failure(FailureKind.ADAPTER, "adapter vanished")
            wait_for(lambda: any("no recovery action registered" in ln
                                 for ln in lines), what="ignore log line")
            self.assertEqual(eng.stats()["incidents"], 0)
        finally:
            eng.shutdown()

    def test_report_failure_validates_kind(self):
        eng = RecoveryEngine(TunnelStateMachine())
        with self.assertRaises(TypeError):
            eng.report_failure("dns")

    def test_max_attempts_must_be_positive(self):
        with self.assertRaises(ValueError):
            RecoveryEngine(TunnelStateMachine(), max_attempts=0)

    def test_register_rejects_empty_ladder(self):
        eng = RecoveryEngine(TunnelStateMachine())
        with self.assertRaises(ValueError):
            eng.register(FailureKind.DNS, [])

    def test_delay_override_beats_ladder_default(self):
        m = TunnelStateMachine(initial=TunnelState.DEGRADED)
        calls = []
        eng = make_engine(m)
        eng.register(FailureKind.DNS, [RecoveryAction(
            "fix", repair=lambda: calls.append(1) or True)],
            first_delay=600)             # would take 10 minutes...
        try:
            eng.report_failure(FailureKind.DNS, delay=0.01)  # ...but no
            wait_for(lambda: len(calls) == 1, what="override-delay repair")
        finally:
            eng.shutdown()

    def test_stats_snapshot(self):
        eng = RecoveryEngine(TunnelStateMachine())
        self.assertEqual(eng.stats(), {"incidents": 0, "repairs_ok": 0,
                                       "repairs_failed": 0, "give_ups": 0})


if __name__ == "__main__":
    unittest.main()



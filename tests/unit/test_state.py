"""Unit tests for tunmood.state - the tunnel state machine.

Pure stdlib (unittest), zero pip dependencies, no Windows-specific calls,
no admin rights required: they run anywhere, including CI.

Run:  python -m unittest discover -s tests -v
"""
import threading
import time
import unittest

from tunmood.state import (
    TRANSITIONS,
    StateTransition,
    TransitionError,
    TunnelState,
    TunnelStateMachine,
)


def walk(machine, *targets):
    """Drive `machine` through a sequence, asserting each step lands."""
    for target in targets:
        event = machine.transition(target, reason=f"walk->{target.value}")
        if event.target is not target or machine.current is not target:
            raise AssertionError(f"transition to {target.value} did not land")


class TestTransitionGraph(unittest.TestCase):
    def test_every_state_has_transition_entry(self):
        for state in TunnelState:
            self.assertIn(state, TRANSITIONS)

    def test_every_declared_target_is_a_state(self):
        for source, targets in TRANSITIONS.items():
            for target in targets:
                self.assertIn(target, TunnelState)
                self.assertIsInstance(target, TunnelState)

    def test_stop_sequence_is_forward_only(self):
        seq = [TunnelState.STARTING, TunnelState.RESOLVING,
               TunnelState.STARTING_TUN, TunnelState.STARTING_TUN2SOCKS,
               TunnelState.INSTALLING_ROUTES, TunnelState.VERIFYING]
        for i, phase in enumerate(seq):
            # Every later phase (skip-ahead) is legal...
            for later in seq[i + 1:]:
                self.assertIn(later, TRANSITIONS[phase])
            # ...but no earlier phase is (restart must go via STOPPING).
            for earlier in seq[:i]:
                self.assertNotIn(earlier, TRANSITIONS[phase])

    def test_operational_states_cannot_jump_to_starting(self):
        # A restart must always go through STOPPING - no shortcuts.
        for state in (TunnelState.RUNNING, TunnelState.DEGRADED,
                      TunnelState.RECOVERING):
            self.assertNotIn(TunnelState.STARTING, TRANSITIONS[state])
            self.assertIn(TunnelState.STOPPING, TRANSITIONS[state])

    def test_running_can_degrade_and_recover(self):
        self.assertIn(TunnelState.DEGRADED, TRANSITIONS[TunnelState.RUNNING])
        self.assertIn(TunnelState.RECOVERING,
                      TRANSITIONS[TunnelState.DEGRADED])
        self.assertIn(TunnelState.RUNNING,
                      TRANSITIONS[TunnelState.RECOVERING])

    def test_failed_can_retry_or_clean_up(self):
        self.assertIn(TunnelState.STARTING, TRANSITIONS[TunnelState.FAILED])
        self.assertIn(TunnelState.STOPPING, TRANSITIONS[TunnelState.FAILED])
        self.assertIn(TunnelState.STOPPED, TRANSITIONS[TunnelState.FAILED])


class TestStateCategories(unittest.TestCase):
    def test_categories(self):
        self.assertTrue(TunnelState.RUNNING.is_operational)
        self.assertTrue(TunnelState.DEGRADED.is_operational)
        self.assertFalse(TunnelState.RUNNING.is_transitioning)
        self.assertTrue(TunnelState.VERIFYING.is_transitioning)
        self.assertTrue(TunnelState.STARTING_TUN.is_transitioning)
        self.assertTrue(TunnelState.STOPPED.is_terminal)
        self.assertTrue(TunnelState.FAILED.is_terminal)
        self.assertFalse(TunnelState.FAILED.is_operational)
        self.assertFalse(TunnelState.STOPPING.is_terminal)


class TestStateMachineBasics(unittest.TestCase):
    def test_initial_state_is_stopped(self):
        m = TunnelStateMachine()
        self.assertIs(m.current, TunnelState.STOPPED)
        self.assertEqual(m.state_name, "STOPPED")

    def test_initial_state_can_be_overridden(self):
        m = TunnelStateMachine(initial=TunnelState.RUNNING)
        self.assertIs(m.current, TunnelState.RUNNING)

    def test_initial_state_type_is_validated(self):
        with self.assertRaises(TypeError):
            TunnelStateMachine(initial="RUNNING")

    def test_full_happy_path_lifecycle(self):
        m = TunnelStateMachine()
        walk(m, TunnelState.STARTING, TunnelState.RESOLVING,
             TunnelState.STARTING_TUN, TunnelState.STARTING_TUN2SOCKS,
             TunnelState.INSTALLING_ROUTES, TunnelState.VERIFYING,
             TunnelState.RUNNING)
        self.assertTrue(m.is_operational)
        self.assertFalse(m.is_terminal)

    def test_skip_ahead_along_start_sequence_is_legal(self):
        # The dashboard only observes some helper phases; skipped phases
        # must not require fake transitions.
        m = TunnelStateMachine()
        walk(m, TunnelState.STARTING, TunnelState.VERIFYING,
             TunnelState.RUNNING)

    def test_illegal_transition_raises_and_keeps_state(self):
        m = TunnelStateMachine()
        with self.assertRaises(TransitionError) as cm:
            m.transition(TunnelState.RUNNING, reason="wishful thinking")
        self.assertIs(cm.exception.source, TunnelState.STOPPED)
        self.assertIs(cm.exception.target, TunnelState.RUNNING)
        self.assertIs(m.current, TunnelState.STOPPED)

    def test_same_state_transition_raises(self):
        m = TunnelStateMachine()
        with self.assertRaises(TransitionError):
            m.transition(TunnelState.STOPPED)

    def test_target_type_is_validated(self):
        m = TunnelStateMachine()
        with self.assertRaises(TypeError):
            m.transition("RUNNING")

    def test_try_transition_returns_none_on_illegal(self):
        m = TunnelStateMachine()
        self.assertIsNone(m.try_transition(TunnelState.RUNNING))
        self.assertIs(m.current, TunnelState.STOPPED)

    def test_force_bypasses_graph_but_still_records(self):
        m = TunnelStateMachine()
        event = m.transition(TunnelState.RUNNING, reason="forced",
                             force=True)
        self.assertIs(m.current, TunnelState.RUNNING)
        self.assertEqual(len(m.history()), 1)
        self.assertEqual(event.reason, "forced")

    def test_can_transition(self):
        m = TunnelStateMachine()
        self.assertTrue(m.can_transition(TunnelState.STARTING))
        self.assertFalse(m.can_transition(TunnelState.RUNNING))
        self.assertFalse(m.can_transition("RUNNING"))

    def test_degraded_recovery_cycle(self):
        m = TunnelStateMachine()
        walk(m, TunnelState.STARTING, TunnelState.VERIFYING,
             TunnelState.RUNNING, TunnelState.DEGRADED,
             TunnelState.RECOVERING, TunnelState.RUNNING)
        self.assertIs(m.current, TunnelState.RUNNING)

    def test_stop_path(self):
        m = TunnelStateMachine()
        walk(m, TunnelState.STARTING, TunnelState.VERIFYING,
             TunnelState.RUNNING, TunnelState.STOPPING, TunnelState.STOPPED)
        self.assertTrue(m.is_terminal)

    def test_verification_is_mandatory_before_running(self):
        # No start phase except VERIFYING may claim the tunnel is up.
        for phase in (TunnelState.STARTING, TunnelState.RESOLVING,
                      TunnelState.STARTING_TUN,
                      TunnelState.STARTING_TUN2SOCKS,
                      TunnelState.INSTALLING_ROUTES):
            self.assertNotIn(TunnelState.RUNNING, TRANSITIONS[phase])
            self.assertNotIn(TunnelState.DEGRADED, TRANSITIONS[phase])

    def test_failed_then_retry(self):
        m = TunnelStateMachine()
        walk(m, TunnelState.STARTING, TunnelState.FAILED,
             TunnelState.STARTING, TunnelState.VERIFYING,
             TunnelState.RUNNING, TunnelState.STOPPING, TunnelState.STOPPED)

    def test_reset_forces_back_to_stopped(self):
        m = TunnelStateMachine()
        walk(m, TunnelState.STARTING, TunnelState.VERIFYING,
             TunnelState.RUNNING)
        event = m.reset(reason="emergency")
        self.assertIs(m.current, TunnelState.STOPPED)
        self.assertEqual(event.reason, "emergency")


class TestEventsAndHistory(unittest.TestCase):
    def test_transition_returns_event_with_reason(self):
        m = TunnelStateMachine()
        event = m.transition(TunnelState.STARTING, reason="user pressed S")
        self.assertIsInstance(event, StateTransition)
        self.assertIs(event.source, TunnelState.STOPPED)
        self.assertIs(event.target, TunnelState.STARTING)
        self.assertEqual(event.reason, "user pressed S")
        self.assertGreater(event.timestamp, 0)
        self.assertGreaterEqual(event.age, 0.0)
        self.assertIn("STOPPED -> STARTING", str(event))
        self.assertIn("user pressed S", str(event))

    def test_history_records_order(self):
        m = TunnelStateMachine()
        walk(m, TunnelState.STARTING, TunnelState.VERIFYING,
             TunnelState.RUNNING, TunnelState.STOPPING, TunnelState.STOPPED)
        hist = m.history()
        self.assertEqual(len(hist), 5)
        self.assertEqual([e.target for e in hist],
                         [TunnelState.STARTING, TunnelState.VERIFYING,
                          TunnelState.RUNNING, TunnelState.STOPPING,
                          TunnelState.STOPPED])

    def test_history_is_bounded(self):
        m = TunnelStateMachine(history_size=5)
        for _ in range(20):
            # force=True cycles without needing a legal path each way.
            m.transition(TunnelState.STARTING, force=True)
            m.transition(TunnelState.FAILED, force=True)
        self.assertEqual(len(m.history()), 5)

    def test_history_snapshot_is_isolated(self):
        m = TunnelStateMachine()
        m.transition(TunnelState.STARTING)
        m.transition(TunnelState.VERIFYING)
        hist = m.history()
        m.transition(TunnelState.RUNNING)
        self.assertEqual(len(hist), 2)   # old snapshot unchanged
        self.assertEqual(len(m.history()), 3)

    def test_time_in_state_grows_and_resets(self):
        m = TunnelStateMachine()
        time.sleep(0.05)
        self.assertGreaterEqual(m.time_in_state(), 0.04)
        m.transition(TunnelState.STARTING)
        self.assertLess(m.time_in_state(), 0.04)  # timer restarted

    def test_reason_and_entered_at_track_last_transition(self):
        m = TunnelStateMachine()
        self.assertEqual(m.reason, "initial state")
        before = time.time()
        m.transition(TunnelState.STARTING, reason="launched")
        self.assertEqual(m.reason, "launched")
        self.assertGreaterEqual(m.entered_at, before)


class TestObservers(unittest.TestCase):
    def test_observer_notified_of_every_transition(self):
        m = TunnelStateMachine()
        events = []
        m.observe(events.append)
        walk(m, TunnelState.STARTING, TunnelState.VERIFYING,
             TunnelState.RUNNING)
        self.assertEqual(len(events), 3)
        self.assertIs(events[0].target, TunnelState.STARTING)
        self.assertIs(events[2].target, TunnelState.RUNNING)

    def test_observer_exception_does_not_break_machine(self):
        m = TunnelStateMachine()

        def bad(_event):
            raise RuntimeError("observer is broken")

        seen = []
        m.observe(bad)
        m.observe(seen.append)
        walk(m, TunnelState.STARTING, TunnelState.VERIFYING,
             TunnelState.RUNNING)
        self.assertEqual(len(seen), 3)   # other observers still notified

    def test_unsubscribe_stops_notifications(self):
        m = TunnelStateMachine()
        events = []
        unsubscribe = m.observe(events.append)
        unsubscribe()
        m.transition(TunnelState.STARTING)
        self.assertEqual(events, [])
        unsubscribe()   # double-unsubscribe is harmless

    def test_observer_may_call_back_into_machine(self):
        # Observers run OUTSIDE the state lock: a callback re-entering the
        # machine (like the dashboard's log sink does) must not deadlock.
        m = TunnelStateMachine()

        def reentrant(_event):
            _ = m.time_in_state()
            _ = m.current

        m.observe(reentrant)
        walk(m, TunnelState.STARTING, TunnelState.VERIFYING,
             TunnelState.RUNNING)


class TestDiagnostics(unittest.TestCase):
    def test_snapshot_shape_and_json_safety(self):
        m = TunnelStateMachine()
        m.transition(TunnelState.STARTING, reason="boot")
        snap = m.snapshot()
        self.assertEqual(snap["state"], "STARTING")
        self.assertEqual(snap["reason"], "boot")
        self.assertIn("since", snap)
        self.assertIn("time_in_state_s", snap)
        self.assertEqual(len(snap["history"]), 1)
        self.assertEqual(snap["history"][0]["from"], "STOPPED")
        self.assertEqual(snap["history"][0]["to"], "STARTING")
        import json
        json.dumps(snap)   # must stay JSON-safe for the diagnostics export

    def test_repr_mentions_state(self):
        m = TunnelStateMachine()
        self.assertIn("STOPPED", repr(m))


class TestThreadSafety(unittest.TestCase):
    def test_concurrent_transitions_never_corrupt_state(self):
        # Hammer the machine from many threads. try_transition must never
        # raise, and each accepted event must chain exactly onto the
        # previous one (no lost updates).
        m = TunnelStateMachine(history_size=100_000)
        accepted = []
        lock = threading.Lock()
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            local = []
            for _ in range(300):
                if m.try_transition(TunnelState.STARTING) is not None:
                    local.append(TunnelState.STARTING)
                if m.try_transition(TunnelState.FAILED) is not None:
                    local.append(TunnelState.FAILED)
            with lock:
                accepted.extend(local)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertIn(m.current, (TunnelState.STARTING, TunnelState.FAILED))
        # The total accepted count must match the machine's own record.
        self.assertEqual(len(accepted), len(m.history()))
        # Every accepted event chains: source == previous accepted target.
        hist = m.history()
        self.assertIs(hist[0].source, TunnelState.STOPPED)
        for prev, cur in zip(hist, hist[1:]):
            self.assertIs(cur.source, prev.target)

    def test_race_produces_single_winner(self):
        # The exact dashboard race: N threads all spot the dead helper and
        # try to drive RUNNING -> STOPPING. Exactly one may win.
        m = TunnelStateMachine(initial=TunnelState.RUNNING)
        barrier = threading.Barrier(6)
        winners = []
        lock = threading.Lock()

        def worker():
            barrier.wait()
            if m.try_transition(TunnelState.STOPPING,
                                reason="dead helper") is not None:
                with lock:
                    winners.append(1)

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(winners), 1)
        stoppings = [e for e in m.history()
                     if e.target == TunnelState.STOPPING]
        self.assertEqual(len(stoppings), 1)
        self.assertIs(m.current, TunnelState.STOPPING)


if __name__ == "__main__":
    unittest.main()

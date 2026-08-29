"""Integration tier: the complete tunnel storyline across modules.

state machine + recovery engine + startup recovery, wired exactly like
the dashboard wires them (observer -> reports -> repairs -> transitions),
run through a whole session: clean start, silent crash, auto-restart,
degrade, self-heal, repeat-failure crash loop, engine give-up.

Run:  python -m unittest discover -s tests -t . -v
"""
import os
import tempfile
import time
import unittest

from tunmood.recovery import FailureKind, RecoveryAction, RecoveryEngine
from tunmood.state import TunnelState, TunnelStateMachine
from tunmood.startup_recovery import read_marker, startup_recover


def wait_for(predicate, timeout=3.0, what="condition"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.005)
    raise AssertionError(f"timed out waiting for {what}")


class FakeHelperWorld:
    """Stands in for the real helper process + Windows state."""

    def __init__(self):
        self.helper_alive = False
        self.stale_wintun_routes = 0
        self.restarts = 0

    def startup_probes(self):
        from tunmood.startup_recovery import Probes
        world = self

        class P:
            tun2socks_count = staticmethod(lambda: 0)
            wintun_route_count = staticmethod(
                lambda: world.stale_wintun_routes)
            host_routes = staticmethod(lambda hosts: [])
            kill_tun2socks = staticmethod(lambda: 0)

            @staticmethod
            def teardown_adapter():
                world.stale_wintun_routes = 0
                return True

            @staticmethod
            def sweep_host_routes(routes):
                return len(routes)

        return P()

    def restart_tunnel(self):
        """What the dashboard's _recover_restart_tunnel does."""
        self.restarts += 1
        self.helper_alive = True
        m.try_transition(TunnelState.STOPPING, "recovery restart")
        m.try_transition(TunnelState.STOPPED, "recovery restart")
        m.try_transition(TunnelState.STARTING, "helper relaunched")
        m.try_transition(TunnelState.VERIFYING, "routes installed")
        m.try_transition(TunnelState.RUNNING, "stable again")
        return True


m = TunnelStateMachine()
world = FakeHelperWorld()
log = []


def wire():
    """The dashboard's exact wiring: machine observer feeds the engine."""
    eng = RecoveryEngine(m, log=lambda s: log.append(s),
                         max_attempts=3, give_up_after=2, delay_scale=0.0)
    eng.register(FailureKind.PROCESS, [RecoveryAction(
        "restart the tunnel helper", repair=world.restart_tunnel,
        verify=lambda: world.helper_alive)])

    def on_change(tr):
        if tr.target is TunnelState.RUNNING:
            eng.report_success()
        elif tr.target is TunnelState.STOPPED and \
                (tr.reason or "").startswith("helper process"):
            eng.report_failure(FailureKind.PROCESS, tr.reason)

    m.observe(on_change)
    eng.start()
    return eng


class TestFullSession(unittest.TestCase):
    def test_whole_session_story(self):
        marker = os.path.join(tempfile.mkdtemp(), "marker.json")
        eng = wire()
        try:
            # 1. Previous run crashed leaving wintun routes: startup
            #    recovery must clean before this session starts.
            world.stale_wintun_routes = 15
            actions = startup_recover(probes=world.startup_probes(),
                                      marker_path=marker)
            self.assertEqual(len(actions), 1)
            self.assertEqual(world.stale_wintun_routes, 0)
            self.assertIsNotNone(read_marker(marker))

            # 2. Normal start.
            m.try_transition(TunnelState.STARTING, "helper launched")
            m.try_transition(TunnelState.VERIFYING, "routes installed")
            m.try_transition(TunnelState.RUNNING, "stable")

            # 3. Silent crash -> engine auto-restarts -> healthy again.
            world.helper_alive = False
            m.try_transition(TunnelState.STOPPING, "helper process exited")
            m.try_transition(TunnelState.STOPPED, "helper process exited")
            wait_for(lambda: m.current is TunnelState.RUNNING,
                     what="auto-restart to RUNNING")
            self.assertEqual(world.restarts, 1)

            # 4. A restart that does NOT come back: incident 2 exhausts
            #    its 3 attempts (streak 1).
            world.helper_alive = False

            def broken_restart():
                world.restarts += 1
                m.try_transition(TunnelState.STARTING, "helper relaunched")
                m.try_transition(TunnelState.STOPPED, "start failed")
                return False

            eng.register(FailureKind.PROCESS, [RecoveryAction(
                "restart the tunnel helper", repair=broken_restart,
                verify=lambda: False)])
            m.try_transition(TunnelState.STOPPING, "helper process exited")
            m.try_transition(TunnelState.STOPPED, "helper process exited")
            wait_for(lambda: eng.stats()["give_ups"] == 1,
                     what="incident exhausted")
            self.assertEqual(world.restarts, 1 + 3)   # 1 ok + 3 failed tries

            # 5. A doomed relaunch dies again before it can verify:
            #    another exhausted incident -> streak 2 -> crash-loop
            #    protection trips.
            m.try_transition(TunnelState.STARTING, "helper relaunched")
            m.try_transition(TunnelState.STOPPING, "helper process exited")
            m.try_transition(TunnelState.STOPPED, "helper process exited")
            wait_for(lambda: eng.gave_up, what="engine gave up")

            # 6. After give-up, crashes are still reported but NOTHING
            #    fires any more.
            restarts_before = world.restarts
            m.try_transition(TunnelState.STARTING, "helper relaunched")
            m.try_transition(TunnelState.STOPPED, "helper process exited")
            time.sleep(0.05)
            self.assertEqual(world.restarts, restarts_before)

            # 7. A fresh user start re-arms the engine (launch->resume()).
            eng.shutdown()
            eng.resume()
            self.assertFalse(eng.gave_up)

            # The event stream the user read along the way is coherent.
            self.assertTrue(any("Recovery verified" in ln for ln in log))
            self.assertTrue(any("gave up" in ln for ln in log))
        finally:
            eng.shutdown()


if __name__ == "__main__":
    unittest.main()


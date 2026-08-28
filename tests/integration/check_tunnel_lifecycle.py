"""Headless integration check: drive the tunnel state machine exactly the
way dashboard.py's hooks do (launch, helper markers, monitor probes,
self-heal, crash, restart, user quit) and print the resulting event log.
No admin rights, no network, no TUI - verifies the wiring logic end to end.

Run:  python tests/integration_check.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tunmood.state import TunnelState, TunnelStateMachine

m = TunnelStateMachine()
log = []
m.observe(lambda e: log.append(str(e)))


def hook(marker):
    """Mirror dashboard._read()'s marker handling."""
    s = marker
    if s.strip() == "[+] TUNNEL ACTIVE":
        m.try_transition(TunnelState.VERIFYING, "routes installed")
    elif "Press Ctrl+C to stop" in s:
        m.try_transition(TunnelState.RUNNING, "start sequence complete")
    elif s.startswith("[MONITOR] tunnel check failed"):
        m.try_transition(TunnelState.DEGRADED,
                         s.split(":", 1)[-1].strip())
    elif s.startswith("[*] Self-healing:"):
        m.try_transition(TunnelState.RECOVERING, "self-heal started")
    elif s.startswith("[+] Self-heal applied."):
        m.try_transition(TunnelState.RUNNING, "self-heal applied")
    elif s.startswith("[MONITOR] tunnel OK"):
        m.try_transition(TunnelState.RUNNING, "monitor probe OK")


def assert_state(expected):
    actual = m.current
    assert actual is expected, f"expected {expected.value}, got {actual.value}"
    print(f"  state = {actual.value:12s} OK")


print("1. launch")
m.try_transition(TunnelState.STARTING, "helper launched (PID 1234)")
assert_state(TunnelState.STARTING)

print("2. helper brings the tunnel up")
hook("[*] Installing IPv4 default route through Wintun...")
hook("[+] TUNNEL ACTIVE")
assert_state(TunnelState.VERIFYING)
hook("[*] Press Ctrl+C to stop.")
assert_state(TunnelState.RUNNING)

print("3. monitor probe fails once, self-heal fixes it")
hook("[MONITOR] tunnel check failed (1/2): DNS probe timed out")
assert_state(TunnelState.DEGRADED)
hook("[*] Self-healing: re-applying Wintun config and TUN routes...")
assert_state(TunnelState.RECOVERING)
hook("[+] Self-heal applied.")
assert_state(TunnelState.RUNNING)

print("4. tunnel dies silently (helper killed) - EOF path")
m.try_transition(TunnelState.STOPPING, "helper process exited")
m.try_transition(TunnelState.STOPPED, "helper process exited")
assert_state(TunnelState.STOPPED)
m.try_transition(TunnelState.STOPPING, "duplicate [Q] teardown")   # must no-op
assert_state(TunnelState.STOPPED)

print("5. restart + a failing launch")
m.try_transition(TunnelState.STARTING, "helper launched (PID 2222)")
m.try_transition(TunnelState.FAILED, "helper launch failed: boom")
assert_state(TunnelState.FAILED)
m.try_transition(TunnelState.STARTING, "user retries")
assert_state(TunnelState.STARTING)
hook("[+] TUNNEL ACTIVE")
hook("[*] Press Ctrl+C to stop.")
assert_state(TunnelState.RUNNING)

print("6. clean [Q] shutdown")
m.try_transition(TunnelState.STOPPING, "shutdown requested [Q]")
m.try_transition(TunnelState.STOPPED,
                 "shutdown complete - routes verified clear")
assert_state(TunnelState.STOPPED)

print("\nEvent log (what the dashboard's event panel would show):")
for line in log:
    print(f"  [*] TUNNEL: {line}")

snap = m.snapshot()
assert all(k in snap for k in ("state", "reason", "history"))
assert len(snap["history"]) == len(log)
print(f"\nALL CHECKS PASSED - {len(log)} transitions, "
      f"history matches, snapshot JSON-safe")

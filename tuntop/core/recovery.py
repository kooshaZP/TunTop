"""Formal recovery engine - what to do when the tunnel breaks, and when.

Phase 2 gave the tunnel explicit DEGRADED / RECOVERING states. This module
is the POLICY that drives them, replacing ad-hoc "something failed, poke it
again" behaviour with a bounded, backoff-based escalation ladder:

    problem detected
          |
    what failed? (FailureKind: process / dns / routes / adapter / proxy)
          |
    targeted repair from the kind's action ladder
          |
    verify
          |
    success? -- yes --> RUNNING, incident closed, counters reset
          | no
    retry with exponential backoff: 1s 2s 4s 8s 16s 30s (capped)
          |
    max attempts exhausted --> give up for this incident, stay DEGRADED

Report floods NEVER accelerate the schedule: a broken tunnel that screams
every second gets repaired on the backoff clock, not every second, so the
"self-healing" itself can never become the source of instability.

Crash-loop protection: if N consecutive incidents each exhaust their
attempts without ever reaching a verified success, the engine pauses
itself and demands a human (one clear log line instead of an infinite
restart loop). One verified success resets the counter.

Thread model: one daemon worker owns all repairs; callers only hand in
reports. Repairs run OUTSIDE the engine lock (a repair that touches the
state machine or the logs must never deadlock the engine). The machine is
driven RECOVERING before each attempt and RUNNING after a verified fix.

Pure stdlib, no Windows calls - fully unit-testable anywhere
(see tests/test_recovery.py).
"""
from __future__ import annotations

import enum
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from tuntop.core.state import TunnelState, TunnelStateMachine


class FailureKind(enum.Enum):
    """What broke. Each kind gets its own action ladder, so a DNS hiccup
    is not "fixed" by nuking the routing table."""

    PROCESS = "process"      # helper / tun2socks process died
    DNS = "dns"              # DNS through the TUN fails
    ROUTES = "routes"        # expected routes missing
    ADAPTER = "adapter"      # Wintun adapter gone/misconfigured
    PROXY = "proxy"          # SOCKS/v2rayN endpoint unreachable
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class RecoveryAction:
    """One rung of an action ladder: what to do, and how to check it worked.

    `repair` does the fix and returns True when it ran without error.
    `verify` (optional) double-checks the result the cheap way - e.g. "is
    the helper process alive again". When verify returns False the attempt
    counts as failed even if repair returned True."""

    name: str
    repair: Callable[[], bool]
    verify: Optional[Callable[[], bool]] = None


@dataclass
class _Incident:
    """One broken-tunnel episode, from first report to verified fix."""

    kind: FailureKind
    detail: str = ""
    attempt: int = 0          # attempts made so far (1-based once scheduled)
    due_at: float = 0.0       # monotonic time of the next attempt


class RecoveryEngine:
    """Bounded, backoff-based repair scheduler driving the tunnel state
    machine. See the module docstring for the policy."""

    #: Seconds to wait before attempt N (1-based). The last entry repeats
    #: for any attempt beyond it - the schedule climbs but never explodes.
    BACKOFF_SCHEDULE = (1.0, 2.0, 4.0, 8.0, 16.0, 30.0)

    def __init__(self, machine: TunnelStateMachine,
                 log: Optional[Callable[[str], None]] = None,
                 max_attempts: int = 3,
                 give_up_after: int = 3,
                 delay_scale: float = 1.0):
        if max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        self._machine = machine
        self._log = log or (lambda msg: None)
        self._max_attempts = max_attempts
        self._give_up_after = give_up_after
        self._delay_scale = float(delay_scale)
        self._ladders: dict = {}
        self._lock = threading.RLock()
        self._wakeup = threading.Event()
        self._stopped = False
        self._paused = False
        self._incident: Optional[_Incident] = None
        self._in_attempt = False     # a repair is executing right now
        self._consecutive_failed = 0  # incidents that exhausted all attempts
        self._gave_up = False
        self._worker: Optional[threading.Thread] = None
        self._stats = {"incidents": 0, "repairs_ok": 0,
                       "repairs_failed": 0, "give_ups": 0}

    # -- Configuration ----------------------------------------------------

    def register(self, kind: FailureKind, actions,
                 first_delay: Optional[float] = None):
        """Set the action ladder for a failure kind (replaces any previous
        ladder for that kind). `first_delay` overrides the schedule's first
        wait - used when an in-process self-heal deserves a chance to work
        before the engine escalates to a heavier repair."""
        if not actions:
            raise ValueError("action ladder must not be empty")
        with self._lock:
            self._ladders[kind] = (tuple(actions), first_delay)

    def start(self):
        """Start the background worker (idempotent)."""
        with self._lock:
            if self._worker is not None:
                return
            self._worker = threading.Thread(
                target=self._work, name="TunTop-recovery", daemon=True)
            self._worker.start()

    def shutdown(self):
        """Stop the worker and drop any pending attempt. Used at app exit -
        a recovery attempt must never keep the process alive or fire while
        the route table is being torn down."""
        with self._lock:
            self._stopped = True
            self._incident = None
        self._wakeup.set()

    def pause(self, reason: str = ""):
        """Suppress all recovery activity (user-initiated stop/restart).
        Pending attempts are cancelled and NOT rescheduled on resume."""
        with self._lock:
            self._paused = True
            self._incident = None
            self._log("[i] Recovery paused" + (f" ({reason})" if reason
                                               else ""))
        self._wakeup.set()

    def resume(self):
        """Re-enable recovery (a fresh tunnel start began). Always re-arms:
        clears crash-loop give-up and any stale incident - the dashboard
        calls this on every launch, and a user-driven start is exactly the
        'human intervened' event that ends a give-up."""
        with self._lock:
            was = self._paused
            had_gave_up = self._gave_up
            self._paused = False
            self._incident = None
            self._consecutive_failed = 0
            self._gave_up = False
        if was:
            self._log("[i] Recovery armed.")
        elif had_gave_up:
            self._log("[i] Recovery re-armed after a fresh start.")

    @property
    def paused(self) -> bool:
        with self._lock:
            return self._paused

    @property
    def gave_up(self) -> bool:
        """True once crash-loop protection engaged (needs resume()/reset)."""
        with self._lock:
            return self._gave_up

    # -- Reporting ----------------------------------------------------------

    @staticmethod
    def delay_for_attempt(attempt: int) -> float:
        """Backoff wait before the given 1-based attempt: 1s, 2s, 4s, 8s,
        16s, then 30s forever. Exposed for tests and log messages."""
        idx = min(max(attempt, 1), len(RecoveryEngine.BACKOFF_SCHEDULE)) - 1
        return RecoveryEngine.BACKOFF_SCHEDULE[idx]

    def report_failure(self, kind: FailureKind, detail: str = "",
                       delay: Optional[float] = None):
        """Report a broken tunnel. Opens a new incident (or is absorbed by
        the one already in flight - a report flood must never accelerate or
        reset the backoff schedule). `delay` overrides the first wait."""
        if not isinstance(kind, FailureKind):
            raise TypeError("kind must be a FailureKind")
        with self._lock:
            if self._stopped or self._paused or self._gave_up:
                return
            if self._incident is not None or self._in_attempt:
                # Already handling something: absorbed, NOT rescheduled.
                return
            if kind not in self._ladders:
                self._log(f"[!] {kind.value} problem reported but no "
                          f"recovery action registered - ignored ({detail})")
                return
            self._incident = _Incident(kind=kind, detail=detail)
            self._stats["incidents"] += 1
            first = delay if delay is not None \
                else self._first_delay_for(kind)
            self._incident.due_at = time.monotonic() + \
                first * self._delay_scale
            self._log(f"[!] Problem detected ({kind.value}"
                      + (f": {detail}" if detail else "")
                      + f") - recovery attempt 1 in {self._fmt(first)}.")
        self._wakeup.set()

    def report_success(self):
        """The tunnel is verified healthy: close any incident and reset the
        crash-loop counter (one verified success wipes the bad streak)."""
        with self._lock:
            had = self._incident is not None
            self._incident = None
            self._consecutive_failed = 0
            if had:
                self._log("[+] Recovery: tunnel verified healthy again - "
                          "incident closed.")
        self._wakeup.set()

    def _first_delay_for(self, kind: FailureKind) -> float:
        _actions, first_delay = self._ladders[kind]
        if first_delay is not None:
            return first_delay
        return self.delay_for_attempt(1)

    @staticmethod
    def _fmt(seconds: float) -> str:
        seconds = round(seconds)
        if seconds >= 90:
            return f"{seconds // 60}m{seconds % 60:02d}s"
        return f"{seconds}s"

    def stats(self) -> dict:
        """Counters for the diagnostics export."""
        with self._lock:
            return dict(self._stats)

    # -- Worker -------------------------------------------------------------

    def _work(self):
        """The single worker: wait out backoffs, run due attempts, reschedule
        on failure. Repairs run OUTSIDE the engine lock so a repair that
        calls back into the machine (and its observers) can never deadlock
        the engine."""
        while True:
            incident = None
            run_now = False
            with self._lock:
                if self._stopped:
                    return
                incident = self._incident
                if incident is None:
                    delay = None            # idle: sleep until woken
                else:
                    delay = incident.due_at - time.monotonic()
                    if delay <= 0:
                        # Due now. Take it off the books BEFORE running so
                        # reports arriving during the repair are absorbed
                        # instead of double-scheduling.
                        self._incident = None
                        self._in_attempt = True
                        run_now = True
            if incident is None or (delay is not None and delay <= 0):
                if run_now:
                    self._run_attempt(incident)
                else:
                    self._wakeup.wait()
                    self._wakeup.clear()
                continue
            # Wait out the backoff. A report/success/pause wakes us early,
            # in which case the loop re-reads the (possibly changed) plan.
            self._wakeup.wait(timeout=delay)
            self._wakeup.clear()

    def _run_attempt(self, incident: _Incident):
        """Execute one ladder rung: RECOVERING, repair, verify, judge."""
        incident.attempt += 1
        with self._lock:
            actions, _fd = self._ladders.get(incident.kind, ((), None))
            if not actions:
                self._in_attempt = False
                return
            # Escalate with the attempt count; the last rung repeats.
            action = actions[min(incident.attempt - 1, len(actions) - 1)]
            st = self._machine.current
            if st.is_operational or st is TunnelState.RECOVERING:
                self._machine.try_transition(
                    TunnelState.RECOVERING,
                    f"recovery attempt {incident.attempt} "
                    f"({incident.kind.value})")
            self._log(f"[*] Recovery attempt {incident.attempt}/"
                      f"{self._max_attempts}: {action.name}...")
        ok = False
        err = ""
        try:
            ok = bool(action.repair())
        except Exception as e:
            ok, err = False, f" (repair raised: {e})"
        if ok and action.verify is not None:
            try:
                ok = bool(action.verify())
            except Exception as e:
                ok, err = False, f" (verify raised: {e})"
        with self._lock:
            self._in_attempt = False
            if ok:
                self._stats["repairs_ok"] += 1
                self._incident = None
                self._consecutive_failed = 0
                st = self._machine.current
                if st in (TunnelState.RECOVERING, TunnelState.DEGRADED):
                    self._machine.try_transition(
                        TunnelState.RUNNING,
                        f"recovery verified after '{action.name}'")
                self._log(f"[+] Recovery verified: {action.name} fixed it.")
                return
            self._stats["repairs_failed"] += 1
            if incident.attempt >= self._max_attempts:
                self._consecutive_failed += 1
                self._stats["give_ups"] += 1
                self._incident = None
                why = err or "repair did not verify"
                self._log(f"[!] Recovery gave up after {incident.attempt} "
                          f"attempts ({why}). Tunnel stays "
                          f"{self._machine.state_name}.")
                # If we claimed RECOVERING for this attempt, walk it back:
                # the tunnel is unhealthy and NOTHING is repairing it now -
                # DEGRADED says exactly that, RECOVERING would be a lie.
                if self._machine.current is TunnelState.RECOVERING:
                    self._machine.try_transition(
                        TunnelState.DEGRADED,
                        f"recovery exhausted ({why})")
                if self._consecutive_failed >= self._give_up_after:
                    self._gave_up = True
                    self._log("[!] Recovery DISABLED after "
                              f"{self._consecutive_failed} consecutive "
                              "failed incidents - manual intervention "
                              "required. It re-arms on the next "
                              "successful start.")
                return
            wait = self.delay_for_attempt(incident.attempt + 1) \
                * self._delay_scale
            incident.due_at = time.monotonic() + wait
            self._incident = incident
            self._log(f"[i] {action.name} did not fix it{err} - retrying "
                      f"as attempt {incident.attempt + 1} in "
                      f"{self._fmt(wait)}.")
        self._wakeup.set()




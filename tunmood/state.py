"""Tunnel state machine - the single source of truth for what the tunnel
is doing.

Historically the dashboard knew exactly two states, derived from one
boolean:

    "RUNNING"  <- helper subprocess alive
    "STOPPED"  <- everything else

That is how bugs like "tun2socks died but the dashboard still says
connected" happen: process-liveness is NOT tunnel-health, and the start
sequence (resolve -> adapter -> tun2socks -> routes -> verify) has no
representation at all.

This module models the tunnel as an explicit, thread-safe state machine
(see TRANSITIONS for the exact graph):

  START SEQUENCE (forward skip-ahead allowed):
    STOPPED -> STARTING -> RESOLVING -> STARTING_TUN ->
    STARTING_TUN2SOCKS -> INSTALLING_ROUTES -> VERIFYING -> RUNNING

  Health cycle:
    RUNNING <-> DEGRADED <-> RECOVERING -> RUNNING   (self-heal loop)

  Exits (the only ways out of the start sequence / operational states):
    anything -> STOPPING -> STOPPED      (clean teardown)
    anything -> FAILED -> STARTING       (retry) | STOPPING | STOPPED

Design rules:

* Forward movement along the START SEQUENCE may skip phases (the dashboard
  observes only some of the helper's phases; unobserved ones are skipped,
  never faked).
* Leaving the start sequence sideways is only possible via FAILED or
  STOPPING - there is no legal path from INSTALLING_ROUTES back to
  RESOLVING, for example. Restarting means going through STOPPING/STOPPED.
* Every transition is recorded (bounded history) and announced to
  observers, so the UI/log/diagnostics all consume one event stream.

Pure stdlib, zero pip dependencies, no Windows-specific calls - fully
unit-testable on any OS (see tests/test_state.py).
"""
from __future__ import annotations

import collections
import enum
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional


class TunnelState(enum.Enum):
    """Every state the tunnel can be in.

    Values are plain uppercase strings so they can be compared directly
    against the dashboard's historical "RUNNING"/"STOPPED" string state.
    """

    STOPPED = "STOPPED"                      # nothing running, system clean
    STARTING = "STARTING"                    # helper launched, bootstrapping
    RESOLVING = "RESOLVING"                  # resolving server/endpoint IPs
    STARTING_TUN = "STARTING_TUN"            # bringing up the Wintun adapter
    STARTING_TUN2SOCKS = "STARTING_TUN2SOCKS"  # tun2socks process starting
    INSTALLING_ROUTES = "INSTALLING_ROUTES"  # default/bypass/geo routes
    VERIFYING = "VERIFYING"                  # routes in; probing real traffic
    RUNNING = "RUNNING"                      # verified healthy, traffic flows
    DEGRADED = "DEGRADED"                    # up, but a health probe failed
    RECOVERING = "RECOVERING"                # self-heal repair in progress
    STOPPING = "STOPPING"                    # teardown / route cleanup running
    FAILED = "FAILED"                        # could not start (retry or stop)

    @property
    def is_operational(self) -> bool:
        """Traffic is (nominally) flowing through the tunnel."""
        return self in _OPERATIONAL

    @property
    def is_terminal(self) -> bool:
        """A resting state: the machine can stay here forever."""
        return self in _TERMINAL

    @property
    def is_transitioning(self) -> bool:
        """A start/stop phase is in flight (not a resting state)."""
        return self not in _OPERATIONAL and self not in _TERMINAL


_OPERATIONAL = frozenset({TunnelState.RUNNING, TunnelState.DEGRADED})
_TERMINAL = frozenset({TunnelState.STOPPED, TunnelState.FAILED})

# The ordered start sequence. Forward movement may skip phases (a phase the
# dashboard never observes simply doesn't get a transition); backward movement
# inside the sequence is illegal - a restart must go through STOPPING.
_START_SEQ = (
    TunnelState.STARTING,
    TunnelState.RESOLVING,
    TunnelState.STARTING_TUN,
    TunnelState.STARTING_TUN2SOCKS,
    TunnelState.INSTALLING_ROUTES,
    TunnelState.VERIFYING,
)


def _build_transitions() -> dict:
    """Build the legal-transition graph.

    The start phases get "any later start phase" edges (skip-ahead), plus
    FAILED/STOPPING escape edges; everything else is hand-written below.
    """
    graph = {state: set() for state in TunnelState}
    for i, phase in enumerate(_START_SEQ):
        graph[phase] |= set(_START_SEQ[i + 1:])          # skip-ahead allowed
        graph[phase] |= {TunnelState.FAILED, TunnelState.STOPPING}
    graph[TunnelState.STOPPED] = {TunnelState.STARTING}
    # Only VERIFYING may enter the operational states: a tunnel that was
    # never probed must never be reported as RUNNING/DEGRADED.
    graph[TunnelState.VERIFYING] |= {TunnelState.RUNNING, TunnelState.DEGRADED}
    graph[TunnelState.RUNNING] = {
        TunnelState.DEGRADED,      # a health probe failed
        TunnelState.RECOVERING,    # self-heal kicked in directly
        TunnelState.STOPPING,
    }
    graph[TunnelState.DEGRADED] = {
        TunnelState.RUNNING,       # probe healthy again
        TunnelState.RECOVERING,    # escalating to a repair
        TunnelState.STOPPING,
        TunnelState.FAILED,        # repair impossible
    }
    graph[TunnelState.RECOVERING] = {
        TunnelState.RUNNING,       # repair verified
        TunnelState.DEGRADED,      # repair applied but still unhealthy
        TunnelState.STOPPING,
        TunnelState.FAILED,
    }
    graph[TunnelState.STOPPING] = {
        TunnelState.STOPPED,       # normal completion
        TunnelState.FAILED,        # teardown hit an unrecoverable error
    }
    graph[TunnelState.FAILED] = {
        TunnelState.STARTING,      # user retries
        TunnelState.STOPPING,      # run the cleanup path anyway
        TunnelState.STOPPED,       # cleanup finished / acknowledged
    }
    return {state: frozenset(targets) for state, targets in graph.items()}


#: state -> frozenset(states it may legally transition to)
TRANSITIONS = _build_transitions()


class TransitionError(Exception):
    """Raised when an illegal state transition is attempted."""

    def __init__(self, source: TunnelState, target: TunnelState,
                 why: str = "transition not allowed"):
        self.source = source
        self.target = target
        self.why = why
        super().__init__(f"illegal tunnel transition {source.value} -> "
                         f"{target.value}: {why}")


@dataclass(frozen=True)
class StateTransition:
    """One immutable record of a state change (an event)."""

    source: TunnelState
    target: TunnelState
    reason: Optional[str] = None
    timestamp: float = 0.0

    def __post_init__(self):
        # Frozen dataclass: default the timestamp once, at construction.
        if not self.timestamp:
            object.__setattr__(self, "timestamp", time.time())

    @property
    def age(self) -> float:
        """Seconds since this transition happened."""
        return max(0.0, time.time() - self.timestamp)

    def __str__(self):
        head = f"{self.source.value} -> {self.target.value}"
        return f"{head} ({self.reason})" if self.reason else head


Observer = Callable[[StateTransition], None]


class TunnelStateMachine:
    """Thread-safe tunnel state machine with observers and bounded history.

    All methods are safe to call from any thread: the dashboard touches the
    machine from the UI thread, the helper-output reader thread AND the
    telemetry thread, often simultaneously (e.g. the reader noticing a dead
    helper while the user presses [Q]).
    """

    def __init__(self, initial: TunnelState = TunnelState.STOPPED,
                 history_size: int = 200):
        if not isinstance(initial, TunnelState):
            raise TypeError("initial must be a TunnelState, got "
                            f"{type(initial).__name__}")
        self._lock = threading.RLock()
        self._current = initial
        self._entered_at = time.time()
        self._last_reason = "initial state"
        self._history = collections.deque(maxlen=history_size)
        self._observers: list = []
        self._obs_lock = threading.Lock()

    # -- Reading state ----------------------------------------------------

    @property
    def current(self) -> TunnelState:
        with self._lock:
            return self._current

    @property
    def state_name(self) -> str:
        """The state as a plain string ("RUNNING", "STOPPED", ...)."""
        return self.current.value

    @property
    def reason(self) -> str:
        """Why the machine entered its current state."""
        with self._lock:
            return self._last_reason

    @property
    def entered_at(self) -> float:
        """Unix timestamp of the last transition into the current state."""
        with self._lock:
            return self._entered_at

    def time_in_state(self) -> float:
        """Seconds spent in the current state."""
        with self._lock:
            return max(0.0, time.time() - self._entered_at)

    def history(self) -> tuple:
        """Snapshot of the transition history (oldest first)."""
        with self._lock:
            return tuple(self._history)

    def can_transition(self, target: TunnelState) -> bool:
        """Whether `transition(target)` would be legal right now."""
        if not isinstance(target, TunnelState):
            return False
        with self._lock:
            return target in TRANSITIONS[self._current]

    @property
    def is_operational(self) -> bool:
        return self.current.is_operational

    @property
    def is_terminal(self) -> bool:
        return self.current.is_terminal

    @property
    def is_transitioning(self) -> bool:
        return self.current.is_transitioning

    # -- Changing state ---------------------------------------------------

    def transition(self, target: TunnelState, reason: str = None,
                   force: bool = False) -> StateTransition:
        """Move to `target`, announcing the change to all observers.

        Raises TransitionError for an illegal move (call try_transition
        instead when the caller races other threads and doesn't care).
        `force=True` bypasses the graph check but still validates the type
        and still records/announces the event - escape hatch for genuinely
        exceptional paths, not for normal control flow.
        """
        if not isinstance(target, TunnelState):
            raise TypeError("target must be a TunnelState, got "
                            f"{type(target).__name__}")
        with self._lock:
            source = self._current
            if source is target:
                raise TransitionError(source, target, "already in that state")
            if not force and target not in TRANSITIONS[source]:
                raise TransitionError(source, target)
            event = StateTransition(source=source, target=target,
                                    reason=reason, timestamp=time.time())
            self._current = target
            self._entered_at = event.timestamp
            self._last_reason = reason or ""
            self._history.append(event)
        # Notify OUTSIDE the lock: an observer that calls back into the
        # machine (or a slow UI log) must never deadlock or stall a
        # transition made from another thread.
        self._notify(event)
        return event

    def try_transition(self, target: TunnelState,
                       reason: str = None) -> Optional[StateTransition]:
        """Like transition(), but an illegal move returns None instead of
        raising. This is what racing threads (reader vs UI vs telemetry)
        should use: two threads spotting the same dead helper both fire
        STOPPING and exactly one wins - the loser's attempt is silently
        ignored, which is exactly the desired behaviour."""
        try:
            return self.transition(target, reason)
        except (TransitionError, TypeError):
            return None

    def reset(self, reason: str = "reset") -> StateTransition:
        """Force back to STOPPED (diagnostics/safety hatch; announced)."""
        return self.transition(TunnelState.STOPPED, reason, force=True)

    # -- Observers ----------------------------------------------------------

    def observe(self, fn: Observer) -> Callable[[], None]:
        """Register `fn(event)` for every transition. Returns an unsubscribe
        callable. Observer exceptions are swallowed (and never re-raised into
        the transitioning thread) - a logging/UI hiccup must not be able to
        corrupt tunnel state handling."""
        with self._obs_lock:
            self._observers.append(fn)

        def unsubscribe():
            with self._obs_lock:
                try:
                    self._observers.remove(fn)
                except ValueError:
                    pass
        return unsubscribe

    def _notify(self, event: StateTransition):
        with self._obs_lock:
            observers = tuple(self._observers)
        for fn in observers:
            try:
                fn(event)
            except Exception:
                # A broken observer must never break the machine itself.
                pass

    # -- Diagnostics --------------------------------------------------------

    def snapshot(self) -> dict:
        """Plain-dict summary for the diagnostics export / bug reports."""
        with self._lock:
            return {
                "state": self._current.value,
                "reason": self._last_reason,
                "since": self._entered_at,
                "time_in_state_s": round(self.time_in_state(), 3),
                "history": [
                    {"from": e.source.value, "to": e.target.value,
                     "reason": e.reason, "ts": e.timestamp}
                    for e in self._history
                ],
            }

    def __repr__(self):
        with self._lock:
            return (f"<TunnelStateMachine {self._current.value} "
                    f"for {self.time_in_state():.1f}s>")

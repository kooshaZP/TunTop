"""Core tunnel orchestration - the single layer the UI is allowed to drive.

Phase 1's whole point is the dependency direction:

    UI  ->  Core (this module)  ->  Network / Tunnel (Windows)

The dashboard must NOT call Windows commands, routing internals or the
tun2socks process directly. Instead it asks a ``TunnelManager`` to start /
stop / recover the tunnel, and the manager drives the state machine, the
recovery engine, startup crash-recovery and the binary integrity check.

The manager is deliberately decoupled from the OS: the actual Windows
operations are injected as callables (``launch`` / ``teardown`` /
``startup_recover`` / ``verify_binaries``). In production those are wired to
``tuntop.tunnel.helper`` and ``tuntop.core.*``; in tests they are tiny
fakes, so the entire lifecycle - including the start sequence and the
recovery loop - is exercised without Administrator rights or a Wintun
adapter.

Pure stdlib, no Windows calls at import time.
"""
from __future__ import annotations

from typing import Callable, Optional

from tuntop.core.state import TunnelState, TunnelStateMachine


class TunnelManager:
    """Owns the tunnel's lifecycle and never touches Windows itself.

    Args (all optional / injectable):
        machine:            the state machine to drive (a fresh one by default)
        recovery:           a RecoveryEngine already wired with action ladders
        on_log:             ``callable(level, component, message)`` sink
        startup_recover:    callable that cleans stale state left by a crash
        verify_binaries:    callable returning True if tun2socks/wintun are OK
        launch:             callable that actually brings the tunnel up
        teardown:           callable that cleanly tears the tunnel down
    """

    def __init__(self,
                 machine: Optional[TunnelStateMachine] = None,
                 recovery=None,
                 on_log: Optional[Callable[[str, str, str], None]] = None,
                 startup_recover: Optional[Callable[[], None]] = None,
                 verify_binaries: Optional[Callable[[], bool]] = None,
                 launch: Optional[Callable[[], None]] = None,
                 teardown: Optional[Callable[[], None]] = None):
        self.machine = machine or TunnelStateMachine()
        self.recovery = recovery
        self._log = on_log or (lambda *a, **k: None)
        self._startup_recover = startup_recover
        self._verify = verify_binaries
        self._launch = launch
        self._teardown = teardown

    # -- Logging helper -------------------------------------------------------
    def _blog(self, level: str, component: str, message: str) -> None:
        try:
            self._log(level, component, message)
        except Exception:
            pass

    # -- Startup hygiene (Phase 5) -------------------------------------------
    def startup_recovery(self) -> None:
        """Clean any tunnel state left behind by an unclean exit, then (if a
        recovery engine is attached) make sure it is running and armed."""
        if self._startup_recover is not None:
            self._startup_recover()
        else:
            from tuntop.core.startup_recovery import startup_recover as _sr
            _sr()
        if self.recovery is not None and not getattr(self.recovery, "running", True):
            self.recovery.start()
        self._blog("INFO", "CORE", "startup recovery complete")

    # -- Integrity (Phase 6) -------------------------------------------------
    def verify_binaries(self) -> bool:
        """Return True only if the vendored binaries pass integrity checks.

        The injected `_verify` callable is the ONLY supported path. The
        previous fallback called `verify_for_launch()` with no argument, and
        that function's first parameter (`tun2socks_path`) is required - so
        constructing a TunnelManager without an explicit verifier and asking
        it to verify raised TypeError instead of returning a verdict. The
        fallback could never have worked; it was dead code that only looked
        like a fallback. A real callable is the caller's to build from the
        resolved binary paths - the dashboard checks integrity itself via
        `integrity.verify_for_launch()` and drives the manager with
        `verify_immediately=False` - so no TunnelManager in this codebase
        is ever built with a verifier. Fail closed instead of crashing.
        """
        if self._verify is None:
            self._blog("WARN", "CORE",
                       "verify_binaries called with no verifier configured - "
                       "treating as FAILED rather than raising")
            return False
        return bool(self._verify())

    # -- Lifecycle -----------------------------------------------------------
    def request_start(self, verify_immediately: bool = True) -> bool:
        """Begin the documented start sequence. Returns False if the current
        state makes starting illegal (the state machine enforces the graph).

        verify_immediately=True (default) walks straight to VERIFYING after
        the launch callable returns - right for callers that launch the
        whole tunnel synchronously (the dashboard's launch() only returns
        once the helper process is up). Pass False when the launch merely
        STARTS the sequence and later phases (RESOLVING -> ... -> RUNNING)
        are observed asynchronously, so the machine doesn't skip states
        that are about to be announced for real."""
        if not self.machine.try_transition(TunnelState.STARTING, "user start"):
            return False
        try:
            if self._launch is not None:
                self._launch()
            # The helper's phases (RESOLVING -> STARTING_TUN -> ...) are
            # observed and announced by the reader thread; here we simply mark
            # the launch attempted and hand control to VERIFYING, where the
            # monitors decide RUNNING vs DEGRADED.
            if verify_immediately:
                self.machine.try_transition(TunnelState.VERIFYING,
                                            "launch attempted")
        except (Exception, SystemExit) as e:           # pragma: no cover
            # SystemExit matters: an IN-PROCESS launch runs helper.main(),
            # and that code exits via sys.exit() on many failure paths. A
            # SystemExit is a BaseException, so `except Exception` let it
            # through - the process died instead of transitioning to FAILED,
            # the UI never learned why, and the route table could be left
            # half-installed.
            self.machine.try_transition(TunnelState.FAILED, f"launch error: {e}")
            self._blog("ERROR", "CORE", f"launch failed: {e}")
            return False
        self._blog("INFO", "CORE", "tunnel launch requested")
        return True

    def mark_verified(self, ok: bool, detail: str = "") -> None:
        """Monitors call this once real traffic has been probed."""
        target = TunnelState.RUNNING if ok else TunnelState.DEGRADED
        self.machine.try_transition(target, detail or ("verified" if ok else "verify failed"))
        self._blog("INFO" if ok else "WARN", "CORE",
                   "tunnel verified" if ok else f"tunnel degraded: {detail}")

    def request_stop(self) -> bool:
        """Cleanly tear the tunnel down."""
        if not self.machine.try_transition(TunnelState.STOPPING, "user stop"):
            return False
        try:
            if self._teardown is not None:
                self._teardown()
        except (Exception, SystemExit) as e:
            # A teardown that raises used to land in STOPPED anyway (the
            # `finally` won), so the UI reported a clean stop while the Wintun
            # adapter, its routes and the NRPT rule were all still installed.
            # FAILED is the honest state, and it is reachable in the graph
            # (STOPPING -> FAILED), which no code path ever used.
            self.machine.try_transition(
                TunnelState.FAILED, f"teardown failed: {e}")
            self._blog("ERROR", "CORE",
                       f"tunnel teardown FAILED - leftover routes may remain: {e}")
            return False
        else:
            self.machine.try_transition(TunnelState.STOPPED,
                                        "teardown complete")
        self._blog("INFO", "CORE", "tunnel stopped")
        return True

    # -- Convenience accessors (UI polling) ----------------------------------
    @property
    def state(self) -> TunnelState:
        return self.machine.current

    @property
    def state_name(self) -> str:
        return self.machine.state_name

    def snapshot(self) -> dict:
        return self.machine.snapshot()

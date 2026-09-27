"""Lifecycle helpers for the Core layer.

Thin glue between ``TunnelManager`` and the real Windows-side code in
``tuntop.tunnel.helper`` / ``tuntop.core.startup_recovery`` /
``tuntop.core.integrity``. Keeping these bindings in one place means the UI
never imports helper internals directly - it only ever talks to Core.

These functions are intentionally lazy (imported on first call) so the Core
package can be imported and unit-tested on a non-Windows box without pulling
in any Administrator-only code paths.
"""
from __future__ import annotations

from typing import Callable


def make_launch() -> Callable[[], None]:
    """Return a callable that starts the real tunnel via helper.main()."""
    def _launch():
        from tuntop.tunnel import helper
        helper.main()
    return _launch


def make_teardown() -> Callable[[], None]:
    """Return a callable that cleanly tears the tunnel down via helper.

    NOTE: the manager calls this and THEN transitions to STOPPED, so the
    callable must RETURN - it must never exit the process. (The old name
    cleanup_and_exit() never existed in helper.py and would have raised
    AttributeError on the first wire_default_manager() use.)"""
    def _teardown():
        from tuntop.tunnel import helper
        helper.cleanup()
    return _teardown


def make_startup_recover() -> Callable[[], None]:
    """Return a callable that runs startup crash recovery."""
    def _recover():
        from tuntop.core import startup_recovery
        startup_recovery.startup_recover()
    return _recover


def make_verify_binaries() -> Callable[[], bool]:
    """Return a callable that verifies the vendored binaries."""
    def _verify() -> bool:
        from tuntop.core import integrity
        try:
            # verify_for_launch REQUIRES the tun2socks path. Calling it with
            # no argument raised TypeError instead of reporting "unverified",
            # and TunnelManager.verify_binaries has no handler - so the
            # documented production wiring (wire_default_manager) crashed
            # rather than answering. Resolve the default here; an absent
            # file is reported as MISSING by verify_file, which is a clean
            # False.
            return bool(integrity.verify_for_launch(_default_tun2socks()))
        except Exception:
            return False
    return _verify


def _default_tun2socks() -> str:
    """The vendored tun2socks next to TunTop.exe / this package."""
    import os
    import sys
    if getattr(sys, "frozen", False):
        base = os.path.dirname(os.path.abspath(sys.executable))
    else:
        base = os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))))
    from tuntop.network.procguard import TUN2SOCKS_BINARY
    return os.path.join(base, TUN2SOCKS_BINARY)


def wire_default_manager(machine=None, recovery=None,
                         on_log=None) -> "object":
    """Build a production ``TunnelManager`` wired to the real Windows side."""
    from tuntop.core.tunnel_manager import TunnelManager
    return TunnelManager(
        machine=machine, recovery=recovery, on_log=on_log,
        startup_recover=make_startup_recover(),
        verify_binaries=make_verify_binaries(),
        launch=make_launch(),
        teardown=make_teardown(),
    )

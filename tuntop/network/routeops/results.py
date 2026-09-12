"""Result type for platform-facing route operations.

The goal is to keep sys.exit() out of library code: a failing lookup or
route mutation is DATA the caller decides how to handle, not a process
kill. CLI boundaries translate a failed RouteResult into an exit message;
library callers (monitor loops, live re-points, watchdogs) just read .ok.
"""
from __future__ import annotations


class RouteResult:
    """Outcome of a route operation. Never raises; check .ok."""

    __slots__ = ("ok", "err", "value")

    def __init__(self, ok: bool, err: str = None, value=None):
        self.ok = bool(ok)
        self.err = err
        self.value = value

    @staticmethod
    def unwrap(fn, *args, **kwargs) -> "RouteResult":
        """Call fn() and turn a raised SystemExit (the legacy failure mode
        of the platform lookups) into RouteResult(ok=False). All other
        exceptions propagate - those are bugs, not expected failures."""
        try:
            return RouteResult(True, None, fn(*args, **kwargs))
        except SystemExit as e:
            msg = str(e.code or "").strip() or "failed"
            return RouteResult(False, msg)

    def __iter__(self):
        # (ok, err) unpacking - reads like the old (bool, str) pairs.
        return iter((self.ok, self.err))

    def __repr__(self):
        return f"RouteResult(ok={self.ok}, err={self.err!r})"


def unwrap(fn, *args, **kwargs):
    """Module-level alias of RouteResult.unwrap (kept for direct imports)."""
    return RouteResult.unwrap(fn, *args, **kwargs)

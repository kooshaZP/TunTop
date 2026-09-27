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

    def __bool__(self):
        # Without this, `if result:` is ALWAYS True (the class has __slots__
        # and no __len__), so the natural shorthand for the __iter__-enabled
        # (ok, err) pair silently turns every failure into a pass. Two
        # different RouteResult classes exist in this codebase and only one
        # had __bool__, which is exactly how that lands unnoticed.
        return self.ok

    def __repr__(self):
        return f"RouteResult(ok={self.ok}, err={self.err!r})"


def unwrap(fn, *args, **kwargs):
    """Module-level alias of RouteResult.unwrap (kept for direct imports)."""
    return RouteResult.unwrap(fn, *args, **kwargs)

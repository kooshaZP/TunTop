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


class SweepResult:
    """Outcome of a leftover-route sweep: what was found, what was actually
    removed, and whether the sweep is TRUSTWORTHY.

    The three are different questions and conflating them is how a failed
    cleanup gets reported as a clean one:

      * `found`   - rows in the live table that matched our rule.
      * `removed` - rows netsh CONFIRMED it deleted (parsed from the batch
                    script's own `Ok.` lines, not `len(chunk)`). netsh exits 0
                    even when an individual line fails, so the chunk size is
                    not a removal count.
      * `ok`      - the sweep could be trusted at all. False when the route
                    table could not be read, when a netsh batch exited
                    non-zero, or when it produced no output (which means the
                    script file was never read). A False here is what keeps the
                    crash marker in place so the next launch retries.

    `__bool__` is `removed > 0`, NOT `ok`, on purpose: the historical return
    value of these sweeps was a plain int and every `if n:` call site means
    "did we remove anything". Flip it to `ok` and a sweep that found 400 rows
    and removed all 400 becomes falsy at every call site that only wanted to
    print a count. Read `.ok` explicitly for the verdict.
    """

    __slots__ = ("found", "removed", "ok", "err")

    def __init__(self, found: int = 0, removed: int = 0, ok: bool = True,
                 err: str = ""):
        self.found = int(found or 0)
        self.removed = int(removed or 0)
        self.ok = bool(ok)
        self.err = str(err or "")

    @classmethod
    def clean(cls, found: int = 0, removed: int = 0) -> "SweepResult":
        return cls(found, removed, True, "")

    @classmethod
    def failed(cls, found: int = 0, reason: str = "") -> "SweepResult":
        return cls(found, 0, False, reason)

    def __bool__(self):
        return self.removed > 0

    def __int__(self):
        # So a sweep result can be printed/formatted where a count was
        # returned before, without turning into a repr mid-message.
        return self.removed

    def __repr__(self):
        return (f"SweepResult(found={self.found}, removed={self.removed}, "
                f"ok={self.ok}, err={self.err!r})")

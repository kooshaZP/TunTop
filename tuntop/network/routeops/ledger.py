"""Thread-safe route tracking with full fidelity.

The old tracking was four bare lists of 4-tuples (fam, dest, iface, gw)
shared as module globals. Two consequences bit repeatedly: the metric was
thrown away at registration time (a LAN bypass installed at metric=10 came
back from a re-point at metric=1 unless a caller hardcoded 10), and nothing
synchronised concurrent mutations (install thread vs cleanup vs gateway
re-point).

RouteLedger keeps the same list-shaped surface the call sites already use
(append / remove / clear / iterate over 4-tuples) but records a full
receipt internally and guards every mutation with a lock.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass


def _unpack4(item):
    """One unpacking helper for every access path.

    append() unpacked with tuple-unpacking (ValueError on a short tuple) while
    remove()/index()/metric_of() indexed (IndexError). Same malformed input,
    two different exception types, depending on which method you called."""
    try:
        return (item[0], item[1], item[2], item[3])
    except (TypeError, IndexError, KeyError) as e:
        raise ValueError(
            f"expected a 4-tuple (fam, dest, iface, gw), got {item!r}") from e


@dataclass(frozen=True)
class RouteReceipt:
    """One installed route, with everything needed to reproduce or undo it."""

    fam: str            # "v4" | "v6"
    dest: str           # prefix, e.g. "1.2.3.4/32"
    iface: str
    gw: str             # next-hop as installed ("" when on-link)
    metric: int = 1
    store: str = "active"   # "active" | "persistent"
    tag: str = ""           # owning subsystem (constructor's ledger tag)

    @property
    def key(self):
        # NOTE: identity deliberately EXCLUDES metric/store. A given
        # (fam, dest, iface, gw) can only be installed once in the live
        # table; two receipts differing only in metric mean one of them is
        # stale bookkeeping, and the first (oldest) match is the stale one -
        # which is exactly the entry remove()/index()/metric_of() should act
        # on. Folding metric into the key would make both survive forever.
        return (self.fam, self.dest, self.iface, self.gw)


class RouteLedger:
    """Registry of routes one process installed. List-compatible: callers
    append/remove/iterate legacy 4-tuples exactly as before; the ledger
    stores the full receipt."""

    def __init__(self, tag: str = ""):
        self._tag = tag
        self._lock = threading.RLock()
        self._entries: list = []

    # ── list-compatible surface ────────────────────────────────────────────
    def append(self, item, metric: int = 1, store: str = "active"):
        """Track a route. `item` is the legacy (fam, dest, iface, gw)
        4-tuple; metric/store enrich the receipt."""
        fam, dest, iface, gw = item
        with self._lock:
            self._entries.append(RouteReceipt(
                str(fam), str(dest), str(iface), str(gw or ""),
                int(metric or 1), store, self._tag))

    def remove(self, item):
        """Untrack a route by its 4-tuple. Raises ValueError when absent
        (mirrors list.remove).

        Duplicates (same 4-tuple, different metric - a re-point that
        re-registered) are COLLAPSED: only the first, oldest receipt is
        dropped, matching list.remove semantics. Call that out rather than
        leaving a second ghost entry that nothing will ever clean up."""
        fam, dest, iface, gw = _unpack4(item)
        with self._lock:
            for i, r in enumerate(self._entries):
                if r.key == (str(fam), str(dest), str(iface), str(gw or "")):
                    del self._entries[i]
                    return
            raise ValueError(tuple(item))

    def extend(self, items, metric: int = 1, store: str = "active"):
        """Track many routes (list.extend compatibility)."""
        for item in items:
            self.append(item, metric=metric, store=store)

    def index(self, item) -> int:
        fam, dest, iface, gw = _unpack4(item)
        with self._lock:
            for i, r in enumerate(self._entries):
                if r.key == (str(fam), str(dest), str(iface), str(gw or "")):
                    return i
        raise ValueError(tuple(item))

    def __contains__(self, item) -> bool:
        try:
            self.index(item)
            return True
        except (ValueError, IndexError, TypeError, KeyError):
            # A short tuple must be "not present", never an exception: a
            # membership test is a QUESTION, and __contains__ propagating
            # IndexError out of `x in ledger` is how a 3-tuple typo becomes a
            # crash on a code path that looks like a plain lookup.
            return False

    def __setitem__(self, key, value):
        """FULL-slice assignment (ledger[:] = [...]) for list compatibility.

        Anything narrower is rejected outright. The start/stop/step were
        silently ignored, so `ledger[1:] = rest` and `ledger[2:5] = x` both
        wiped the ENTIRE registry and appended only the replacement - and the
        ledger is the authority on what gets torn down, so the effect was
        "every live route became invisible to cleanup()". A loud TypeError
        at the call site is strictly better than that.
        new items get the default metric/store."""
        with self._lock:
            if not isinstance(key, slice):
                raise TypeError("RouteLedger supports only slice assignment")
            if key.start not in (None, 0) or key.stop not in (None, -1) \
                    or key.step not in (None, 1):
                raise TypeError(
                    "RouteLedger supports only full-slice assignment "
                    "(ledger[:] = ...); a partial range would silently drop "
                    "live routes from cleanup tracking")
            self._entries.clear()
            for item in value:
                fam, dest, iface, gw = item
                self._entries.append(RouteReceipt(
                    str(fam), str(dest), str(iface), str(gw or ""),
                    1, "active", self._tag))

    def clear(self):
        with self._lock:
            self._entries.clear()

    def __iter__(self):
        with self._lock:
            return iter([r.key for r in self._entries])

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def __bool__(self) -> bool:
        with self._lock:
            return bool(self._entries)

    # ── full-fidelity access ───────────────────────────────────────────────
    def receipts(self) -> list:
        """Snapshot of the stored RouteReceipt objects."""
        with self._lock:
            return list(self._entries)

    def metric_of(self, item, default: int = 1) -> int:
        """The metric a route was installed with (default when untracked)."""
        fam, dest, iface, gw = _unpack4(item)
        with self._lock:
            for r in self._entries:
                if r.key == (str(fam), str(dest), str(iface), str(gw or "")):
                    return r.metric
        return default

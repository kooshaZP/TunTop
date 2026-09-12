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
        (mirrors list.remove)."""
        fam, dest, iface, gw = (item[0], item[1], item[2], item[3])
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
        fam, dest, iface, gw = (item[0], item[1], item[2], item[3])
        with self._lock:
            for i, r in enumerate(self._entries):
                if r.key == (str(fam), str(dest), str(iface), str(gw or "")):
                    return i
        raise ValueError(tuple(item))

    def __contains__(self, item) -> bool:
        try:
            self.index(item)
            return True
        except ValueError:
            return False

    def __setitem__(self, key, value):
        """Slice assignment (ledger[:] = [...]) for list compatibility;
        new items get the default metric/store."""
        with self._lock:
            if not isinstance(key, slice):
                raise TypeError("RouteLedger supports only slice assignment")
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
        fam, dest, iface, gw = (item[0], item[1], item[2], item[3])
        with self._lock:
            for r in self._entries:
                if r.key == (str(fam), str(dest), str(iface), str(gw or "")):
                    return r.metric
        return default

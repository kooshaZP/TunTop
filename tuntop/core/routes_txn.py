"""Transactional route management - the Windows routing table is NOT the
place for half-applied changes.

The old install paths added routes one by one and kept going on failure.
A single failed `route add` could leave a HALF-CONFIGURED bypass: IPv4 of
an entry routed direct while its IPv6 still dies inside the TUN, or three
of four default routes replaced - silently, discovered only when traffic
misbehaves.

A RouteTransaction makes that impossible:

    plan        - collect every add/remove the change needs
    apply       - execute in order, VERIFYING each (an add that "succeeded"
                  but didn't actually install is a failure, not a pass)
    verify/     - any failure aborts the run...
    rollback    - ...and undoes everything already applied, in REVERSE
                  order: added routes are removed, REPLACED routes are
                  restored with their original gateway/metric
    commit      - only when every op verified

Rollback is best-effort and never raises: if the system fights the undo
(route vanished mid-rollback), the error is recorded in the result and
surfaced to the log, but the transaction still returns a truthful report
instead of exploding in a cleanup path.

The Windows bindings are injected via `Backend` (defaulting to the
battle-tested helpers in tuntop.routing), so tests run against a tiny
in-memory routing table on any OS (see tests/test_routes_txn.py).

Pure stdlib, zero pip dependencies.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from tuntop.network import routing


@dataclass(frozen=True)
class RouteOp:
    """One planned change to the routing table."""

    action: str                    # "add" | "remove"
    family: str                    # "v4" | "v6"
    dest: str                      # prefix, e.g. "1.2.3.4/32" or "::1/128"
    iface: str                     # interface alias
    gateway: Optional[str] = None  # next hop (None = on-link)
    metric: int = 1

    def __str__(self):
        via = f" via {self.gateway}" if self.gateway else " (on-link)"
        return f"{self.action} {self.dest} on {self.iface}{via}"


@dataclass
class RouteResult:
    """Truthful report of what a commit() actually did."""

    ok: bool = False
    applied: list = field(default_factory=list)   # RouteOps that verified
    failed: list = field(default_factory=list)    # [(RouteOp, error), ...]
    rolled_back: list = field(default_factory=list)  # undo ops that verified
    errors: list = field(default_factory=list)    # rollback failures (text)

    def __bool__(self):
        return self.ok


class Backend:
    """The Windows primitives a transaction needs, injectable for tests.

    REQUIRED (legacy contract, unchanged): add/exists/del per family.
    `add`/`del` return True on success; `exists(dest)` is the coarse
    prefix probe used by older backends.

    OPTIONAL identity-aware primitives (Phase: exact verification):
      * verify_*(dest, iface, gateway, metric) -> bool
        "is OUR EXACT route present?" - the correct gate for both an add
        (must be true) and a remove (must be false). When absent, the
        transaction falls back to the prefix-level exists() probe, so every
        pre-existing custom backend keeps working unchanged.
      * table_*(dest) -> [{'iface','nexthop','eff'}] best-first
        all live routes for the prefix with their EFFECTIVE metric, used
        to catch the "half-true" install: our /32 is present but a foreign
        same-prefix route with a better metric owns the traffic. Only
        checked for host routes (/32, /128) where sole ownership is the
        whole point; default/split routes legitimately co-exist.

    `del` may return a bool or a (removed, foreign) tuple - both honored
    (the old code took bool() of the tuple, which is ALWAYS true: a
    silently failed delete used to pass; that bug is now closed)."""

    def __init__(self,
                 add_v4: Callable, exists_v4: Callable, del_v4: Callable,
                 add_v6: Callable, exists_v6: Callable, del_v6: Callable,
                 verify_v4: Optional[Callable] = None,
                 verify_v6: Optional[Callable] = None,
                 table_v4: Optional[Callable] = None,
                 table_v6: Optional[Callable] = None):
        self._add = {"v4": add_v4, "v6": add_v6}
        self._exists = {"v4": exists_v4, "v6": exists_v6}
        self._del = {"v4": del_v4, "v6": del_v6}
        self._verify = {"v4": verify_v4, "v6": verify_v6}
        self._table = {"v4": table_v4, "v6": table_v6}

    def add(self, op: RouteOp) -> bool:
        return bool(self._add[op.family](op.dest, op.iface, op.gateway,
                                         op.metric))

    def exists(self, op: RouteOp) -> bool:
        return bool(self._exists[op.family](op.dest))

    def remove(self, op: RouteOp) -> bool:
        res = self._del[op.family](op.dest, op.iface, op.gateway)
        if isinstance(res, tuple):        # (removed, foreign)
            res = res[0]
        return bool(res)

    def verify(self, op: RouteOp) -> bool:
        """Is our EXACT route present? Falls back to the legacy prefix
        probe for backends without an identity-aware verifier."""
        fn = self._verify[op.family]
        if fn is None:
            return self.exists(op)
        try:
            return bool(fn(op.dest, op.iface, op.gateway, op.metric))
        except TypeError:               # custom backends with fewer params
            return bool(self._exists[op.family](op.dest))

    def shadow(self, op: RouteOp) -> Optional[str]:
        """For host routes: return a human-readable conflict description
        when a FOREIGN same-prefix route owns the traffic (strictly better
        effective metric than ours). None = no conflict / not checkable."""
        fn = self._table[op.family]
        if fn is None or not _is_host_route(op.dest):
            return None
        try:
            rows = fn(op.dest) or []
        except TypeError:
            return None
        ours = None
        for r in rows:
            if (str(r.get("iface", "")).lower() == str(op.iface or "").lower()
                    and _norm_gw(op.family, r.get("nexthop"))
                    == _norm_gw(op.family, op.gateway)):
                ours = r
                break
        if ours is None or not rows:
            return None
        best = min(rows, key=lambda r: int(r.get("eff", 0) or 0))
        if int(best.get("eff", 0) or 0) < int(ours.get("eff", 0) or 0):
            return (f"shadowed by better-metric route "
                    f"on '{best.get('iface')}'")
        return None


def _is_host_route(dest: str) -> bool:
    """/32 (IPv4) or /128 (IPv6): single-destination routes, where co-
    existing same-prefix routes on other interfaces are a CONFLICT, not a
    normal state like the default-route coexistence the split /1 trick
    relies on."""
    try:
        plen = int((dest or "").rsplit("/", 1)[1])
    except (ValueError, IndexError):
        return False
    return plen == 128 if ":" in (dest or "") else plen == 32


def _norm_gw(fam, gw):
    g = (gw or "").strip()
    return g or ("0.0.0.0" if fam == "v4" else "::")


#: The real Windows backend (netsh add/verify + PowerShell delete with
#: fallbacks - the exact helpers the non-transactional paths always used),
#: upgraded with the identity-aware verify/table primitives.
WINDOWS_BACKEND = Backend(
    add_v4=routing._add_route_v4, exists_v4=routing._route_exists_v4,
    del_v4=routing._del_route_v4,
    add_v6=routing._add_route_v6, exists_v6=routing._route_exists_v6,
    del_v6=routing._del_route_v6,
    verify_v4=routing._route_matches_v4, verify_v6=routing._route_matches_v6,
    table_v4=routing._route_table_v4, table_v6=routing._route_table_v6,
)


class RouteTransaction:
    """A planned set of route changes applied as ONE unit (all-or-nothing).

    Typical use - install both families of a bypass entry atomically:

        txn = RouteTransaction()
        txn.add_v4("1.2.3.4/32", "Wi-Fi", "192.168.1.1")
        txn.add_v6("2606:4700::1111/128", "Wi-Fi", "fe80::1")
        result = txn.commit()
        if result:
            ... all routes verified present ...
        else:
            ... system routing table is UNCHANGED; result.failed says why ...

    Removals are rollback-aware too: `remove_*` remembers the full route
    (dest/iface/gateway/metric), so a later failed op restores the removed
    routes instead of leaving them deleted.
    """

    def __init__(self, backend: Optional[Backend] = None,
                 log: Optional[Callable[[str], None]] = None):
        self._backend = backend or WINDOWS_BACKEND
        self._log = log or (lambda msg: None)
        self._ops: list = []

    # -- Planning -----------------------------------------------------------

    def add_v4(self, dest: str, iface: str, gateway: Optional[str] = None,
               metric: int = 1) -> "RouteTransaction":
        self._ops.append(RouteOp("add", "v4", dest, iface, gateway, metric))
        return self

    def add_v6(self, dest: str, iface: str, gateway: Optional[str] = None,
               metric: int = 1) -> "RouteTransaction":
        self._ops.append(RouteOp("add", "v6", dest, iface, gateway, metric))
        return self

    def remove_v4(self, dest: str, iface: str,
                  gateway: Optional[str] = None,
                  metric: int = 1) -> "RouteTransaction":
        # The full route is remembered (incl. metric): rollback re-adds it
        # verbatim.
        self._ops.append(RouteOp("remove", "v4", dest, iface, gateway,
                                 metric))
        return self

    def remove_v6(self, dest: str, iface: str,
                  gateway: Optional[str] = None,
                  metric: int = 1) -> "RouteTransaction":
        self._ops.append(RouteOp("remove", "v6", dest, iface, gateway,
                                 metric))
        return self

    @property
    def ops(self) -> tuple:
        """The planned operations, in apply order."""
        return tuple(self._ops)

    def __len__(self):
        return len(self._ops)

    # -- Execution ------------------------------------------------------------

    def commit(self, progress: Optional[Callable] = None) -> RouteResult:
        """Apply the plan with all-or-nothing semantics.

        `progress(done, total, op)` is called before each op (for progress
        UIs); it must not mutate the transaction. Returns a RouteResult:
        ok=True  - every op applied AND verified;
        ok=False - the first failure aborted the run and everything already
                   applied was rolled back (result.rolled_back lists the
                   undo ops that verified; result.errors what fought back).
        """
        result = RouteResult()
        if not self._ops:
            result.ok = True
            return result
        total = len(self._ops)
        applied = []
        for i, op in enumerate(self._ops):
            if progress is not None:
                try:
                    progress(i, total, op)
                except Exception:
                    pass                      # a broken UI must not abort
            err = self._apply_one(op)
            if err is None:
                applied.append(op)
                continue
            # The op FAILED but may have installed a route anyway (verified
            # present yet shadowed / half-committed): remove it before
            # unwinding, so a failed op can never leak live state.
            if op.action == "add":
                try:
                    if self._backend.verify(op):
                        self._backend.remove(op)
                except Exception:
                    pass
            result.failed.append((op, err))
            self._log(f"[!] Route transaction aborted at '{op}': {err}")
            break
        else:
            result.applied = applied
            result.ok = True
            return result
        # A failure happened: undo everything applied so far, in reverse.
        result.errors = self._rollback(applied, result.rolled_back)
        return result

    def _apply_one(self, op: RouteOp) -> Optional[str]:
        """Execute one op and VERIFY it took effect. Returns an error string
        or None on verified success.

        Verification is IDENTITY-aware when the backend provides it:
        an add passes only if OUR exact route (dest + interface + next-hop
        + metric) is live and, for host routes, no foreign better-metric
        route shadows the prefix; a remove passes only if OUR route is gone
        (a foreign same-prefix route on another interface is NOT a failure
        - it was never ours)."""
        be = self._backend
        try:
            if op.action == "add":
                if not be.add(op):
                    return "route add reported failure"
                if not be.verify(op):
                    # netsh said OK but our exact route is not in the table
                    # - the classic silent half-install; treat as a failure.
                    return ("route add claimed success but the exact route "
                            "is not in the table")
                conflict = be.shadow(op)
                if conflict:
                    return f"route add verified but {conflict}"
            else:
                # A scoped delete may honestly report "not fully removed"
                # because a FOREIGN same-prefix route survives on another
                # interface - that is not our failure if OUR exact route
                # is gone. The identity verify decides.
                if not be.remove(op) and be.verify(op):
                    return "route delete reported failure"
                if be.verify(op):
                    return ("route delete claimed success but our exact "
                            "route is still in the table")
        except Exception as e:
            return f"{type(e).__name__}: {e}"
        return None

    def _rollback(self, applied: list, into: list) -> list:
        """Undo applied ops in reverse order. Best-effort: records errors,
        never raises. `into` collects the undo ops that verified."""
        errors = []
        for op in reversed(applied):
            undo = RouteOp(
                "remove" if op.action == "add" else "add",
                op.family, op.dest, op.iface, op.gateway, op.metric)
            try:
                err = self._apply_one(undo)
            except Exception as e:            # _apply_one already guards;
                err = f"{type(e).__name__}: {e}"   # belt for custom backends
            if err is None:
                into.append(undo)
            else:
                errors.append(f"rollback of '{op}' failed: {err}")
                self._log(f"[!] Rollback: could not undo '{op}' ({err}) - "
                          "route table may need a manual check.")
        return errors


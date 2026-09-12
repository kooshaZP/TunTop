"""Shared test doubles for the whole suite.

`FakeRouter` is the in-memory routing table used wherever the real
Windows route store would be touched (transactional route tests, the
dashboard's bypass-install flow). Keeping it in one place guarantees the
same semantics everywhere a route is faked.
"""


class FakeRouter:
    """In-memory routing table with failure injection.

    `fail_on` maps a dest prefix to a failure for add;
    `silent_fail` makes add() return True WITHOUT installing (the silent
    half-install the transaction must catch via verification);
    `fail_deletes` makes del() claim success but remove nothing."""

    def __init__(self):
        self.table = {}        # (family, dest) -> (iface, gateway, metric)
        self.fail_on = {}
        self.silent_fail = set()
        self.fail_deletes = False
        self.calls = []

    def backend(self):
        from tuntop.routes_txn import Backend
        return Backend(add_v4=self._add, exists_v4=self._exists,
                       del_v4=self._del, add_v6=self._add,
                       exists_v6=self._exists, del_v6=self._del)

    def _add(self, dest, iface, gateway, metric=1):
        family = "v6" if ":" in dest else "v4"
        self.calls.append(("add", family, dest))
        if dest in self.fail_on:
            return False
        if dest in self.silent_fail:
            return True                     # claims success, installs nothing
        self.table[(family, dest)] = (iface, gateway, metric)
        return True

    def _exists(self, dest):
        family = "v6" if ":" in dest else "v4"
        return (family, dest) in self.table

    def _del(self, dest, iface, gateway):
        family = "v6" if ":" in dest else "v4"
        self.calls.append(("del", family, dest))
        if self.fail_deletes:
            return True                     # claims success, removes nothing
        return self.table.pop((family, dest), None) is not None


class FakeExactRouter:
    """Multi-slot in-memory routing table for the IDENTITY-aware backend
    contract (routes_txn.Backend verify/table). Unlike FakeRouter (one slot
    per prefix, prefix-only semantics), this models Windows' real behavior:
    SEVERAL routes can share one prefix on different interfaces, and the
    winner is picked by EFFECTIVE metric (route metric + interface metric).

    Failure/conflict injection:
      fail_on[dest]            - add returns False (netsh error)
      silent_fail{dest}        - add returns True but installs NOTHING
      misdirect[dest]=(if,gw)  - add installs under a DIFFERENT identity
                                 than requested (the half-commit netsh
                                 "success" the old prefix check accepted)
      ifmetric[iface]=N        - per-interface metric (effective-metric
                                 winner computation)
      seed(dest, iface, gw, m) - pre-existing / foreign routes

    `calls` records every operation for ordering assertions."""

    def __init__(self):
        self.table = {}          # (family, dest) -> list of row dicts
        self.ifmetric = {}       # iface -> interface metric
        self.fail_on = {}
        self.silent_fail = set()
        self.misdirect = {}
        self.fail_deletes = False
        self.calls = []

    @staticmethod
    def _fam(dest):
        return "v6" if ":" in dest else "v4"

    @staticmethod
    def _norm(fam, gw):
        g = (gw or "").strip()
        return g or ("0.0.0.0" if fam == "v4" else "::")

    def _rows(self, dest):
        return self.table.setdefault((self._fam(dest), dest), [])

    def add(self, dest, iface, gateway, metric=1):
        fam = self._fam(dest)
        self.calls.append(("add", fam, dest, iface, gateway, metric))
        if dest in self.fail_on:
            return False
        if dest in self.silent_fail:
            return True                     # claims success, installs nothing
        if dest in self.misdirect:
            iface, gateway = self.misdirect[dest]
        self._rows(dest).append({"iface": iface, "gateway": gateway,
                                 "metric": int(metric)})
        return True

    def exists(self, dest):
        """Legacy prefix-level probe (kept for the fallback path)."""
        return bool(self.table.get((self._fam(dest), dest)))

    def verify(self, dest, iface, gateway, metric):
        fam = self._fam(dest)
        want = self._norm(fam, gateway)
        for r in self.table.get((fam, dest), []):
            if (r["iface"].lower() == str(iface or "").lower()
                    and self._norm(fam, r["gateway"]) == want
                    and int(r["metric"]) == int(metric or 0)):
                return True
        return False

    def table_rows(self, dest):
        """routes_txn.Backend.shadow contract: best-first eff rows."""
        fam = self._fam(dest)
        rows = [{"iface": r["iface"], "nexthop": r["gateway"],
                 "eff": int(r["metric"]) + int(self.ifmetric.get(r["iface"], 0))}
                for r in self.table.get((fam, dest), [])]
        return sorted(rows, key=lambda r: r["eff"])

    def remove(self, dest, iface, gateway):
        fam = self._fam(dest)
        self.calls.append(("del", fam, dest, iface, gateway))
        if self.fail_deletes:
            return (True, False)            # claims success, removes nothing
        rows = self.table.get((fam, dest), [])
        want = self._norm(fam, gateway)
        keep = [r for r in rows
                if not (r["iface"].lower() == str(iface or "").lower()
                        and self._norm(fam, r["gateway"]) == want)]
        removed = len(keep) != len(rows)
        self.table[(fam, dest)] = keep
        return (removed, bool(keep))        # (removed, foreign-left-behind)

    def backend(self):
        from tuntop.routes_txn import Backend
        return Backend(add_v4=self.add, exists_v4=self.exists,
                       del_v4=self.remove, add_v6=self.add,
                       exists_v6=self.exists, del_v6=self.remove,
                       verify_v4=self.verify, verify_v6=self.verify,
                       table_v4=self.table_rows, table_v6=self.table_rows)

    def seed(self, dest, iface, gateway, metric=1):
        self._rows(dest).append({"iface": iface, "gateway": gateway,
                                 "metric": int(metric)})

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
        from tunmood.routes_txn import Backend
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

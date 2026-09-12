"""Route-ops layer: the single place that defines how TunTop ACCOUNTS for
routes it installs and how it MATCHES leftovers in the live table.

Two halves:
  * ledger.RouteLedger - a thread-safe registry of every route a process
    installed, carrying FULL fidelity (family, prefix, interface, next-hop,
    metric, store, tag) instead of bare 4-tuples. A route that was installed
    with metric=10 is remembered with metric=10, so re-points and teardowns
    reproduce it exactly.
  * sweeps - pure matching functions (LAN victims, geo victims, host-route
    statement builder) shared by the dashboard's exit sweeps, the helper's
    cleanup, the startup recovery and the detached watchdog. ONE
    implementation of the matching rules instead of four drifting copies.

No Windows calls happen in this package: everything here is pure logic the
platform callers drive.
"""
from tuntop.network.routeops.ledger import RouteLedger, RouteReceipt
from tuntop.network.routeops.results import RouteResult, unwrap
from tuntop.network.routeops import sweeps

__all__ = [
    "RouteLedger", "RouteReceipt", "RouteResult", "unwrap", "sweeps",
]

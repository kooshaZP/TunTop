"""Leak-test interface (Monitor layer).

The stdlib-only probe mechanics (SOCKS5 client, IP-echo endpoint racing,
IP validation, verdict matrix) live in tuntop/network/leak_probe.py - a
neutral stdlib leaf that BOTH this module and the standalone tunnel helper
(tuntop/tunnel/helper.py) import.  Keeping ONE implementation is what
closed the gap where the helper's autonomous monitor and the dashboard's
[L]/[C] checks could silently drift apart (the inverted-verdict bug lived
in exactly that shape: logic copied per component, tested in one place).

This module owns the Monitor-layer face of the probe:
  * run_leak_probe / LEAK_TIMEOUT - re-exported for the dashboard
  * as_check_result - maps a probe status onto the health-check suite's
    (ok, detail) tuple

See tuntop/network/leak_probe.py for the method (direct vs SOCKS-proxied
egress, raced endpoints) and the full verdict table.
"""
from __future__ import annotations

from tuntop.network.leak_probe import (        # noqa: F401
    run_leak_probe,
    LEAK_TIMEOUT,
)

__all__ = ["run_leak_probe", "as_check_result", "LEAK_TIMEOUT"]


def as_check_result(status, message):
    """Map a probe status onto the health-check suite's (ok, detail) tuple.

    "inconclusive" counts as a PASS: the tunnel leg was proven working and
    only the direct comparison could not be made - that is not a tunnel
    fault (see the verdict table in tuntop/network/leak_probe.py)."""
    if status == "inconclusive":
        return True, message
    return status == "ok", message

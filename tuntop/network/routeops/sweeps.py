"""Pure matching rules for the leftover sweeps.

Every exit path (dashboard [Q]/[T]/atexit/close, helper cleanup, startup
recovery, detached watchdog) needs to answer the same question: "which
routes in the live table are OURS?" Four modules used to carry four
hand-synced copies of that answer. These functions are the one copy; the
callers hand in a route-table dump (list of dicts with DestinationPrefix /
InterfaceAlias / NextHop) and get back the delete rows.

No Windows calls: everything is string/list handling, unit-testable
anywhere.
"""
from __future__ import annotations

from tuntop.config.defaults import LAN_BYPASS_PREFIXES


def lan_victims(rows, iface, gw, prefixes=None):
    """LAN-bypass routes on the CURRENT physical adapter that are ours:
    next-hop == the current gateway, on-link Windows-managed noise, empty
    next-hop - or a REAL next-hop from a PREVIOUS network on the same
    adapter (a stale pin; the caller deletes it next-hop-exact, so a
    foreign static route via another gateway is never touched)."""
    prefixes = set(prefixes or LAN_BYPASS_PREFIXES)
    victims = []
    for r in rows:
        dp = str(r.get("DestinationPrefix", ""))
        if dp not in prefixes:
            continue
        alias = str(r.get("InterfaceAlias", "") or "")
        nh = str(r.get("NextHop", "") or "")
        if alias != str(iface):
            continue
        victims.append((dp, alias, nh))
    return victims


def geo_victims(rows, cidrs):
    """Live routes whose DestinationPrefix is EXACTLY one of `cidrs` (a
    geoip country's set) - on any interface/gateway. Exact matching means a
    foreign more-specific route inside a country range is never touched."""
    cidrs = set(cidrs or ())
    if not cidrs:
        return []
    victims = []
    for r in rows:
        dp = str(r.get("DestinationPrefix", ""))
        if dp in cidrs:
            victims.append((dp,
                            str(r.get("InterfaceAlias", "") or ""),
                            str(r.get("NextHop", "") or "")))
    return victims


def host_route_stmts(ips):
    """PowerShell statements removing the /32 (v4) and /128 (v6) host route
    for every IP in `ips`, regardless of interface/gateway. One statement
    per family per IP; idempotent (removing an absent prefix is ignored)."""
    stmts = []
    for ip in ips:
        ip = str(ip).replace("'", "")
        if ":" in ip:
            stmts.append(f"Remove-NetRoute -DestinationPrefix '{ip}/128' "
                         f"-AddressFamily IPv6 -Confirm:$false "
                         f"-ErrorAction SilentlyContinue | Out-Null")
        else:
            stmts.append(f"Remove-NetRoute -DestinationPrefix '{ip}/32' "
                         f"-AddressFamily IPv4 -Confirm:$false "
                         f"-ErrorAction SilentlyContinue | Out-Null")
    return stmts

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

import ipaddress

from tuntop.config.defaults import LAN_BYPASS_PREFIXES
from tuntop.psshell import ps_quote

#: Next-hop spellings Windows uses for "on-link / no gateway". A route with
#: one of these carries no gateway identity of its own, so it cannot be a
#: foreign static route pinned to some other router.
ON_LINK_NH = frozenset(("", "0.0.0.0", "::", "on-link", "0.0.0.0,0.0.0.0"))


def _lit(text) -> str:
    """A quoted, escaped PowerShell single-quoted string literal.

    ps_quote() only DOUBLES embedded apostrophes - the surrounding quotes are
    the caller's job (same convention as routing.py)."""
    return "'" + ps_quote(text) + "'"


def _canon_cidr(text):
    """Normalise a CIDR to the canonical string, or None if unparsable.

    Windows stores and reports the CANONICAL form, while a geoip CIDR can
    arrive uncompressed ("2001:db8:0:0:0:0:0:0/32") or with host bits set
    ("1.2.3.4/24"). A string compare misses both, so every IPv6 geo route
    survived every sweep and a whole country kept routing around a dead
    tunnel. Comparing ip_network objects closes the gap.
    """
    try:
        return str(ipaddress.ip_network(str(text), strict=False))
    except ValueError:
        return None


def _canon_cidrs(values):
    return {_canon_cidr(v) for v in (values or ())} - {None}


def lan_victims(rows, iface, gw, prefixes=None):
    """LAN-bypass routes on the CURRENT physical adapter that are OURS.

    "Ours" means: the next hop is the CURRENT gateway, or one of the
    on-link/empty spellings (Windows-managed noise that the helper's own
    install leaves behind). `gw` is REQUIRED and used - accepting "a real
    next-hop from a previous network" as well is not a safety property: a
    next-hop-exact delete of a row you selected is still a delete, and a
    corporate static route (10.0.0.0/8 -> 10.20.30.1 on Ethernet, a VPN
    split tunnel, a NAS subnet) is indistinguishable from our own stale
    pin. Deleting those broke LAN/VPN connectivity on quit, and the crash
    watchdog fed the same victim list straight into a `netsh -f` script.

    Genuinely-installed stale routes are tracked in the RouteLedger with
    their gateway and metric precisely so the exit sweep can remove exactly
    what THIS run installed, without guessing.
    """
    prefixes = (_canon_cidrs(prefixes) if prefixes is not None
                else _canon_cidrs(LAN_BYPASS_PREFIXES))
    want_iface = str(iface or "").strip().casefold()
    want_gw = str(gw or "").strip().casefold()
    victims = []
    for r in rows or []:
        dp = _canon_cidr(r.get("DestinationPrefix", ""))
        if dp is None or dp not in prefixes:
            continue
        alias = str(r.get("InterfaceAlias", "") or "").strip().casefold()
        nh = str(r.get("NextHop", "") or "").strip()
        if alias != want_iface:
            continue
        if nh.strip().casefold() in ON_LINK_NH:
            victims.append((dp, str(r.get("InterfaceAlias", "") or ""), nh))
        elif want_gw and nh.strip().casefold() == want_gw:
            victims.append((dp, str(r.get("InterfaceAlias", "") or ""), nh))
    return victims


def geo_victims(rows, cidrs):
    """Live routes whose DestinationPrefix is EXACTLY one of `cidrs` (a
    geoip country's set) - on any interface/gateway. Exact matching means a
    foreign MORE-SPECIFIC route inside a country range is never touched."""
    wanted = _canon_cidrs(cidrs)
    if not wanted:
        return []
    victims = []
    for r in rows or []:
        dp = _canon_cidr(r.get("DestinationPrefix", ""))
        if dp in wanted:
            victims.append((dp,
                            str(r.get("InterfaceAlias", "") or ""),
                            str(r.get("NextHop", "") or "")))
    return victims


def host_route_stmts(ips, aliases=()):
    """PowerShell statements removing the /32 (v4) and /128 (v6) host route
    for every IP in `ips`, SCOPED to `aliases` when they are given.

    This is the last-resort exit sweep, and the scoping is not a nicety:
    routing.py documents at length that a bare
    `Remove-NetRoute -DestinationPrefix '<dest>'` deletes that prefix on
    EVERY interface, and that "TunTop must not delete a route it did not
    create". Without -InterfaceAlias this function did exactly that - on
    quit it removed the server/bypass /32 from a corporate VPN adapter too,
    breaking a VPN-client-pinned host route the VPN client did not always
    re-add. When no aliases are supplied the caller gets unscoped
    statements and must justify that itself (there is no interface to scope
    to when the route table could not be read).

    Free-text values go through ps_quote(), which DOUBLES embedded quotes;
    the old `replace("'", "")` stripped them instead and left `;`, `$(...)`
    and backticks intact.
    """
    stmts = []
    scope = [str(a) for a in (aliases or ()) if str(a).strip()]
    for ip in ips or ():
        ip = str(ip).strip()
        if not ip:
            continue
        fam, plen = ("IPv6", 128) if ":" in ip else ("IPv4", 32)
        prefix = _lit(f"{ip}/{plen}")
        base = (f"Remove-NetRoute -DestinationPrefix {prefix} "
                f"-AddressFamily {fam} -Confirm:$false "
                f"-ErrorAction SilentlyContinue")
        if not scope:
            stmts.append(base + " | Out-Null")
            continue
        cond = " -or ".join(
            f"$_.InterfaceAlias -eq {_lit(a)}" for a in scope)
        stmts.append(
            f"Get-NetRoute -DestinationPrefix {prefix} "
            f"-AddressFamily {fam} -ErrorAction SilentlyContinue | "
            f"Where-Object {{ {cond} }} | "
            f"Remove-NetRoute -Confirm:$false "
            f"-ErrorAction SilentlyContinue | Out-Null")
    return stmts

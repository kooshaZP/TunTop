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
from tuntop.network import egress_scripts as _egress_scripts
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


def lan_victim_deletes(rows, iface, gw, prefixes=None):
    """`lan_victims` shaped for a caller that must emit a delete, i.e.
    (dest, alias, next_hop_or_empty) tuples where an EMPTY next hop means
    "delete every route for this prefix on this interface".

    WHY THE WIDENING IS HERE AND NOT IN THE CALLER
    -----------------------------------------------
    Two of lan_victims' three match classes are on-link or exactly the current
    gateway. For those, `netsh interface <v4|v6> delete route <prefix> <iface>`
    (no next-hop token) is the ONLY form netsh accepts - passing the on-link
    spelling is rejected outright, which is why `_norm_v4_gw` exists at all.

    So the delete token has to differ by class, and the dashboard's copy of that
    rule was the only place encoding it - three branches in
    `_sweep_lan_leftovers`, reimplementing a decision that belongs beside the
    match rule. It also meant the watchdog, which calls `lan_victims` directly,
    could not express the same result at all: it emitted a next-hop-exact delete
    for the current-gateway class, so a LAN pin left by a crashed run with a
    network change in between (still on the current adapter, pointing at the
    OLD gateway) was invisible to its sweep while the dashboard removed it. Same
    state, two verdicts - exactly the drift this module exists to prevent.

    Every victim gets the WIDENED (next-hop-less) token, and that is not a
    convenience - it is the only form that works:

      * on-link / empty spellings: netsh REJECTS them as a next-hop token, so
        the exact form cannot delete the row at all;
      * the current gateway: Windows does not hold two rows with the same
        prefix, adapter, next hop and route metric, so on THIS adapter for
        THIS gateway "delete every route for the prefix" removes precisely the
        row we selected and nothing else.

    A real next hop that is NOT the current gateway is never widened, because
    it is never a victim either: a corporate static route
    (10.0.0.0/8 -> 10.20.30.1 on Ethernet), a VPN split tunnel and a NAS
    subnet are indistinguishable from one of our own stale pins, so
    `lan_victims` refuses the class outright and this function has nothing to
    widen. The dashboard's old inline copy carried a third branch for it -
    unreachable, since its input was already `lan_victims` output, which is why
    no test ever noticed it contradicting the watchdog.
    """
    return [(dest, alias, "") for dest, alias, _nh
            in lan_victims(rows, iface, gw, prefixes=prefixes)]


#: The minimum prefix length a geo range may have, per family. The mirror of
#: helper._is_routable_bypass_cidr's floor - kept as a constant here because the
#: sweep needs the same rule and the install-side rule lives in the helper (see
#: geo_victims for why the sweep must enforce it at all).
MIN_PREFIXLEN = {4: 8, 6: 16}


def is_sweepable_geo_cidr(cidr):
    """True when a geo range is one the SWEEP is allowed to delete.

    THIS IS NOT A REDUNDANT COPY OF THE INSTALL RULE - it closes a live bug.
    `helper._is_routable_bypass_cidr` refuses private / loopback / link-local /
    / multicast / reserved ranges, the tunnel's own subnets, and anything broader
    than a /8 (v4) or /16 (v6) before it is ever INSTALLED. `geo_victims` used
    to filter nothing at all: it compared prefixes and deleted whatever matched.

    The two lists are derived from different sources, so they are not the same
    set. `parse_geoip('private')` against the shipped geofil/geoip.dat returns
    10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 AND
    **100.64.0.0/10** - and CGNAT is the one that matters, because it is NOT
    `is_private` on Python 3.10-3.12 (only 3.13+ learned it), so the install
    accepted it as a routable country range, AND `100.64.0.0/10` is a
    LAN_BYPASS_PREFIX - the LAN bypass installs it on every run. The geo sweep
    then deleted TunTop's own LAN bypass route on every [R]/[F]->5 apply, every
    [Q], and every watchdog pass. The route came straight back on the next
    start, and in between the CGNAT range (Tailscale, mobile-broadband handsets)
    rode the physical NIC against the user's intent.

    The invariant geoip.py already states - "install is protected, but the SWEEP
    is not, so the sweep boundary has to refuse them too" - was half-implemented:
    the prefix-length floor was enforced here, the routability half was not.

    Routability comes from `egress_scripts.is_globally_routable` - the SAME
    predicate the install side uses, over an explicit IANA special-purpose
    registry, so the two boundaries cannot drift and the answer does not depend
    on which CPython is running. The floor is re-applied rather than assumed, so
    a caller passing a hand-built CIDR list cannot widen the sweep past what
    install would accept."""
    if not _egress_scripts.is_globally_routable(cidr):
        return False
    try:
        net = ipaddress.ip_network(str(cidr).strip(), strict=False)
    except ValueError:
        return False
    return net.prefixlen >= MIN_PREFIXLEN.get(net.version, 8)


def geo_victims(rows, cidrs):
    """Live routes whose DestinationPrefix is EXACTLY one of `cidrs` (a
    geoip country's set) - on any interface/gateway. Exact matching means a
    foreign MORE-SPECIFIC route inside a country range is never touched.

    Non-routable and over-broad ranges are refused, not matched - see
    `is_sweepable_geo_cidr`. Without that filter the sweep deleted the project's
    OWN 100.64.0.0/10 LAN bypass route, because that prefix is in
    LAN_BYPASS_PREFIXES *and* in a `.dat`'s country list, and Python does not
    consider CGNAT private."""
    wanted = _canon_cidrs(cidrs)
    if not wanted:
        return []
    victims = []
    for r in rows or []:
        dp = _canon_cidr(r.get("DestinationPrefix", ""))
        if dp in wanted and is_sweepable_geo_cidr(dp):
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

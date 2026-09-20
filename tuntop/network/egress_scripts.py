"""Single source of truth for the PowerShell TEXT every egress route
lookup uses - in BOTH processes (the tun2socks helper and the dashboard).

Reviewer issue #5 (duplicated routing logic): the tunnel/VPN alias
preambles used to exist twice - once in ``tuntop.tunnel.helper`` and once
mirrored inside ``tuntop.network.routing`` - and every fix had to land in
both (the ``^wintun`` alias filter -> driver-description change had to be
applied twice in 1.0.26, and an earlier VPN-exclusion fix was once missed
in the mirror and shipped broken). Both sides now import the script text
from HERE, and ``tests/routing/test_egress_scripts_drift.py`` asserts the
mirrored wrappers keep resolving to this module.

Pure strings: no Windows imports, no execution. Callers embed these
preambles in their own script and run them through their own runner.
"""
import re

from tuntop.config.defaults import TUN, TUN2, VPN_IFACE_RE
from tuntop.psshell import ps_quote

#: Foreign full-tunnel TUN detection. 'Wintun' alone was NOT enough: Throne's
#: 'sing-tun Tunnel' adapter (a sing-box TUN) owns 176.0.0.0/4 - a quarter of
#: the IPv4 space - so Find-NetRoute resolved the VLESS server IP ONTO that
#: TUN, the "bypass" /32 got pinned to it, and vanished when the adapter
#: churned. The server's traffic then fell into OUR TUN and looped. ANY
#: adapter whose description matches this is a tunnel: never an egress.
#: (PS -match is case-insensitive already; (?i) kept for the Python twin.)
#:
#: 1.0.33 adds 'tun2socks': the VENDORED tun2socks creates OUR OWN adapter
#: with a tunnelType whose description matched NEITHER 'wintun' nor any other
#: alternative - so the egress lookups saw our own TUN's 0/0 + 0/1 routes as
#: valid "physical" candidates and pinned every server /32 ONTO our own
#: wintun (the "the server IP goes to the wintun" report). 'tun2socks' never
#: appears in a physical NIC description.
TUN_DRIVER_RE = ("(?i)(wintun|tun2socks|sing-tun|\\btun\\b|\\btap\\b|tunnel|wireguard"
                 "|tailscale|openvpn|softether|zerotier|nekoray|mihomo|clash)")


def is_tun_iface(alias):
    """Python-side twin of the $tunAliases PS filter: True when an adapter
    alias/description looks like ANY tunnel adapter (ours, foreign TUN
    drivers, VPN tunnel clients). Used by the endpoint-route self-heal to
    recognise a bypass route that got pinned to the WRONG (tunnel) interface.
    Physical NIC descriptions (Intel Wi-Fi, Realtek GbE, ...) never match."""
    return bool(alias) and bool(re.search(TUN_DRIVER_RE, str(alias)))


def is_vpn_iface(alias):
    """Python-side twin of the VPN-alias filter: True when an adapter alias
    looks like a Windows-VPN pattern interface (pptp/l2tp/sstp/ikev2/vpn/
    wan miniport). Used by the endpoint-route self-heal to recognise a
    bypass that got pinned onto a CONNECTED VPN while in DIRECT mode - the
    transport may ride the VPN only in [V] vless-over-vpn mode. Plain
    physical NIC descriptions never match."""
    return bool(alias) and bool(re.search(VPN_IFACE_RE, str(alias)))

#: VPN alias regex as embedded PS literal (built from the single-source
#: config.defaults.VPN_IFACE_RE - never re-hardcode it).
VPN_ALIAS_PS_RE = "'" + VPN_IFACE_RE + "'"


def tun_alias_ps(var="$tunAliases"):
    """PowerShell preamble building ``$tunAliases``: names of ALL tunnel
    adapters (ours, AND foreign full-tunnel tools - v2rayN/xray Wintuns,
    Throne's 'sing-tun Tunnel', WireGuard/Tailscale/OpenVPN clients; see
    TUN_DRIVER_RE). Consumers filter with
    ``$tunAliases -notcontains $_.InterfaceAlias``.

    1.0.33: the collection matches the TUN driver on the DESCRIPTION *and*
    on the NAME (alias), and OUR OWN adapter aliases (TUN/TUN2) are always
    included. The vendored tun2socks creates our adapter with a tunnelType
    whose description matched NEITHER the old regex nor 'wintun' - so
    $tunAliases was blind to our own adapter, Find-NetRoute resolved every
    server IP through OUR 0/0 + 0/1 routes, and every bypass install
    ([A]/[U]/[R]/geo/self-heal) pinned the /32 ONTO our own wintun - the
    "the server IP goes to the wintun" report. A physical NIC is never
    named 'wintun*'/'tun2socks*', so name matching can only ever exclude
    tunnel adapters.
    """
    ours = ", ".join("'" + a + "'" for a in (TUN, TUN2))
    return (var + " = @(" + ours + ")\n"
            "Get-NetAdapter -ErrorAction SilentlyContinue | "
            "Where-Object { ($_.InterfaceDescription -match '"
            + TUN_DRIVER_RE + "') -or ($_.Name -match '" + TUN_DRIVER_RE
            + "') } | Select-Object -ExpandProperty Name | "
            "ForEach-Object { " + var + " += $_ }\n"
            + var + " = @(" + var + " | Select-Object -Unique)\n")


def vpn_alias_ps(var="$vpnAliases"):
    """PowerShell preamble building ``$vpnAliases``: every connected
    Windows VPN interface alias (correlated via Get-VpnConnection, which
    is name-reliable for built-in VPNs) plus any route whose alias
    text-matches the VPN heuristic. Used by every default-route lookup so
    a VPN is excluded no matter how the user named the connection."""
    return var + r""" = @(
    @(Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue) +
    @(Get-VpnConnection -ErrorAction SilentlyContinue) |
    Where-Object { $_.ConnectionStatus -eq 'Connected' } |
    Select-Object -ExpandProperty Name -Unique |
    ForEach-Object {
        $n = $_
        $_
        Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -InterfaceAlias $n -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty InterfaceAlias -Unique
        Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -InterfaceAlias $n -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty InterfaceAlias -Unique
    }
)
Get-NetRoute -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceAlias -match __VPN_RE__ } |
    Select-Object -ExpandProperty InterfaceAlias -Unique | ForEach-Object { __VAR__ += $_ }
__VAR__ = @(__VAR__ | Where-Object { $_ } | Select-Object -Unique)
""".replace("__VPN_RE__", VPN_ALIAS_PS_RE).replace("__VAR__", var)


def v4_default_filter_ps(strict=True):
    """Where-Object body selecting the REAL IPv4 default route: alive,
    has a gateway, lives on no TUN adapter; when ``strict`` also on no
    VPN-pattern interface (the last-resort fallback relaxes only the VPN
    exclusion, never the TUN one). Consumers must prepend tun_alias_ps().
    """
    clause = ("$_.NextHop -ne '0.0.0.0' -and $_.State -eq 'Alive' -and "
              + var_tun_notcontains()
              )
    if strict:
        clause += " -and $_.InterfaceAlias -notmatch " + VPN_ALIAS_PS_RE
    return clause


def var_tun_notcontains(var="$tunAliases"):
    """The standard 'this route is not on a TUN' predicate."""
    return var + " -notcontains $_.InterfaceAlias"


# ─── The FULL physical-IPv4-default lookup script (single source) ────────────
# Both processes run this EXACT text:
#   * helper process:  tunnel/helper.get_ipv4_default()
#   * dashboard mirror: network/routing._get_ipv4_default()
#
# History: the two sides each carried their own copy of this BODY. 1.0.28
# single-sourced only the preambles/filters above, so the bodies kept
# drifting - and the helper's CIM fallback carried a literal '%s' where the
# VPN-alias regex belonged. A literal '%s' regex never matches anything, so
# the VPN exclusion in that fallback was a silent NO-OP: with a full-tunnel
# VPN connected (which deletes the physical default route - exactly the
# VPN+TunTop scenario) the fallback returned the VPN adapter's gateway as
# the "physical" egress, the VLESS server's /32 bypass rode the VPN, and the
# server transport looped back into the TUN ("bypass doesn't work"). The
# dashboard mirror had the CORRECT predicate all along - pure copy drift.

_IPV4_DEFAULT_BODY = r"""
$r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Where-Object {
        $_.NextHop -ne '0.0.0.0' -and $_.State -eq 'Alive' -and
        $tunAliases -notcontains $_.InterfaceAlias -and
        ($vpnAliases.Count -eq 0 -or -not ($vpnAliases -contains $_.InterfaceAlias))
    } |
    Sort-Object @{Expression={ [int]$_.RouteMetric + [int]$_.InterfaceMetric }} |
    Select-Object -First 1 NextHop, InterfaceAlias, InterfaceIndex
if ($null -eq $r) {
    # Full-tunnel VPN likely removed the physical default route.  Recover the
    # physical NIC's configured gateway (survives the route being deleted).
    $r = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction SilentlyContinue |
        Where-Object { $_.DefaultIPGateway } |
        ForEach-Object {
            $gw = @($_.DefaultIPGateway) | Where-Object { $_ -and $_ -ne '0.0.0.0' -and $_ -ne '::' } | Select-Object -First 1
            if ($gw) {
                $na = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue
                [PSCustomObject]@{
                    NextHop = $gw
                    InterfaceAlias = if ($na) { $na.InterfaceAlias } else { $_.Description }
                    InterfaceIndex = $_.InterfaceIndex
                }
            }
        } |
        Where-Object { $tunAliases -notcontains $_.InterfaceAlias -and ($vpnAliases.Count -eq 0 -or -not ($vpnAliases -contains $_.InterfaceAlias)) } |
        Select-Object -First 1
}
if ($null -eq $r) {
    # Last resort only: any non-wintun 0.0.0.0/0 route (may be the VPN).
    $r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -ne '0.0.0.0' -and $_.State -eq 'Alive' -and $tunAliases -notcontains $_.InterfaceAlias } |
        Sort-Object RouteMetric, InterfaceMetric |
        Select-Object -First 1 NextHop, InterfaceAlias, InterfaceIndex
}
if ($null -eq $r) { exit 1 }
$r | ConvertTo-Json -Compress
"""


def ipv4_default_ps():
    """The complete physical-IPv4-default-route lookup script (see
    _IPV4_DEFAULT_BODY for the bug history). Returns NextHop, InterfaceAlias
    AND InterfaceIndex - the helper needs the index; the mirror ignores it."""
    return tun_alias_ps() + vpn_alias_ps() + _IPV4_DEFAULT_BODY


# === The FULL per-IP egress lookup (single source for BOTH processes) ========
# History (fixed in 1.0.32): the dashboard mirror (routing._get_egress_for)
# had drifted - it filtered TUN adapters but NOT VPN-pattern interfaces.
# With a Windows VPN connected, Find-NetRoute resolved the server's egress
# onto the VPN adapter (the most-specific non-TUN route while our TUN owns
# the default), the dashboard pinned the server's /32 bypass ONTO the VPN,
# and the "direct" bypass rode the VPN or looped back into the TUN ("server
# bypass doesn't work"). The helper's copy had the exclusion; the mirror did
# not - pure copy drift, eliminated by single-sourcing the WHOLE script here.

_EGRESS_FOR_BODY = r"""
$r = Find-NetRoute -RemoteIPAddress '__IP__' -ErrorAction SilentlyContinue
if ($r) {
    # Find-NetRoute emits TWO objects per hit: a NetIPAddress row (which
    # carries NO NextHop) and the NetRoute row. Without the route check the
    # address row can win the sort and the script returns
    # {"InterfaceAlias":..,"NextHop":null} - add_v4 then installs the bypass
    # with gateway 0.0.0.0 onto an interface whose actual route has a real
    # next-hop, and Windows drops the packet (the "bypass doesn't work even
    # when manually bypassed" report).
    $r = @($r) | Where-Object { $_.DestinationPrefix -and
            $tunAliases -notcontains $_.InterfaceAlias__VPN_CLAUSE__ } |
        Sort-Object -Property @{Expression={ ($_.DestinationPrefix -split '/')[1] -as [int] }; Descending=$true}, @{Expression={ [int]$_.RouteMetric + [int]$_.InterfaceMetric }} |
        Select-Object -First 1
}
if (-not $r) {
    # Fallback to the real default route. Exclude TUN AND VPN-pattern
    # interfaces (same protection as the physical-default lookup); only if
    # literally nothing non-VPN exists do we relax to TUN-only.
    $r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Where-Object { __V4FILTER_STRICT__ } |
        Sort-Object @{Expression={ [int]$_.RouteMetric + [int]$_.InterfaceMetric }} | Select-Object -First 1
}
if (-not $r) {
    $r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Where-Object { __V4FILTER_RELAXED__ } |
        Sort-Object @{Expression={ [int]$_.RouteMetric + [int]$_.InterfaceMetric }} | Select-Object -First 1
}
if ($null -eq $r) { exit 1 }
$r | Select-Object InterfaceAlias, NextHop | ConvertTo-Json -Compress
"""

_EGRESS_TOKENS = ("__IP__", "__VPN_CLAUSE__",
                  "__V4FILTER_STRICT__", "__V4FILTER_RELAXED__")


def egress_lookup_ps(ip, exclude_vpn=True):
    """The complete 'which (interface, gateway) reaches `ip` outside the
    TUNs' script - ONE source for BOTH processes (tunnel/helper's
    get_egress_for and network/routing's _get_egress_for).

    exclude_vpn=True (the safe default for direct bypass installs) also
    drops VPN-pattern interfaces from the primary lookup: with a connected
    Windows VPN the most-specific non-TUN route for a server IP is
    frequently the VPN's own, and pinning a bypass there hijacks the
    transport into the VPN (or loops it back into our TUN). The default-
    route fallbacks keep the strict-then-relaxed ladder from the physical
    default lookup. Pass exclude_vpn=False only where riding the VPN is
    intentional ([V] vless-over-vpn mode).
    """
    vpn_clause = (" -and $_.InterfaceAlias -notmatch " + VPN_ALIAS_PS_RE
                  if exclude_vpn else "")
    body = (_EGRESS_FOR_BODY
            .replace("__IP__", ps_quote(ip))
            .replace("__VPN_CLAUSE__", vpn_clause)
            .replace("__V4FILTER_STRICT__", v4_default_filter_ps(True))
            .replace("__V4FILTER_RELAXED__", v4_default_filter_ps(False)))
    for token in _EGRESS_TOKENS:
        if token in body:
            raise RuntimeError("egress_lookup_ps: unsubstituted " + token)
    return tun_alias_ps() + body

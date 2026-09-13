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
from tuntop.config.defaults import VPN_IFACE_RE

#: Every wintun-driver adapter is a TUN, whatever alias its owner picked:
#: ours are 'wintun'/'wintun2'; v2rayN/xray names theirs 'xray_tun' or
#: 'Wintun Tunnel'. Alias-prefix matching silently misses renames (the
#: 1.0.26 lesson) - the DRIVER DESCRIPTION is the reliable test.
TUN_DRIVER_RE = "Wintun"

#: VPN alias regex as embedded PS literal (built from the single-source
#: config.defaults.VPN_IFACE_RE - never re-hardcode it).
VPN_ALIAS_PS_RE = "'" + VPN_IFACE_RE + "'"


def tun_alias_ps(var="$tunAliases"):
    """PowerShell preamble building ``$tunAliases``: names of ALL
    Wintun-driver adapters (ours AND foreign full-tunnel tools).
    Consumers filter with ``$tunAliases -notcontains $_.InterfaceAlias``."""
    return (var + " = @(Get-NetAdapter -ErrorAction SilentlyContinue | "
            "Where-Object { $_.InterfaceDescription -match '"
            + TUN_DRIVER_RE + "' } | "
            "Select-Object -ExpandProperty Name)\n")


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

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

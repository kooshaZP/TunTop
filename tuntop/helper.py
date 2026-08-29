#!/usr/bin/env python3
"""
tuntop/helper.py

Windows-wide TUN routing for v2rayN + xjasonlyu/tun2socks.

Fixes:
  1. Do NOT pass tun2socks --interface by default. This avoids the
     Windows UDP bind failure:
         listen udp :0: An invalid argument was supplied.
  2. Prevent the local SOCKS/VLESS connection from looping into the TUN
     with explicit host routes for EVERY resolved VLESS server address.
  3. Verify 127.0.0.1:<SOCKS port> is listening before changing routes.
  4. Never invent an IPv6 gateway.
  5. Clean up routes and tun2socks on exit.
  6. Keep connected Windows VPNs (PPTP/L2TP/SSTP/IKEv2) alive by adding
     physical-network bypass routes for their VPN server addresses.
  7. Detect the connected Windows VPN's own default route by correlating
     Get-VpnConnection with Get-NetRoute (name-based), instead of guessing
     from the interface alias text. The old alias-pattern guess silently
     failed on any VPN connection not literally named "vpn"/"pptp"/etc,
     which made --vless-over-vpn exit before touching the routing table.
  8. Replace, instead of failing on, a route that already exists for the
     same destination via a different interface/gateway. Switching between
     modes (e.g. plain bypass -> --vless-over-vpn) reuses the same VLESS
     server IP, so the second run always used to hit this and abort.
  9. Clear any Wintun-bound routes and kill any orphaned tun2socks.exe left
     over from a previous run that didn't exit cleanly, before doing
     anything else.
 10. IPv6 VLESS bypass now also honors --vless-over-vpn, instead of always
     using the native IPv6 default route regardless of mode.
 11. After the tunnel is up, and periodically afterward, re-check that the
     Windows VPN connection used for --vless-over-vpn is still Connected,
     and say so plainly instead of leaving that to guesswork.

Usage (Administrator PowerShell/CMD):
  python tuntop/helper.py --server YOUR_SERVER --port 10808 ^
      --tun2socks "C:\\tools\\tun2socks.exe"

Your v2rayN SOCKS inbound must support UDP if you want UDP applications.
"""

import argparse
import atexit
import base64
import concurrent.futures
import ctypes
import ipaddress
import json
import os
import pickle
import signal
import hashlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

TUN = "wintun"
# tun2socks' Windows/Wintun configuration uses this same interface address
# as the route next hop (per the project's Windows example).
TUN4 = "192.168.123.1"
TUN4_MASK = "255.255.255.0"
TUN6 = "fd00:dead:beef::1"
DNS4 = "8.8.8.8"
DNS6 = "2606:4700:4700::1111"

# Active DNS servers resolved from the CLI --dns4/--dns6 flags at the top of
# main().  _ensure_wintun_address() reads these so that re-adding the Wintun
# address mid-run (e.g. after tun2socks recreates the adapter) keeps the
# user's DNS choice instead of silently reverting to the DNS4/DNS6 defaults.
_ACTIVE_DNS4 = DNS4
_ACTIVE_DNS6 = DNS6
# Wintun DNS delivery mode: "plain" = UDP/53 (needs UDP relay through the
# proxy), "doh" = DNS-over-HTTPS over TCP/443 (works whenever TCP relays),
# "auto" = start plain, escalate to DoH if resolution through the TUN fails.
_ACTIVE_DNS_MODE = "plain"
_ACTIVE_DOH_TEMPLATE = None

added_routes = []
geoip_added = []   # country-range bypass routes from --geoip (potentially thousands)

# When a connected Windows VPN injects its own default + /32 routes (often at a
# very low metric), those /32s are MORE specific than Wintun's /1 split routes
# and escape the tunnel - splitting traffic across the VPN (the "Chrome uses
# wifi + VPN + tun at the same time" bug). We neutralize that by shadowing every
# injected VPN route with an equivalent Wintun route at a lower effective metric
# (achieved by dropping Wintun's interface metric below the VPN's). The VPN link
# itself stays up because its server endpoint remains bypassed separately. The
# lists below track what to undo on cleanup.
vpn_override_routes = []      # (fam, dest, iface, gateway) entries to remove
vpn_saved_routes = []        # original VPN routes we shadowed (for restoration)
wintun_saved_metric = None    # Wintun InterfaceMetric to restore on exit
vpn_override_iface = None     # connected VPN interface we shadowed (set in main)
phys_bypass_metric_saved = None  # physical (geo) InterfaceMetric to restore on exit
phys_bypass_iface = None
tun_proc = None
cleaned = False

# Windows caps a whole CreateProcess command line at 32767 chars; the encoded
# form of a big bulk-removal script exceeds it, so run_ps() falls back to
# executing such scripts from a temp .ps1 file (mirrors tuntop/routing.py).
_PS_CMDLINE_SAFE = 20000

# NOTE: bulk geoip route removal (_remove_routes_bulk) deliberately shares the
# installer's tuning (GEO_SUB_BATCH / GEO_MAX_WORKERS) and its `netsh -f`
# fast path, so tearing down mirrors bringing up in speed.


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def run(cmd, check=False, timeout=15):
    """Run a command and return (returncode, stdout, stderr).

    A timeout is enforced so a hung child cannot freeze the whole script.
    Windows networking cmdlets (Get-VpnConnection / Find-NetRoute /
    Get-NetRoute) can block indefinitely when the RasMan service is busy or
    the routing table is mid-change - without a timeout this stalls the
    helper forever ("not crashed but unresponsive"). On timeout the child is
    killed and a nonzero code is returned, letting callers fall back instead
    of stalling.

    15s is chosen as a bound: these cmdlets are normally sub-second, so a
    real hang is caught quickly without cutting off a legitimately slow one.
    Hot-path callers (e.g. get_egress_for, called once per server) pass a
    shorter timeout so N servers can't multiply the stall into minutes.
    """
    try:
        p = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except (FileNotFoundError, OSError) as e:
        msg = str(e)
        if check:
            print(f"[!] Command failed to start: {' '.join(cmd)}")
            if msg:
                print(f"    {msg}")
        return 1, "", msg
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            p.kill()
        except Exception:
            pass
        # Bound the post-kill read too: if a child (e.g. netsh) inherited the
        # stdout pipe and is still alive, a bare communicate() could hang again.
        try:
            out, err = p.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            out, err = "", ""
        if check:
            print(f"[!] Command timed out ({timeout}s): {' '.join(cmd)}")
        return 124, (out or "").strip(), f"timed out after {timeout}s"
    if check and p.returncode:
        msg = (err or "").strip() or (out or "").strip()
        print(f"[!] Command failed: {' '.join(cmd)}")
        if msg:
            print(f"    {msg}")
    return p.returncode, (out or "").strip(), (err or "").strip()


def ps_quote(s):
    """Escape a string for safe interpolation inside a single-quoted
    PowerShell literal.  PowerShell escapes an embedded single quote by
    doubling it, so e.g. "Bob's VPN" -> "Bob''s VPN" and can no longer
    break out of the surrounding quotes in a generated script."""
    return str(s).replace("'", "''")


def ps_json(script, timeout=15):
    # -EncodedCommand (UTF-16LE, base64) instead of raw -Command text.
    # -Command re-parses the string as if typed at a console, which can
    # mis-split scripts containing nested single quotes, braces, or
    # pipes. All the VPN-detection PowerShell above relies on this being
    # reliable, so encode it rather than risk a silent parse failure.
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    code, out, _ = run([
        "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-EncodedCommand", encoded
    ], timeout=timeout)
    if code or not out:
        return None
    try:
        return json.loads(out)
    except Exception:
        return None


# Interface alias text pattern for Windows VPN tunnels.  A literal text match
# on the alias is unreliable (a user can rename a VPN connection to anything),
# so it is only ever used as a last-resort fallback, never the primary path.
VPN_IFACE_RE = r"(?i)(pptp|l2tp|sstp|ikev2|vpn|wan miniport)"


def _v4_default_filter(strict):
    """Return the PowerShell Where-Object clause that selects the real IPv4
    default route, excluding the wintun adapter.  When `strict`, also excludes
    VPN-pattern interface aliases; the non-strict variant is the last-resort
    fallback used only when no non-VPN route exists at all.

    Both get_ipv4_default() and get_egress_for()'s fallback share this so the
    VPN exclusion logic is defined in exactly one place.
    """
    clause = (r"$_.NextHop -ne '0.0.0.0' -and $_.State -eq 'Alive' -and "
              r"$_.InterfaceAlias -ne 'wintun'")
    if strict:
        clause += r" -and $_.InterfaceAlias -notmatch '%s'" % VPN_IFACE_RE
    return clause


def _vpn_alias_powershell():
    """Return a PowerShell snippet that builds $vpnAliases: every connected
    Windows VPN interface alias (correlated via Get-VpnConnection, which is
    name-reliable for built-in VPNs) plus any route whose alias text-matches
    the VPN heuristic.  Used by get_ipv4_default()/get_ipv6_default() so a VPN
    is excluded regardless of how the user named the connection."""
    return r"""
$vpnAliases = @(
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
    Where-Object { $_.InterfaceAlias -match '(?i)(pptp|l2tp|sstp|ikev2|vpn|wan miniport)' } |
    Select-Object -ExpandProperty InterfaceAlias -Unique | ForEach-Object { $vpnAliases += $_ }
$vpnAliases = @($vpnAliases | Where-Object { $_ } | Select-Object -Unique)
"""


def get_ipv4_default():
    """Return the NON-VPN IPv4 default route used to reach the Internet.

    When a Windows VPN is connected it must never be returned here: that
    gateway is what the VLESS endpoint bypass and the geoip country bypass use,
    so handing them the VPN gateway routes that traffic straight into the
    Windows VPN (and, once the Wintun default route is up, can loop it back
    into the TUN).

    Two real-world failure modes are handled explicitly:
      * The VPN connection is renamed to something the text heuristic misses.
        We also correlate Get-VpnConnection (reliable for built-in Windows
        VPNs) with their live routes, so those interfaces are excluded no
        matter what they are called.
      * A *full-tunnel* VPN deletes/replaces the physical adapter's 0.0.0.0/0
        route, so there is no non-VPN default route left to find.  We then
        recover the physical NIC's *configured* gateway straight from the
        adapter config (still set on the NIC even after its route is gone)
        rather than falling through to the VPN gateway.  The VPN gateway is
        only ever used as an absolute last resort when nothing physical exists.
    """
    ps = (
        _vpn_alias_powershell() + r"""
$r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Where-Object {
        $_.NextHop -ne '0.0.0.0' -and $_.State -eq 'Alive' -and
        $_.InterfaceAlias -ne 'wintun' -and
        ($vpnAliases.Count -eq 0 -or -not ($vpnAliases -contains $_.InterfaceAlias))
    } |
    Sort-Object RouteMetric, InterfaceMetric |
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
        Where-Object { $_.InterfaceAlias -ne 'wintun' -and ($vpnAliases.Count -eq 0 -or -not ($vpnAliases -contains $_.InterfaceAlias)) } |
        Select-Object -First 1
}
if ($null -eq $r) {
    # Last resort only: any non-wintun 0.0.0.0/0 route (may be the VPN).
    $r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -ne '0.0.0.0' -and $_.State -eq 'Alive' -and $_.InterfaceAlias -ne 'wintun' } |
        Sort-Object RouteMetric, InterfaceMetric |
        Select-Object -First 1 NextHop, InterfaceAlias, InterfaceIndex
}
if ($null -eq $r) { exit 1 }
$r | ConvertTo-Json -Compress
"""
    )
    d = ps_json(ps)
    if not d:
        sys.exit("[!] Cannot determine the active IPv4 gateway/interface.")
    return d["InterfaceAlias"], d["NextHop"], int(d["InterfaceIndex"])


def get_ipv6_default():
    """Return the non-VPN IPv6 default route used to reach the Internet.

    Mirror get_ipv4_default(): exclude the wintun adapter and any VPN-pattern
    interface alias so a connected Windows VPN that advertises its own IPv6
    ::/0 route (common with IKEv2/SSTP, often at a lower metric to capture all
    traffic) is never picked as the "safe" native gateway for the VLESS server,
    VPN-endpoint or geoip bypasses.  Falls back to excluding only
    wintun when no non-VPN IPv6 default route exists at all.

    Returns {"InterfaceAlias":..,"NextHop":..} or None.  IPv6 may legitimately
    be absent, so this must NOT sys.exit() the way get_ipv4_default() does.
    """
    ps = (
        _vpn_alias_powershell() + r"""
$r = Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue |
    Where-Object {
        $_.NextHop -ne '::' -and $_.State -eq 'Alive' -and
        $_.InterfaceAlias -ne 'wintun' -and
        ($vpnAliases.Count -eq 0 -or -not ($vpnAliases -contains $_.InterfaceAlias))
    } |
    Sort-Object RouteMetric, InterfaceMetric |
    Select-Object -First 1 NextHop, InterfaceAlias
if ($null -eq $r) {
    # Last resort only: any non-wintun IPv6 default route (may be the VPN).
    $r = Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -ne '::' -and $_.State -eq 'Alive' -and $_.InterfaceAlias -ne 'wintun' } |
        Sort-Object RouteMetric, InterfaceMetric |
        Select-Object -First 1 NextHop, InterfaceAlias
}
if ($null -eq $r) { exit 1 }
$r | ConvertTo-Json -Compress
"""
    )
    d = ps_json(ps)
    return d


def get_egress_for(ip, exclude_vpn=True):
    """Return the (interface, gateway) Windows would actually use to reach `ip`
    over its REAL (non-wintun) path.

    Unlike get_ipv4_default() — which only knows the system default route —
    this respects split-tunnel VPNs: a destination that is reachable ONLY via
    the VPN (or via a more-specific route) gets that interface/gateway, not the
    physical default. Using the wrong gateway for a bypass route is exactly
    what makes a bypassed IP "not work". Prefers the most-specific non-wintun
    route, then falls back to the real default route.

    `exclude_vpn` (default True) also drops VPN-pattern interface aliases from
    the primary lookup. This is the SAFE default for tunnel-only operation and
    mirrors get_ipv4_default()'s strict filter: a connected Windows VPN (e.g.
    Shirazu-VPN) frequently injects low-metric default + /32 routes, and if
    those are allowed to win here the VLESS transport gets hijacked through the
    VPN (or, worse, loops back into the TUN). Pass exclude_vpn=False only when
    running with --vless-over-vpn, where riding the VPN is intentional.
    """
    vpn_clause = (" -and $_.InterfaceAlias -notmatch '%s'" % VPN_IFACE_RE) if exclude_vpn else ""
    ps = (
        "$r = Find-NetRoute -RemoteIPAddress '" + ps_quote(ip) + "' -ErrorAction SilentlyContinue\n"
        "if ($r) {\n"
        "    $r = @($r) | Where-Object { $_.InterfaceAlias -ne 'wintun'" + vpn_clause + " } |\n"
        "        Sort-Object { ($_.DestinationPrefix -split '/')[1] -as [int] } -Descending, RouteMetric, InterfaceMetric |\n"
        "        Select-Object -First 1\n"
        "}\n"
        "if (-not $r) {\n"
        "    # Fallback to the real default route.  Exclude wintun AND VPN-pattern\n"
        "    # interfaces (same protection as get_ipv4_default); only if literally\n"
        "    # nothing non-VPN exists do we relax to wintun-only.\n"
        "    $r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |\n"
        "        Where-Object { " + _v4_default_filter(True) + " } |\n"
        "        Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1\n"
        "}\n"
        "if (-not $r) {\n"
        "    $r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |\n"
        "        Where-Object { " + _v4_default_filter(False) + " } |\n"
        "        Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1\n"
        "}\n"
        "if ($null -eq $r) { exit 1 }\n"
        "$r | Select-Object InterfaceAlias, NextHop | ConvertTo-Json -Compress\n"
    )
    d = ps_json(ps, timeout=10)
    if not d:
        return None
    iface = str(d.get("InterfaceAlias", ""))
    gw = str(d.get("NextHop", "") or "")
    if not iface:
        return None
    return iface, (gw or "0.0.0.0")


def get_active_windows_vpn_servers():
    """Return (connection name, server address) pairs for connected Windows VPNs.

    Get-VpnConnection covers VPNs created in Windows Settings/RAS, including
    PPTP.  Some third-party clients are not exposed by this command; callers
    can use --vpn-server for those.
    """
    ps = r"""
try {
    $v = @(Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue) +
         @(Get-VpnConnection -ErrorAction SilentlyContinue)
    $v | Where-Object {$_.ConnectionStatus -eq 'Connected' -and $_.ServerAddress} |
        Sort-Object Name, ServerAddress -Unique |
        Select-Object Name, ServerAddress | ConvertTo-Json -Compress
} catch { exit 0 }
"""
    d = ps_json(ps)
    if not d:
        return []
    records = d if isinstance(d, list) else [d]
    return [(str(x.get("Name", "Windows VPN")), str(x["ServerAddress"]))
            for x in records if x.get("ServerAddress")]


def get_vpn_ipv4_default(vpn_interface=None):
    """Return the active Windows VPN's IPv4 default route, including PPP.

    Correlates Get-VpnConnection (reliable, name-based) with its matching
    route instead of guessing from interface-alias text. A Windows VPN
    connection's InterfaceAlias is normally the connection's own display
    name, which the user can set to anything - a text match on
    "vpn"/"pptp"/etc silently misses most real-world connection names.
    That alias-text guess is kept as a last-resort fallback for third-party
    clients Get-VpnConnection doesn't expose.
    """
    if vpn_interface:
        d = ps_json(rf"""
$r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -InterfaceAlias '{ps_quote(vpn_interface)}' -ErrorAction SilentlyContinue |
    Sort-Object RouteMetric, InterfaceMetric |
    Select-Object -First 1 NextHop, InterfaceAlias, InterfaceIndex
if ($null -eq $r) {{ exit 1 }}
$r | ConvertTo-Json -Compress
""")
        if not d:
            return None
        return d["InterfaceAlias"], d["NextHop"], int(d["InterfaceIndex"])

    ps = r"""
$names = @(
    @(Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue) +
    @(Get-VpnConnection -ErrorAction SilentlyContinue) |
    Where-Object {$_.ConnectionStatus -eq 'Connected'} |
    Select-Object -ExpandProperty Name -Unique
)
$best = $null
foreach ($n in $names) {
    $r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -InterfaceAlias $n -ErrorAction SilentlyContinue |
        Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
    if ($r) { $best = $r; break }
}
if ($null -eq $best) {
    # Fallback for VPN clients Get-VpnConnection does not expose.
    $best = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' |
        Where-Object {
            $_.State -eq 'Alive' -and $_.InterfaceAlias -ne 'wintun' -and
            $_.InterfaceAlias -match '(?i)(pptp|l2tp|sstp|ikev2|vpn|wan miniport)'
        } |
        Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
}
if ($null -eq $best) { exit 1 }
$best | Select-Object NextHop, InterfaceAlias, InterfaceIndex | ConvertTo-Json -Compress
"""
    d = ps_json(ps)
    if not d:
        return None
    return d["InterfaceAlias"], d["NextHop"], int(d["InterfaceIndex"])


def get_vpn_ipv6_default(vpn_interface=None):
    """IPv6 counterpart of get_vpn_ipv4_default. Most Windows VPN profiles
    (PPTP in particular) are IPv4-only, so returning None here is normal
    and expected, not an error."""
    if vpn_interface:
        d = ps_json(rf"""
$r = Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -InterfaceAlias '{ps_quote(vpn_interface)}' -ErrorAction SilentlyContinue |
    Where-Object {{$_.NextHop -ne '::'}} |
    Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1 NextHop, InterfaceAlias
if ($null -eq $r) {{ exit 1 }}
$r | ConvertTo-Json -Compress
""")
        return (d["InterfaceAlias"], d["NextHop"]) if d else None

    ps = r"""
$names = @(
    @(Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue) +
    @(Get-VpnConnection -ErrorAction SilentlyContinue) |
    Where-Object {$_.ConnectionStatus -eq 'Connected'} |
    Select-Object -ExpandProperty Name -Unique
)
$best = $null
foreach ($n in $names) {
    $r = Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -InterfaceAlias $n -ErrorAction SilentlyContinue |
        Where-Object {$_.NextHop -ne '::'} |
        Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
    if ($r) { $best = $r; break }
}
# Only VPNs Get-VpnConnection exposes are found here.  We deliberately do NOT
# fall back to an InterfaceAlias -match '(?i)(pptp|l2tp|sstp|ikev2|vpn|wan
# miniport)' text heuristic: a user-renamed VPN connection defeats it, so it is
# unreliable.  Pass --vpn-interface <alias> for third-party clients Windows
# does not expose via Get-VpnConnection.
if ($null -eq $best) { exit 1 }
$best | Select-Object NextHop, InterfaceAlias | ConvertTo-Json -Compress
"""
    d = ps_json(ps)
    return (d["InterfaceAlias"], d["NextHop"]) if d else None


def get_vpn_connection_names_status():
    """Return {connection name: ConnectionStatus} for every VPN Windows
    knows about via Get-VpnConnection. Used to verify, after we've changed
    the routing table, that we haven't knocked a VPN offline."""
    ps = r"""
$c = @(Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue) +
     @(Get-VpnConnection -ErrorAction SilentlyContinue) |
     Select-Object Name, ConnectionStatus -Unique
if (@($c).Count -eq 0) { exit 1 }
@($c) | ConvertTo-Json -Compress
"""
    d = ps_json(ps)
    if not d:
        return {}
    records = d if isinstance(d, list) else [d]
    return {str(x["Name"]): str(x["ConnectionStatus"]) for x in records}


def run_ps(script, timeout=15):
    """Run a PowerShell script and return its raw stdout, for callers that
    don't need ps_json's JSON parsing.

    Small scripts use -EncodedCommand as before. Scripts whose encoded command
    line would approach the Windows 32767-char CreateProcess cap - notably
    _remove_routes_bulk's multi-hundred-statement geoip teardown batches,
    which silently NEVER STARTED over the limit (why geoip routes survived
    every cleanup) - are written to a temp .ps1 file and run with -File
    instead."""
    base_cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass"]
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    if len(encoded) + 80 > _PS_CMDLINE_SAFE:
        fd, path = tempfile.mkstemp(suffix=".ps1", prefix="TunTop_helper_")
        try:
            with os.fdopen(fd, "w", encoding="utf-8-sig") as f:
                f.write(script)
            return run(base_cmd + ["-File", path], timeout=timeout)
        finally:
            try:
                os.unlink(path)
            except Exception:
                pass
    return run(base_cmd + ["-EncodedCommand", encoded], timeout=timeout)


def preflight_cleanup():
    """Clear state left behind by a run that didn't exit cleanly (window
    closed forcibly, process killed, previous crash). Leftover Wintun
    routes or an orphaned tun2socks are the main reason a *later* run can
    fail to configure routes, look like it dropped the VPN, or crash on
    startup. Also drop the Wintun adapter itself so tun2socks recreates it
    fresh (a stale adapter can make tun2socks fail to bind)."""
    print("[*] Checking for leftover state from a previous run...")
    run_ps(f"Get-NetRoute -InterfaceAlias '{TUN}' -ErrorAction SilentlyContinue | "
           "Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue")

    _, out, _ = run_ps("Get-Process | Where-Object {$_.ProcessName -like 'tun2socks*'} | "
                        "Select-Object -ExpandProperty Id")
    pids = [p for p in out.split() if p.strip().isdigit()]
    if pids:
        print(f"[*] Stopping leftover tun2socks process(es): {', '.join(pids)}")
        for pid in pids:
            run(["taskkill", "/F", "/PID", pid])
        time.sleep(1)

    run_ps(f"Remove-NetAdapter -Name '{TUN}' -Force -Confirm:$false -ErrorAction SilentlyContinue")
    time.sleep(1)


def resolve_all(server):
    try:
        ip = ipaddress.ip_address(server)
        return ([str(ip)] if ip.version == 4 else [],
                [str(ip)] if ip.version == 6 else [])
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(server, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        sys.exit(f"[!] Could not resolve {server}: {e}")

    v4, v6 = [], []
    for fam, _, _, _, sa in infos:
        if fam == socket.AF_INET and sa[0] not in v4:
            v4.append(sa[0])
        elif fam == socket.AF_INET6 and sa[0] not in v6:
            v6.append(sa[0])

    if not v4 and not v6:
        sys.exit(f"[!] {server} resolved to no usable addresses.")
    return v4, v6


def _host_from_url(url):
    """Extract a plain hostname from a URL-like string.  Resolvers (and
    socket.getaddrinfo) cannot take a scheme/path, so 'https://api.ipify.org/'
    must become 'api.ipify.org'.  Factored out so every resolver call benefits,
    not just wait_for_tunnel_stable()."""
    if not url:
        return url
    h = str(url).split("://", 1)[-1]
    h = h.split("/", 1)[0]
    h = h.split("?", 1)[0]
    h = h.split("#", 1)[0]
    h = h.split("@", 1)[-1]
    return h.strip().rstrip(".")


def resolve_all_safe(server, label=None):
    """resolve_all() that NEVER calls sys.exit.  Returns (v4, v6) on success, or
    (None, None) on failure (after printing a warning).  A failed lookup must
    not tear down the whole tunnel - the caller decides what to skip."""
    host = _host_from_url(server)
    try:
        return resolve_all(host)
    except SystemExit:
        name = label or server
        print(f"[!] Could not resolve {name} ({host}); skipping (tunnel stays up).")
        return None, None


# ─── v2rayN geoip.dat parsing ────────────────────────────────────────────────
# v2rayN's geoip.dat is a protobuf-encoded GeoIPList (per country: a country
# code plus a list of CIDR ranges). We parse it in pure Python (no extra deps)
# so a chosen country's IP ranges can be installed as OS bypass routes - the
# route-level equivalent of v2rayN's "geoip:cn / bypass mainland" routing rule.

def _read_varint(buf, pos):
    result = 0
    shift = 0
    while pos < len(buf):
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def _read_bytes(buf, pos):
    length, pos = _read_varint(buf, pos)
    return buf[pos:pos + length], pos + length


import os as _os
import sys as _sys
_PKG_PARENT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _PKG_PARENT not in _sys.path:
    _sys.path.insert(0, _PKG_PARENT)

from tuntop.geoip import parse_geoip  # noqa: E402


def test_local_socks(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.5)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def wait_for_tun(timeout=15):
    ps = (
        "Get-NetAdapter -Name 'wintun' -ErrorAction SilentlyContinue | "
        "Select-Object -First 1 Name,ifIndex | ConvertTo-Json -Compress"
    )
    for _ in range(timeout):
        d = ps_json(ps)
        if d:
            return True
        time.sleep(1)
    return False


_DOH_TEMPLATES = {
    "8.8.8.8": "https://dns.google/dns-query",
    "8.8.4.4": "https://dns.google/dns-query",
    "1.1.1.1": "https://cloudflare-dns.com/dns-query",
    "1.0.0.1": "https://cloudflare-dns.com/dns-query",
    "9.9.9.9": "https://dns.quad9.net/dns-query",
    "149.112.112.112": "https://dns.quad9.net/dns-query",
}


def _doh_template_for(ip, override=None):
    if override:
        return override
    return _DOH_TEMPLATES.get(ip)


def _set_wintun_addresses_plain(dns4, dns6):
    """Assign the Wintun IPv4/IPv6 addresses and set the DNS servers the plain
    (UDP/53) way. Shared by configure_tun() and the DoH path (which layers DoH
    on top of the addresses)."""
    run([
        "netsh", "interface", "ipv4", "set", "address",
        f"name={TUN}", "source=static", f"addr={TUN4}", f"mask={TUN4_MASK}"
    ], check=True)
    run([
        "netsh", "interface", "ipv4", "set", "dnsservers",
        f"name={TUN}", "source=static", f"address={dns4}",
        "register=none", "validate=no"
    ])
    run([
        "netsh", "interface", "ipv6", "add", "address",
        TUN, f"{TUN6}/64"
    ])
    run([
        "netsh", "interface", "ipv6", "add", "dnsserver",
        TUN, dns6, "index=1"
    ])


def _enable_doh_on_wintun(ip, template):
    """Best-effort: register + enable DNS-over-HTTPS for `ip` on wintun so DNS
    rides over TCP/443 (which proxies reliably) instead of raw UDP/53 (which
    many SOCKS/VLESS setups do not relay). Returns True if the cmdlets reported
    success. Failures are non-fatal - caller falls back to plain UDP DNS."""
    if not ip or not template:
        return False
    ps = (
        "$ip='" + ps_quote(ip) + "'; $tpl='" + ps_quote(template) + "'; "
        "try { "
        "Add-DnsClientDohServer -ServerAddress $ip -DohTemplate $tpl "
        "-AllowFallbackToUdp $false -ErrorAction SilentlyContinue; "
        "Set-DnsClientDohServer -ServerAddress $ip -DohTemplate $tpl "
        "-AllowFallbackToUdp $false -ErrorAction SilentlyContinue; "
        "Set-DnsClientServerAddress -InterfaceAlias '" + TUN + "' "
        "-ServerAddresses @($ip) -ErrorAction Stop; "
        "Write-Output 'DOH_OK' "
        "} catch { Write-Output ('DOH_FAIL:' + $_.Exception.Message) }"
    )
    _, out, _ = run_ps(ps)
    return "DOH_OK" in out


def _disable_netbios_on_wintun():
    """Disable NetBIOS-over-TCP/IP on the wintun adapter.  Windows otherwise
    blasts NBNS broadcasts (UDP/137 to the subnet broadcast address) out EVERY
    interface - including wintun - and tun2socks forwards each one to the SOCKS
    proxy.  The resulting flood both spams the tunnel log and exhausts the
    loopback ephemeral ports (the 'Only one usage of each socket address'
    connectex errors), because every packet becomes a proxy connection.  Best
    effort; ignore failures on adapters that lack the binding."""
    ps = (
        "try { "
        "$a = Get-NetAdapter -Name '" + TUN + "' -ErrorAction Stop; "
        "Disable-NetAdapterBinding -Name '" + TUN + "' "
        "-ComponentID 'ms_tcpip_netbios' -ErrorAction SilentlyContinue; "
        "$idx = $a.ifIndex; "
        "Get-WmiObject -Class Win32_NetworkAdapterConfiguration "
        "-ErrorAction SilentlyContinue | "
        "Where-Object { $_.InterfaceIndex -eq $idx -and $_.IPEnabled } | "
        "ForEach-Object { $null = $_.SetTcpipNetbios(2) }; "
        "Write-Output 'NETBIOS_DISABLED' "
        "} catch { Write-Output ('NETBIOS_FAIL:' + $_.Exception.Message) }"
    )
    _, out, _ = run_ps(ps)
    return "NETBIOS_DISABLED" in out


def _add_lan_bypass(iface, gateway):
    """Install direct (bypass) routes for the private/local IPv4 ranges via the
    REAL physical adapter so LAN traffic never enters the tunnel.

    Without this, the wintun default route captures ALL traffic - including
    Windows LAN services like NetBIOS (UDP/137) and Delivery Optimization
    (TCP/7680) that probe neighbors on the local subnet.  Those packets get
    forwarded to the SOCKS proxy (one connection each), which both fails and, at
    volume, exhausts the loopback ephemeral ports ('connectex: Only one usage of
    each socket address').  The ranges below are all MORE specific than the TUN
    split-defaults (0.0.0.0/1, 128.0.0.0/1), so they win for LAN destinations
    and keep that traffic on the physical NIC where it belongs."""
    ranges = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "224.0.0.0/4",
        "255.255.255.255/32",
    ]
    print(f"[*] Installing LAN-bypass routes via {iface} ({gateway}) so local "
          f"traffic stays off the tunnel...")
    for r in ranges:
        if not add_v4(r, iface, gateway, metric=10):
            print(f"[!] Could not install LAN-bypass route {r}; continuing.")


def configure_tun(dns4=None, dns6=None):
    dns4 = dns4 or DNS4
    dns6 = dns6 or DNS6
    mode = _ACTIVE_DNS_MODE
    template = _ACTIVE_DOH_TEMPLATE or _doh_template_for(dns4)

    _set_wintun_addresses_plain(dns4, dns6)

    # Kill NBNS broadcasts leaving the TUN (a major source of the proxy-port
    # exhaustion spam).  Best-effort; report but never fail the setup on it.
    if _disable_netbios_on_wintun():
        print("[*] NetBIOS-over-TCP/IP disabled on wintun (stops UDP/137 flood).")
    else:
        print("[*] NetBIOS disable on wintun skipped/unavailable (non-fatal).")

    if mode == "doh" and template:
        if _enable_doh_on_wintun(dns4, template):
            print(f"[*] Wintun DNS set to DoH: {dns4} -> {template} (TCP/443)")
        else:
            print(f"[!] DoH enable failed for {dns4}; falling back to plain UDP DNS.")
    elif mode == "auto":
        # Start plain; the monitor/verify loop escalates to DoH if plain DNS
        # through the TUN proves unreliable.
        pass


def get_existing_v4_routes(dest):
    """Return existing IPv4 routes for an exact destination prefix."""
    ps = rf"""
$r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '{ps_quote(dest)}' -ErrorAction SilentlyContinue |
    Select-Object DestinationPrefix, InterfaceAlias, NextHop, RouteMetric, InterfaceIndex
if ($null -eq $r) {{ exit 0 }}
@($r) | ConvertTo-Json -Compress
"""
    d = ps_json(ps)
    if not d:
        return []
    return d if isinstance(d, list) else [d]


def add_v4(dest, iface, gateway, metric=1):
    """
    Add an IPv4 route idempotently.

    Windows returns "The object already exists" when the route is already
    present. That is NOT a failure if the existing route is already the
    correct one.

    If a route to the same destination exists via a DIFFERENT interface or
    gateway, remove it first instead of failing. This happens routinely
    when switching modes between runs (e.g. plain bypass -> --vless-over-vpn
    both add a host route for the same VLESS server IP, just via different
    interfaces) or after a run that left routes behind without cleaning up.

    CRITICAL: when installing a *default* route (0.0.0.0/0) we must NEVER
    delete a pre-existing default route that lives on a real (non-wintun)
    interface. That route IS the machine's actual Internet path; removing it
    would leave the system with no default route after cleanup, killing
    Internet until the adapter is reconnected. The wintun default route is
    installed *alongside* the real one (lower metric wins), and the
    split-default /1 routes carry the traffic.
    """
    existing = get_existing_v4_routes(dest)
    is_default = (dest == "0.0.0.0/0")

    # Don't return as soon as one correct route is found: a second, stale entry
    # for the same destination (via a different interface/gateway) must still be
    # cleaned up. Track the match and keep scanning the whole list.
    found_correct = False
    for r in existing:
        r_iface = str(r.get("InterfaceAlias", ""))
        r_gw = str(r.get("NextHop", ""))
        same_iface = r_iface.lower() == iface.lower()
        same_gateway = r_gw == gateway

        if same_iface and same_gateway:
            print(f"    [=] Route already exists and is correct: {dest} -> {iface} ({gateway})")
            found_correct = True
            continue

        # A default route on a real interface is the user's Internet route —
        # leave it untouched, never delete it.
        if is_default and r_iface.lower() != iface.lower():
            continue

        stale_iface = r_iface
        stale_gateway = r_gw
        print(f"    [~] Replacing stale route: {dest} -> {stale_iface} ({stale_gateway})")
        run(["netsh", "interface", "ipv4", "delete", "route", dest, stale_iface, stale_gateway])

    if found_correct:
        # The route is already present, but older builds installed it
        # PERSISTENTLY (registry) so it survived reboots.  Convert it to
        # active-store-only: delete it (clears both stores) and re-add with
        # store=active below.  If this is the machine's real default route it
        # lives on a different interface and was never marked found_correct, so
        # we never touch it here.
        run(["netsh", "interface", "ipv4", "delete", "route", dest, iface, gateway])

    code, out, err = run([
        "netsh", "interface", "ipv4", "add", "route",
        dest, iface, gateway, f"metric={metric}", "store=active"
    ])

    if code:
        # A race or Windows duplicate-route response may happen between the
        # check above and the add. Re-check before declaring failure.
        existing_after = get_existing_v4_routes(dest)
        for r in existing_after:
            same_iface = str(r.get("InterfaceAlias", "")).lower() == iface.lower()
            same_gateway = str(r.get("NextHop", "")) == gateway
            if same_iface and same_gateway:
                print(f"    [=] Route appeared during add and is correct: {dest}")
                return True

        print(f"[!] IPv4 route failed: {dest} -> {err or out}")
        return False

    added_routes.append(("v4", dest, iface, gateway))
    return True


def get_existing_v6_routes(dest):
    ps = rf"""
$r = Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '{ps_quote(dest)}' -ErrorAction SilentlyContinue |
    Select-Object DestinationPrefix, InterfaceAlias, NextHop, RouteMetric
if ($null -eq $r) {{ exit 0 }}
@($r) | ConvertTo-Json -Compress
"""
    d = ps_json(ps)
    if not d:
        return []
    return d if isinstance(d, list) else [d]


def add_v6(dest, iface, gateway=None, metric=1):
    existing = get_existing_v6_routes(dest)
    is_default = (dest == "::/0")

    # Don't return as soon as one correct route is found: a second, stale entry
    # for the same destination (via a different interface/gateway) must still be
    # cleaned up. Track the match and keep scanning the whole list.
    found_correct = False
    for r in existing:
        r_iface = str(r.get("InterfaceAlias", ""))
        r_gw = str(r.get("NextHop", "") or "")
        same_iface = r_iface.lower() == iface.lower()
        same_gateway = r_gw == (gateway or "")
        if same_iface and same_gateway:
            print(f"    [=] Route already exists and is correct: {dest} -> {iface}")
            found_correct = True
            continue
        # A default route on a real interface is the user's Internet route —
        # leave it untouched, never delete it.
        if is_default and r_iface.lower() != iface.lower():
            continue
        stale_iface = r_iface
        stale_gateway = r_gw
        del_cmd = ["netsh", "interface", "ipv6", "delete", "route", dest, stale_iface]
        if stale_gateway and stale_gateway != "::":
            del_cmd.append(stale_gateway)
        print(f"    [~] Replacing stale route: {dest} -> {stale_iface}")
        run(del_cmd)

    if found_correct:
        # Same persistent->active conversion as add_v4 (see there for why).
        del_cmd = ["netsh", "interface", "ipv6", "delete", "route", dest, iface]
        if gateway:
            del_cmd.append(gateway)
        run(del_cmd)

    cmd = ["netsh", "interface", "ipv6", "add", "route", dest, iface]
    if gateway:
        cmd.append(gateway)
    cmd.append(f"metric={metric}")
    cmd.append("store=active")
    code, out, err = run(cmd)
    if code:
        # A race or Windows duplicate-route response may happen between the
        # check above and the add. Re-check before declaring failure.
        existing_after = get_existing_v6_routes(dest)
        for r in existing_after:
            same_iface = str(r.get("InterfaceAlias", "")).lower() == iface.lower()
            same_gateway = str(r.get("NextHop", "") or "") == (gateway or "")
            if same_iface and same_gateway:
                print(f"    [=] Route appeared during add and is correct: {dest}")
                added_routes.append(("v6", dest, iface, gateway))
                return True
        print(f"[!] IPv6 route failed: {dest} -> {err or out}")
        return False
    added_routes.append(("v6", dest, iface, gateway))
    return True


def remove_route(item):
    fam, dest, iface, gateway = item
    if fam == "v4":
        run([
            "netsh", "interface", "ipv4", "delete", "route",
            dest, iface, gateway
        ])
    else:
        cmd = ["netsh", "interface", "ipv6", "delete", "route", dest, iface]
        if gateway:
            cmd.append(gateway)
        run(cmd)


def _ensure_wintun_address(family, addr, suffix):
    """Ensure the Wintun adapter carries `addr` (IPv4: `suffix`=mask,
    IPv6: `suffix`=prefix length). Check, re-add (retrying), and re-verify.

    tun2socks recreates the Wintun adapter on its restart, which can wipe the
    address configure_tun() set; and a single `netsh set/add address` can race
    the freshly-created adapter. If the address is missing, every IPv4/IPv6
    route add fails (Windows rejects a next-hop that isn't on the interface),
    so the TUN comes up with no default route. Retry+verify until it sticks."""
    check = rf"""
$r = Get-NetIPAddress -InterfaceAlias '{ps_quote(TUN)}' -AddressFamily {family} -ErrorAction SilentlyContinue |
    Where-Object {{ $_.IPAddress -eq '{addr}' }} | Select-Object -First 1 IPAddress
if ($r) {{ $r | ConvertTo-Json -Compress }} else {{ exit 1 }}
"""
    for attempt in range(4):
        if ps_json(check):
            return True
        print(f"[*] Wintun {family} address {addr} missing (attempt {attempt + 1}) - re-adding.")
        if family == "IPv4":
            run(["netsh", "interface", "ipv4", "set", "address",
                 f"name={TUN}", "source=static", f"addr={addr}", f"mask={suffix}"])
            run(["netsh", "interface", "ipv4", "set", "dnsservers",
                 f"name={TUN}", "source=static", f"address={_ACTIVE_DNS4}",
                 "register=none", "validate=no"])
            # If we're in DoH mode, re-enable DoH on the recreated adapter so
            # DNS keeps riding over TCP/443 instead of broken UDP/53.
            if _ACTIVE_DNS_MODE == "doh":
                tmpl = _ACTIVE_DOH_TEMPLATE or _doh_template_for(addr)
                _enable_doh_on_wintun(addr, tmpl)
        else:
            run(["netsh", "interface", "ipv6", "add", "address", TUN, f"{addr}/{suffix}"])
            run(["netsh", "interface", "ipv6", "add", "dnsserver", TUN, _ACTIVE_DNS6, "index=1"])
        time.sleep(1)
    print(f"[!] Could not ensure Wintun {family} address {addr}; route installs may fail.")
    return False


def _vpn_self_addresses(iface):
    """Return the IP addresses assigned to `iface`, so we never shadow the VPN
    adapter's own address (that would break the VPN link)."""
    ps = (f"Get-NetIPAddress -InterfaceAlias '{ps_quote(iface)}' "
          f"-ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress")
    _, out, _ = run_ps(ps)
    addrs = set()
    for line in out.splitlines():
        a = line.strip()
        if a:
            addrs.add(a.split("%")[0])
    return addrs


def _set_wintun_interface_metric(metric):
    """Set the Wintun adapter's InterfaceMetric (lower = more preferred). Saves
    the previous value in wintun_saved_metric so cleanup can restore it. Best-effort."""
    global wintun_saved_metric
    try:
        ps = (f"$a = Get-NetIPInterface -InterfaceAlias '{TUN}' -AddressFamily IPv4 "
              f"-ErrorAction SilentlyContinue | Select-Object -First 1 InterfaceMetric; "
              f"if ($a) {{ $a.InterfaceMetric }} else {{ 'NONE' }}")
        _, out, _ = run_ps(ps)
        cur = out.strip()
        if cur and cur != "NONE" and cur.isdigit():
            wintun_saved_metric = int(cur)
        run_ps(f"Set-NetIPInterface -InterfaceAlias '{TUN}' -InterfaceMetric {metric}")
    except Exception:
        pass


def _raw_add_route(fam, dest, iface, gateway, metric):
    """Add a route directly via netsh, WITHOUT deleting any pre-existing route to
    the same destination. This lets our Wintun override coexist with the VPN's own
    route; the lower effective metric then wins, and the VPN route is left intact
    (so cleanup only has to remove our override). Ignores 'already exists'."""
    verb = "ipv4" if fam == "v4" else "ipv6"
    cmd = ["netsh", "interface", verb, "add", "route", dest, iface]
    if gateway:
        cmd.append(gateway)
    cmd.append(f"metric={metric}")
    code, out, err = run(cmd)
    if code and "already exists" not in (out + err).lower():
        print(f"[!] VPN-override add failed for {dest}: {err or out}")
        return False
    return True


def override_vpn_routes(vpn_iface, skip_ips):
    """Shadow every injected route on the connected Windows VPN with an equivalent
    Wintun route at a lower effective metric, so ALL traffic (except the explicitly
    bypassed VLESS/VPN server endpoints) is forced through the tunnel.

    We first drop Wintun's interface metric below the VPN's, then add Wintun /32
    (or /128) overrides at route-metric 1. Because a /32 is the most specific
    prefix possible, the only thing that can beat our override is a same-prefix
    route with a lower effective metric - which the VPN cannot produce once Wintun
    is the lowest-metric interface. The VPN link itself stays up because its server
    endpoint is bypassed separately and is excluded from `skip_ips`.

    `skip_ips` holds IPs we must NOT shadow (VLESS server IPs, VPN server endpoint
    IPs, the VPN adapter's own address): shadowing those would capture the proxy or
    VPN transport and loop it back into the TUN.
    """
    global vpn_override_routes, vpn_saved_routes
    if not vpn_iface or vpn_iface.lower() == TUN.lower():
        return
    # Never shadow a route whose prefix is part of the geoip country bypass:
    # those CIDRs are deliberately routed DIRECT via the physical adapter
    # (see add_geoip_bypass), so redirecting them into the tunnel would undo
    # the whole point of the bypass.
    geo_dests = {r[1] for r in geoip_added}
    # Make Wintun decisively the lowest-metric interface so our overrides win.
    _set_wintun_interface_metric(2)
    for fam, get_fam, gw, add in (
        ("v4", "IPv4", TUN4, add_v4),
        ("v6", "IPv6", TUN6, add_v6),
    ):
        ps = (f"Get-NetRoute -AddressFamily {get_fam} -InterfaceAlias '{ps_quote(vpn_iface)}' "
               f"-ErrorAction SilentlyContinue | Where-Object {{ $_.State -eq 'Alive' }} | "
               f"Select-Object DestinationPrefix, NextHop, RouteMetric | ConvertTo-Json -Compress")
        d = ps_json(ps)
        if not d:
            continue
        for r in (d if isinstance(d, list) else [d]):
            prefix = str(r.get("DestinationPrefix", "")).strip()
            if not prefix or prefix in ("0.0.0.0/0", "::/0"):
                continue  # /0 already covered by Wintun's more-specific /1 splits
            if prefix in geo_dests:
                continue  # leave geoip country bypass routes direct (physical)
            host = prefix.split("/")[0]
            if host in skip_ips:
                continue
            # Skip link-local / multicast / loopback - never real leaks.
            if host.startswith("fe80:") or host.startswith("ff") or host == "::1":
                continue
            if host.startswith("169.254.") or host.startswith("224."):
                continue
            try:
                ipaddress.ip_address(host)
            except ValueError:
                continue
            # Save the VPN's original route so cleanup can fully restore it. add_v4/
            # add_v6 then replace the stale (VPN) route with our Wintun override
            # (recording it in added_routes for normal cleanup too).
            vpn_saved_routes.append((fam, prefix, vpn_iface,
                                     str(r.get("NextHop", "") or ""),
                                     int(r.get("RouteMetric", 1) or 1)))
            if add(prefix, TUN, gw, metric=1):
                vpn_override_routes.append((fam, prefix, TUN, gw))


def ensure_wintun_ipv6():
    """Ensure the Wintun IPv6 address (fd00:dead:beef::1/64) is present before
    pointing IPv6 routes at it - otherwise ::/0, ::/1 and 8000::/1 all fail to
    install and the 'Default IPv6 route' check fails."""
    return _ensure_wintun_address("IPv6", TUN6, 64)


def ensure_physical_metric_below_vpn(phys_iface):
    """Lower the physical (geo/default) interface metric below the connected
    Windows VPN's so our DIRECT geo bypass routes win the tiebreak against the
    VPN's self-injected routes for the same country CIDRs.

    A managed Windows VPN (e.g. Shirazu-VPN) continuously re-injects its own
    routes for the exact geo CIDRs via the VPN interface. Both that route and
    our direct route share an identical prefix and metric, so Windows breaks
    the tie by INTERFACE metric - and with Wi-Fi at ~4270 and the VPN at ~25
    the VPN always wins, pushing geo traffic into the VPN regardless of the
    next-hop we choose. Deleting the VPN route is futile: the client puts it
    straight back. Dropping the physical interface metric below the VPN's (but
    keeping it strictly above Wintun's, so the tunnel's /1 splits still carry
    general traffic) makes the direct geo routes win durably.

    The original metric is saved globally and restored in cleanup()."""
    global phys_bypass_metric_saved, phys_bypass_iface
    if not phys_iface or phys_iface.lower() == TUN.lower():
        return
    vpn = get_vpn_ipv4_default()
    if not vpn:
        return
    vpn_iface = vpn[0]
    if vpn_iface.lower() == phys_iface.lower():
        return  # geo is explicitly routed via this VPN; leave it alone
    try:
        _, out, _ = run_ps(
            f"$v = Get-NetIPInterface -InterfaceAlias '{ps_quote(vpn_iface)}' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1 InterfaceMetric; "
            f"$p = Get-NetIPInterface -InterfaceAlias '{ps_quote(phys_iface)}' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1 InterfaceMetric; "
            f"if ($v -and $p) {{ Write-Output ($v.InterfaceMetric.ToString() + ',' + $p.InterfaceMetric.ToString()) }}"
        )
    except Exception:
        return
    m = out.strip().split(",")
    if len(m) != 2 or not m[0].isdigit() or not m[1].isdigit():
        return
    vpn_metric = int(m[0])
    phys_metric = int(m[1])
    # Keep the physical interface just below the VPN but strictly above Wintun (2).
    target = max(3, min(10, vpn_metric - 1))
    if target >= vpn_metric or phys_metric <= target:
        return  # already winning, or cannot beat the VPN without dropping below Wintun
    if phys_bypass_metric_saved is None:
        phys_bypass_metric_saved = phys_metric
        phys_bypass_iface = phys_iface
    run_ps(f"Set-NetIPInterface -InterfaceAlias '{ps_quote(phys_iface)}' -InterfaceMetric {target}")


def restore_physical_metric():
    """Undo ensure_physical_metric_below_vpn() if it changed the metric."""
    global phys_bypass_metric_saved, phys_bypass_iface
    if phys_bypass_iface is not None and phys_bypass_metric_saved is not None:
        try:
            run_ps(f"Set-NetIPInterface -InterfaceAlias '{ps_quote(phys_bypass_iface)}' "
                   f"-InterfaceMetric {phys_bypass_metric_saved}")
        except Exception:
            pass
    phys_bypass_metric_saved = None
    phys_bypass_iface = None


def ensure_wintun_ipv4():
    """Ensure the Wintun IPv4 address (192.168.123.1/24) is present before
    pointing IPv4 routes at it. If it is missing, every IPv4 wintun route add
    fails and the 'TUN default route' check reports 'Wintun split-default
    routes missing'."""
    return _ensure_wintun_address("IPv4", TUN4, TUN4_MASK)


# The Wintun adapter owns these subnets; a bypass route that overlaps either
# would shadow the tunnel's own next-hop and break every Wintun route add.
_WINTUN4_NET = ipaddress.ip_network("192.168.123.0/24")
_WINTUN6_NET = ipaddress.ip_network("fd00:dead:beef::/64")


def _is_routable_bypass_cidr(cidr):
    """Return True only if `cidr` is a public, globally-routable range that is
    safe to install as a direct (bypass) route.

    Some geoip.dat files (e.g. geoip:ir) ship private/loopback/link-local/
    reserved ranges by mistake. Installing those as direct routes collides with
    the user's LAN and/or shadows the Wintun next-hop (192.168.123.1 /
    fd00:dead:beef::1), which makes every subsequent Wintun route add fail
    silently - the whole tunnel then comes up with no default/split routes.
    They are also never part of a country's real public address space, so
    dropping them loses nothing."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    if (net.is_private or net.is_loopback or net.is_link_local
            or net.is_multicast or net.is_reserved):
        return False
    if net.version == 4 and net.overlaps(_WINTUN4_NET):
        return False
    if net.version == 6 and net.overlaps(_WINTUN6_NET):
        return False
    return True


# Geo install tuning.  Sub-batch size (routes per `netsh -f` invocation), worker
# cap (concurrent netsh writers against the Windows route store), and the hard
# per-sub-batch timeout that lets a hung `netsh add route` be killed instead of
# freezing the whole install.
GEO_SUB_BATCH = 100
GEO_MAX_WORKERS = 6
GEO_SUB_TIMEOUT = 90


def _geo_remove_conflicts(cidrs, iface, fam):
    """Single batched removal of any pre-existing route for our geo prefixes
    (on any real interface except wintun).

    This drops BOTH routes a self-healing Windows VPN re-injected on a different
    interface AND stale routes left behind by a previous run on the SAME physical
    interface.  The latter matters because earlier builds installed the geoip
    bypass with `netsh ... add route`, which is PERSISTENT by default - those
    entries lived in the registry and survived reboots, so a plain re-install
    would just hit "already exists" and leave the persistent copy in place.  By
    removing them here (a `Remove-NetRoute` clears the persistent store too) the
    following `add route ... store=active` re-creates them as active-only, so
    they no longer outlive a reboot.

    This is ONE Get-NetRoute scan over the whole table plus one Remove-NetRoute
    per matching route - O(n), cheap even when the table is bloated with
    thousands of leftover geo routes.  That bloat is exactly what made the old
    per-route Get-NetRoute loop O(n^2) and appear to hang on repeat runs, so the
    removal is done here once instead of inside the per-route add loop."""
    if not cidrs:
        return
    af = "IPv4" if fam == "v4" else "IPv6"
    routes_lit = ",".join("'%s'" % ps_quote(r) for r in cidrs)
    iface_dq = ps_quote(iface)
    ps = (
        "$hs = [System.Collections.Generic.HashSet[string]]::new(); "
        "%s | ForEach-Object { $null = $hs.Add($_) }; "
        "Get-NetRoute -AddressFamily '%s' -ErrorAction SilentlyContinue | "
        "Where-Object { $hs.Contains($_.DestinationPrefix) -and "
        "$_.InterfaceAlias -ne 'wintun' } | "
        "ForEach-Object { Remove-NetRoute -DestinationPrefix $_.DestinationPrefix "
        "-InterfaceAlias $_.InterfaceAlias -Confirm:$false -ErrorAction SilentlyContinue }"
    ) % (routes_lit, af)
    run_ps(ps, timeout=120)


# Per-process deduplication for repeated geoip diagnostics. A given country's
# install emits the same "skipped N non-routable" / "batch had route failures"
# notes every time it runs. When add_geoip_bypass() is called repeatedly in one
# process (e.g. the dashboard's live [R] re-apply, or any future caller that
# re-runs the install), these notes would otherwise reprint verbatim. Keying on
# a stable (kind, code, fam) tuple collapses them to a single emission instead
# of adding a one-off special case every time a new sibling diagnostic appears.
_GEO_DIAG_SEEN = set()


def _geo_diag(key, msg):
    """Emit `msg` to stdout at most once per `key` for the life of this
    process. Returns True if it was printed (new), False if it was suppressed
    as a repeat of an already-seen diagnostic."""
    if key in _GEO_DIAG_SEEN:
        return False
    _GEO_DIAG_SEEN.add(key)
    print(msg)
    return True


def add_geoip_bypass(code, cidrs, iface, gateway, v6iface=None, v6gw=None):
    """Install every CIDR in `cidrs` as a bypass route via the real (non-TUN)
    interface, so that country's traffic never enters the tunnel.

    A full country list (e.g. geoip:ir ~ 2900 CIDRs) is too many to add one
    route at a time. We split the list into chunks and run the chunks
    CONCURRENTLY, each a single `netsh ... add route` script (the same fast
    path add_v4/add_v6 use - NOT the slow New-NetRoute cmdlet, which costs
    ~50-100ms/route and would make a few thousand CIDRs take several minutes).
    The adds are disjoint, so parallel installs cannot collide and wall-clock
    time drops to ~one chunk. Routes are recorded in geoip_added so cleanup()
    can bulk-remove them later."""
    # Skip any full-default prefixes: a country list should never contain them,
    # but if it did they would collide with the TUN default/split-default routes
    # (and trip add_v4's stale-route deletion), not act as a useful bypass.
    _skip = {"0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1", "::/0", "::/1", "8000::/1"}
    cidrs = [c for c in cidrs if c not in _skip]
    if not cidrs:
        _geo_diag(("skip_nodefault", code),
                  f"[!] geoip:{code} bypass skipped (no usable non-default CIDRs).")
        return
    v4_all = [c for c in cidrs if ":" not in c]
    v6_all = [c for c in cidrs if ":" in c]
    v4 = [c for c in v4_all if _is_routable_bypass_cidr(c)]
    v6 = [c for c in v6_all if _is_routable_bypass_cidr(c)]
    skipped = (len(v4_all) + len(v6_all)) - (len(v4) + len(v6))
    if skipped:
        _geo_diag(("skip_nonroutable", code),
                  f"[!] geoip:{code} bypass: skipped {skipped} non-routable CIDR(s) "
                  f"(private/loopback/link-local/reserved or overlapping the Wintun subnet).")
    if not v4 and not v6:
        _geo_diag(("skip_noroutable", code),
                  f"[!] geoip:{code} bypass skipped (no routable CIDRs remain after filtering).")
        return
    print(f"[*] Installing geoip:{code} bypass ({len(v4)} IPv4, {len(v6)} IPv6) via {iface}...")
    # Direct (physical) geo case: a self-healing Windows VPN re-injects its own
    # routes for these exact CIDRs, so beating it requires the physical
    # interface metric to sit below the VPN's.  No-op when geo is routed via
    # wintun (--geoip-via-vpn) or the VPN itself (--geoip-via-win-vpn).
    if iface and iface.lower() != TUN.lower():
        vpn = get_vpn_ipv4_default()
        if not (vpn and vpn[0].lower() == iface.lower()):
            ensure_physical_metric_below_vpn(iface)
    # One batched removal pass per family: drop any PRE-EXISTING route for our
    # geo prefixes that lives on a *different* interface (a self-healing Windows
    # VPN that re-injected its own route for the same CIDR, or a stale route left
    # behind by a previous run).  This is a single Get-NetRoute scan over the
    # whole table + one Remove-NetRoute per conflicting route - O(n), cheap even
    # when the table is already bloated with thousands of leftover geo routes
    # (which is exactly what made the old per-route Get-NetRoute loop O(n^2) and
    # appear to hang on repeat runs).  Doing it once here - instead of inside the
    # per-route add loop - also removes the per-route route-store lock churn that
    # could deadlock the concurrent installers below.
    for fam, subset, ifa, gw in (("v4", v4, iface, gateway),
                                 ("v6", v6, v6iface, v6gw)):
        if subset and ifa and gw is not None:
            _geo_remove_conflicts(subset, ifa, fam)

    # Install the routes in sub-batches of GEO_SUB_BATCH entries.  Each sub-batch
    # is a single `netsh -f` script (one netsh process for the whole batch, not
    # one per route) - this avoids both the per-route process-startup cost AND
    # the old per-route Get-NetRoute/Remove-NetRoute scan that was O(n^2) against
    # a route table already holding thousands of stale geo routes.  Every
    # sub-batch goes through run() with a hard GEO_SUB_TIMEOUT, so a single route
    # that makes `netsh add route` block can never freeze the whole install -
    # run() kills the hung child and we move on.  Sub-batches run under a capped
    # ThreadPoolExecutor (GEO_MAX_WORKERS) so we don't hammer the Windows route
    # store with too many simultaneous writers (which serializes and can
    # deadlock).  A "[GEO-LOAD] loaded/total" marker is emitted after each
    # sub-batch so the dashboard animates smoothly.  "already exists" counts as
    # success (a previous run already installed it); any other error is captured
    # once per family as a warning.  Routes are recorded in geoip_added for
    # cleanup() later.
    sub_batches = []
    for fam, subset, ifa, gw in (("v4", v4, iface, gateway),
                                 ("v6", v6, v6iface, v6gw)):
        if not subset or not ifa or gw is None:
            continue
        for i in range(0, len(subset), GEO_SUB_BATCH):
            grp = subset[i:i + GEO_SUB_BATCH]
            sub_batches.append((fam, grp, ifa, gw))
            for r in grp:
                geoip_added.append((fam, r, ifa, gw))
    if not sub_batches:
        _geo_diag(("skip_noiface", code),
                  f"[!] geoip:{code} bypass skipped (no usable CIDRs / no interface + next-hop).")
        return
    total = sum(len(g) for _, g, _, _ in sub_batches)
    loaded = 0
    geo_lock = threading.Lock()
    err_by_fam = {}
    if total:
        print(f"[GEO-LOAD] code={code} loaded=0 total={total}", flush=True)

    def _install_sub(fam, grp, ifa, gw):
        nonlocal loaded
        netsh_verb = "ipv4" if fam == "v4" else "ipv6"
        iface_dq = '"' + str(ifa).replace('"', '') + '"'
        gw_part = str(gw) if gw else ""
        # The CIDR is passed BARE - netsh treats single/double quotes around the
        # prefix as part of the token and rejects it ("Invalid prefix parameter
        # ('5.72.0.0/15')").  Only the interface name (which can contain spaces
        # like "Wi-Fi") is quoted.
        lines = ["interface %s add route %s %s %s metric=1 store=active"
                 % (netsh_verb, r, iface_dq, gw_part) for r in grp]
        fd, path = tempfile.mkstemp(suffix=".txt", prefix="geo_")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            rc, out, err = run(["netsh", "-f", path], timeout=GEO_SUB_TIMEOUT)
        finally:
            try:
                os.unlink(path)
            except Exception:
                pass
        # Count successes: netsh prints "Ok." per good line and
        # "The object already exists." for an already-installed identical route
        # (both are fine).  Anything else is a real failure.
        done = 0
        for ln in (out or "").splitlines():
            s = ln.strip()
            if s == "Ok." or "already exists" in s:
                done += 1
        if done == 0 and rc == 0:
            done = len(grp)   # no per-line output but the batch succeeded
        if done < len(grp) or rc != 0:
            first_err = None
            for ln in (out or "").splitlines() + (err or "").splitlines():
                s = ln.strip()
                if s and s != "Ok." and "already exists" not in s:
                    first_err = s
                    break
            if not first_err:
                first_err = _clean_err(err)
            if first_err:
                with geo_lock:
                    if fam not in err_by_fam:
                        err_by_fam[fam] = first_err
        if done:
            with geo_lock:
                loaded += done
                cur = loaded
            if total:
                print(f"[GEO-LOAD] code={code} loaded={cur} total={total}", flush=True)

    with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(len(sub_batches), GEO_MAX_WORKERS)) as ex:
        futures = [ex.submit(_install_sub, fam, grp, ifa, gw)
                   for fam, grp, ifa, gw in sub_batches]
    for fut in concurrent.futures.as_completed(futures):
        try:
            fut.result()
        except Exception:
            pass
    for fam in ("v4", "v6"):
        if fam in err_by_fam:
            msg = f"[!] geoip:{code} {fam} batch had route failures (continuing)."
            diag = err_by_fam[fam]
            if diag:
                msg += f"  first error: {diag}"
            _geo_diag(("routefail", code, fam), msg)
    # Signal the dashboard that this category's install pass is finished - even
    # if some routes failed (loaded < total).  Without this, the dashboard's
    # progress panel would stay on screen forever once any route failed, since
    # its "incomplete" condition never clears.  The dashboard starts a linger
    # window on this marker and then hides the panel.
    if total:
        print(f"[GEO-DONE] code={code} loaded={loaded} total={total}", flush=True)


def _remove_routes_bulk(routes):
    """Remove many routes FAST - the exact same mechanism the installer uses.

    Symmetry with add_geoip_bypass(): the routes are deleted with concurrent
    `netsh -f` batch scripts (GEO_SUB_BATCH destinations per script,
    GEO_MAX_WORKERS scripts in flight), NOT with the Remove-NetRoute cmdlet,
    which costs ~50-100ms PER ROUTE and made the teardown of a few thousand
    geoip bypass routes take tens of seconds longer than the install itself.
    netsh delete clears BOTH stores (active + persistent), so it also catches
    PERSISTENT leftovers from builds older than the store=active change.

    Anything netsh cannot see (e.g. a route re-injected mid-delete by a VPN
    client) is caught afterwards by the dashboard's leftover sweep, which
    re-checks the live table against the geo CIDRs. Errors are ignored: a
    route already gone is the desired end state."""
    if not routes:
        return

    def _drop_chunk(grp):
        lines = []
        for fam, dest, iface, gw in grp:
            verb = "ipv4" if fam == "v4" else "ipv6"
            iface_dq = '"' + str(iface).replace('"', '') + '"'
            # Bare prefix / gateway tokens - quoting is rejected by netsh for
            # add (see _install_sub); delete follows the same rule.
            gw_tok = (" %s" % str(gw)) if gw else ""
            lines.append("interface %s delete route %s %s%s"
                         % (verb, dest, iface_dq, gw_tok))
        fd, path = tempfile.mkstemp(suffix=".txt", prefix="geo_del_")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            run(["netsh", "-f", path], timeout=180)
        finally:
            try:
                os.unlink(path)
            except Exception:
                pass

    chunks = [routes[i:i + GEO_SUB_BATCH]
              for i in range(0, len(routes), GEO_SUB_BATCH)]
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(len(chunks), GEO_MAX_WORKERS)) as ex:
        for _fut in concurrent.futures.as_completed(
                [ex.submit(_drop_chunk, c) for c in chunks]):
            try:
                _fut.result()
            except Exception:
                pass


def cleanup():
    global cleaned
    global wintun_saved_metric
    if cleaned:
        return
    cleaned = True
    # Restore the physical (geo) interface metric we may have lowered to beat a
    # self-healing Windows VPN, before touching any other state.
    restore_physical_metric()

    # Bulk-remove geoip bypass routes first (can be thousands of entries).
    if geoip_added:
        print(f"[*] Cleaning up {len(geoip_added)} geoip bypass routes...")
        _remove_routes_bulk(geoip_added)
        geoip_added.clear()

    print("\n[*] Cleaning up routes...")
    # Remove the VPN-override routes we added to keep the tunnel the sole egress,
    # then restore the VPN's original injected routes we shadowed.
    if vpn_override_routes:
        print(f"[*] Removing {len(vpn_override_routes)} VPN-override routes...")
        for item in reversed(vpn_override_routes):
            remove_route(item)
        vpn_override_routes.clear()
    if vpn_saved_routes:
        print(f"[*] Restoring {len(vpn_saved_routes)} VPN routes...")
        for fam, dest, iface, gateway, metric in reversed(vpn_saved_routes):
            _raw_add_route(fam, dest, iface, gateway, metric)
        vpn_saved_routes.clear()
    # Restore Wintun's original interface metric.
    if wintun_saved_metric is not None:
        try:
            run_ps(f"Set-NetIPInterface -InterfaceAlias '{TUN}' "
                    f"-InterfaceMetric {wintun_saved_metric}")
        except Exception:
            pass
        wintun_saved_metric = None
    for item in reversed(added_routes):
        remove_route(item)

    if tun_proc is not None and tun_proc.poll() is None:
        print("[*] Stopping tun2socks...")
        tun_proc.terminate()
        try:
            tun_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            tun_proc.kill()

    print("[*] Done.")


def _probe_tunnel_once(url="https://api.ipify.org/", timeout=5):
    """One-shot verification that DNS resolves AND HTTPS fetches through the
    TUN. Returns (ok, message). Does NOT retry - the caller loops / self-heals.

    The host is derived from the URL WITHOUT its scheme or path, so a literal
    like "https://api.ipify.org/" is normalized to "api.ipify.org" before being
    handed to getaddrinfo (passing the scheme is exactly what produced the old
    "[Errno 11001] getaddrinfo failed" crash)."""
    import urllib.request
    host = _host_from_url(url)
    if not host:
        host = "api.ipify.org"
    try:
        infos = socket.getaddrinfo(host, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
        addrs = sorted({sa[0] for _, _, _, _, sa in infos})
    except socket.gaierror as e:
        return False, f"DNS resolve {host}: {e}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "tun-probe/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(64).decode("utf-8", "replace").strip()
        if body:
            return True, f"{host} resolved -> {', '.join(addrs)}; public IP = {body}"
        return False, f"{host} resolved ({', '.join(addrs)}) but empty body"
    except Exception as e:
        return False, f"{host} resolved ({', '.join(addrs)}) but fetch failed: {e}"


# Fast, reliable verification endpoints — tried in order.
# connectivitycheck.gstatic.com (Android check) and cp.cloudflare.com both
# respond in <100ms from almost anywhere; api.ipify.org is a slow fallback.
_VERIFY_URLS = [
    "http://connectivitycheck.gstatic.com/generate_204",
    "http://cp.cloudflare.com/",
    "https://api.ipify.org/",
]


def wait_for_tunnel_stable(timeout=5):
    """Block until DNS + HTTP verification through the TUN succeeds.

    Tries each of _VERIFY_URLS in order.  For each URL, up to 5 probes
    with 2-second gaps (10 s max per URL).  If all URLs fail, auto-escalates
    to DoH DNS and retries.  Total worst-case: ~60 s (down from ~160 s).

    Returns True if the tunnel is verified, False if all attempts fail."""
    global _ACTIVE_DNS_MODE

    for phase, url in enumerate(["plain DNS"] + _VERIFY_URLS):
        is_dns_phase = (phase == 0)
        if is_dns_phase:
            continue  # DNS mode doesn't need its own loop; each URL tests DNS+HTTP

    last_err = ""
    for url in _VERIFY_URLS:
        for i in range(1, 6):  # 5 attempts per URL
            ok, msg = _probe_tunnel_once(url, timeout=timeout)
            if ok:
                print(f"[+] Tunnel stable: {msg}", flush=True)
                return True
            last_err = msg.split(": ", 1)[-1] if ": " in msg else msg
            print(f"    [{i}/5] {url}: {msg}", flush=True)
            time.sleep(2)
        # This URL failed all 5 attempts; try the next one.
        print(f"    [*] {url} unreachable, trying next endpoint...", flush=True)

    print(f"[!] All verification endpoints failed (last: {last_err}). "
          f"Routes are installed but egress through the TUN is not working yet.",
          flush=True)

    # Auto-escalate to DoH if plain DNS appears broken.
    if _ACTIVE_DNS_MODE == "auto":
        print("[*] Auto-switching wintun DNS to DoH (HTTPS) so name resolution "
              "rides over TCP/443...", flush=True)
        _ACTIVE_DNS_MODE = "doh"
        try:
            configure_tun(_ACTIVE_DNS4, _ACTIVE_DNS6)
        except Exception as e:
            print(f"[!] DoH switch failed: {e}", flush=True)
        for url in _VERIFY_URLS:
            for i in range(1, 6):
                ok, msg = _probe_tunnel_once(url, timeout=timeout)
                if ok:
                    print(f"[+] Tunnel stable (via DoH): {msg}", flush=True)
                    return True
                last_err = msg.split(": ", 1)[-1] if ": " in msg else msg
                print(f"    [{i}/5] (DoH) {url}: {msg}", flush=True)
                time.sleep(2)
    return False


def self_heal_tunnel(dns4, dns6):
    """Re-apply the Wintun address/DNS and the IPv4/IPv6 default + split-default
    routes WITHOUT restarting tun2socks.  Called by the monitor loop when the
    tunnel verification fails, so a transient DNS/route hiccup self-recovers
    instead of requiring a full restart.

    Best-effort: every step is individually guarded so one failing add cannot
    abort the rest, and the whole thing is wrapped so an unexpected error never
    crashes the running tunnel."""
    print("[*] Self-healing: re-applying Wintun config and TUN routes...", flush=True)
    try:
        if not wait_for_tun(timeout=5):
            print("[!] Self-heal: Wintun adapter is gone; cannot re-apply routes.")
            return
        configure_tun(dns4, dns6)
        ensure_wintun_ipv4()
        add_v4("0.0.0.0/0", TUN, TUN4, metric=1)
        for prefix in ("0.0.0.0/1", "128.0.0.0/1"):
            ensure_wintun_ipv4()
            add_v4(prefix, TUN, TUN4, metric=1)
        ensure_wintun_ipv6()
        add_v6("::/0", TUN, TUN6, metric=1)
        for prefix in ("::/1", "8000::/1"):
            ensure_wintun_ipv6()
            add_v6(prefix, TUN, TUN6, metric=1)
        # Re-apply LAN-bypass so local traffic (NetBIOS/Delivery Optimization)
        # stays off the tunnel after a self-heal too.
        try:
            _phys = get_ipv4_default()
            if _phys:
                _add_lan_bypass(_phys[0], _phys[1])
        except Exception:
            pass
        print("[+] Self-heal applied.", flush=True)
    except Exception as e:
        print(f"[!] Self-heal failed: {e}")


def main():
    global tun_proc

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--server", nargs="+", required=True,
                    help="VLESS server hostname or IP (repeatable: --server a b)")
    ap.add_argument("--port", type=int, default=10808,
                    help="v2rayN local SOCKS5 port")
    ap.add_argument("--tun2socks", default="tun2socks.exe",
                    help="Path to tun2socks.exe")
    ap.add_argument("--vpn-server", action="append", default=[], metavar="HOST_OR_IP",
                    help="Windows VPN server to bypass (repeatable; needed for some third-party VPN clients)")
    ap.add_argument("--no-vpn-bypass", action="store_true",
                    help="Do not add bypass routes for connected Windows VPN endpoints")
    ap.add_argument("--vless-over-vpn", action="store_true",
                    help="Send the VLESS server connection through the active Windows VPN (its server remains bypassed)")
    ap.add_argument("--vpn-interface", default=None, metavar="ALIAS",
                    help="Manually specify the Windows VPN adapter's InterfaceAlias for "
                         "--vless-over-vpn, if auto-detection via Get-VpnConnection fails")
    ap.add_argument("--dns4", default=DNS4, metavar="IP",
                    help=f"DNS server to set on the Wintun adapter for IPv4 (default {DNS4}). "
                         "If DNS lookups fail even though the tunnel itself works, try a "
                         "different resolver here - some networks block specific DNS IPs "
                         "directly, and some VLESS configs route well-known DNS IPs "
                         "'direct' (outside the tunnel) by routing-rule default.")
    ap.add_argument("--dns6", default=DNS6, metavar="IP",
                    help=f"DNS server to set on the Wintun adapter for IPv6 (default {DNS6})")
    ap.add_argument("--dns-mode", choices=["plain", "doh", "auto"], default="auto",
                    help="Wintun DNS delivery: plain (UDP/53 - needs UDP relay through "
                         "the proxy), doh (DNS-over-HTTPS over TCP/443 - works whenever TCP "
                         "relays), or auto (start plain, escalate to DoH if resolution "
                         "through the TUN keeps failing). Default auto.")
    ap.add_argument("--doh-template", default=None, metavar="URL",
                    help="Override the DoH template URL (e.g. https://dns.google/dns-query). "
                         "Auto-selected from the DNS IP when omitted.")
    ap.add_argument("--bypass-ip", action="append", default=[], metavar="HOST_OR_IP",
                    help="Additional IP(s) or hostname(s) to bypass the TUN (repeatable)")
    ap.add_argument("--geoip", default=None, metavar="PATH",
                    help="Path to v2rayN geoip file (.dat OR .json; format auto-detected); "
                         "install bypass routes for every CIDR of --geoip-code "
                         "(e.g. cn = bypass mainland traffic through the TUN)")
    ap.add_argument("--geoip-code", default="cn", metavar="CC",
                     help="Country code inside the geoip file to bypass (default cn)")
    ap.add_argument("--geoip-via-vpn", action="store_true",
                     help="Route the geoip country ranges THROUGH the tunnel (wintun) "
                          "instead of bypassing them via the physical adapter. Use this "
                          "when you want the geoip country's traffic to also exit with the "
                          "VPN IP (full-tunnel style) rather than going direct.")
    ap.add_argument("--geoip-via-win-vpn", action="store_true",
                     help="Route the geoip country ranges out through a CONNECTED Windows "
                          "VPN (instead of the physical adapter or wintun). Use this to "
                          "send the geoip country's traffic via your Windows VPN egress. "
                          "Overrides --geoip-via-vpn. Falls back to the physical adapter "
                          "if no connected Windows VPN default route is found.")
    ap.add_argument("--monitor-interval", type=int, default=30, metavar="SEC",
                    help="Seconds between tunnel health probes in the monitor loop (default 30)")
    ap.add_argument("--monitor-retries", type=int, default=2, metavar="N",
                    help="Consecutive probe failures before self-healing the TUN routes (default 2)")
    ap.add_argument("--no-monitor", action="store_true",
                    help="Disable the live monitor/self-heal loop (just keep the tunnel up)")
    ap.add_argument("--live-bypass", action="store_true",
                    help="Add bypass routes for --bypass-ip/--server to an ALREADY-running "
                         "TUN without starting or restarting tun2socks. No restart needed.")
    args = ap.parse_args()

    # Live bypass mode: resolve hosts and add their bypass routes to a TUN that
    # is already up, WITHOUT touching tun2socks.  This is the "add or resolve
    # without restart" path - run it any time the tunnel is active.
    if args.live_bypass:
        do_live_bypass(args)
        return

    # Resolve the user's DNS choices into module state so _ensure_wintun_address()
    # (called on every route install, and again if tun2socks recreates the adapter)
    # uses them instead of falling back to the hardcoded DNS4/DNS6 defaults.
    global _ACTIVE_DNS4, _ACTIVE_DNS6, _ACTIVE_DNS_MODE, _ACTIVE_DOH_TEMPLATE
    global vpn_override_iface
    _ACTIVE_DNS4 = args.dns4
    _ACTIVE_DNS6 = args.dns6
    _ACTIVE_DNS_MODE = args.dns_mode
    _ACTIVE_DOH_TEMPLATE = args.doh_template

    if not is_admin():
        sys.exit("[!] Run this script as Administrator.")

    atexit.register(cleanup)
    # Also run cleanup() on termination signals so the routing is removed when
    # the tunnel is switched off / the process is signalled (e.g. the dashboard
    # sends CTRL_BREAK_EVENT) - not only on a clean interpreter exit. cleanup()
    # is idempotent, so a later atexit call is a harmless no-op.
    def _on_signal(signum, frame):
        try:
            cleanup()
        finally:
            os._exit(0)
    for _sig in (getattr(signal, "SIGINT", None),
                 getattr(signal, "SIGTERM", None),
                 getattr(signal, "SIGBREAK", None)):
        if _sig is not None:
            try:
                signal.signal(_sig, _on_signal)
            except (ValueError, OSError, AttributeError, RuntimeError):
                pass
    preflight_cleanup()

    iface, gateway, ifindex = get_ipv4_default()
    print(f"[*] Physical interface: {iface}  IfIndex={ifindex}  Gateway={gateway}")
    vless_iface, vless_gateway = iface, gateway
    vpn_conn_name_for_check = None
    if args.vless_over_vpn:
        vpn_default = get_vpn_ipv4_default(args.vpn_interface)
        if not vpn_default:
            hint = (" (--vpn-interface did not match any live route)" if args.vpn_interface else
                    " Use --vpn-interface <alias> if this VPN isn't visible to Get-VpnConnection.")
            sys.exit(f"[!] --vless-over-vpn was selected but no active Windows VPN default route was found.{hint}")
        vless_iface, vless_gateway, vpn_ifindex = vpn_default
        vpn_conn_name_for_check = vless_iface
        print(f"[*] VLESS transport via Windows VPN: {vless_iface}  IfIndex={vpn_ifindex}  Gateway={vless_gateway}")

    # Resolve every configured server (repeatable --server) and combine the
    # resulting IPs so a bypass route is installed for each VLESS endpoint.
    v4, v6 = [], []
    for _s in args.server:
        print(f"[*] Resolving {_s}...")
        _a4, _a6 = resolve_all(_s)
        for ip in _a4:
            if ip not in v4:
                v4.append(ip)
        for ip in _a6:
            if ip not in v6:
                v6.append(ip)
    for x in v4:
        print(f"    IPv4: {x}")
    for x in v6:
        print(f"    IPv6: {x}")

    # A Windows VPN's control/data connection has to remain on the physical
    # network. Otherwise the 0/0 Wintun route captures it and disconnects the
    # VPN.  Resolve before altering routes so DNS itself is not redirected.
    vpn_servers = [] if args.no_vpn_bypass else get_active_windows_vpn_servers()
    if not args.no_vpn_bypass:
        vpn_servers.extend(("manual VPN server", server) for server in args.vpn_server)
    elif args.vpn_server:
        print("[!] --vpn-server values ignored because --no-vpn-bypass was selected.")

    # A connected Windows VPN injects its own default + /32 routes, often at a
    # very low metric (e.g. Shirazu-VPN at effective metric ~26). If we are NOT
    # in --vless-over-vpn mode, those routes can shadow the VLESS bypass routes
    # this helper installs via the physical adapter (which sits at a much higher
    # metric), hijacking the proxy transport through the VPN - or, if the VPN
    # cannot reach the VLESS server, looping it back into the TUN. Warn so the
    # operator picks the correct mode instead of hitting that loop.
    if not args.vless_over_vpn and not args.no_vpn_bypass:
        _vpn_def = get_vpn_ipv4_default()
        if _vpn_def:
            vpn_override_iface = _vpn_def[0]
            print("[!] Connected Windows VPN detected (" + _vpn_def[0] + ") but --vless-over-vpn "
                  "was NOT specified. Its low-metric /32 routes will be shadowed by the tunnel "
                  "so all app traffic goes through Wintun (the VPN link itself stays up via its "
                  "server bypass). If your VLESS server is meant to ride this VPN, re-run with "
                  "--vless-over-vpn (or --vpn-interface " + _vpn_def[0] + ").")

    vpn_v4, vpn_v6 = [], []
    seen_vpn_servers = set()
    if vpn_servers:
        print("[*] Resolving Windows VPN endpoint bypasses...")
    for name, server in vpn_servers:
        key = server.strip().lower()
        if not key or key in seen_vpn_servers:
            continue
        seen_vpn_servers.add(key)
        try:
            ep4, ep6 = resolve_all(server)
        except SystemExit as e:
            # Do not drop the whole system tunnel merely because a stale VPN
            # profile cannot resolve. A currently connected VPN normally has
            # a resolvable ServerAddress.
            print(f"[!] Could not resolve VPN endpoint '{name}' ({server}): {e}")
            continue
        vpn_v4.extend(x for x in ep4 if x not in vpn_v4)
        vpn_v6.extend(x for x in ep6 if x not in vpn_v6)
        print(f"    {name}: {server} -> {', '.join(ep4 + ep6)}")

    print(f"[*] Checking v2rayN SOCKS5 at 127.0.0.1:{args.port}...")
    if not test_local_socks(args.port):
        sys.exit(
            f"[!] 127.0.0.1:{args.port} is not accepting TCP connections. "
            "Start v2rayN and verify the SOCKS inbound."
        )

    # Critical: no --interface.
    # This avoids the Windows UDP bind path that produced WSAEINVAL.
    cmd = [
        args.tun2socks,
        "--device", TUN,
        "--proxy", f"socks5://127.0.0.1:{args.port}",
    ]
    print("[*] Starting tun2socks without --interface:")
    print("    " + " ".join(cmd))

    try:
        tun_proc = subprocess.Popen(cmd)
    except FileNotFoundError:
        sys.exit(f"[!] tun2socks not found: {args.tun2socks}")

    time.sleep(1)
    if tun_proc.poll() is not None:
        sys.exit(f"[!] tun2socks exited immediately: {tun_proc.returncode}")

    if not wait_for_tun():
        sys.exit("[!] Wintun adapter did not appear.")

    print(f"[*] Configuring Wintun: DNS4={args.dns4}  DNS6={args.dns6}")
    configure_tun(args.dns4, args.dns6)

    # ── Install bypass routes NOW (before the tun2socks IPv6 restart) ──
    # Resolving the egress and adding the /32 (and /128) bypass routes here
    # makes them take effect the instant the Wintun adapter is up, instead of
    # only after the restart. They use the physical/VPN gateway and do not
    # depend on tun2socks, so doing them early is safe and removes the wait.
    # Install the bypass routes BEFORE the default TUN route.
    # These are more specific than 0/0, so v2rayN's connection to the
    # VLESS endpoint remains on the physical network instead of entering
    # tun2socks and recursively returning to 127.0.0.1:10808.
    print("[*] Installing VLESS IPv4 bypass routes...")
    # NOTE: a failed bypass route for ONE server must NOT abort the whole
    # setup (and especially not skip IPv6). With multiple --server values the
    # chance of one /32 failing rises, and the old sys.exit here would kill the
    # run before the IPv6 default routes were ever installed - so adding a
    # second server could leave IPv6 dead. Warn and continue instead; the worst
    # case is that one VLESS transport may loop, not that the entire tunnel
    # (incl. IPv6) fails to come up.
    failed_vless = []
    for ip in v4:
        eg = get_egress_for(ip, exclude_vpn=not args.vless_over_vpn) or (vless_iface, vless_gateway)
        print(f"    VLESS {ip} -> via {eg[0]} ({eg[1]})")
        if not add_v4(f"{ip}/32", eg[0], eg[1], metric=1):
            failed_vless.append(ip)
    if failed_vless:
        print(f"[!] Could not install a bypass route for {len(failed_vless)} VLESS "
              f"server IP(s): {', '.join(failed_vless)}. That server's transport may "
              f"loop into the tunnel, but IPv4/IPv6 default routing is still configured.")

    extra_bypass_v4 = []
    extra_bypass_v6 = []
    for entry in args.bypass_ip:
        ep4, ep6 = resolve_all_safe(entry, label=f"bypass-ip {entry}")
        if ep4 is None and ep6 is None:
            continue
        extra_bypass_v4.extend(x for x in (ep4 or []) if x not in extra_bypass_v4 and x not in v4)
        extra_bypass_v6.extend(x for x in (ep6 or []) if x not in extra_bypass_v6 and x not in v6)
        if ep4 or ep6:
            print(f"    [bypass-ip] {entry} -> {', '.join((ep4 or []) + (ep6 or []))}")

    for ip in extra_bypass_v4:
        eg = get_egress_for(ip, exclude_vpn=not args.vless_over_vpn) or (vless_iface, vless_gateway)
        print(f"    bypass {ip} -> via {eg[0]} ({eg[1]})")
        if not add_v4(f"{ip}/32", eg[0], eg[1], metric=1):
            print(f"[!] Could not install bypass route for {ip}; continuing.")

    if vpn_v4:
        print("[*] Installing Windows VPN IPv4 bypass routes...")
        for ip in vpn_v4:
            eg = get_egress_for(ip) or (iface, gateway)
            if not add_v4(f"{ip}/32", eg[0], eg[1], metric=1):
                print(f"[!] Could not install VPN bypass route for {ip}; continuing.")

    # Only add IPv6 bypass if there's a usable IPv6 gateway to use for it.
    if v6:
        if args.vless_over_vpn:
            vpn6 = get_vpn_ipv6_default(args.vpn_interface)
            if vpn6:
                v6_iface, v6_gateway = vpn6
                print(f"[*] VLESS IPv6 transport via Windows VPN: {v6_iface} -> {v6_gateway}")
                for ip in v6:
                    add_v6(f"{ip}/128", v6_iface, v6_gateway, 1)
                for ip in extra_bypass_v6:
                    add_v6(f"{ip}/128", v6_iface, v6_gateway, 1)
            else:
                print("[!] --vless-over-vpn has no IPv6 route on that VPN (common for "
                      "IPv4-only VPNs like PPTP); IPv6 VLESS bypass not installed. "
                      "If the server also resolved an IPv6 address, that address will "
                      "not be reachable while this mode is active.")
        else:
            d6 = get_ipv6_default()
            if d6:
                print(f"[*] Native IPv6 route: {d6['InterfaceAlias']} -> {d6['NextHop']}")
                for ip in v6:
                    add_v6(f"{ip}/128", d6["InterfaceAlias"], d6["NextHop"], 1)
                for ip in extra_bypass_v6:
                    add_v6(f"{ip}/128", d6["InterfaceAlias"], d6["NextHop"], 1)
            else:
                print("[!] No usable native IPv6 gateway; IPv6 VLESS bypass not installed.")

    # VPN IPv6 endpoints use the same native gateway selection as VLESS.
    # Re-use the safe behavior above: do not manufacture an IPv6 next hop.
    if vpn_v6:
        d6 = get_ipv6_default()
        if d6:
            print("[*] Installing Windows VPN IPv6 bypass routes...")
            for ip in vpn_v6:
                add_v6(f"{ip}/128", d6["InterfaceAlias"], d6["NextHop"], 1)
        else:
            print("[!] No usable native IPv6 gateway; IPv6 VPN bypass not installed.")

    # tun2socks initializes its IPv6 stack from the Wintun addresses at startup.
    # We had to start it before configure_tun could assign fd00:dead:beef::1/64,
    # so its IPv6 handler never came up (IPv4 still works because it reads that
    # address post-start). Restart tun2socks now that the IPv6 address exists;
    # the fresh adapter keeps the addresses, and we re-apply them to be safe.
    # This is what makes IPv6-through-the-tunnel actually forward.
    print("[*] Restarting tun2socks to pick up the Wintun IPv6 address...")
    if tun_proc is not None and tun_proc.poll() is None:
        tun_proc.terminate()
        try:
            tun_proc.wait(timeout=5)
        except Exception:
            tun_proc.kill()
    time.sleep(1)
    tun_proc = subprocess.Popen(cmd)
    time.sleep(1)
    if tun_proc.poll() is not None:
        sys.exit(f"[!] tun2socks exited after restart: {tun_proc.returncode}")
    if not wait_for_tun():
        sys.exit("[!] Wintun adapter did not reappear after restart.")
    configure_tun(args.dns4, args.dns6)

    # (Bypass routes are now installed right after the first Wintun config,
    #  before the tun2socks IPv6 restart, so they take effect instantly.)

    # ── geoip.dat bypass (route-level "bypass mainland" / geoip:cn) ─────────
    # Install these BEFORE the TUN default route so domestic destinations are
    # captured by the more-specific country ranges and stay direct, while the
    # TUN split-default still carries the rest of the world.
    if args.geoip:
        code = args.geoip_code
        print(f"[*] Loading geoip file bypass for code '{code}' from {args.geoip} ...")
        try:
            # Emit a [GEO-PARSE] marker as the file is decoded so the dashboard
            # shows the *file load* phase (not just the later route install) and
            # never sits at 0% then snaps to 100% when parsing finishes.
            def _geo_progress(pos, total):
                if total:
                    print(f"[GEO-PARSE] code={code} loaded={pos} total={total}", flush=True)
            cidrs = parse_geoip(args.geoip, code, on_progress=_geo_progress)
        except Exception as e:
            print(f"[!] Could not load geoip bypass ({code}): {e}")
        else:
            if args.geoip_via_win_vpn:
                # Route the country's ranges out through a CONNECTED Windows VPN
                # (the VPN adapter + its next-hop), so geoip country traffic exits
                # via the Windows VPN rather than the physical adapter or wintun.
                # Conflicts with --geoip-via-vpn (wintun) - the Windows VPN egress
                # wins when both are given.
                vpn4 = get_vpn_ipv4_default(args.vpn_interface)
                vpn6 = get_vpn_ipv6_default(args.vpn_interface)
                if not vpn4:
                    print(f"[!] geoip:{code} via Windows VPN requested but no connected "
                          f"Windows VPN default route found - falling back to the physical "
                          f"adapter ({iface}).")
                    v6iface = v6gw = None
                    d6 = get_ipv6_default()
                    if d6:
                        v6iface, v6gw = d6["InterfaceAlias"], d6["NextHop"]
                    g_iface, g_gw = iface, gateway
                else:
                    g_iface, g_gw = vpn4[0], vpn4[1]
                    if vpn6:
                        v6iface, v6gw = vpn6[0], vpn6[1]
                    else:
                        v6iface = v6gw = None
                    print(f"[*] geoip:{code} routed via connected Windows VPN "
                          f"({g_iface}) - country traffic will use the VPN egress.")
            elif args.geoip_via_vpn:
                # Mode 3 ("vpn as geo"): route the country's ranges THROUGH the
                # tunnel so that traffic also exits with the VPN IP. The Wintun
                # address must exist because it is the next-hop for every wintun
                # route we are about to install.
                ensure_wintun_ipv4()
                g_iface, g_gw = TUN, TUN4
                v6iface, v6gw = TUN, TUN6
                print(f"[*] geoip:{code} tunneled via Wintun ({TUN}) - "
                      f"country traffic will use the VPN IP.")
            else:
                v6iface = v6gw = None
                d6 = get_ipv6_default()
                if d6:
                    v6iface, v6gw = d6["InterfaceAlias"], d6["NextHop"]
                g_iface, g_gw = iface, gateway
            # Guarded so a geoip route-install failure can NEVER abort the whole
            # tunnel setup - the wintun default + split-default routes below must
            # always be installed even if the country bypass blows up.
            try:
                add_geoip_bypass(code, cidrs, g_iface, g_gw, v6iface, v6gw)
            except Exception as e:
                print(f"[!] geoip bypass install failed ({code}): {e}; continuing without it.")

    print("[*] Installing IPv4 default route through Wintun...")
    # The wintun IPv4 address (192.168.123.1) is the next-hop for every IPv4
    # wintun route below. If tun2socks dropped it on its restart, add_v4() would
    # fail. Re-ensure it (idempotent) right before every add, so a route add can
    # never fail just because the adapter address momentarily went missing.
    #
    # CRITICAL (this was the bug behind the 'TUN default route' and 'Default
    # IPv6 route' health-check failures): a failing split-default add must NOT
    # abort the whole setup. The old code did `sys.exit()` on the first failed
    # split route, which left IPv4 with only 0.0.0.0/0 and SKIPPED every IPv6
    # route. Now we only warn and keep going, so IPv4 splits and the entire IPv6
    # stack still get installed even if one add hiccups.
    ipv4_ok = True
    ensure_wintun_ipv4()
    if not add_v4("0.0.0.0/0", TUN, TUN4, metric=1):
        print("[!] Failed to add IPv4 default route; continuing with split-defaults anyway.")
        ipv4_ok = False

    # A connected Windows VPN often supplies its own 0.0.0.0/0 route with a
    # very low metric. Route metrics cannot reliably beat every VPN client.
    # These two routes cover the whole IPv4 Internet yet are more specific
    # than any /0, so system traffic still enters Wintun.  The /32 routes for
    # the VLESS/VPN endpoints above remain more specific and keep those
    # transport connections on the physical adapter.
    print("[*] Installing IPv4 split-default routes through Wintun...")
    for prefix in ("0.0.0.0/1", "128.0.0.0/1"):
        ensure_wintun_ipv4()
        if not add_v4(prefix, TUN, TUN4, metric=1):
            print(f"[!] Failed to add IPv4 split-default route {prefix}; "
                  f"IPv4 may not cover the entire range via Wintun. Continuing.")
            ipv4_ok = False

    print("[*] Installing IPv6 default route through Wintun...")
    # IPv6 routes through the TUN need the Wintun adapter's own IPv6 address as
    # the next-hop (exactly like IPv4 uses TUN4). Omitting it yields
    # `netsh interface ipv6 add route ... wintun` with no gateway, which Windows
    # rejects. Re-ensure that address is present before every add.
    ensure_wintun_ipv6()
    if not add_v6("::/0", TUN, TUN6, metric=1):
        print("[!] Failed to add IPv6 default route ::/0; continuing with IPv6 split-defaults.")

    # Mirror the IPv4 strategy: install the split-default ::/1 + 8000::/1
    # routes unconditionally. They are more specific than ::/0, so they carry
    # all IPv6 traffic yet Windows more reliably accepts them than a bare ::/0
    # default route (which it often rejects when a real adapter already owns
    # ::/0). The VLESS/VPN /128 bypasses above stay more specific and keep
    # those transports on the physical adapter. This is what actually
    # "activates" IPv6 through the tunnel in the common case.
    print("[*] Installing IPv6 split-default routes through Wintun...")
    ipv6_ok = True
    for prefix in ("::/1", "8000::/1"):
        ensure_wintun_ipv6()
        if not add_v6(prefix, TUN, TUN6, metric=1):
            print(f"[!] Failed to add IPv6 split-default route {prefix}; "
                  f"IPv6 may not be fully tunneled. Continuing.")
            ipv6_ok = False

    # Verdict for the dashboard's two route checks. We explicitly list what is
    # present so an operator can see, at a glance, exactly why a check passed or
    # failed instead of guessing from a bare "missing" message.
    wintun_routes = ps_json(
        "$r = Get-NetRoute -InterfaceAlias 'wintun' -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty DestinationPrefix; "
        "if ($r) { $r | ConvertTo-Json -Compress } else { Write-Output 'NONE' }")
    if isinstance(wintun_routes, list):
        wintun_routes = ", ".join(wintun_routes)
    elif wintun_routes is None:
        wintun_routes = "NONE"
    print(f"[*] Wintun routes now installed: {wintun_routes}")

    # Neutralize a connected Windows VPN's injected routes so the tunnel is the
    # SOLE egress (kills the wifi/VPN/tun split). We shadow every VPN-injected
    # route with a lower-metric Wintun route; the VPN link itself stays up because
    # its server endpoint remains bypassed. Skipped in --vless-over-vpn mode, where
    # riding the VPN is intentional.
    if vpn_override_iface and not args.vless_over_vpn:
        _skip = set()
        _skip.update(str(x) for x in v4)
        _skip.update(str(x) for x in v6)
        _skip.update(str(x) for x in vpn_v4)
        _skip.update(str(x) for x in vpn_v6)
        _skip.update(_vpn_self_addresses(vpn_override_iface))
        print(f"[*] Shadowing {vpn_override_iface} injected routes with Wintun (sole egress)...")
        override_vpn_routes(vpn_override_iface, _skip)

    if not ipv6_ok:
        print("[!] IPv6 split-default routes could not be installed; IPv6 will "
              "NOT be tunneled (IPv4 remains fully active). This usually means "
              "the VLESS server does not provide IPv6 egress, or Windows "
              "rejected the ::/1 routes. Check the dashboard's IPv6 row.")

    if args.vless_over_vpn and vpn_conn_name_for_check:
        status = get_vpn_connection_names_status().get(vpn_conn_name_for_check)
        if status and status != "Connected":
            print(f"[!] Windows VPN '{vpn_conn_name_for_check}' is no longer Connected "
                  f"(status: {status}) right after configuring routes.")
        elif status == "Connected":
            print(f"[*] Windows VPN '{vpn_conn_name_for_check}' confirmed still Connected.")

    # Keep LAN traffic (NetBIOS, Delivery Optimization, mDNS, local printers,
    # router, etc.) on the physical adapter so it never enters the tunnel or
    # exhausts the proxy's loopback ports.  Done last so it can't preempt the
    # public default/split routes during install ordering.
    _add_lan_bypass(iface, gateway)

    print(flush=True)
    print("[+] TUNNEL ACTIVE", flush=True)
    if ipv4_ok:
        print("[+] IPv4: system -> Wintun -> tun2socks -> v2rayN (VPN-proof split default)")
    else:
        print("[#] IPv4: default/split routes did NOT all install - IPv4 may be partial or dead")
    if ipv6_ok:
        print("[+] IPv6: system -> Wintun -> tun2socks -> v2rayN (VPN-proof split default)")
    else:
        print("[#] IPv6: split-default routes did NOT install - IPv6 is NOT tunneled (expected if the VLESS server has no IPv6 egress)")
    print(f"[+] VLESS endpoint(s): {'Windows VPN transport' if args.vless_over_vpn else 'physical adapter bypass'}")
    if vpn_v4 or vpn_v6:
        print("[+] Windows VPN endpoint(s): physical adapter bypass")
    print("[+] tun2socks --interface: OFF")

    # Verify the tunnel is actually carrying traffic before declaring success.
    # This retries until the tunnel stabilizes (it can still be "warming up"
    # right after the tun2socks restart) and fixes the old
    # "Could not resolve https://api.ipify.org/" failure, which was just the
    # full URL (scheme + path) being fed to getaddrinfo instead of a hostname.
    print("[*] Verifying the tunnel is stable...", flush=True)
    wait_for_tunnel_stable()

    print("[*] Press Ctrl+C to stop.", flush=True)
    print(flush=True)

    last_vpn_status = None
    last_probe = 0.0
    fails = 0
    mon_interval = max(5, args.monitor_interval)
    mon_retries = max(1, args.monitor_retries)
    try:
        while tun_proc.poll() is None:
            time.sleep(1)
            now = time.time()
            if args.vless_over_vpn and vpn_conn_name_for_check and int(now) % 10 == 0:
                status = get_vpn_connection_names_status().get(vpn_conn_name_for_check)
                if status != last_vpn_status:
                    if status and status != "Connected":
                        print(f"[!] Windows VPN '{vpn_conn_name_for_check}' status changed: {status}")
                    last_vpn_status = status
            # Live monitor / debug loop: periodically verify the tunnel resolves
            # and carries traffic through the TUN. On repeated failure, self-heal
            # (re-apply Wintun DNS + default/split routes) instead of requiring a
            # manual restart. --no-monitor disables this entirely.
            if not args.no_monitor and (now - last_probe) >= mon_interval:
                last_probe = now
                ok, msg = _probe_tunnel_once()
                if ok:
                    fails = 0
                    print(f"[MONITOR] tunnel OK: {msg}", flush=True)
                else:
                    fails += 1
                    print(f"[MONITOR] tunnel check failed ({fails}/{mon_retries}): {msg}", flush=True)
                    if fails >= mon_retries:
                        # Still in auto mode? Escalate DNS to DoH so resolution
                        # rides over TCP/443 instead of the broken UDP/53 path.
                        if _ACTIVE_DNS_MODE == "auto":
                            print("[*] Monitor: repeated DNS/egress failures; "
                                  "escalating wintun DNS to DoH.")
                            _ACTIVE_DNS_MODE = "doh"
                        self_heal_tunnel(args.dns4, args.dns6)
                        fails = 0
    except KeyboardInterrupt:
        pass


def do_live_bypass(args):
    """Add bypass routes to an ALREADY-running TUN without restarting
    tun2socks.  Resolves each --bypass-ip / --server host and installs a /32
    (or /128) route via the real egress, so the traffic stays direct.  No
    tunnel restart is needed - use this to add/resolve on the fly."""
    if not is_admin():
        sys.exit("[!] Run this script as Administrator.")

    if not wait_for_tun(timeout=10):
        sys.exit("[!] Wintun adapter not present. Start the tunnel first "
                 "(run without --live-bypass).")

    iface, gateway, _ = get_ipv4_default()
    print(f"[*] Live bypass: physical egress {iface} ({gateway}); "
          f"adding routes to the running TUN.")

    hosts = list(args.bypass_ip) + list(args.server)
    if not hosts:
        sys.exit("[!] --live-bypass needs at least one --bypass-ip or --server host.")

    d6 = get_ipv6_default()
    added = 0
    for h in hosts:
        v4, v6 = resolve_all_safe(h, label=f"bypass {h}")
        if v4 is None and v6 is None:
            continue
        for ip in (v4 or []):
            eg = get_egress_for(ip) or (iface, gateway)
            if add_v4(f"{ip}/32", eg[0], eg[1], metric=1):
                added += 1
                print(f"    [+] bypass {ip} -> via {eg[0]} ({eg[1]})")
            else:
                print(f"    [!] could not add bypass route for {ip}")
        for ip in (v6 or []):
            if d6:
                if add_v6(f"{ip}/128", d6["InterfaceAlias"], d6["NextHop"], 1):
                    added += 1
                    print(f"    [+] bypass {ip} (v6) -> via {d6['InterfaceAlias']}")
            else:
                print(f"    [!] no IPv6 gateway; skipped v6 bypass {ip}")
    print(f"[+] Live bypass done: {added} route(s) added to the running TUN. "
          f"No restart needed.")


if __name__ == "__main__":
    main()

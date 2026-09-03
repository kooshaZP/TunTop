"""PowerShell / netsh routing helpers (moved verbatim from the old
single-file dashboard): route add/delete with verification fallbacks,
egress + default-route discovery, wintun teardown."""
import base64
import json
import os
import subprocess
import tempfile

from tuntop.psshell import ps_quote

# Windows caps a whole CreateProcess command line at 32767 characters.
# -EncodedCommand puts the ENTIRE script on the command line (base64 of
# UTF-16LE ≈ 2.7x the script size), so any batched bulk operation - e.g.
# hundreds of Remove-NetRoute statements to tear down thousands of geoip
# bypass routes - blows past the cap and the process NEVER STARTS. Stay well
# under it: anything larger runs from a temp .ps1 file instead (-File has no
# such limit). Before this fallback existed, every large cleanup batch failed
# to launch and its error was swallowed, which is exactly why leftover geoip
# routes survived every quit ("routing stays on system").
_PS_CMDLINE_SAFE = 20000


def _ps_process_out(p):
    """Shared stdout/stderr post-processing for _ps / _ps_file."""
    out = (p.stdout or "").strip() or (p.stderr or "").strip()
    # Drop any stray PowerShell CLIXML markers (progress/error records)
    # that can still leak into stderr/error output.
    out = "\n".join(
        ln for ln in out.splitlines() if not ln.startswith("#<")
    ).strip()
    out = out or "No result"
    return p.returncode == 0 and bool(out), out


def _ps_file(script, timeout=8):
    """Run PowerShell with the script written to a temp .ps1 FILE.

    No command-line length limit (the script travels via the filesystem), so
    arbitrarily large batched removals work. UTF-8 BOM so Windows PowerShell
    5.1 reads non-ASCII interface names correctly."""
    fd, path = tempfile.mkstemp(suffix=".ps1", prefix="TunTop_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8-sig") as f:
            f.write(script)
        try:
            p = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                 "-File", path],
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=timeout,
            )
        except Exception as e:
            return False, str(e)
        return _ps_process_out(p)
    finally:
        try:
            os.unlink(path)
        except Exception:
            pass


def _ps(script, timeout=8):
    """Run PowerShell and return (ok, stdout_text).

    Small scripts go through -EncodedCommand as before; scripts whose encoded
    command line would approach the 32767-char CreateProcess limit are run
    from a temp .ps1 file instead (see _PS_CMDLINE_SAFE / _ps_file)."""
    # Silence progress/verbose records so they never leak as CLIXML into the
    # dashboard; checks report their own status via stdout (+exit code).
    script = "$ProgressPreference='SilentlyContinue'; " + script
    enc = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    if len(enc) + 80 > _PS_CMDLINE_SAFE:
        return _ps_file(script, timeout)
    try:
        p = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-EncodedCommand", enc],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=timeout,
        )
        return _ps_process_out(p)
    except Exception as e:
        return False, str(e)


def _teardown_wintun():
    """Best-effort teardown of stale tunnel state: removes routes from BOTH
    tunnel adapters (the primary 'wintun' and, when a previous run used
    --proxy2-port, the secondary 'wintun2') and force-kills every orphaned
    tun2socks process. A crash mid-session with proxy2 active otherwise
    leaves the second adapter and its routes behind for the next launch."""
    try:
        for adapter in ("wintun", "wintun2"):
            _ps(f"Get-NetRoute -InterfaceAlias '{adapter}' -ErrorAction SilentlyContinue | "
                "Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue")
        _ps("Get-Process -ErrorAction SilentlyContinue | Where-Object {$_.ProcessName -like 'tun2socks*'} | "
            "ForEach-Object { Stop-Process -Force -Id $_.Id -ErrorAction SilentlyContinue }")
    except Exception:
        pass


# ─── Live route helpers (for in-dashboard bypass-IP editing) ─────────────────
# Re-implemented locally rather than imported from tuntop/helper.py, same
# as everything else in this file - these mirror get_ipv4_default() and
# get_vpn_ipv4_default() there closely enough to pick the same interface.

def _get_ipv4_default():
    """IPv4 default route used to reach the Internet (interface + gateway).

    Mirrors tuntop/helper.py:get_ipv4_default(): never returns a connected
    Windows VPN as the "physical" gateway (so geo/bypass traffic is not routed
    into the VPN), and recovers the physical NIC's configured gateway via CIM
    when a full-tunnel VPN has deleted the Wi-Fi default route.  The VPN
    gateway is only used as an absolute last resort."""
    ps = r"""
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
$r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Where-Object {
        $_.NextHop -ne '0.0.0.0' -and $_.State -eq 'Alive' -and
        $_.InterfaceAlias -ne 'wintun' -and
        ($vpnAliases.Count -eq 0 -or -not ($vpnAliases -contains $_.InterfaceAlias))
    } |
    Sort-Object RouteMetric, InterfaceMetric |
    Select-Object -First 1 NextHop, InterfaceAlias
if ($null -eq $r) {
    $r = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction SilentlyContinue |
        Where-Object { $_.DefaultIPGateway } |
        ForEach-Object {
            $gw = @($_.DefaultIPGateway) | Where-Object { $_ -and $_ -ne '0.0.0.0' -and $_ -ne '::' } | Select-Object -First 1
            if ($gw) {
                $na = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue
                [PSCustomObject]@{
                    NextHop = $gw
                    InterfaceAlias = if ($na) { $na.InterfaceAlias } else { $_.Description }
                }
            }
        } |
        Where-Object { $_.InterfaceAlias -ne 'wintun' -and ($vpnAliases.Count -eq 0 -or -not ($vpnAliases -contains $_.InterfaceAlias)) } |
        Select-Object -First 1
}
if ($null -eq $r) {
    $r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Where-Object {$_.NextHop -ne '0.0.0.0' -and $_.State -eq 'Alive' -and $_.InterfaceAlias -ne 'wintun'} |
        Sort-Object RouteMetric, InterfaceMetric |
        Select-Object -First 1 NextHop, InterfaceAlias
}
if ($null -eq $r) { exit 1 }
$r | ConvertTo-Json -Compress
"""
    ok, out = _ps(ps)
    if not ok:
        return None
    try:
        d = json.loads(out)
        return d["InterfaceAlias"], d["NextHop"]
    except Exception:
        return None


def _get_egress_for(ip):
    """Return (interface, gateway) Windows would actually use to reach `ip`
    over its real (non-wintun) path. Respects split-tunnel VPNs (a destination
    reachable only via the VPN gets that gateway), unlike _get_ipv4_default()
    which only knows the system default route. Prefers the most-specific
    non-wintun route, then falls back to the real default route."""
    ps = rf"""
$r = Find-NetRoute -RemoteIPAddress '{ps_quote(ip)}' -ErrorAction SilentlyContinue
if ($r) {{
    $r = @($r) | Where-Object {{ $_.InterfaceAlias -ne 'wintun' }} |
        Sort-Object {{ ($_.DestinationPrefix -split '/')[1] -as [int] }} -Descending, RouteMetric, InterfaceMetric |
        Select-Object -First 1
}}
if (-not $r) {{
    $r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Where-Object {{ $_.InterfaceAlias -ne 'wintun' -and $_.NextHop -ne '0.0.0.0' }} |
        Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
}}
if ($null -eq $r) {{ exit 1 }}
$r | Select-Object InterfaceAlias, NextHop | ConvertTo-Json -Compress
"""
    ok, out = _ps(ps)
    if not ok:
        return None
    try:
        d = json.loads(out)
    except Exception:
        return None
    iface = str(d.get("InterfaceAlias", ""))
    gw = str(d.get("NextHop", "") or "")
    if not iface:
        return None
    return iface, (gw or "0.0.0.0")


def _get_vpn_ipv4_default(vpn_interface=None):
    """Connected Windows VPN's IPv4 default route (for --proxy-over-vpn)."""
    if vpn_interface:
        ps = rf"""
$r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -InterfaceAlias '{ps_quote(vpn_interface)}' -ErrorAction SilentlyContinue |
    Sort-Object RouteMetric, InterfaceMetric |
    Select-Object -First 1 NextHop, InterfaceAlias
if ($null -eq $r) {{ exit 1 }}
$r | ConvertTo-Json -Compress
"""
    else:
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
if ($null -eq $best) { exit 1 }
$best | Select-Object NextHop, InterfaceAlias | ConvertTo-Json -Compress
"""
    ok, out = _ps(ps)
    if not ok:
        return None
    try:
        d = json.loads(out)
        return d["InterfaceAlias"], d["NextHop"]
    except Exception:
        return None


def _get_vpn_ipv6_default(vpn_interface=None):
    """IPv6 counterpart of _get_vpn_ipv4_default for --proxy-over-vpn."""
    if vpn_interface:
        ps = rf"""
$r = Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -InterfaceAlias '{ps_quote(vpn_interface)}' -ErrorAction SilentlyContinue |
    Where-Object {{$_.NextHop -ne '::'}} |
    Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1 NextHop, InterfaceAlias
if ($null -eq $r) {{ exit 1 }}
$r | ConvertTo-Json -Compress
"""
    else:
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
if ($null -eq $best) { exit 1 }
$best | Select-Object NextHop, InterfaceAlias | ConvertTo-Json -Compress
"""
    ok, out = _ps(ps)
    if not ok:
        return None
    try:
        d = json.loads(out)
        return d["InterfaceAlias"], d["NextHop"]
    except Exception:
        return None


def _netsh(args_list, timeout=10):
    try:
        p = subprocess.run(["netsh"] + args_list, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=timeout)
        return p.returncode == 0, (p.stdout or p.stderr or "").strip()
    except Exception as e:
        return False, str(e)


def _add_route_v4(dest, iface, gateway, metric=1):
    ok, msg = _netsh(["interface", "ipv4", "add", "route", dest, iface, gateway, f"metric={metric}", "store=active"])
    # "The object already exists" just means the bypass route is already
    # installed (e.g. by the helper at startup, or a previous live add) - that
    # is a successful bypass, not a failure. Treating it as success is what
    # lets a live [A] add report correctly without needing a tunnel restart.
    if ok:
        return True
    if "already exists" in msg.lower():
        # Could be a PERSISTENT leftover from an older build (registry) that
        # would survive a reboot. Convert it to active-store-only: delete then
        # re-add with store=active.
        _netsh(["interface", "ipv4", "delete", "route", dest, iface, gateway])
        ok2, msg2 = _netsh(["interface", "ipv4", "add", "route", dest, iface, gateway, f"metric={metric}", "store=active"])
        return ok2 or "already exists" in msg2.lower()
    return False


def _route_exists_v4(dest):
    """True if any IPv4 route with exactly this prefix is in the live table."""
    ok, out = _ps(
        f"if (Get-NetRoute -DestinationPrefix '{dest}' -AddressFamily IPv4 "
        f"-ErrorAction SilentlyContinue) {{ 'yes' }}")
    return ok and "yes" in out


def _route_exists_v6(dest):
    ok, out = _ps(
        f"if (Get-NetRoute -DestinationPrefix '{dest}' -AddressFamily IPv6 "
        f"-ErrorAction SilentlyContinue) {{ 'yes' }}")
    return ok and "yes" in out


def _del_route_v4(dest, iface, gateway):
    """Delete an IPv4 route. Robust against parameter drift: netsh only
    removes the route when iface AND next-hop BOTH match what was recorded at
    install time. If the egress changed since then (Wi-Fi switch, DHCP renew,
    on-link <-> gateway form), netsh answers 'element not found' - which looks
    identical to 'route was never there'. Left alone, that silently KEEPS the
    /32 route alive and traffic keeps flowing DIRECT after [X] remove."""
    ok, msg = _netsh(["interface", "ipv4", "delete", "route", dest, iface, gateway])
    low = msg.lower()
    if ok:
        return True
    claims_gone = "not found" in low or "element" in low
    # Ambiguous failure: either genuinely absent, or our parameters don't
    # match the installed route. Check the live table before believing it...
    if claims_gone and not _route_exists_v4(dest):
        return True
    # ...and fall back to a prefix-wide delete that ignores iface/nexthop.
    _ps(f"Remove-NetRoute -DestinationPrefix '{dest}' -AddressFamily IPv4 "
        f"-Confirm:$false -ErrorAction SilentlyContinue | Out-Null")
    return not _route_exists_v4(dest)


def _del_route_v6(dest, iface, gateway):
    cmd = ["interface", "ipv6", "delete", "route", dest, iface]
    if gateway:
        cmd.append(gateway)
    ok, msg = _netsh(cmd)
    low = msg.lower()
    if ok:
        return True
    claims_gone = "not found" in low or "element" in low
    if claims_gone and not _route_exists_v6(dest):
        return True
    _ps(f"Remove-NetRoute -DestinationPrefix '{dest}' -AddressFamily IPv6 "
        f"-Confirm:$false -ErrorAction SilentlyContinue | Out-Null")
    return not _route_exists_v6(dest)


def _add_route_v6(dest, iface, gateway, metric=1):
    cmd = ["interface", "ipv6", "add", "route", dest, iface]
    if gateway:
        cmd.append(gateway)
    cmd.append(f"metric={metric}")
    cmd.append("store=active")
    ok, msg = _netsh(cmd)
    if ok:
        return True
    if "already exists" in msg.lower():
        # Convert a persistent leftover (see _add_route_v4 for why).
        del_cmd = ["interface", "ipv6", "delete", "route", dest, iface]
        if gateway:
            del_cmd.append(gateway)
        _netsh(del_cmd)
        ok2, msg2 = _netsh(cmd)
        return ok2 or "already exists" in msg2.lower()
    return False


def _get_ipv6_default(vpn_interface=None):
    """IPv6 default route (next hop) used to send a bypass entry's IPv6
    address directly. Mirrors the VPN-exclusion fix in
    tuntop/helper.py:get_ipv6_default() so a connected Windows VPN is never
    picked as the "safe" native gateway."""
    if vpn_interface:
        ps = rf"""
$r = Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -InterfaceAlias '{ps_quote(vpn_interface)}' -ErrorAction SilentlyContinue |
    Where-Object {{$_.NextHop -ne '::'}} |
    Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1 NextHop, InterfaceAlias
if ($null -eq $r) {{ exit 1 }}
$r | ConvertTo-Json -Compress
"""
    else:
        ps = r"""
$vpnAliases = @(
    @(Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue) +
    @(Get-VpnConnection -ErrorAction SilentlyContinue) |
    Where-Object { $_.ConnectionStatus -eq 'Connected' } |
    Select-Object -ExpandProperty Name -Unique |
    ForEach-Object {
        $n = $_
        $_
        Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -InterfaceAlias $n -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty InterfaceAlias -Unique
    }
)
Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceAlias -match '(?i)(pptp|l2tp|sstp|ikev2|vpn|wan miniport)' } |
    Select-Object -ExpandProperty InterfaceAlias -Unique | ForEach-Object { $vpnAliases += $_ }
$vpnAliases = @($vpnAliases | Where-Object { $_ } | Select-Object -Unique)
$r = Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue |
    Where-Object {
        $_.NextHop -ne '::' -and $_.State -eq 'Alive' -and
        $_.InterfaceAlias -ne 'wintun' -and
        ($vpnAliases.Count -eq 0 -or -not ($vpnAliases -contains $_.InterfaceAlias))
    } |
    Sort-Object RouteMetric, InterfaceMetric |
    Select-Object -First 1 NextHop, InterfaceAlias
if ($null -eq $r) {
    $r = Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -ne '::' -and $_.State -eq 'Alive' -and $_.InterfaceAlias -ne 'wintun' } |
        Sort-Object RouteMetric, InterfaceMetric |
        Select-Object -First 1 NextHop, InterfaceAlias
}
if ($null -eq $r) { exit 1 }
$r | ConvertTo-Json -Compress
"""
    ok, out = _ps(ps)
    if not ok:
        return None
    try:
        d = json.loads(out)
        return d["InterfaceAlias"], d["NextHop"]
    except Exception:
        return None

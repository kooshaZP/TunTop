#!/usr/bin/env python3
"""
tuntop/helper.py

Windows-wide TUN routing for any local SOCKS5 proxy + xjasonlyu/tun2socks.

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
  This module is launched and owned by tuntop/ui/dashboard.py (run
  Run_Helper.ps1).  It is not invoked directly:
  python tuntop/ui/dashboard.py --server YOUR_SERVER --port 10808 ^
       --tun2socks "C:\\tools\\tun2socks.exe"

Your proxy client's SOCKS5 inbound must support UDP if you want UDP applications.
"""

import argparse
import atexit
import concurrent.futures
import ctypes
import ipaddress
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

# Bootstrap sys.path so shared package leaves resolve when this file runs
# standalone (python tuntop/tunnel/helper.py), not just as a package module.
# Everything imported from the package below this point (psshell here,
# geo.geoip further down) relies on it.
import os as _os
import sys as _sys
_PKG_PARENT = _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
if _PKG_PARENT not in _sys.path:
    _sys.path.insert(0, _PKG_PARENT)

from tuntop.psshell import ps_quote  # noqa: E402
from tuntop.config import defaults as _cfgdef  # noqa: E402
from tuntop.config.defaults import (  # noqa: E402  (single source of truth)
    TUN, TUN4, TUN4_MASK, TUN6, TUN2, TUN2_IP4, TUN2_IP6,
    DNS4, DNS6, LAN_BYPASS_PREFIXES, GEO_SUB_BATCH, GEO_MAX_WORKERS, GEO_SUB_TIMEOUT,
    DEFAULT_SOCKS_PORT, WINTUN4_NET, WINTUN6_NET,
)
from tuntop.network import egress_scripts as _es
from tuntop.network import dns_guard as _dns_guard  # noqa: E402  (DNS leak guard)
from tuntop.network.dns import _host_from_url as _shared_host_from_url  # noqa: E402
from tuntop.network.routeops import RouteLedger, RouteResult  # noqa: E402
from tuntop.tunnel.exec import (  # noqa: E402  (moved Phase 4: state-free primitives)
    run, ps_json, run_ps, _clean_err, _NO_WINDOW,
)


def _resolve_dns_choice(d4, d6):
    """Resolve the user's --dns4/--dns6 input into the DNS servers to set on
    the Wintun adapter. A None result for one family means "do not set (and
    remove any stale) DNS for that family".

    The rule itself lives in tuntop.config.defaults.resolve_dns_choice, which
    the DASHBOARD also calls (for the health rows and the live-reconfig control
    file). It used to be duplicated here, and the copies drifting apart is what
    let a server edit write `dns4: null` into the control file, wipe the
    running resolver and take the catch-all leak pin down with it."""
    return _cfgdef.resolve_dns_choice(d4, d6)

# Second proxy pipe (optional, behind --proxy2-port).  A second TUN adapter +
# tun2socks process against a second local SOCKS5 port; specific destinations
# can then be routed through it while the PRIMARY pipe keeps owning the default
# route.  CRITICAL: TUN2 must never receive a default route (0/0) - two
# adapters fighting over 0/0 is exactly the routing-loop bug the teardown
# guarantees exist to prevent.  TUN2 only ever receives specific-destination
# routes (see the dashboard's proxy2 bypass targeting). The TUN2 constants
# are imported from tuntop.config.defaults above.

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
#: Resolution-fallback policy ('availability' | 'strict'). The helper
#: itself never queries the UDP/53+DoH fallback stack (that lives in the
#: dashboard's bypass resolver), but it carries the setting through the
#: control channel and any future self-heal resolver must honor it.
_ACTIVE_DNS_POLICY = "availability"
_ACTIVE_DOH_TEMPLATE = None
# ── DNS leak guard state ────────────────────────────────────────────────────
# While the tunnel is up, a catch-all NRPT rule pins the Windows DNS client
# to the resolvers above (see tuntop/network/dns_guard.py). On by default:
# without it Windows queries every adapter's resolver in parallel (Smart
# Multi-Homed Name Resolution) and a DHCP-assigned physical resolver answers
# first - the "the app's test says no leak but dnsleaktest.com shows my ISP"
# bug. `_ACTIVE_DNS_GUARD` mirrors --dns-guard/--no-dns-guard;
# `_ACTIVE_DNS_GUARD_EXEMPT` mirrors the repeatable --dns-guard-exempt.
_ACTIVE_DNS_GUARD = True
_ACTIVE_DNS_GUARD_EXEMPT = []
#: Last guard state reported, so the monitor's re-assert only logs changes.
_dns_guard_state = None

added_routes = RouteLedger("helper")
geoip_added = RouteLedger("geo")   # country-range bypass routes from --geoip (potentially thousands)

# ── Live-reconfiguration channel (dashboard -> running helper) ──────────────
# The dashboard owns the UI and this helper runs as its child process. For
# settings that must take effect WITHOUT a tunnel restart (DNS for now), the
# dashboard writes this tiny JSON file and the monitor loop (1 s tick) picks
# the change up, rebinds the _ACTIVE_DNS* globals and re-applies the Wintun
# config - so self-heal also keeps the NEW choice instead of reverting to the
# launch-time --dns4/--dns6 values. Cheap: the loop only stats the file until
# its mtime actually changes.
# Re-exported for tests and for callers that already import the helper's
# symbols wholesale. Unused inside this module, but part of its public
# surface - do not let an "unused import" sweep delete it.
from tuntop.network.dns_guard import NRPT_PS_ROOT as NRPT_PS_ROOT  # noqa: F401
from tuntop.config.defaults import VPN_IFACE_RE as VPN_IFACE_RE  # noqa: F401

CONTROL_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            ".tuntop_control.json")
_control_mtime = 0.0

#: Sentinel returned by _validated_dns for a present-but-invalid value, so
#: "invalid" and "cleared" (None) stay distinguishable.
_INVALID = object()


def _validated_dns(value, family):
    """Normalise a control-file DNS value: None when cleared, a validated
    address string, or _INVALID when present but not a usable address.

    Control-file values are written by another process. Without this check a
    truncated or malformed value reaches `netsh ... address=<garbage>` and the
    catch-all NRPT rule's GenericDNSServers - pinning ALL of Windows name
    resolution to a resolver that does not exist.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return _INVALID
    if addr.version != family:
        return _INVALID
    return str(addr)


def poll_control_file():
    """Apply dashboard-written live changes (DNS4/DNS6 and the [V]/[Y]
    transport-mode toggles). Returns True when a change was applied.
    Never raises - a malformed/partial write must not take the tunnel down."""
    global _ACTIVE_DNS4, _ACTIVE_DNS6, _control_mtime
    global _ACTIVE_DNS_POLICY
    try:
        mtime = os.path.getmtime(CONTROL_FILE)
    except OSError:
        return False
    if mtime == _control_mtime:
        return False
    # NOTE: _control_mtime is committed only AFTER a successful parse (below).
    # The dashboard writer truncates the file before dumping JSON, so the
    # 1 s monitor tick can read a zero-length/partial file. Consuming the
    # mtime first would mark that change as seen and never retry it - the
    # DNS the user just picked with [N] would be silently discarded for the
    # rest of the session.
    try:
        with open(CONTROL_FILE, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return False
    if not isinstance(data, dict):
        return False
    _control_mtime = mtime
    changed = []
    # Key-aware: the dashboard writes BOTH keys on every [N] change, so a
    # present-but-empty value means "clear this family" (e.g. the user picked
    # an IPv4-only DNS), not "leave it alone". A missing key = no change.
    if "dns4" in data:
        d4 = _validated_dns(data["dns4"], 4)
        if d4 is _INVALID:
            print("[!] Live DNS4 change ignored: not a valid IPv4 address.", flush=True)
        else:
            if d4 != _ACTIVE_DNS4:
                _ACTIVE_DNS4 = d4
                changed.append(f"DNS4 -> {d4 or '(cleared - IPv4 DNS unset)'}")
    if "dns6" in data:
        d6 = _validated_dns(data["dns6"], 6)
        if d6 is _INVALID:
            print("[!] Live DNS6 change ignored: not a valid IPv6 address.", flush=True)
        else:
            if d6 != _ACTIVE_DNS6:
                _ACTIVE_DNS6 = d6
                changed.append(f"DNS6 -> {d6 or '(cleared - IPv6 DNS unset)'}")
    if "dns_policy" in data:
        pol = str(data["dns_policy"] or "availability")
        if pol not in ("availability", "strict"):
            pol = "availability"
        if pol != _ACTIVE_DNS_POLICY:
            _ACTIVE_DNS_POLICY = pol
            changed.append(f"DNS policy -> {pol}")
    dns_changed = bool(changed)
    # [V]/[Y] mode toggles (same channel as the DNS): an absent key = no
    # change; a present bool = the mode the dashboard now runs. The helper
    # re-routes its own endpoint/VPN bypass routes LIVE (see _live_mode) so
    # the mode change takes effect without stopping/restarting the tunnel.
    _args = _live_mode.get("args")
    if "vless_over_vpn" in data:
        want = bool(data["vless_over_vpn"])
        if want != _live_mode["vless_over_vpn"]:
            ok, lines = _live_switch_vless(want)
            for ln in lines:
                print(ln, flush=True)
            if ok:
                _live_mode["vless_over_vpn"] = want
                if _args is not None:
                    _args.vless_over_vpn = want
                changed.append("VLESS transport -> "
                               + ("Windows VPN" if want
                                  else "physical adapter bypass"))
    if "no_vpn_bypass" in data:
        want = bool(data["no_vpn_bypass"])
        if want != _live_mode["no_vpn_bypass"]:
            ok, lines = _live_switch_vpn_bypass(want)
            for ln in lines:
                print(ln, flush=True)
            if ok:
                _live_mode["no_vpn_bypass"] = want
                if _args is not None:
                    _args.no_vpn_bypass = want
                changed.append("VPN endpoint bypass -> "
                               + ("removed (VPN traffic is tunneled)" if want
                                  else "installed (VPN endpoints stay direct)"))
    if "servers" in data:
        # Live [U] server change (the dashboard's _edit_servers). The
        # dashboard installs the new host routes itself, but the tracked
        # endpoint list (self-heal + gateway-change re-point) must be
        # reconciled HERE - the dashboard's routes are invisible to the
        # helper's ledger, and a later Wi-Fi change used to leave them
        # pinned to the dead gateway.
        _hosts = data["servers"]
        if isinstance(_hosts, list):
            _lines = _live_apply_servers(
                _hosts, data.get("server_endpoints") or {})
            for ln in _lines:
                print(ln, flush=True)
            changed.append("server list updated live ([U])")
    if data.get("vpn_endpoint_reapply"):
        # ONE-SHOT (the dashboard's _on_vpn_arrived writes this): a Windows
        # VPN connected AFTER this helper started. Startup only bypasses the
        # endpoints of VPNs ALREADY connected, so this VPN's server has no
        # /32 bypass - the Wintun split-defaults (0/1+128/1) then capture the
        # VPN's own control/data traffic and the VPN dies inside the tunnel
        # ("the VPN server traffic goes into the tuntop"). Re-run the enable
        # side of the [Y] toggle: resolve every CURRENTLY connected VPN's
        # ServerAddress and install /32+/128 bypasses via the physical
        # egress, then re-establish the sole-egress shadowing exactly as
        # startup would have. Idempotent (add_v4 keeps identical routes).
        # Gated on the same startup conditions: skipped when the user turned
        # the VPN bypass off ([Y]) or VLESS rides the VPN ([V]).
        if not _live_mode["no_vpn_bypass"] and not _live_mode["vless_over_vpn"]:
            lines = _live_apply_vpn_bypass_routes(True)
            if _live_set_vpn_shadow(True):
                lines.append("[*] VPN injected routes shadowed with Wintun "
                             "(sole egress) - as on startup.")
            for ln in lines:
                print(ln, flush=True)
            changed.append("VPN endpoint bypass re-applied "
                           "(VPN connected after tunnel start)")
    if not changed:
        return False
    print(f"[*] Live config change applied: {'; '.join(changed)}", flush=True)
    if dns_changed:
        try:
            configure_tun(_ACTIVE_DNS4, _ACTIVE_DNS6)
            # Re-pin the catch-all NRPT rule to the NEW resolver(s): leaving
            # the old pin in place would keep sending every query to the
            # previous server while wintun's adapter list says otherwise.
            _install_dns_guard()
        except Exception as e:
            print(f"[!] Live DNS re-apply failed: {e}", flush=True)
    return True


def _baseline_control_file():
    """Baseline the live-reconfig channel to the control file's CURRENT mtime.

    The monitor loop treats any mtime DIFFERENT from _control_mtime as a live
    change - and _control_mtime starts at 0.0, so a control file left over
    from a PREVIOUS session (e.g. a [N] DNS change from a run that has since
    exited) used to be applied to a fresh run, silently overriding the
    --dns4/--dns6 choices that run was launched with. Calling this at helper
    startup makes only writes made while THIS run is up count as live
    changes; a fresh run always starts with exactly the DNS its launch flags
    chose."""
    global _control_mtime
    try:
        _control_mtime = os.path.getmtime(CONTROL_FILE)
    except OSError:
        _control_mtime = 0.0

# When a connected Windows VPN injects its own default + /32 routes (often at a
# very low metric), those /32s are MORE specific than Wintun's /1 split routes
# and escape the tunnel - splitting traffic across the VPN (the "Chrome uses
# wifi + VPN + tun at the same time" bug). We neutralize that by shadowing every
# injected VPN route with an equivalent Wintun route at a lower effective metric
# (achieved by dropping Wintun's interface metric below the VPN's). The VPN link
# itself stays up because its server endpoint remains bypassed separately. The
# ledgers below track what to undo on cleanup (thread-safe, metric-faithful).
vpn_override_routes = RouteLedger("vpn-override")
# The VPN's own routes we shadowed, for restoration on [V] toggle-off and on
# exit. Guarded by _vpn_saved_lock, unlike its RouteLedger neighbour: this one
# is appended to by override_vpn_routes (the VPN-shadow pass, which a live
# [Y]/VPN-arrival can trigger) while cleanup() walks it in reverse and then
# clears it. CPython makes list.append atomic, so the append itself is safe -
# but `for ... in reversed(vpn_saved_routes): ...` followed by
# `vpn_saved_routes.clear()` is not: an append landing between the walk and the
# clear is restored (fine) but an append landing after `clear()` started
# iterating can be dropped mid-iteration, leaking a shadowed VPN route with no
# receipt. The same reasoning the RouteLedger types document for themselves.
_vpn_saved_lock = threading.Lock()
vpn_saved_routes = []        # original VPN routes we shadowed (for restoration)
# Wintun InterfaceMetric saved per family so cleanup() can restore the EXACT
# originals the user had before we lowered them to 2 (below VPN ~25 and the
# physical adapter's typical ~4270). Captured once on the first set and left
# alone on later re-sets (idempotent re-apply in self_heal / VPN-shadow path).
wintun_saved_metric = {"v4": None, "v6": None}
vpn_override_iface = None     # connected VPN interface we shadowed (set in main)
phys_bypass_metric_saved = None  # physical (geo) InterfaceMetric to restore on exit
phys_bypass_iface = None
tun_proc = None
tun2_proc = None   # second proxy pipe's tun2socks process (None = disabled)
cleaned = False

#: Set while cleanup() is running so a repeat Ctrl+C (the dashboard retries
#: the break, and a user mashing Ctrl+C does too) cannot re-enter the signal
#: handler and os._exit() out of a half-finished teardown.
_cleanup_in_progress = False

# NOTE: bulk geoip route removal (_remove_routes_bulk) deliberately shares the
# installer's tuning (GEO_SUB_BATCH / GEO_MAX_WORKERS) and its `netsh -f`
# fast path, so tearing down mirrors bringing up in speed.


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# Interface alias text pattern for Windows VPN tunnels is defined ONCE in
# tuntop.config.defaults (VPN_IFACE_RE) and imported above - it used to be
# re-hardcoded in seven places across three modules.


def _is_wintun_alias(alias):
    """True for ANY Wintun-driver adapter: ours ('wintun', 'wintun2') and
    foreign full-tunnel tools that share the driver naming (v2rayN/xray's
    'Wintun Tunnel'). Exact-match comparisons miss those foreign adapters."""
    return bool(alias) and str(alias).lower().startswith("wintun")


def _v4_default_filter(strict):
    """The real-IPv4-default-route Where-Object clause. Lives in
    tuntop.network.egress_scripts so the dashboard-side mirror emits
    byte-identical script text (see test_egress_scripts_drift)."""
    return _es.v4_default_filter_ps(strict)


def _tun_alias_powershell(var="$tunAliases"):
    """PowerShell preamble collecting EVERY Wintun-driver adapter name
    (ours AND foreign TUNs like v2rayN/xray's 'xray_tun'). Delegates to
    tuntop.network.egress_scripts - single source for both processes."""
    return _es.tun_alias_ps(var)


def _vpn_alias_powershell():
    """PowerShell preamble building $vpnAliases (connected Windows VPN
    interfaces, name-correlated via Get-VpnConnection plus the alias-text
    heuristic). Delegates to tuntop.network.egress_scripts."""
    return _es.vpn_alias_ps()


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
    ps = _es.ipv4_default_ps()
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
    VPN-endpoint or geoip bypasses.  The last-resort fallback is VPN-excluded
    too, not just TUN-excluded: relaxing only the VPN clause made the corporate
    adapter the first candidate on a box with no native IPv6 default, which is
    the hijack the primary block exists to prevent.

    On-link IPv6 routes (NextHop = '::') are ACCEPTED: they are the normal
    form of an IPv6 default route on most physical adapters (the next-hop is
    resolved via neighbor discovery, so there is no gateway address).  An
    on-link NextHop is normalized to '' so callers (add_v6, the geo installer)
    treat it as an on-link install with no gateway token.  add_v6 now ALSO
    normalizes on the way in, so a caller that passes a raw '::' cannot
    hand netsh an invalid next hop (the IPv4 half of this - '0.0.0.0' - is
    _norm_v4_gw/add_v4).

    Returns {"InterfaceAlias":..,"NextHop":..} or None.  IPv6 may legitimately
    be absent, so this must NOT sys.exit() the way get_ipv4_default() does.
    """
    ps = (
        _tun_alias_powershell() + _vpn_alias_powershell() + r"""
$r = Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue |
    Where-Object {
        $_.State -eq 'Alive' -and
        $tunAliases -notcontains $_.InterfaceAlias -and
        ($vpnAliases.Count -eq 0 -or -not ($vpnAliases -contains $_.InterfaceAlias))
    } |
    Sort-Object @{Expression={ [int]$_.RouteMetric + [int]$_.InterfaceMetric }} |
    Select-Object -First 1 NextHop, InterfaceAlias
if ($null -eq $r) {
    # Last resort only - and STILL VPN-excluded. The comment here used to
    # read "any non-wintun IPv6 default route (may be the VPN)", which is the
    # defect the dashboard mirror in tuntop/network/routing.py documents as
    # already fixed: on a box with a connected IKEv2/SSTP VPN and no native
    # IPv6 default, the first candidate IS the corporate adapter, and every
    # IPv6 /128 built from this gateway gets pinned onto the VPN - the
    # "Chrome uses wifi + VPN + tun at the same time" split this module exists
    # to prevent. The two copies had drifted; this one is now the live one
    # (the mirror's hardened block was unreachable behind a '//' comment
    # parse error), so the fix has to be HERE too.
    $r = Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue |
        Where-Object {
            $_.State -eq 'Alive' -and
            $tunAliases -notcontains $_.InterfaceAlias -and
            ($vpnAliases.Count -eq 0 -or -not ($vpnAliases -contains $_.InterfaceAlias))
        } |
        Sort-Object @{Expression={ [int]$_.RouteMetric + [int]$_.InterfaceMetric }} |
        Select-Object -First 1 NextHop, InterfaceAlias
}
if ($null -eq $r) { exit 1 }
$r | ConvertTo-Json -Compress
"""
    )
    d = ps_json(ps)
    # IPv6 on-link routes report NextHop '::' (unspecified address).  Normalize
    # to '' so downstream installers get an on-link route (no gateway token)
    # instead of passing '::' as a bogus next-hop.  Mirrors IPv4's '0.0.0.0' -> ''
    # normalization in _route_identity_present / _norm_gw.
    if d and str(d.get("NextHop", "")).strip() == "::":
        d["NextHop"] = ""
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
    # The WHOLE lookup script is single-sourced in egress_scripts
    # (egress_lookup_ps) - the dashboard mirror used to run a drifted copy
    # WITHOUT the VPN exclusion and pinned server bypasses onto a connected
    # Windows VPN (see egress_scripts.egress_lookup_ps for the history).
    d = ps_json(_es.egress_lookup_ps(ip, exclude_vpn=exclude_vpn), timeout=10)
    if not d:
        return None
    iface = str(d.get("InterfaceAlias", ""))
    gw = str(d.get("NextHop", "") or "")
    if not iface:
        return None
    # Fail-closed at the Python twin too (1.0.33): the PS $tunAliases filter
    # already excludes every tunnel-family adapter, but if the adapter
    # enumeration hiccupped the resolver could hand back OUR tunnel (or,
    # with exclude_vpn, a VPN) as the "physical" egress - pinning a bypass
    # route onto the tunnel loops the transport (the "the server IP goes to
    # the wintun" report). Refusing here makes every caller fall back to
    # the last-known-good physical egress instead of installing a loop.
    if _es.is_tun_iface(iface):
        return None
    if exclude_vpn and _es.is_vpn_iface(iface):
        return None
    return iface, (gw or "0.0.0.0")


def physical_egress(fallback=None):
    """The best available PHYSICAL (non-VPN, non-TUN) IPv4 egress, or None.

    `fallback` (normally `_live_mode['phys']`) is a cached value, and a
    cache is only as good as its validation. get_ipv4_default()'s LAST-RESORT
    clause deliberately returns "any non-wintun 0.0.0.0/0 route, may be the
    VPN" - correct when all you need is *some* egress, but poison for a value
    labelled "physical": every bypass route built from it (VPN endpoint /32s,
    LAN bypasses, geo) would be pinned ONTO the VPN, i.e. the VPN's own
    server reached through the VPN - a self-referential route that starves
    the very transport it is meant to protect.

    So the cached value is validated here, on every use, and anything that is
    not a physical adapter is rejected. `fallback` is returned only after it
    passes; None means "caller must handle it".
    """
    cand = fallback if fallback else _live_mode.get("phys")
    if not cand or not cand[0]:
        return None
    iface, gw = str(cand[0]), str(cand[1] or "")
    if _es.is_tun_iface(iface) or _es.is_vpn_iface(iface):
        return None
    if _wrong_family_gw(gw, 4):
        return None
    return (iface, _norm_v4_gw(gw))


def _direct_bypass_egress(ip, fallback=None):
    """Egress for a route that must NOT ride any tunnel or VPN: the proxy
    (VLESS) server's own /32, a user-added bypass, or - the case this exists
    for - a connected Windows VPN's server address.

    Order: the real per-IP egress (respects split-tunnel VPNs) with VPN
    excluded, then the validated physical egress, then nothing. The result is
    re-validated, so neither a poisoned cache nor a resolver quirk can
    produce a self-referential route. Returns None rather than a bad answer:
    the caller reports it and leaves the route out, which is a visible,
    recoverable state - much better than silently looping the transport.
    """
    eg = get_egress_for(ip, exclude_vpn=True)
    if eg and eg[0]:
        iface, gw = str(eg[0]), _norm_v4_gw(eg[1])
        if (not _es.is_tun_iface(iface) and not _es.is_vpn_iface(iface)
                and not _wrong_family_gw(gw, 4)):
            return (iface, gw)
    return physical_egress(fallback)


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
if ($null -eq $r) {{
    # No default route on the adapter (split-tunnel / on-link-only VPN):
    # fall back to the most-specific Alive route it DOES have.
    $r = Get-NetRoute -AddressFamily IPv4 -InterfaceAlias '{ps_quote(vpn_interface)}' -ErrorAction SilentlyContinue |
        Where-Object {{ $_.State -eq 'Alive' }} |
        Sort-Object -Property @{{Expression={{ ($_.DestinationPrefix -split '/')[1] -as [int] }}; Descending=$true}},
            RouteMetric, InterfaceMetric |
        Select-Object -First 1 NextHop, InterfaceAlias, InterfaceIndex
}}
if ($null -eq $r) {{ exit 1 }}
$r | ConvertTo-Json -Compress
""")
        if not d:
            return None
        return d["InterfaceAlias"], d["NextHop"], int(d["InterfaceIndex"])

    ps = (_tun_alias_powershell() + r"""
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
            $_.State -eq 'Alive' -and $tunAliases -notcontains $_.InterfaceAlias -and
            $_.InterfaceAlias -match __VPN_RE__
        } |
        Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
}
if ($null -eq $best) {
    # Split-tunnel / on-link-only VPNs: a connected VPN client whose adapter
    # installs NO 0.0.0.0/0 (e.g. only a /32 on-link or a small split list).
    # Match the CONNECTED Get-VpnConnection names against ANY Alive IPv4
    # route (most-specific first) instead of requiring a default route.
    foreach ($n in $names) {
        $r = Get-NetRoute -AddressFamily IPv4 -InterfaceAlias $n -ErrorAction SilentlyContinue |
            Where-Object { $_.State -eq 'Alive' } |
            Sort-Object -Property @{Expression={ ($_.DestinationPrefix -split '/')[1] -as [int] }; Descending=$true},
                RouteMetric, InterfaceMetric | Select-Object -First 1
        if ($r) { $best = $r; break }
    }
}
if ($null -eq $best) {
    # Third-party VPN clients Get-VpnConnection does not expose at all
    # (e.g. "VPN Client Adapter - VPN"): scan VPN-pattern interface aliases
    # for ANY Alive IPv4 route, not just a default route.
    $best = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.State -eq 'Alive' -and $tunAliases -notcontains $_.InterfaceAlias -and
            $_.InterfaceAlias -match __VPN_RE__
        } |
        Sort-Object -Property @{Expression={ ($_.DestinationPrefix -split '/')[1] -as [int] }; Descending=$true},
            RouteMetric, InterfaceMetric | Select-Object -First 1
}
if ($null -eq $best) { exit 1 }
$best | Select-Object NextHop, InterfaceAlias, InterfaceIndex | ConvertTo-Json -Compress
""").replace("__VPN_RE__", _es.VPN_ALIAS_PS_RE)
    d = ps_json(ps)
    if not d:
        return None
    return d["InterfaceAlias"], d["NextHop"], int(d["InterfaceIndex"])


def get_vpn_ipv6_default(vpn_interface=None):
    """IPv6 counterpart of get_vpn_ipv4_default. Most Windows VPN profiles
    (PPTP in particular) are IPv4-only, so returning None here is normal
    and expected, not an error.

    On-link IPv6 routes (NextHop = '::') are accepted and normalized to ''
    so the caller installs them as on-link routes - the same treatment
    get_ipv6_default() gives the physical IPv6 default."""
    if vpn_interface:
        d = ps_json(rf"""
$r = Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -InterfaceAlias '{ps_quote(vpn_interface)}' -ErrorAction SilentlyContinue |
    Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1 NextHop, InterfaceAlias
if ($null -eq $r) {{ exit 1 }}
$r | ConvertTo-Json -Compress
""")
        if d and str(d.get("NextHop", "")).strip() == "::":
            d["NextHop"] = ""
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
    if d and str(d.get("NextHop", "")).strip() == "::":
        d["NextHop"] = ""
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


def get_foreign_tun_adapters():
    """Tunnel adapters that are NOT ours (e.g. v2rayN/xray in TUN mode creates
    'Wintun Tunnel'; sing-box, Clash/Mihomo, WireGuard, Tailscale, OpenVPN
    create their own). Returns [(alias, default_route)] - a non-empty result
    means a competing full-tunnel program owns a default route too, so only the
    lowest-metric tunnel actually carries traffic. Read-only: we never touch
    another program's adapter.

    Uses the SHARED TUN_DRIVER_RE, not a hardcoded 'Wintun'. This one script
    still filtered on `-match 'Wintun'` while every other classifier in the
    project (_es.tun_alias_ps, is_tun_iface, the geo sweeper, the foreign-route
    check) had moved to the shared pattern - so it missed every competing TUN
    that is not built on the Wintun driver, and `reject_competing_tun` let
    start proceed. That is the exact "Throne's sing-tun Tunnel owned 176.0.0.0/4
    and the dashboard never saw it" class of bug the shared pattern was
    introduced to close. The IfType/PhysicalMediaType terms are carried over
    from the shared preamble so a driver we have never heard of is still
    caught by its Windows-reported characteristics.
    """
    ps = (
        "$names = @('" + ps_quote(TUN) + "','" + ps_quote(TUN2) + "')\n"
        "$ours = Get-NetAdapter -ErrorAction SilentlyContinue |\n"
        "    Where-Object { ($_.InterfaceDescription -match '"
        + _es.TUN_DRIVER_RE + "') -or ($_.Name -match '"
        + _es.TUN_DRIVER_RE + "') -or ($_.InterfaceType -eq 131) -or "
        "($_.PhysicalMediaType -eq 'Tunnel') } |\n"
        "    Where-Object { $names -notcontains $_.Name } |\n"
        "    Select-Object -ExpandProperty Name\n"
        "$out = @()\n"
        "foreach ($n in $ours) {\n"
        "    $d = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -InterfaceAlias $n -ErrorAction SilentlyContinue |\n"
        "        Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1\n"
        "    if ($d) {\n"
        "        $out += [PSCustomObject]@{ Alias = $n; Default = 'yes' }\n"
        "    } else {\n"
        "        $out += [PSCustomObject]@{ Alias = $n; Default = 'no' }\n"
        "    }\n"
        "}\n"
        "ConvertTo-Json -InputObject @($out) -Compress\n"
    )
    d = ps_json(ps)
    if not d:
        return []
    records = d if isinstance(d, list) else [d]
    return [(str(x.get("Alias", "")), str(x.get("Default", "")))
            for x in records if x.get("Alias")]


def reject_competing_tun():
    """Refuse to start when another Wintun TUN program owns a default route
    (v2rayN/xray/sing-box TUN mode): whichever adapter owns the lowest-metric
    0.0.0.0/0 silently steals all traffic. The old soft warning let the operator
    burn hours debugging an empty "RUNNING" tunnel (the "the server IP goes to
    the wintun" report: the moment a server /32 bypass drops, the transport
    falls into the foreign TUN and loops back into this one - and because the
    foreign adapter survives THIS program's cleanup it keeps breaking even
    after closing and reopening). A foreign TUN without a default route cannot
    capture anything and is left untouched (just noted)."""
    _foreign = get_foreign_tun_adapters()
    _blocked = [a for a, _d in _foreign if _d == "yes"]
    if _blocked:
        sys.exit(
            "[!] TUN CONFLICT: another program's TUN adapter already owns the "
            f"IPv4 default route: {', '.join(_blocked)} (e.g. v2rayN/xray TUN "
            "mode). It would steal the VLESS server bypass and route the proxy "
            "transport back into its own tunnel - TunTop refuses to start into "
            "a broken routing state. Turn the other app's TUN mode OFF (keep "
            "only its SOCKS proxy, e.g. 127.0.0.1:10808), then start again.")
    for _fx_alias, _fx_def in _foreign:
        if _fx_def != "yes":
            print(f"[*] Foreign Wintun adapter '{_fx_alias}' present (no "
                  "default route) - left untouched.")


def remove_stale_wintun_devices():
    """Remove ORPHANED Wintun PnP device nodes (status != OK).

    `Remove-NetAdapter` above only clears the NETWORK ADAPTER. After a hard
    kill the device node itself survives in the device tree as
    `SWD\\WINTUN\\{GUID}` with status Unknown, and the Wintun driver then
    enumerates that stale node instead of creating a fresh adapter - the new
    tun2socks finds no interface, exits, and the dashboard restarts it, which
    is a restart loop that never converges. This is the observed state after
    one crashed session (Get-PnpDevice -Class Net shows
    'tun2socks Tunnel' / SWD\\WINTUN\\{...} / Unknown while Get-NetAdapter
    lists no wintun at all).

    Only nodes that are NOT status OK are touched, so a foreign Wintun
    adapter that is actually running (v2rayN/xray TUN mode) keeps its device.
    Best-effort: a machine that refuses the removal just keeps the old
    behaviour."""
    try:
        _, out, _ = run_ps(
            "$stale = Get-PnpDevice -Class Net -ErrorAction SilentlyContinue | "
            "Where-Object { $_.InstanceId -like 'SWD\\WINTUN\\*' -and "
            "$_.Status -ne 'OK' }; "
            "$n = @($stale).Count; "
            "if ($n -gt 0) { $stale | ForEach-Object { "
            "Remove-PnpDevice -InstanceId $_.InstanceId -Confirm:$false "
            "-ErrorAction SilentlyContinue } }; "
            "Write-Output $n")
    except Exception:
        return 0
    n = 0
    for tok in str(out or "").split():
        if tok.isdigit():
            n = int(tok)
            break
    if n:
        print(f"[*] Removed {n} orphaned Wintun device node(s) from a "
              "previous run - tun2socks can create its adapter again.")
    return n


def preflight_cleanup(tun2socks_path=None):
    """Clear state left behind by a run that didn't exit cleanly (window
    closed forcibly, process killed, previous crash). Leftover Wintun
    routes or an orphaned tun2socks are the main reason a *later* run can
    fail to configure routes, look like it dropped the VPN, or crash on
    startup. Also drop the Wintun adapter itself so tun2socks recreates it
    fresh (a stale adapter can make tun2socks fail to bind), and any
    ORPHANED Wintun PnP device node (see remove_stale_wintun_devices).

    tun2socks_path: the --tun2socks path this run is about to use. Orphan
    kills are OWNERSHIP-SCOPED (vendored binary name or exactly this path),
    so a tun2socks.exe another tool is running is never terminated."""
    print("[*] Checking for leftover state from a previous run...")
    # Both pipes: the primary 'wintun' and (when a previous run used
    # --proxy2-port) the secondary 'wintun2'. Removing state for an adapter
    # that doesn't exist is a harmless no-op.
    run_ps(f"Get-NetRoute -InterfaceAlias '{TUN}' -ErrorAction SilentlyContinue | "
           "Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue")
    run_ps(f"Get-NetRoute -InterfaceAlias '{TUN2}' -ErrorAction SilentlyContinue | "
           "Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue")

    _, out, _ = run_ps(
        "Get-CimInstance Win32_Process "
        "-Filter \"Name LIKE 'tun2socks%'\" -ErrorAction SilentlyContinue | "
        "Where-Object { ($_.ExecutablePath -and "
        "($_.ExecutablePath -like '*tun2socks-windows-amd64-v3.exe')) -or "
        f"($_.ExecutablePath -eq '{ps_quote(tun2socks_path or '')}') }} | "
        "Select-Object -ExpandProperty ProcessId")
    pids = [p for p in out.split() if p.strip().isdigit()]
    if pids:
        print(f"[*] Stopping leftover TunTop tun2socks process(es): "
              f"{', '.join(pids)}")
        for pid in pids:
            run(["taskkill", "/F", "/T", "/PID", pid])
        time.sleep(1)

    run_ps(f"Remove-NetAdapter -Name '{TUN}' -Force -Confirm:$false -ErrorAction SilentlyContinue")
    run_ps(f"Remove-NetAdapter -Name '{TUN2}' -Force -Confirm:$false -ErrorAction SilentlyContinue")
    # The network adapter is gone; its DEVICE node may not be. This must run
    # after Remove-NetAdapter, or a still-present adapter would make every
    # node look legitimately OK.
    remove_stale_wintun_devices()
    time.sleep(1)


def resolve_all(server):
    try:
        ip = ipaddress.ip_address(server)
        if ip.version == 4:
            print(f"[*] {server} is an IP literal (no DNS query needed)")
            return ([str(ip)], [])
        return ([], [str(ip)])
    except ValueError:
        pass

    print(f"[*] Resolving {server} ...", flush=True)
    try:
        infos = socket.getaddrinfo(server, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        print(f"[!] DNS resolution failed for {server}: {e}", flush=True)
        sys.exit(f"[!] Could not resolve {server}: {e}")

    v4, v6 = [], []
    for fam, _, _, _, sa in infos:
        if fam == socket.AF_INET and sa[0] not in v4:
            v4.append(sa[0])
        elif fam == socket.AF_INET6 and sa[0] not in v6:
            v6.append(sa[0])

    if not v4 and not v6:
        print(f"[!] {server} resolved to no usable addresses.", flush=True)
        sys.exit(f"[!] {server} resolved to no usable addresses.")
    print(f"[*] {server} -> IPv4: {', '.join(v4) if v4 else '(none)'}  "
          f"IPv6: {', '.join(v6) if v6 else '(none)'}", flush=True)
    return v4, v6


def _host_from_url(url):
    """Deprecated alias - the implementation now lives in ONE place.

    This was a second, weaker copy of tuntop.network.dns._host_from_url, and
    the two had already drifted. The helper's copy used `split("@", 1)[-1]`
    where the shared one uses `rsplit("@", 1)[1]`, so a credential containing
    an '@' turned "user:p@ss@host.com" into "ss@host.com"; it also kept the
    :port and the IPv6 brackets, so "example.com:443" reached
    socket.getaddrinfo intact and "[2001:db8::1]:8443" was never unwrapped.
    Both copies resolved the same addresses for well-formed input, which is
    exactly why the drift survived: the bug class is invisible until someone
    pastes a URL with an '@' in the password.

    The real function is imported at the top of this module. This alias stays
    so any existing `helper._host_from_url` caller keeps working.
    """
    return _shared_host_from_url(url)


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


from tuntop.geo.geoip import parse_geoip  # noqa: E402


def test_local_socks(port, timeout=1.5):
    """Is the LOCAL SOCKS5 inbound answering on 127.0.0.1:port?

    `timeout` is a parameter because this is called from two very different
    places: the startup gate (a slow, generous connect is fine - we are about
    to fail the whole run) and the 1 Hz monitor loop (where a blocking connect
    would stall tunnel health, gateway and endpoint healing alike). The
    monitor passes a short timeout so a closed port costs milliseconds."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def wait_for_tun(timeout=15, name=None):
    name = name or TUN
    ps = (
        f"Get-NetAdapter -Name '{ps_quote(name)}' -ErrorAction SilentlyContinue | "
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
    # IPv6 resolvers too: without a v6 DoH mapping, DoH mode still leaves the
    # v6 resolver on raw UDP/53 - and on SOCKS setups whose UDP relay is
    # broken ("client handshake: EOF"), every v6 DNS query dies in the TUN.
    "2606:4700:4700::1111": "https://cloudflare-dns.com/dns-query",
    "2606:4700:4700::1001": "https://cloudflare-dns.com/dns-query",
    "2001:4860:4860::8888": "https://dns.google/dns-query",
    "2001:4860:4860::8844": "https://dns.google/dns-query",
    "2620:fe::fe": "https://dns.quad9.net/dns-query",
}


def _doh_template_for(ip, override=None):
    if override:
        return override
    return _DOH_TEMPLATES.get(ip)


def _set_wintun_addresses_plain(dns4, dns6, device=None, ip4=None, ip6=None,
                                 set_dns=True):
    """Assign the Wintun IPv4/IPv6 addresses and set the DNS servers the plain
    (UDP/53) way. Shared by configure_tun() and the DoH path (which layers DoH
    on top of the addresses). A dns4/dns6 of None means "no DNS for that
    family" - the stale static entry is removed instead of re-adding a
    hardcoded default.

    `device`/`ip4`/`ip6` default to the PRIMARY pipe's adapter; the second
    proxy pipe (TUN2) passes its own. `set_dns=False` assigns addresses only -
    a secondary pipe must never steal DNS resolution from the primary."""
    device = device or TUN
    ip4 = ip4 or TUN4
    ip6 = ip6 or TUN6
    run([
        "netsh", "interface", "ipv4", "set", "address",
        f"name={device}", "source=static", f"addr={ip4}", f"mask={TUN4_MASK}"
    ], check=True)
    if set_dns:
        if dns4:
            run([
                "netsh", "interface", "ipv4", "set", "dnsservers",
                f"name={device}", "source=static", f"address={dns4}",
                "register=none", "validate=no"
            ])
        else:
            # dns4=None means "no IPv4 DNS by choice": remove any stale
            # static entries so the adapter never keeps an old resolver.
            run(["netsh", "interface", "ipv4", "delete", "dnsservers",
                 f"name={device}"])
    # "set", not "add". `netsh interface ipv6 add address` APPENDS, and
    # configure_tun() runs again on every self-heal pass and after every
    # [N] DNS change - so a Windows build that does not dedupe a repeated
    # address accumulated a duplicate fd00:dead:beef::1/64 on the adapter
    # each time. The address list then holds several copies with
    # different lifetimes, and ::/0 + ::/1 + 8000::/1 can resolve against a
    # stale one after a re-point. `set` REPLACES, which is what the IPv4
    # line above already did, so the two families now behave the same.
    # _ensure_wintun_address is the idempotent reader used before an add.
    run([
        "netsh", "interface", "ipv6", "set", "address",
        f"name={device}", f"address={ip6}/64"
    ], check=True)
    if set_dns:
        if dns6:
            run([
                "netsh", "interface", "ipv6", "add", "dnsserver",
                device, dns6, "index=1"
            ])
        else:
            # Same as above for the IPv6 stack (e.g. a v4-only DNS choice).
            run(["netsh", "interface", "ipv6", "delete", "dnsservers",
                 f"name={device}"])


def _register_doh_server(ip, template):
    """Register/refresh ONE DoH mapping (Add-/Set-DnsClientDohServer). Does
    NOT touch the adapter's ServerAddresses list - that is done separately by
    _set_wintun_dns_servers, so DNS4 and DNS6 can both be registered without
    the second call wiping the first (Set-DnsClientServerAddress REPLACES the
    whole list, which is exactly what the old two-step enable did).

    VERIFY THE RESULT, do not trust the cmdlets. Both calls carry
    -ErrorAction SilentlyContinue, which makes the ordinary failures
    NON-TERMINATING: DoH absent from this Windows build, the server not in
    the list, access denied, a rejected template. Nothing is thrown, execution
    falls straight through to `Write-Output 'DOH_OK'`, and the catch block
    could only ever fire on a parse or parameter-binding error. So the function
    reported success for a registration that never happened - the caller put
    the resolver into the `registered` state, printed "Wintun DNS set to DoH",
    and pointed the adapter at it, while resolution was still raw UDP/53 into
    a TUN whose SOCKS proxy has no UDP relay: every name lookup timed out and
    the log claimed DoH was active. The `failed` list was therefore always
    empty and the "DoH registration FAILED" warning could never print.
    (_set_wintun_dns_servers right below already uses -ErrorAction Stop for
    exactly this reason - this call was the outlier.)

    So: attempt, then ASK the OS whether the server is actually registered."""
    if not ip or not template:
        return False
    ps = (
        "$ip='" + ps_quote(ip) + "'; $tpl='" + ps_quote(template) + "'; "
        "try { "
        "Add-DnsClientDohServer -ServerAddress $ip -DohTemplate $tpl "
        "-AllowFallbackToUdp $false -ErrorAction SilentlyContinue; "
        "Set-DnsClientDohServer -ServerAddress $ip -DohTemplate $tpl "
        "-AllowFallbackToUdp $false -ErrorAction SilentlyContinue; "
        # Ground truth, not the suppressed exit status of the two calls above.
        "$n = @(Get-DnsClientDohServer -ErrorAction SilentlyContinue | "
        "Where-Object { $_.ServerAddress -eq $ip }).Count; "
        "if ($n -gt 0) { Write-Output 'DOH_OK' } "
        "else { Write-Output ('DOH_FAIL:not registered: ' + $ip) } "
        "} catch { Write-Output ('DOH_FAIL:' + $_.Exception.Message) }"
    )
    _, out, _ = run_ps(ps)
    return "DOH_OK" in out


def _set_wintun_dns_servers(servers):
    """Point the wintun adapter at the FULL DNS server list in one cmdlet
    (plus a resolver-cache flush, so the very next lookup uses the new
    servers instead of the stale/failing ones)."""
    addrs = ",".join("'" + ps_quote(s) + "'" for s in (servers or []) if s)
    if not addrs:
        return False
    ps = (
        "try { "
        f"Set-DnsClientServerAddress -InterfaceAlias '{TUN}' "
        f"-ServerAddresses @({addrs}) -ErrorAction Stop; "
        "Clear-DnsClientCache -ErrorAction SilentlyContinue; "
        "ipconfig /flushdns | Out-Null; "
        "Write-Output 'DNS_SET' "
        "} catch { Write-Output ('DNS_FAIL:' + $_.Exception.Message) }"
    )
    _, out, _ = run_ps(ps)
    return "DNS_SET" in out


def _enable_doh_on_wintun(ip, template):
    """Best-effort: register + enable DNS-over-HTTPS for `ip` on wintun so DNS
    rides over TCP/443 (which proxies reliably) instead of raw UDP/53 (which
    many SOCKS/VLESS setups do not relay). Sets the adapter's DNS list to
    exactly [ip]. Returns True if the cmdlets reported success. Failures are
    non-fatal - caller falls back to plain UDP DNS."""
    if not ip or not template:
        return False
    if not _register_doh_server(ip, template):
        return False
    return _set_wintun_dns_servers([ip])


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


#: LAN bypass prefixes the helper installs EVERY run (and the gateway-change
#: re-point re-installs). Supernet prefixes Windows never creates on its own,
#: so a route for one of these via a real gateway is always OURS.
# LAN bypass prefixes: imported from tuntop.config.defaults (LAN_BYPASS_PREFIXES)
# - the single copy shared with the dashboard's sweep and the watchdog.
_LAN_BYPASS_RANGES = LAN_BYPASS_PREFIXES


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
    print(f"[*] Installing LAN-bypass routes via {iface} ({gateway}) so local "
          f"traffic stays off the tunnel...")
    for r in _LAN_BYPASS_RANGES:
        if not add_v4(r, iface, gateway, metric=10):
            print(f"[!] Could not install LAN-bypass route {r}; continuing.")


def configure_tun(dns4=None, dns6=None):
    """Apply the Wintun address/DNS configuration. A dns4/dns6 of None means
    "the user did not choose a DNS server for that family": that family's DNS
    is left unset (and any stale entry removed), NOT silently replaced with
    the hardcoded DNS4/DNS6 defaults - the old `dns6 = dns6 or DNS6` fallback
    made a v4-only DNS choice impossible.

    Returns True when the adapter's resolver is now DoH over TCP/443, False
    otherwise (plain/auto mode, or a DoH registration that did not take).
    Only the start sequence's DoH escalation uses that answer, to avoid
    re-probing a resolver it has just proved cannot be reached."""
    mode = _ACTIVE_DNS_MODE

    # Whether the RESOLVER actually ended up on DoH. Initialised ONCE, here,
    # because the three modes are not all covered below: "plain" matches
    # neither `mode == "doh"` nor `mode == "auto"`, so with the assignment
    # living inside the branches the final `return applied` raised
    # UnboundLocalError - i.e. `--dns-mode plain`, a documented and supported
    # choice, crashed the helper at tunnel bring-up (and again in
    # self_heal_tunnel), not just in the DoH path that guards its call.
    applied = False

    _set_wintun_addresses_plain(dns4, dns6)

    # Kill NBNS broadcasts leaving the TUN (a major source of the proxy-port
    # exhaustion spam).  Best-effort; report but never fail the setup on it.
    if _disable_netbios_on_wintun():
        print("[*] NetBIOS-over-TCP/IP disabled on wintun (stops UDP/137 flood).")
    else:
        print("[*] NetBIOS disable on wintun skipped/unavailable (non-fatal).")

    if mode == "doh":
        # BUG FIX (1.0.40): this block used to be gated on `dns4 and
        # template`, so a v6-ONLY DNS choice (--dns6 <ip> alone, the supported
        # "IPv6 DNS only" selection) never registered DoH for anything and
        # silently stayed on raw UDP/53 - which is exactly the path that dies
        # inside a TUN whose SOCKS proxy has no UDP relay. Register EVERY
        # family the user chose that has a known template, then set the
        # adapter's server list once (Set-DnsClientServerAddress REPLACES the
        # whole list, so the two registrations must be followed by ONE set).
        registered = []
        failed = []
        t4 = _ACTIVE_DOH_TEMPLATE or _doh_template_for(dns4)
        if dns4:
            if t4 and _register_doh_server(dns4, t4):
                registered.append((dns4, t4))
            else:
                failed.append(dns4)
        t6 = _ACTIVE_DOH_TEMPLATE or _doh_template_for(dns6)
        if dns6:
            if t6 and _register_doh_server(dns6, t6):
                registered.append((dns6, t6))
            else:
                failed.append(dns6)
        chosen = [s for s in (dns4, dns6) if s]
        if registered and _set_wintun_dns_servers(chosen):
            applied = True
            for ip, tmpl in registered:
                print(f"[*] Wintun DNS set to DoH: {ip} -> {tmpl} (TCP/443)")
        elif chosen:
            print("[!] DoH enable failed for %s; falling back "
                  "to plain UDP DNS (the addresses set above stay as-is)."
                  % ", ".join(chosen))
        # Per-family failures are reported separately: the success line above
        # only names the families that DID register, so without this a v4
        # registration that failed next to a v6 one that succeeded was
        # silently downgraded to raw UDP/53 - the exact path that dies inside
        # a TUN whose SOCKS proxy has no UDP relay.
        if failed:
            print(f"[!] DoH registration FAILED for {', '.join(failed)} - "
                  f"those resolver(s) stay on raw UDP/53 and may fail to "
                  f"resolve through the tunnel.", flush=True)
    # mode == "auto": start plain; the monitor/verify loop escalates to DoH if
    # plain DNS through the TUN proves unreliable. mode == "plain": the user
    # pinned it. Both leave `applied` False, which is what the return means -
    # "the resolver is not on DoH", the only question the caller asks.

    # Prefer Wintun for DNS at the OS level: lower the Wintun adapter's
    # InterfaceMetric below the physical adapter's so Windows selects Wintun
    # (not a DHCP-assigned physical-NIC resolver such as 192.168.1.1) when
    # building the DNS server selection order for the configured public
    # resolvers. The split-defaults (0.0.0.0/1, ::/1) already pull the public
    # resolvers through the TUN; this metric step closes the on-link gap where
    # a physical adapter's *local* resolver would otherwise win. Targets 2, the
    # same value the Windows-VPN shadow path uses, so regular and VPN paths
    # converge on identical precedence. Re-applied by wait_for_tunnel_stable's
    # DoH re-call and by self_heal_tunnel() (both go through configure_tun()).
    _set_wintun_interface_metric(2)

    # Whether the RESOLVER actually changed to DoH. Only meaningful in doh
    # mode, and only the caller that is about to re-probe needs it: when
    # nothing registered, the adapter still carries the same plain UDP/53
    # resolver that just failed to resolve through the tunnel, so a re-probe
    # costs a full round and returns the identical getaddrinfo failure. That
    # is start latency spent on a foregone conclusion.
    return applied


# ── DNS leak guard (catch-all NRPT rule) ────────────────────────────────────
# Keeps the Windows DNS client from querying a physical adapter's resolver in
# parallel with the tunnel's (Smart Multi-Homed Name Resolution) - the real
# "dnsleaktest.com shows my ISP while TunTop's own test says no leak" bug.
# Installed once the TUN routes are live (see main), re-asserted by
# self_heal_tunnel / the monitor loop / a live [N] DNS change, and removed by
# EVERY teardown path (cleanup() here; plus the watchdog, startup recovery and
# the dashboard's stop/quit sweeps for hard kills).
# See tuntop/network/dns_guard.py.

def _dns_guard_exempt():
    """Namespaces Windows must keep resolving while the guard is up: the
    always-on mDNS (.local) exemption plus the user's --dns-guard-exempt
    entries (a home/corporate domain only a LAN resolver can answer)."""
    out = []
    for name in (list(_dns_guard.DEFAULT_EXEMPT_NAMESPACES)
                 + list(_ACTIVE_DNS_GUARD_EXEMPT or [])):
        n = str(name).strip().lower()
        if n and n not in out:
            out.append(n)
    return out


def _dns_guard_report(ok, msg, verbose):
    """Print the guard's state, but only when it CHANGED (the monitor
    re-assert calls this on every healthy cycle)."""
    global _dns_guard_state
    state = "on" if ok else "failed"
    if verbose or state != _dns_guard_state:
        if ok:
            print(f"[*] DNS leak guard: Windows DNS pinned to {msg} - the "
                  "catch-all NRPT rule stops Windows querying a physical "
                  "adapter's resolver in parallel.", flush=True)
        else:
            print(f"[!] DNS leak guard NOT active: {msg} - Windows may still "
                  "ask a physical adapter's resolver in parallel (a real "
                  "leak).", flush=True)
    _dns_guard_state = state


def _install_dns_guard(verbose=True):
    """Install/refresh the catch-all NRPT rule pinning DNS to the tunnel
    resolvers. Returns True when the guard is in place.

    Never fatal by design: refusing to bring the tunnel up because a registry
    write was blocked would be worse than the leak - the failure is reported
    loudly instead (and the dashboard's DNS-leak-protection row keeps saying
    so).

    NOTE: `global _dns_guard_state` is REQUIRED and was missing. The function
    ASSIGNS that name (the "off"/"none" bookkeeping below), so Python compiled
    it as a function-local throughout - and the READ in the --no-dns-guard
    branch therefore raised `UnboundLocalError: cannot access local variable
    '_dns_guard_state'`. That propagated out of self_heal_tunnel's call to this
    function, aborting the REST of the self-heal (every Wintun address, the
    default/split routes, the IPv6 stack and the LAN bypass re-apply), so a
    cosmetic state-bookkeeping bug silently disabled self-healing entirely and
    the tunnel escalated to a helper restart instead."""
    global _dns_guard_state
    if not _ACTIVE_DNS_GUARD:
        # Disabled (--no-dns-guard, or turned off live): make sure a previous
        # run's rule cannot keep hijacking name resolution.
        try:
            ok, msg = _dns_guard.ensure_removed()
        except Exception as e:
            ok, msg = False, str(e)
        if verbose or _dns_guard_state != "off":
            if ok:
                print("[*] DNS leak guard: disabled (--no-dns-guard) - Windows "
                      "may query a physical adapter's resolver in parallel.",
                      flush=True)
            else:
                print(f"[!] DNS leak guard: could not remove the previous rule:"
                      f" {msg}", flush=True)
        _dns_guard_state = "off"
        return False
    resolvers = _dns_guard.guard_resolvers(_ACTIVE_DNS4, _ACTIVE_DNS6)
    if not resolvers:
        # No resolver to pin: a rule with an empty server list would black
        # hole resolution, so keep DNS unguarded and say so.
        try:
            _dns_guard.ensure_removed()
        except Exception:
            pass
        if verbose or _dns_guard_state not in ("none", "off"):
            print("[i] DNS leak guard: skipped - no DNS resolver is "
                  "configured for the Wintun adapter.", flush=True)
        _dns_guard_state = "none"
        return False
    try:
        ok, msg = _dns_guard.ensure_installed(_ACTIVE_DNS4, _ACTIVE_DNS6,
                                              _dns_guard_exempt())
    except Exception as e:
        ok, msg = False, str(e)
    _dns_guard_report(bool(ok), msg, verbose)
    return bool(ok)


def _dns_guard_reassert():
    """Cheap periodic check for the monitor loop: the catch-all rule can be
    wiped mid-session (a VPN client's own NRPT rule, a Group Policy refresh,
    another tool's cleanup) and the leak silently comes back. Only shells out
    for the fix when the guard is actually missing."""
    if not _ACTIVE_DNS_GUARD:
        return
    try:
        ok, state = _dns_guard.detect()
    except Exception:
        return
    if ok and state.get("ok"):
        _dns_guard_report(True, state.get("servers") or "the tunnel resolvers",
                          False)
        return
    _install_dns_guard(verbose=False)


def _remove_dns_guard(verbose=True):
    """Remove the catch-all rule and its record (teardown). Idempotent and
    safe when the guard was never installed. Returns True when nothing of
    ours is left on the system."""
    global _dns_guard_state
    try:
        ok, msg = _dns_guard.ensure_removed()
    except Exception as e:
        ok, msg = False, str(e)
    if not ok and verbose:
        print(f"[!] DNS leak guard removal failed: {msg} - a stale NRPT rule "
              "may keep DNS pinned until the next TunTop start (which "
              "removes it during startup recovery).", flush=True)
    _dns_guard_state = None
    return bool(ok)


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


def _route_identity_present(rows, fam, iface, gateway, metric=None):
    """Pure check over get_existing_v*_routes output: does the EXACT route
    (interface + normalized next-hop [+ route metric]) live in the table?
    Windows keeps multiple routes per prefix, so 'the prefix exists' proves
    nothing about OUR route being installed."""
    # Normalize BOTH sides through _norm_v4_gw so on-link is '' on each. They
    # must agree on that spelling before being handed to _gw_matches: it
    # recognises the tunnel's own address by comparing against an on-link
    # report, so mixing '0.0.0.0' (this function's old sentinel) with ''
    # (_norm_v4_gw's) made that case unreachable here even though add_v4
    # reaches it.
    want_gw = _norm_v4_gw(gateway)
    for r in rows or []:
        if str(r.get("InterfaceAlias", "")).lower() != str(iface or "").lower():
            continue
        r_gw = _norm_v4_gw(r.get("NextHop", ""))
        if not _gw_matches(iface, want_gw, r_gw, fam):
            continue
        if metric is not None:
            try:
                if int(r.get("RouteMetric", 0) or 0) != int(metric):
                    continue
            except (TypeError, ValueError):
                continue
        return True
    return False


def _norm_v4_gw(gw):
    """Canonical form of an IPv4 next hop: on-link ('' ) for '0.0.0.0'/'::'.

    Windows reports an on-link route as NextHop '0.0.0.0' (and '::' for
    IPv6), but netsh must be given NO next-hop token at all for those - a
    literal 0.0.0.0 is rejected with "The filename, directory name, or
    volume label syntax is incorrect". Normalising here makes an existing
    on-link route compare equal to an on-link install, which is what stops
    the add/re-add/re-fail loop the 15 s endpoint heal used to be stuck in.
    """
    g = str(gw or "").strip()
    if g in ("0.0.0.0", "::", "0", ""):
        return ""
    return g


#: Each Wintun adapter's own address per family, keyed by its alias. Every
#: route this helper installs through a TUN uses that adapter's own address
#: as the next hop (TUN4/TUN6 for the primary pipe, TUN2_IP4/TUN2_IP6 for the
#: secondary one).
_TUN_OWN_ADDRS = {
    TUN: {"v4": TUN4, "v6": TUN6},
    TUN2: {"v4": TUN2_IP4, "v6": TUN2_IP6},
}


def _gw_matches(iface, want, have, fam):
    """Do a wanted next hop and a reported one describe the SAME route?

    `want` is what we asked for, `have` is what Get-NetRoute reported (both
    already run through _norm_v4_gw, so on-link is '').

    The extra case beyond equality is the tunnel's own address. Windows
    reports a next hop that is the outgoing interface's own address as
    on-link, so `192.168.123.1` on wintun comes back as ''. Comparing them
    literally made EVERY TUN route look stale on every add: the self-heal
    deleted and re-added 0.0.0.0/1, 128.0.0.0/1, ::/0, ::/1 and 8000::/1 on
    every cycle - a reinstall of unchanged state, which is the "self-heal
    fires even though nothing happened" report and a large part of the
    start-to-RUNNING latency (each cycle is several PowerShell/netsh
    processes).
    """
    if want == have:
        return True
    if want == "" or have != "":
        return False
    own = _TUN_OWN_ADDRS.get(str(iface or ""), {}).get(fam, "")
    return bool(own) and want == own


def _wrong_family_gw(gw, family):
    """True when `gw` is a well-formed address of the WRONG family, or a
    NextHop string that is plainly not an address of this family at all.

    Defence in depth for the gateway-change monitor: on a dual-stack NIC an
    IPv6 next hop once reached the IPv4 route installer, and every add failed
    with netsh's opaque "Invalid nexthop parameter" / "filename ... syntax"
    text while the tracked egress was committed in that broken state. A cheap
    local check turns a whole-table failure into one clear refusal.

    family is 4 or 6. An empty gateway is on-link and always allowed.
    """
    g = str(gw or "").strip()
    if not g:
        return False            # on-link: valid for both families
    if family == 4:
        return ":" in g         # any IPv6 literal (incl. mapped forms)
    return ":" not in g         # any IPv4 literal


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

    ON-LINK GATEWAYS (0.0.0.0). A PPP/PPTP Windows VPN reports NextHop
    '0.0.0.0' - the normal "no gateway, resolve by neighbour discovery"
    form, exactly like '::' for IPv6. netsh REJECTS a literal 0.0.0.0 next
    hop ("The filename, directory name, or volume label syntax is
    incorrect"), so passing it through made every on-VPN route add fail: the
    VLESS transport pin in --vless-over-vpn mode, and the VPN endpoint bypass
    /32, both died with it - leaving the proxy server with no bypass at all,
    so its traffic fell into the TUN and looped (the "tunnel up, proxy down,
    connection lost" symptom). It also made `r_gw == gateway` compare
    '0.0.0.0' against '' and never match, so a correctly installed on-link
    route was re-added and re-failed on every single call - the endless
    "[HEAL] ... re-install FAILED - retrying next cycle".
    add_v6 has normalised '::' -> '' and omitted the token since 1.0.30;
    this is the missing IPv4 half.
    """
    gateway = _norm_v4_gw(gateway)
    if _wrong_family_gw(gateway, 4):
        print(f"[!] IPv4 route failed: {dest} -> refusing a non-IPv4 next hop "
              f"({gateway!r}); an IPv4 prefix cannot use one.")
        return False
    existing = get_existing_v4_routes(dest)
    is_default = (dest == "0.0.0.0/0")

    # Don't return as soon as one correct route is found: a second, stale entry
    # for the same destination (via a different interface/gateway) must still be
    # cleaned up. Track the match and keep scanning the whole list.
    found_correct = False
    for r in existing:
        r_iface = str(r.get("InterfaceAlias", ""))
        r_gw = _norm_v4_gw(r.get("NextHop", ""))
        same_iface = r_iface.lower() == iface.lower()
        same_gateway = _gw_matches(iface, gateway or "", r_gw, "v4")

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
        del_cmd = ["netsh", "interface", "ipv4", "delete", "route", dest,
                   stale_iface]
        if stale_gateway:
            del_cmd.append(stale_gateway)   # omit the token => on-link
        run(del_cmd)

    if found_correct and ("v4", dest, iface, gateway) not in added_routes:
        # The route is already present, but older builds installed it
        # PERSISTENTLY (registry) so it survived reboots.  Convert it to
        # active-store-only: delete it (clears both stores) and re-add with
        # store=active below.  If this is the machine's real default route it
        # lives on a different interface and was never marked found_correct, so
        # we never touch it here.
        #
        # SKIPPED when this process is the one that installed the route: our
        # own adds always pass store=active, so there is no persistent copy to
        # clear and the delete+re-add pair is pure cost. The self-heal re-adds
        # every TUN route on every cycle, so paying two extra netsh processes
        # per route there was a real part of the start-to-RUNNING latency. A
        # route this process did not install (a legacy persistent leftover)
        # is not in the ledger and is still converted.
        del_cmd = ["netsh", "interface", "ipv4", "delete", "route", dest, iface]
        if gateway:
            del_cmd.append(gateway)
        run(del_cmd)

    cmd = ["netsh", "interface", "ipv4", "add", "route", dest, iface]
    if gateway:
        cmd.append(gateway)            # omit the token entirely => on-link
    cmd.append(f"metric={metric}")
    cmd.append("store=active")
    code, out, err = run(cmd)

    if code:
        # A race or Windows duplicate-route response may happen between the
        # check above and the add. Re-check before declaring failure.
        existing_after = get_existing_v4_routes(dest)
        if _route_identity_present(existing_after, "v4", iface, gateway, metric):
            print(f"    [=] Route appeared during add and is correct: {dest}")
            added_routes.append(("v4", dest, iface, gateway), metric=metric)
            return True

        print(f"[!] IPv4 route failed: {dest} -> {err or out}")
        return False

    # netsh said OK - Windows says OK a lot of things. Confirm our EXACT
    # route is live for HOST routes (/32): bypass/VLESS installs are the
    # few routes where a silent half-commit means the whole design leaks,
    # and every one is worth a verification spawn. Default/LAN/split adds
    # are verified continuously by the monitor loop instead - polling the
    # table after each of those dozens of installs would add tens of
    # PowerShell spawns to every start on AV-slow machines.
    if dest.endswith("/32") and not _route_identity_present(
            get_existing_v4_routes(dest), "v4", iface, gateway, metric):
        print(f"[!] IPv4 route vanished after add: {dest} -> {iface} "
              f"({gateway} m={metric}) - not recording it")
        return False
    added_routes.append(("v4", dest, iface, gateway), metric=metric)
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
    gateway = _norm_v4_gw(gateway)   # '::' / '' => on-link, no token
    if _wrong_family_gw(gateway, 6):
        print(f"[!] IPv6 route failed: {dest} -> refusing a non-IPv6 next hop "
              f"({gateway!r}); an IPv6 prefix cannot use one.")
        return False
    existing = get_existing_v6_routes(dest)
    is_default = (dest == "::/0")

    # Don't return as soon as one correct route is found: a second, stale entry
    # for the same destination (via a different interface/gateway) must still be
    # cleaned up. Track the match and keep scanning the whole list.
    found_correct = False
    for r in existing:
        r_iface = str(r.get("InterfaceAlias", ""))
        r_gw = _norm_v4_gw(r.get("NextHop", ""))
        # IPv6 on-link routes report NextHop '::' (unspecified) - normalize
        # to '' so it compares equal to an on-link install (gateway='').
        same_iface = r_iface.lower() == iface.lower()
        same_gateway = _gw_matches(iface, gateway or "", r_gw, "v6")
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

    if found_correct and ("v6", dest, iface, gateway) not in added_routes:
        # Same persistent->active conversion as add_v4, and skipped under the
        # same condition (see there: our own adds are already store=active).
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
        if _route_identity_present(existing_after, "v6", iface, gateway, metric):
            print(f"    [=] Route appeared during add and is correct: {dest}")
            added_routes.append(("v6", dest, iface, gateway), metric=metric)
            return True
        print(f"[!] IPv6 route failed: {dest} -> {err or out}")
        return False

    # Identity verify for host routes after a "successful" add
    # (see add_v4 for the policy and reasoning).
    if dest.endswith("/128") and not _route_identity_present(
            get_existing_v6_routes(dest), "v6", iface, gateway, metric):
        print(f"[!] IPv6 route vanished after add: {dest} -> {iface} "
              f"({gateway} m={metric}) - not recording it")
        return False
    added_routes.append(("v6", dest, iface, gateway), metric=metric)
    return True


def remove_route(item):
    fam, dest, iface, gateway = item
    if fam == "v4":
        cmd = ["netsh", "interface", "ipv4", "delete", "route", dest, iface]
        # Omit the next-hop token for an on-link route. The v4 branch used to
        # append `gateway` unconditionally, so an entry recorded with the
        # on-link spelling ('' - what _norm_v4_gw now produces, and what a
        # PPP VPN's routes get) was deleted with an EMPTY argument, which
        # netsh rejects - so those routes were never actually removed and
        # survived every teardown. The v6 branch already did this.
        if gateway and gateway != "0.0.0.0":
            cmd.append(gateway)
        run(cmd)
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
            if _ACTIVE_DNS4:      # None = the user chose no IPv4 DNS
                run(["netsh", "interface", "ipv4", "set", "dnsservers",
                     f"name={TUN}", "source=static", f"address={_ACTIVE_DNS4}",
                     "register=none", "validate=no"])
            _res = _ACTIVE_DNS4
        else:
            run(["netsh", "interface", "ipv6", "add", "address", TUN, f"{addr}/{suffix}"])
            if _ACTIVE_DNS6:  # None = the user chose no IPv6 DNS
                run(["netsh", "interface", "ipv6", "add", "dnsserver",
                     TUN, _ACTIVE_DNS6, "index=1"])
            _res = _ACTIVE_DNS6
        # If we're in DoH mode, re-enable DoH on the recreated adapter so
        # DNS keeps riding over TCP/443 instead of broken UDP/53. The
        # RESOLVER must be passed here, NOT `addr`: `addr` is the adapter's
        # own TUN4/TUN6 address, and registering DoH against it would set
        # wintun's entire resolver list to the adapter itself - every lookup
        # would be sent to 192.168.123.1 and nothing would resolve.
        if _ACTIVE_DNS_MODE == "doh" and _res:
            tmpl = _ACTIVE_DOH_TEMPLATE or _doh_template_for(_res)
            _enable_doh_on_wintun(_res, tmpl)
        # tun2socks recreates the adapter, so NetBIOS-over-TCP/IP is enabled
        # again (the UDP/137 broadcast flood + loopback-port exhaustion
        # configure_tun() guards against). Re-disable on every re-add.
        if family == "IPv4":
            _disable_netbios_on_wintun()
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
    """Lower BOTH IPv4 and IPv6 InterfaceMetric on the Wintun adapter for the
    `metric` argument (lower = more preferred). Windows DNS-client server
    selection AND next-hop resolution are metric-ordered, so making Wintun
    decisively preferred stops a DHCP-assigned physical adapter (e.g. its
    on-link 192.168.1.1 resolver) from winning DNS lookups over the tunnel.

    The previous value is saved per-family in wintun_saved_metric so cleanup()
    can restore the exact originals. The save is captured ONCE: wintun_saved_metric
    is only written when it is still None for that family, so re-calling this on
    a self-heal or in the VPN-shadow path (override_vpn_routes) is idempotent and
    never clobbers the real starting metric. Best-effort: never raises, so a
    non-elevated session or an oddly-named adapter can't fail bring-up."""
    global wintun_saved_metric
    if not isinstance(wintun_saved_metric, dict):
        wintun_saved_metric = {"v4": None, "v6": None}
    for fam, key in (("IPv4", "v4"), ("IPv6", "v6")):
        try:
            ps = (f"$a = Get-NetIPInterface -InterfaceAlias '{TUN}' "
                  f"-AddressFamily {fam} -ErrorAction SilentlyContinue | "
                  f"Select-Object -First 1 InterfaceMetric; "
                  f"if ($a) {{ $a.InterfaceMetric }} else {{ 'NONE' }}")
            _, out, _ = run_ps(ps)
            cur = out.strip()
            if cur and cur != "NONE" and cur.isdigit():
                if wintun_saved_metric.get(key) is None:
                    wintun_saved_metric[key] = int(cur)
            run_ps(f"Set-NetIPInterface -InterfaceAlias '{TUN}' -AddressFamily {fam} "
                   f"-InterfaceMetric {metric}")
        except Exception:
            pass


def _raw_add_route(fam, dest, iface, gateway, metric, store="active"):
    """Add a route directly via netsh, WITHOUT deleting any pre-existing route to
    the same destination. This lets our Wintun override coexist with the VPN's own
    route; the lower effective metric then wins, and the VPN route is left intact
    (so cleanup only has to remove our override). Ignores 'already exists'.

    `store` defaults to "active" on purpose. `netsh interface <v4|v6> add
    route` DEFAULTS TO PERSISTENT, and every other installer in this file passes
    store= explicitly (add_v4, add_v6, the geo installer, the geo repoint). This
    one did not, so the Wintun VPN-override shadows were written into the
    registry's PersistentRoutes: after a crash, a taskkill or a reboot, /32 and
    /128 rows with NextHop=TUN4/TUN6 survived pointing at a Wintun adapter that
    no longer existed. Windows keeps the row and silently drops the packets, so
    the corporate subnets a connected VPN injects stay dead - and no generic
    startup sweep covers these, since the leftover-recovery pass is geo-CIDR
    specific. A normal cleanup() hides it (netsh delete clears both stores).

    Callers RESTORING the VPN's own routes pass store="persistent" - see the two
    `vpn_saved_routes` restore sites.
    """
    verb = "ipv4" if fam == "v4" else "ipv6"
    cmd = ["netsh", "interface", verb, "add", "route", dest, iface]
    # ON-LINK NORMALISATION. netsh rejects the unspecified address as a
    # next-hop token ("The filename, directory name, or volume label syntax is
    # incorrect" - documented three times elsewhere in this file, and the whole
    # reason _norm_v4_gw exists). `vpn_saved_routes` stores the RAW
    # Get-NetRoute NextHop, which for IKEv2/L2TP/PPTP/SSTP VPNs is
    # "0.0.0.0" (v4) or "::" (v6) - truthy, so it used to be appended here and
    # the restore silently failed, leaving the user's VPN with none of its
    # injected routes after a [V] toggle OR after TunTop exited.
    gateway = _norm_v4_gw(gateway)
    if gateway:
        cmd.append(gateway)
    cmd.append(f"metric={metric}")
    if store:
        cmd.append(f"store={store}")
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
    # No `global` needed: the ledgers are mutated in place (.append /
    # .remove / .clear), never rebound, and vpn_iface is a parameter.
    if not vpn_iface or _is_wintun_alias(vpn_iface):
        return
    # Never shadow a route whose prefix is part of the geoip country bypass:
    # those CIDRs are deliberately routed DIRECT via the physical adapter
    # (see add_geoip_bypass), so redirecting them into the tunnel would undo
    # the whole point of the bypass.
    geo_dests = {r[1] for r in geoip_added}
    # Make Wintun decisively the lowest-metric interface so our overrides win.
    _set_wintun_interface_metric(2)
    for fam, get_fam, gw in (
        ("v4", "IPv4", TUN4),
        ("v6", "IPv6", TUN6),
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
            # Save the VPN's original route so cleanup can restore it if needed.
            # _raw_add_route adds our Wintun override WITHOUT deleting the VPN
            # route; the lower effective metric then wins and the VPN route is
            # left intact (persistent store preserved).
            with _vpn_saved_lock:
                vpn_saved_routes.append(
                    (fam, prefix, vpn_iface,
                     str(r.get("NextHop", "") or ""),
                     int(r.get("RouteMetric", 1) or 1)))
            if _raw_add_route(fam, prefix, TUN, gw, metric=1):
                vpn_override_routes.append((fam, prefix, TUN, gw))


# ── Live [V]/[Y] mode switching (dashboard -> running helper) ───────────────
# The dashboard's [V] (VLESS-over-VPN) and [Y] (VPN endpoint bypass) toggles
# used to require a full stop+start (the modes shape the ROUTES, so the old
# path restarted the whole tunnel - the TUN reset the user felt on every
# toggle). The dashboard now pushes the requested modes through the SAME
# control file the [N] DNS handoff uses, and the monitor loop applies them
# HERE: every route this helper installed at startup is re-pointed at the
# new mode's egress, the VPN-override shadowing is undone/re-established to
# match, and tun2socks never stops. State lives in _live_mode, armed by
# main() once every startup route is installed.

_live_mode = {
    "args": None,             # parsed argparse namespace (set in main())
    "vless_over_vpn": False,  # mode currently ROUTED in the table
    "no_vpn_bypass": False,
    "v4": [], "v6": [],       # VLESS endpoint IPs (resolved at startup)
    "vpn_v4": [], "vpn_v6": [],   # VPN endpoint IPs
    "phys": (None, None),     # physical iface/gateway captured at startup
    "vpn_conn": None,         # VPN connection name the transport rides
    "vpn_routes": [],         # (fam, dest, iface, gw) VPN bypass routes WE added
}


def _remove_host_routes_v6(dest):
    """Delete every existing IPv6 route for `dest` (used when a mode switch
    leaves no usable IPv6 gateway for a host: without its direct /128 the
    traffic rides the TUN splits instead, exactly like the startup path).

    Returns True when at least one route was actually deleted, so a caller
    can report the removal only when there was something to remove - the
    dashboard often cleans the same route up first, and an unconditional
    "host route removed" line then reported a change that never happened."""
    removed = False
    for r in get_existing_v6_routes(dest):
        remove_route(("v6", dest, str(r.get("InterfaceAlias", "")),
                      str(r.get("NextHop", "") or "")))
        removed = True
    return removed


def _remove_host_routes_v4(dest):
    """Delete every existing IPv4 route for `dest` before a (re-)install.
    A stale host route pinned via the OLD egress is the longest match for
    the endpoint IP, so Find-NetRoute inside get_egress_for() returns the
    stale route itself - which makes a direct->over-VPN mode switch a
    silent no-op (the VPN's lower-metric default can never beat our own
    /32). Removing first lets egress resolution see the real table.

    Returns True when at least one route was actually deleted (see
    _remove_host_routes_v6 for why the caller needs to know)."""
    removed = False
    for r in get_existing_v4_routes(dest):
        remove_route(("v4", dest, str(r.get("InterfaceAlias", "")),
                      str(r.get("NextHop", "") or "")))
        removed = True
    return removed


def _live_set_vpn_shadow(active):
    """Undo (active=False) or (re)establish (active=True) the low-metric
    Wintun shadowing of a connected Windows VPN's injected routes. Mirrors
    the startup call and cleanup()'s restore path, so the same bookkeeping
    (vpn_override_routes / vpn_saved_routes) stays valid for teardown.
    Returns True when a shadow is (now) in place."""
    global vpn_override_iface
    if active:
        if vpn_override_routes or vpn_saved_routes:
            return True                     # already shadowed
        args = _live_mode.get("args")
        vdef = get_vpn_ipv4_default(
            getattr(args, "vpn_interface", None) if args else None)
        if not vdef:
            return False                    # no connected VPN - nothing to shadow
        vpn_override_iface = vdef[0]
        skip = set(str(x) for x in (_live_mode["v4"] + _live_mode["v6"]
                                    + _live_mode["vpn_v4"]
                                    + _live_mode["vpn_v6"]))
        skip.update(_vpn_self_addresses(vpn_override_iface))
        print(f"[*] Shadowing {vpn_override_iface} injected routes with "
              "Wintun (sole egress)...", flush=True)
        override_vpn_routes(vpn_override_iface, skip)
        return True
    if not (vpn_override_routes or vpn_saved_routes):
        return False
    print("[*] Removing VPN-override routes (mode switch) - the VPN's own "
          "routes are restored...", flush=True)
    for item in reversed(list(vpn_override_routes)):
        remove_route(item)
    vpn_override_routes.clear()
    with _vpn_saved_lock:
        for fam, dest, iface, gateway, metric in reversed(vpn_saved_routes):
            # store="persistent": these are the VPN's OWN routes being put
            # back, so they must land in the same store they were observed
            # in - an on-link VPN /32 is persistent by nature. The on-link
            # gateway token itself is normalised inside _raw_add_route.
            _raw_add_route(fam, dest, iface, gateway, metric,
                           store="persistent")
        vpn_saved_routes.clear()
    vpn_override_iface = None
    return False


def _live_apply_vpn_bypass_routes(enable):
    """Install (enable) or remove (disable) the Windows-VPN endpoint bypass
    routes. Mirrors the startup logic (resolve connected VPNs' ServerAddress
    values, /32 + /128 via the physical egress). Returns log lines."""
    lines = []
    args = _live_mode.get("args")
    if enable:
        src = get_active_windows_vpn_servers()
        if args is not None and getattr(args, "vpn_server", None):
            src = src + [("manual VPN server", s) for s in args.vpn_server]
        v4n, v6n, seen = [], [], set()
        for name, server in src:
            key = str(server).strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            ep4, ep6 = resolve_all_safe(server, label=f"VPN endpoint {server}")
            if ep4 is None and ep6 is None:
                lines.append(f"[!] Could not resolve VPN endpoint "
                             f"'{name}' ({server}) - skipped.")
                continue
            v4n.extend(x for x in (ep4 or []) if x not in v4n)
            v6n.extend(x for x in (ep6 or []) if x not in v6n)
        added = []
        d6 = get_ipv6_default()
        for ip in v4n:
            # A VPN's OWN server address must be pinned to the physical
            # adapter. `_direct_bypass_egress` enforces that and refuses to
            # fall back onto the VPN itself - the log line
            #   'add 185.64.178.62/32 on Shirazu-VPN via 0.0.0.0'
            # is a bypass route pointing the VPN's server at the VPN, which
            # is how the VPN transport dies (and takes the tunnel with it).
            eg = _direct_bypass_egress(ip)
            if not eg:
                lines.append(f"[!] No physical egress for VPN endpoint {ip} "
                             "- not installing its bypass (it must not ride "
                             "the VPN itself).")
                continue
            if add_v4(f"{ip}/32", eg[0], eg[1], metric=1):
                added.append(("v4", f"{ip}/32", eg[0], eg[1]))
                lines.append(f"    VPN {ip} -> via {eg[0]} ({eg[1]})")
        for ip in v6n:
            if d6:
                if add_v6(f"{ip}/128", d6["InterfaceAlias"], d6["NextHop"], 1):
                    added.append(("v6", f"{ip}/128", d6["InterfaceAlias"],
                                  d6["NextHop"]))
        _live_mode["vpn_v4"], _live_mode["vpn_v6"] = v4n, v6n
        _live_mode["vpn_routes"] = added
        # TRACK WHAT MUST BE BYPASSED, NOT ONLY WHAT INSTALLED. `added` above
        # receives a row only on a successful add_v4/add_v6, and it is the
        # ONLY list _heal_endpoint_routes and _tracked_endpoint_ips consume.
        # So a VPN endpoint whose _direct_bypass_egress() returned None (Wi-Fi
        # not up yet, physical default not yet captured) or whose add failed
        # was silently dropped and never retried: the VPN's control/data
        # traffic had no /32, fell into the Wintun /1 splits, and the VPN died
        # inside the tunnel - the "the VPN server traffic goes into the tun"
        # report that the `vpn_endpoint_reapply` key exists to fix once. The
        # VLESS side does not have this hole: it tracks the FULL list in
        # _live_mode["v4"], so the heal retries a failed install every 15s.
        # Mirror that: record the misses so the heal can pick them up.
        _live_mode["vpn_pending"] = [
            ("v4", f"{ip}/32") for ip in v4n
            if ("v4", f"{ip}/32") not in added
        ] + [
            ("v6", f"{ip}/128") for ip in v6n
            if ("v6", f"{ip}/128") not in added
        ]
        if _live_mode["vpn_pending"]:
            lines.append(f"[!] {len(_live_mode['vpn_pending'])} VPN endpoint "
                         "bypass(es) could not be installed yet - the "
                         "self-heal retries them every 15s.")
        lines.insert(0, f"[+] VPN endpoint bypass installed live "
                        f"({len(added)} route(s)).")
    else:
        removed = 0
        for fam, dest, iface, gw in _live_mode.get("vpn_routes", []):
            remove_route((fam, dest, iface, gw))
            removed += 1
        _live_mode["vpn_routes"] = []
        _live_mode["vpn_pending"] = []
        lines.insert(0, f"[-] VPN endpoint bypass removed live "
                        f"({removed} route(s)) - VPN traffic is tunneled now.")
    return lines


def _live_switch_vless(over):
    """Re-point every VLESS endpoint bypass route at the mode-appropriate
    gateway WITHOUT touching tun2socks. Returns (ok, log_lines); ok=False
    means the switch was REFUSED (mode stays unchanged)."""
    lines = []
    args = _live_mode.get("args")
    vpn_interface = getattr(args, "vpn_interface", None) if args else None
    if over:
        # The VPN's own injected routes must be able to carry the transport
        # again - undo the sole-egress shadowing FIRST, then verify a VPN
        # default route actually exists (same check as startup's pre-flight,
        # but non-fatal: a refused switch keeps the old mode).
        _live_set_vpn_shadow(False)
        vdef = get_vpn_ipv4_default(vpn_interface)
        if not vdef:
            lines.append("[!] VLESS-over-VPN switch refused: no connected "
                         "Windows VPN default route was found. Connect the "
                         "VPN and toggle [V] again.")
            return False, lines
        _live_mode["over"] = (vdef[0], vdef[1])
        _live_mode["vpn_conn"] = vdef[0]
        v6d = get_vpn_ipv6_default(vpn_interface)
        eg6 = (v6d[0], v6d[1]) if v6d else None
    else:
        v6d = get_ipv6_default()
        eg6 = (v6d["InterfaceAlias"], v6d["NextHop"]) if v6d else None
    ok = True
    for ip in _live_mode["v4"]:
        if over:
            # Deterministic VPN pin (same rule as the startup install):
            # _live_mode["over"] was JUST validated against the live VPN
            # default route above. The Find-NetRoute lookup can return the
            # physical NIC (VPN adapters matching the tunnel-driver
            # description filter are invisible to it) and would silently
            # leave the transport on Wi-Fi while [V] says "via VPN".
            eg = _live_mode["over"]
        else:
            eg = _direct_bypass_egress(ip)
        if not eg or eg[0] is None:
            ok = False
            lines.append(f"[!] No usable physical egress for VLESS endpoint "
                         f"{ip} - existing bypass left untouched.")
            continue
        # NO pre-clean of the /32. add_v4 REPLACES a same-prefix route
        # installed via a different interface/gateway (see its own stale-copy
        # loop), so the flip is a true re-point without one. The pre-clean
        # this used to do was strictly destructive: it ran BEFORE the egress
        # check above, so every "no usable egress" / "add failed" path left
        # the proxy server with NO /32 at all - its traffic then fell into
        # the Wintun /1 splits and the tunnel swallowed its own upstream
        # (total blackout). _live_apply_servers hit the identical bug and
        # removed its copy for exactly this reason.
        if add_v4(f"{ip}/32", eg[0], eg[1], metric=1):
            lines.append(f"    VLESS {ip} -> via {eg[0]} ({eg[1]})")
        else:
            ok = False
            lines.append(f"[!] Could not re-route VLESS endpoint {ip}.")
    for ip in _live_mode["v6"]:
        if eg6:
            if add_v6(f"{ip}/128", eg6[0], eg6[1], metric=1):
                lines.append(f"    VLESS {ip} (v6) -> via {eg6[0]} ({eg6[1]})")
        else:
            # No usable IPv6 gateway in this mode (e.g. IPv4-only VPN):
            # drop the direct /128 so the endpoint rides the TUN, the same
            # state a fresh start in this mode would produce.
            _remove_host_routes_v6(f"{ip}/128")
    if not over and not _live_mode["no_vpn_bypass"]:
        # Back to direct mode with VPN endpoints still bypassed: re-shadow a
        # connected VPN's injected routes (the startup condition, restored).
        if _live_set_vpn_shadow(True):
            lines.append("[*] VPN injected routes shadowed with Wintun "
                         "(sole egress) - as on startup.")
    lines.insert(0, "[*] VLESS transport -> "
                 + ("Windows VPN" if over else "physical adapter bypass"))
    return ok, lines


def _live_switch_vpn_bypass(disable):
    """disable=True: remove the Windows-VPN endpoint bypass routes (the VPN
    traffic itself is tunneled). disable=False: resolve + install them (VPN
    endpoints stay direct). The VPN-override shadowing follows, because at
    startup it only ever coexists with bypassed VPN endpoints (the VPN's own
    server endpoint must stay reachable outside the TUN)."""
    lines = _live_apply_vpn_bypass_routes(not disable)
    if disable:
        if not _live_mode["vless_over_vpn"] and _live_set_vpn_shadow(False):
            lines.append("[i] VPN route shadowing removed together with the "
                         "bypass - the VPN connection must stay reachable.")
    else:
        if not _live_mode["vless_over_vpn"] and _live_set_vpn_shadow(True):
            lines.append("[*] VPN injected routes shadowed with Wintun "
                         "(sole egress) - as on startup.")
    return True, lines


def _live_apply_servers(hosts, endpoints):
    """Live [U] server change from the dashboard (control-file keys
    'servers' + 'server_endpoints').

    The dashboard installs the new endpoints' host routes itself, but the
    HELPER's route tracking (added_routes) and the 15 s self-heal
    (_heal_endpoint_routes) only knew the STARTUP server list - a
    live-[U]-added server was invisible to both, so a later Wi-Fi change
    left its /32 pinned to the dead gateway and the transport looped (the
    "the U ip goes to the wintun" report). This reconciles the tracked
    list: (re)install the current endpoints via the mode-appropriate egress
    (which also adopts them under THIS helper's tracking), drop the
    bypasses of servers that left the list, and re-arm _live_mode (+ the
    launch args) so the self-heal and _check_gateway_change follow the NEW
    servers. `endpoints` maps host -> {"v4": [...], "v6": [...]} and comes
    pre-resolved from the dashboard (it already applied its DNS policy);
    hosts without addresses are skipped without touching the tracked state.
    Returns log lines."""
    lines = []
    hosts = [str(h).strip() for h in (hosts or []) if str(h).strip()]
    if not hosts:
        return ["[i] [U] empty server list ignored - nothing changed."]
    endpoints = endpoints if isinstance(endpoints, dict) else {}
    args = _live_mode.get("args")
    over = _live_mode["vless_over_vpn"]
    new_v4, new_v6 = [], []
    for host in hosts:
        eps = endpoints.get(host) or {}
        # TRUST BOUNDARY. `endpoints` came out of the control file, which
        # lives in a user-writable folder and is read by this ELEVATED
        # process. Every address is interpolated into an f"{ip}/32" and then
        # into PowerShell/netsh, so a malformed or hostile value is a
        # script-injection primitive, not just a broken route. DNS values on
        # the same channel already go through _validated_dns(); these did
        # not. Validate per family, drop the bad ones with a line, and keep
        # going - one poisoned address must not abort the whole [U] change.
        v4, v6, bad = [], [], []
        for family, raw in ((4, eps.get("v4")), (6, eps.get("v6"))):
            dest = v4 if family == 4 else v6
            for ip in (raw or []):
                clean = _validated_dns(ip, family)
                if clean in (None, _INVALID):
                    bad.append(str(ip))
                elif str(clean) not in dest:
                    dest.append(str(clean))
        if bad:
            lines.append(f"[!] [U] server '{host}': ignoring invalid address(es) "
                         f"{', '.join(bad)} from the control file.")
        if not v4 and not v6:
            lines.append(f"[i] [U] server '{host}' has no resolved address "
                         "yet - its bypass is (re)installed by the "
                         "dashboard's resolver / the next self-heal.")
            continue
        for ip in v4:
            if ip not in new_v4:
                new_v4.append(ip)
        for ip in v6:
            if ip not in new_v6:
                new_v6.append(ip)
        lines.append(f"[+] [U] server {host} -> {', '.join(v4 + v6)}")
    if not new_v4 and not new_v6:
        # Nothing resolved: NEVER strip the tracked endpoints on a
        # transient resolution failure - the self-heal must keep covering
        # the currently-working servers.
        lines.append("[!] [U] no server address resolved - tracked "
                     "endpoints kept unchanged.")
        return lines
    # Drop the bypasses of servers that left the list (REPLACE mode). A
    # stale extra /32 (a server whose IP changed) is harmless until the
    # next restart sweeps it - losing coverage would not be.
    for ip in list(_live_mode["v4"]):
        if ip not in new_v4:
            if _remove_host_routes_v4(f"{ip}/32"):
                lines.append(f"[-] [U] old server {ip} host route removed")
    for ip in list(_live_mode["v6"]):
        if ip not in new_v6:
            if _remove_host_routes_v6(f"{ip}/128"):
                lines.append(f"[-] [U] old server {ip} host route removed")
    # (Re)install every current endpoint so it lands under THIS helper's
    # route tracking: the gateway-change re-point and the self-heal only
    # see routes the helper installed itself. add_v4/add_v6 replace any
    # same-prefix copy, so a dashboard-installed route is adopted, never
    # duplicated.
    for ip in new_v4:
        # NO pre-clean of the NEW server's /32. The dashboard resolves the
        # server and installs its /32 itself before writing the control file
        # (see _rehost_endpoint_routes), so this reconcile only has to make the
        # HELPER's tracking and its 15 s endpoint heal cover the new server.
        # The pre-clean deleted that live, correct route and then re-added it,
        # so one [U] server change performed the work TWICE - the "server
        # change happens twice" report. add_v4 already replaces a drifted
        # same-prefix copy on its own, so a stale copy is still cleaned up.
        if over:
            # Same deterministic VPN pin as the startup/[V] paths: in
            # over-VPN mode a fresh [U] server's /32 must land on the VPN,
            # never on whatever Find-NetRoute ranks first (which can be the
            # physical NIC - see _live_switch_vless / the startup install).
            eg = _live_mode.get("over") or get_egress_for(ip, exclude_vpn=False)
        else:
            eg = _direct_bypass_egress(ip)
        if not eg or not eg[0]:
            lines.append(f"[!] [U] no usable egress for {ip} - the "
                         "self-heal retries.")
            continue
        if add_v4(f"{ip}/32", eg[0], eg[1], metric=1):
            lines.append(f"    [U] {ip}/32 via {eg[0]} ({eg[1]})")
        else:
            lines.append(f"[!] [U] could not install the {ip}/32 bypass - "
                         "the self-heal retries.")
    for ip in new_v6:
        d6 = get_ipv6_default()
        if d6 and add_v6(f"{ip}/128", d6["InterfaceAlias"],
                         d6.get("NextHop") or "", 1):
            lines.append(f"    [U] {ip}/128 via {d6['InterfaceAlias']}")
        else:
            lines.append(f"[i] [U] no IPv6 gateway - {ip} rides the TUN "
                         "(same as a fresh start).")
    # Re-arm the tracking so the self-heal and the gateway re-point cover
    # the NEW server list from now on.
    _live_mode["v4"] = new_v4
    _live_mode["v6"] = new_v6
    if args is not None:
        args.server = list(hosts)
    return lines


def _bad_endpoint_rows(rows, over, over_iface=None):
    """Which of the existing /32 route rows for a proxy endpoint are UNSAFE.

    A row is bad when it is pinned to a tunnel adapter (the proxy's own
    transport would be swallowed by a TUN and loop back to 127.0.0.1 - this
    is the "TUN starts, then the proxy and the whole connection die" failure),
    or when it contradicts the current transport mode: DIRECT mode must not
    ride a VPN-pattern interface, and over-VPN mode must ride exactly the
    validated VPN egress and nothing else.

    Returns (bad_rows, healthy_exists). `healthy_exists` says whether at
    least one row is safe - several rows for one /32 can coexist (a stale
    high-metric one plus the good low-metric one), and only the bad ones must
    be removed.

    Single source of truth on purpose: the startup loop guard
    (`verify_endpoints_off_tun`) and the periodic self-heal
    (`_heal_endpoint_routes`) MUST agree on what "healthy" means, otherwise
    the guard can green-light a route the heal then tears down (or worse, the
    heal can re-install one the guard called broken, forever).
    """
    bad = []
    healthy = False
    for r in rows:
        alias = str(r.get("InterfaceAlias", ""))
        unsafe = _es.is_tun_iface(alias)
        if not over and _es.is_vpn_iface(alias):
            unsafe = True
        if over and over_iface and alias.lower() != str(over_iface[0]).lower():
            unsafe = True
        if unsafe:
            bad.append(r)
        else:
            healthy = True
    return bad, healthy


def _tracked_endpoint_ips():
    """Every endpoint IP the tunnel must keep off its own TUN: the VLESS
    server(s) (BOTH families) and the Windows-VPN endpoint bypasses.
    Deduplicated, order-preserving.

    `_live_mode["v4"]` only was listed here, which left two holes: a VLESS
    IPv6 endpoint was never checked at all, and the vpn_routes entries are
    family-agnostic, so an IPv6 VPN `ServerAddress` was checked as IPv4."""
    out = []
    for ip in list(_live_mode.get("v4") or []) + list(_live_mode.get("v6") or []):
        if ip not in out:
            out.append(ip)
    for entry in (_live_mode.get("vpn_routes") or []):
        ip = str(entry[1]).split("/")[0]
        if ip not in out:
            out.append(ip)
    # Endpoints that are supposed to be bypassed but have not installed yet:
    # the loop guard must still see them, otherwise a missing VPN /32 is
    # invisible right up until the VPN dies inside the tunnel.
    for _fam, dest in (_live_mode.get("vpn_pending") or []):
        ip = str(dest).split("/")[0]
        if ip not in out:
            out.append(ip)
    return out


def _endpoint_prefix_and_lookup(ip):
    """(prefix, route-lookup) for one endpoint IP.

    The lookup is family-correct. This used to hardcode f"{ip}/32" +
    get_existing_v4_routes, so an IPv6 endpoint built "2001:db8::1/32" and
    asked Get-NetRoute about it in IPv4 - always empty, always reported as a
    problem, and the heal below it skips non-v4, so the "problem" survived
    every repair pass. On any machine whose Windows-VPN ServerAddress (or
    VLESS server) resolves to IPv6 that meant a permanent false
    "TUNNEL DEGRADED - proxy endpoint routes loop" on a perfectly healthy
    tunnel, which also kept the dashboard's endpoint-loop repair ladder
    running forever."""
    is6 = ":" in str(ip)
    return (f"{ip}/128" if is6 else f"{ip}/32",
            get_existing_v6_routes if is6 else get_existing_v4_routes)


def verify_endpoints_off_tun(tag="startup"):
    """Startup loop guard: prove the proxy transports still bypass the TUN
    AFTER the default/split routes went in.

    The bypass /32s are installed before the 0/0 and the /1 splits, which is
    the right order - but "right order" is not a guarantee. A competing
    adapter, a route-metric race, or a country-bypass sweep can still leave a
    server /32 pointing at a tunnel, and the moment the default route is live
    that server's traffic is captured: the proxy client can no longer reach
    its own server, and because tun2socks has no upstream, every connection
    the TUN carries dies with it. That is a full, silent blackout caused by
    the tunnel coming up - the single worst failure this program has.

    So the start sequence does not announce success on the strength of the
    install alone. Returns (ok, problems): `ok` is False when any tracked
    endpoint is missing or pinned to a tunnel, and the caller must say so out
    loud instead of claiming the tunnel is ready. Idempotent, and a repair is
    attempted once via the same healer the monitor uses.
    """
    over = bool(_live_mode["vless_over_vpn"])
    over_eg = _live_mode.get("over") or None
    problems = []
    for ip in _tracked_endpoint_ips():
        dest, get_routes = _endpoint_prefix_and_lookup(ip)
        rows = get_routes(dest)
        bad, _healthy = _bad_endpoint_rows(rows, over, over_eg)
        if rows and not bad:
            continue                      # present and safe
        if rows:
            why = ("pinned to tunnel adapter "
                   f"{bad[0].get('InterfaceAlias', '?')!r}")
        else:
            why = f"no /{dest.split('/', 1)[1]} bypass route in the table"
        problems.append(f"{ip} ({why})")
        # Repair in place rather than only reporting: a fixed transport now
        # is worth far more than a warning the user cannot act on.
        try:
            for ln in _heal_endpoint_routes():
                print(ln, flush=True)
        except Exception as e:
            print(f"[!] endpoint loop-guard repair failed: {e}", flush=True)
            continue
        # Re-read after the repair so the verdict reflects reality.
        rows2 = get_routes(dest)
        bad2, _healthy2 = _bad_endpoint_rows(rows2, over, over_eg)
        if rows2 and not bad2:
            problems.pop()      # repaired successfully - not a problem
            print(f"[LOOPGUARD] {ip} bypass was {why}; repaired to "
                  f"{rows2[0].get('InterfaceAlias', '?')}", flush=True)
    if problems:
        print(f"[!] [LOOPGUARD] {len(problems)} proxy endpoint(s) would loop "
              f"back through the TUN: {'; '.join(problems)}. The proxy's own "
              "connection to its server is being captured by the tunnel, so it "
              "will look dead and every TUN connection with it. Fix the "
              "network/other VPN client, or start the proxy on a physical "
              "adapter, then press [T] then [S].", flush=True)
    else:
        print(f"[+] [LOOPGUARD] All proxy endpoints bypass the TUN "
              f"({tag}).", flush=True)
    return (not problems), problems


def _heal_endpoint_routes():
    """Periodic self-heal for the tracked endpoint bypass routes. The /32s
    can vanish WITHOUT any local fault - seen live (1.0.30): a foreign TUN
    adapter (Throne's 'sing-tun Tunnel', missed by the then-Wintun-only
    driver filter) owns 176.0.0.0/4, the egress resolver pinned the server
    bypass ONTO it, and the route disappeared when that adapter churned.
    The server's traffic then falls into OUR TUN and loops - the
    '192.168.123.1 -> server:443' rows in the connections panel, while the
    BYPASS LIST still claims ROUTED DIRECT. Verify every tracked endpoint:
    a MISSING bypass, one pinned to a TUN-family interface, or (in DIRECT
    mode) one pinned onto a VPN-pattern interface - the transport may ride
    the VPN only in [V] mode - gets re-resolved and re-installed via the
    mode-appropriate egress. Returns
    log lines (empty = everything healthy). Idempotent; runs in the single
    monitor thread, so it never races the [V]/[Y] switches."""
    lines = []
    over = _live_mode["vless_over_vpn"]
    # In over-VPN mode the ONLY correct interface for a server /32 is the
    # validated Windows-VPN egress - a route that resolved onto the physical
    # NIC (Wi-Fi) is a silent mode violation and gets re-pointed below, the
    # same way a TUN-pinned route always was.
    over_eg = _live_mode.get("over") or None
    for ip in list(_live_mode["v4"]):
        dest = f"{ip}/32"
        rows = get_existing_v4_routes(dest)
        bad, _healthy = _bad_endpoint_rows(rows, over, over_eg)
        if rows and not bad:
            continue                       # healthy - leave it alone
        for r in bad:
            remove_route(("v4", dest, str(r.get("InterfaceAlias", "")),
                          str(r.get("NextHop", "") or "")))
        if over:
            # Deterministic VPN pin (see _live_switch_vless): the validated
            # VPN egress, not a Find-NetRoute lookup that can return Wi-Fi.
            eg = over_eg or get_egress_for(ip, exclude_vpn=False)
        else:
            eg = get_egress_for(ip, exclude_vpn=True) or _live_mode.get("phys")
        if not eg or not eg[0]:
            lines.append(f"[HEAL] VLESS {ip} bypass is gone but no usable "
                         "egress was found - retrying next cycle.")
            continue
        if add_v4(dest, eg[0], eg[1], metric=1):
            lines.append(f"[HEAL] VLESS {ip} bypass re-installed via "
                         f"{eg[0]} ({eg[1]})")
        else:
            lines.append(f"[HEAL] VLESS {ip} bypass re-install FAILED - "
                         "retrying next cycle.")
    for ip in list(_live_mode["v6"]):
        dest = f"{ip}/128"
        if over:
            # Over-VPN mode: resolve the VPN's IPv6 egress FIRST so the
            # identity check below can treat a /128 pinned anywhere else as
            # bad (same rule as the v4 path).
            v6d = get_vpn_ipv6_default(
                getattr(_live_mode.get("args"), "vpn_interface", None))
            eg = (v6d[0], v6d[1]) if v6d else None
        else:
            d6 = get_ipv6_default()
            eg = (d6["InterfaceAlias"], d6["NextHop"]) if d6 else None
        rows = get_existing_v6_routes(dest)
        bad, _healthy = _bad_endpoint_rows(rows, over, eg)
        if rows and not bad:
            continue
        for r in bad:
            remove_route(("v6", dest, str(r.get("InterfaceAlias", "")),
                          str(r.get("NextHop", "") or "")))
        if not eg:
            continue                       # no native v6 - same as startup
        if add_v6(dest, eg[0], eg[1], 1):
            lines.append(f"[HEAL] VLESS {ip} (v6) bypass re-installed via {eg[0]}")
    for entry in list(_live_mode.get("vpn_routes") or []):
        fam, dest, _iface, _gw = entry
        if fam != "v4":
            continue
        rows = get_existing_v4_routes(dest)
        if rows and not any(_es.is_tun_iface(r.get("InterfaceAlias", ""))
                            for r in rows):
            continue
        ip = dest.split("/")[0]
        eg = get_egress_for(ip, exclude_vpn=True) or _live_mode.get("phys")
        if not eg or not eg[0]:
            continue
        if add_v4(dest, eg[0], eg[1], metric=1):
            lines.append(f"[HEAL] VPN endpoint {ip} bypass re-installed via "
                         f"{eg[0]} ({eg[1]})")
    # ENDPOINTS THAT NEVER INSTALLED AT ALL. See _live_apply_vpn_bypass_routes:
    # a route that failed to install is not in vpn_routes, so the loop above
    # cannot see it. Retry it here (this is the 15s self-heal, so a
    # temporarily-absent physical egress recovers on its own).
    for fam, dest in list(_live_mode.get("vpn_pending") or []):
        if not _live_mode.get("vpn_pending"):
            break
        is6 = fam == "v6"
        rows = (get_existing_v6_routes(dest) if is6
                else get_existing_v4_routes(dest))
        if rows:
            # Present after all (someone else installed it) - stop tracking.
            if (fam, dest) not in _live_mode["vpn_routes"]:
                _live_mode["vpn_routes"].append(
                    (fam, dest, rows[0].get("InterfaceAlias", ""),
                     rows[0].get("NextHop", "") or ""))
            _live_mode["vpn_pending"] = [p for p in _live_mode["vpn_pending"]
                                         if p != (fam, dest)]
            continue
        ip = dest.split("/")[0]
        if is6:
            d6 = get_ipv6_default()
            eg = (d6["InterfaceAlias"], _norm_v4_gw(d6.get("NextHop"))) if d6 \
                else None
        else:
            eg = get_egress_for(ip, exclude_vpn=True) \
                or _live_mode.get("phys")
        if not eg or not eg[0]:
            lines.append(f"[HEAL] VPN endpoint {ip} bypass is still missing "
                         "and no usable egress was found - retrying next cycle.")
            continue
        ok = (add_v6(dest, eg[0], eg[1], 1) if is6
              else add_v4(dest, eg[0], eg[1], metric=1))
        if ok:
            _live_mode["vpn_pending"] = [p for p in _live_mode["vpn_pending"]
                                         if p != (fam, dest)]
            _live_mode["vpn_routes"].append((fam, dest, eg[0], eg[1]))
            lines.append(f"[HEAL] VPN endpoint {ip} bypass installed via "
                         f"{eg[0]} ({eg[1]})")
    return lines


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
    if not phys_iface or _is_wintun_alias(phys_iface):
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


# ── Gateway-change auto re-route ─────────────────────────────────────────────
# When the physical network changes under a running tunnel (Wi-Fi roam, a DHCP
# renew handing out a different gateway, dock/undock), every route we PINNED
# to the old gateway stays in the table pointing at a next-hop that no longer
# exists: the VLESS endpoint /32s, the LAN bypasses and the geo bypasses all
# go dark - the system "loses the internet" even though the new network is
# fine. The monitor loop polls the default gateway every few seconds and
# re-points every pinned route at the new one. TUN routes are untouched: they
# ride the wintun adapter and are unaffected by the change.

#: Seconds between gateway-change polls in the monitor loop.
_GW_CHECK_EVERY = 5
# Endpoint bypass self-heal cadence (see _heal_endpoint_routes): foreign TUN
# churn can silently strip the server /32s - cheap identity checks, re-resolve
# + re-add only for the broken ones.
_HEAL_EVERY = 15
# Windows-VPN transport status poll cadence ([V] mode only): detects the VPN
# flapping so the VLESS /32s fall back to the physical egress while it is
# down and re-point onto the VPN when it returns.
_VPN_STATUS_EVERY = 10
# Local SOCKS5 inbound liveness poll cadence. Deliberately much faster than
# the traffic probe (mon_interval, 30 s): a TCP connect to a closed loopback
# port costs microseconds, and the whole point is to notice the proxy coming
# BACK quickly so the tunnel can be re-promoted to RUNNING instead of sitting
# DEGRADED for up to half a minute after the user restarted their proxy.
_SOCKS_CHECK_EVERY = 5

#: Serialises the geo re-point so a slow bulk move can never overlap itself.
_geo_repoint_lock = threading.Lock()

#: Guards EVERY mutation of geoip_added (registration during install,
#: gateway re-point tracking rewrite, cleanup snapshot+clear). Without it a
#: CIDR batch registered while cleanup() was snapshotting leaked untracked
#: routes - the signal handler could then os._exit() with a half-installed
#: country still in the table.
_geo_state_lock = threading.Lock()

#: Set by _on_signal: the background geo install skips its remaining
#: netsh sub-batches so it cannot add routes behind cleanup()'s back.
_geo_install_cancel = threading.Event()

#: The geo-install daemon thread (set in main() so _on_signal can join it).
_geo_install_thread = None

#: The gateway-re-point daemon thread. Also published so cleanup() can join
#: it: it installs replacement routes BEFORE rewriting the ledger, so a
#: cleanup() that snapshotted the ledger in between recorded nothing while
#: the new-gateway routes sat in the table - permanently untrackable.
_geo_repoint_thread = None

#: Debounce state for the gateway monitor (candidate, first-seen timestamp).
_gw_pending = None
_gw_pending_since = 0.0


def _repoint_geo_batch(rows):
    """Batch-add replacement routes and return the number netsh accepted.

    Replacement routes are intentionally added before the old routes are
    removed by _repoint_geo_routes().  A gateway transition must not create a
    window where a large country prefix falls through the Wintun default.
    """
    if not rows:
        return 0
    chunks = [rows[i:i + GEO_SUB_BATCH] for i in range(0, len(rows), GEO_SUB_BATCH)]
    accepted = 0

    def _add_chunk(grp):
        lines = []
        for fam, dest, iface, gw in grp:
            verb = "ipv4" if fam == "v4" else "ipv6"
            iface_dq = '"' + str(iface).replace('"', '') + '"'
            gw_tok = (" %s" % str(gw)) if gw else ""
            lines.append("interface %s add route %s %s%s metric=1 store=active"
                         % (verb, dest, iface_dq, gw_tok))
        fd, path = tempfile.mkstemp(suffix=".txt", prefix="geo_rep_")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            code, out, _err = run(["netsh", "-f", path], timeout=GEO_SUB_TIMEOUT)
            if code:
                return 0
            return sum(1 for line in (out or "").splitlines()
                       if line.strip() == "Ok."
                       or "already exists" in line.lower())
        finally:
            try:
                os.unlink(path)
            except Exception:
                pass

    with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(len(chunks), GEO_MAX_WORKERS)) as ex:
        for _fut in concurrent.futures.as_completed(
                [ex.submit(_add_chunk, c) for c in chunks]):
            try:
                accepted += _fut.result()
            except Exception:
                pass
    return accepted


def _repoint_geo_routes(old_iface, new_iface, new_gw):
    """Re-point geo routes without opening a Wintun fallback window.

    Add replacements first, then remove the old-gateway copies. If any
    replacement cannot be installed, leave the old routes/tracking intact for
    the next gateway check instead of opening a routing gap.
    """
    rows = [it for it in list(geoip_added)
            if str(it[2]).lower() == str(old_iface).lower()]
    if not rows:
        return 0
    new_rows = []
    d6 = None
    for fam, dest, iface, gw in rows:
        if fam == "v4":
            new_rows.append((fam, dest, new_iface, new_gw))
        else:
            if d6 is None:
                d6 = get_ipv6_default()
            if d6:
                new_rows.append((fam, dest, d6["InterfaceAlias"],
                                 _norm_v4_gw(d6.get("NextHop"))))
    if not new_rows:
        return 0
    # ONLY REPLACE WHAT WE ACTUALLY REPLACED. With no usable IPv6 egress,
    # new_rows holds v4 only - and the old code still passed that list to
    # _remove_routes_bulk, deleting every v6 geo route while only the v4 half
    # had a replacement. The country bypass then silently stopped existing
    # for IPv6 (all country v6 traffic re-entered the tunnel), the ledger
    # forgot about it, and nothing ever re-installed it until a full restart -
    # while the worker cheerfully logged "[+] geoip: N route(s) re-pointed"
    # counting only v4.
    replaced = {r[0] for r in new_rows}
    kept = [r for r in rows if r[0] not in replaced]
    if kept:
        print(f"[!] geoip: {len(kept)} IPv6 route(s) left on the old gateway - "
              "no usable IPv6 egress on this network.", flush=True)
    # REGISTER BEFORE INSTALLING. The rewrite used to sit at the very END of
    # this function - after the batch install AND after _remove_routes_bulk -
    # so between the install and the rewrite there was a multi-second window
    # (thousands of rows through a 6-way ThreadPoolExecutor) in which the
    # new-gateway routes were live in the OS table and in NO ledger. A
    # teardown arriving in that window snapshotted and cleared the ledger, and
    # every one of those routes was then unreachable by cleanup, by the
    # startup sweep and by the dashboard's CIDR sweep. This mirrors what the
    # geo INSTALL path already does correctly (upfront, lock-guarded
    # registration); the re-point path was the drifted copy.
    with _geo_state_lock:
        for r in rows:
            if r[0] in replaced:
                try:
                    geoip_added.remove(r)
                except ValueError:
                    pass
        for r in new_rows:
            geoip_added.append(r)
    accepted = _repoint_geo_batch(new_rows)
    if accepted != len(new_rows):
        # Partial (or total) failure. We registered up front, so roll the
        # receipt back for exactly the rows that did not land - and put the
        # ORIGINAL rows back too, so the old gateway copies stay tracked for
        # the next check and for cleanup. Claiming nothing would leak the
        # rows that DID install; claiming all of them would make cleanup
        # chase routes that were never created.
        with _geo_state_lock:
            for r in new_rows:
                try:
                    geoip_added.remove(r)
                except ValueError:
                    pass
            for r in rows:
                if r[0] in replaced and r not in geoip_added:
                    geoip_added.append(r)
        return 0
    _remove_routes_bulk([r for r in rows if r[0] in replaced])
    return len(new_rows)


def _repoint_pinned_routes(old_iface, old_gw, new_iface, new_gw,
                           old6=None, new6=None):
    """Re-point every route THIS helper pinned to the old physical egress
    (added_routes: endpoint /32+/128 bypasses, LAN bypasses, proxy2 server
    bypasses) at the new gateway. add_v4/add_v6 replace any drifted copy of
    the same destination, so the old-gw route is gone after each re-add, and
    the appended tracking tuple keeps cleanup() exact. Routes that were NOT
    pinned to the old egress (TUN routes, VPN-transport endpoints in
    over-VPN mode) never match and are left alone. Returns how many routes
    moved."""
    moved = 0
    for item in list(added_routes):
        fam, dest, iface, gw = item
        if fam == "v4":
            if (str(iface).lower() != str(old_iface).lower()
                    or str(gw or "") != str(old_gw or "")):
                continue
            tgt = (new_iface, new_gw)
            metric = added_routes.metric_of(item,
                                            10 if dest in _LAN_BYPASS_RANGES
                                            else 1)
        else:
            if not old6 or not new6:
                continue
            if (str(iface).lower() != str(old6[0]).lower()
                    or str(gw or "") != str(old6[1] or "")):
                continue
            tgt = (new6[0], new6[1])
            metric = added_routes.metric_of(item, 1)
        try:
            added_routes.remove(item)
        except ValueError:
            continue
        ok = (add_v4(dest, tgt[0], tgt[1], metric=metric) if fam == "v4"
              else add_v6(dest, tgt[0], tgt[1], metric))
        if ok:
            moved += 1
        else:
            # The old route is NOT still installed. add_v4/add_v6 REPLACE a
            # drifted same-prefix copy, and they do it by DELETING the stale
            # one first - so by the time they return False the old-gateway
            # route is already gone from the table. The previous message here
            # ("it stays on the old egress") was simply false, and the
            # consequence is the worst one available: the VLESS endpoint /32
            # silently vanished during a Wi-Fi roam, its traffic fell into the
            # Wintun /1 splits, and the tunnel swallowed its own upstream -
            # "tunnel up, proxy down" with a log claiming the route was fine.
            #
            # So re-pin the old egress as the fallback and keep the receipt.
            try:
                if fam == "v4":
                    add_v4(dest, item[2], item[3], metric=metric)
                else:
                    add_v6(dest, item[2], item[3], metric)
            except Exception:
                pass
            try:
                added_routes.append(item, metric=metric)
            except Exception:
                pass
            print(f"[!] Could not re-point {dest} to {tgt[0]} ({tgt[1]}); "
                  f"re-pinned to the OLD egress ({item[2]}) and still tracked "
                  "for cleanup.", flush=True)
    return moved


def _check_gateway_change():
    """Monitor-loop hook: detect a changed physical default gateway and
    re-point every route pinned to the old one. Debounced - a candidate
    gateway must be seen twice (>=2s apart) before anything moves - so a
    mid-DHCP transition is never mistaken for the final state. Never raises;
    prints [GATEWAY] markers the dashboard surfaces."""
    global _gw_pending, _gw_pending_since
    global _geo_repoint_thread
    phys = _live_mode.get("phys")
    if not phys:
        return
    # A missing default route is a normal moment during a network transition,
    # never a reason to die here - the safe wrapper turns the legacy
    # sys.exit() failure mode into a plain None.
    res = RouteResult.unwrap(get_ipv4_default)
    if not res.ok or not res.value:
        return
    cur = res.value
    # NORMALISE THE ON-LINK NEXT HOP. get_ipv4_default() returns NextHop
    # verbatim, and for a DHCP-less / static / PPP adapter that is literally
    # "0.0.0.0" - the normal form of an IPv4 default route with no gateway.
    # Everything that COMPARES or STORES an egress normalises it through
    # _norm_v4_gw (physical_egress on the way into the cache, add_v4 on the
    # way into the ledger), so `added_routes` rows hold "" while this
    # function held "0.0.0.0". Two consequences, both observed:
    #   * the first comparison below saw "0.0.0.0" != "" and declared a
    #     gateway change on the SAME interface, re-pointing the entire geo
    #     set (thousands of add+delete) for nothing;
    #   * the unnormalised value was then COMMITTED to _live_mode['phys'],
    #     so on the next real change `old_gw` was "0.0.0.0" while every
    #     tracked row was "", no v4 row ever matched, and the VLESS endpoint
    #     /32 was never re-pointed - the exact failure this function exists
    #     to prevent.
    iface, gw = str(cur[0]), _norm_v4_gw(cur[1])
    # REFUSE a next hop that is not IPv4. The candidate comes from a
    # PowerShell lookup, and one lookup bug must never be able to re-point
    # every route we own: the re-point below moves the LAN bypasses, the
    # endpoint /32s and the geo set, then COMMITS the new egress in
    # _live_mode['phys'] - so a bad value poisons egress resolution for the
    # rest of the session, not just this call. An IPv6 next hop here (which
    # is exactly what a dual-stack CIM DefaultIPGateway lookup returned) made
    # every single add fail with "Invalid nexthop parameter ... should be a
    # valid IPv4 address" and left the proxy endpoint bypass uninstallable.
    if _wrong_family_gw(gw, 4):
        print(f"[!] Gateway check: the reported IPv4 default on {iface} has a "
              f"non-IPv4 next hop ({gw!r}) - ignoring it rather than "
              "re-pointing every route onto it.", flush=True)
        return
    # Same reasoning, one step up: a VPN or tunnel interface is not a change
    # of PHYSICAL egress. get_ipv4_default()'s last-resort clause can answer
    # with the VPN when a full-tunnel VPN replaced the physical default (e.g.
    # mid-reconnect), and committing that would move the LAN bypasses, the
    # proxy /32 and the geo set onto the VPN - including the VPN endpoint's
    # own route, which then points the VPN server at the VPN. Ignore it and
    # keep the last-known-good physical egress.
    if _es.is_vpn_iface(iface) or _es.is_tun_iface(iface):
        print(f"[!] Gateway check: the reported IPv4 default is on {iface} "
              "(a VPN/tunnel adapter), not a physical egress change - keeping "
              "the current physical gateway.", flush=True)
        return
    if (iface.lower() == str(phys[0]).lower()
            and gw == str(phys[1] or "")):
        _gw_pending = None          # back on the known egress - drop candidate
        return
    now = time.time()
    cand = (iface, gw)
    if _gw_pending != cand or (now - _gw_pending_since) < 2.0:
        if _gw_pending != cand:
            _gw_pending, _gw_pending_since = cand, now
        return
    _gw_pending = None
    old_iface, old_gw = str(phys[0]), _norm_v4_gw(phys[1])
    print(f"[GATEWAY] Physical egress changed: "
          f"{old_iface} ({old_gw}) -> {iface} ({gw})", flush=True)
    print("[*] Re-pointing pinned routes to the new gateway...", flush=True)
    old6 = _live_mode.get("phys6") or None
    try:
        d6 = get_ipv6_default()
        new6 = ((d6["InterfaceAlias"], d6.get("NextHop") or "")
                if d6 else None)
    except Exception:
        new6 = None
    try:
        moved = _repoint_pinned_routes(old_iface, old_gw, iface, gw,
                                       old6=old6, new6=new6)
        print(f"[+] {moved} endpoint/LAN route(s) re-pointed "
              f"to {iface} ({gw}).", flush=True)
    except Exception as e:
        print(f"[!] Endpoint re-point failed: "
              f"{e.__class__.__name__}: {e}", flush=True)
    # Geo bypasses: potentially thousands of routes - move them on a worker
    # thread so the monitor loop never stalls. Only the physical-egress rows
    # are touched (geo via wintun/VPN never matches the old physical iface).
    if any(str(it[2]).lower() == old_iface.lower() for it in list(geoip_added)):
        def _worker():
            try:
                # Honour a teardown that started while we were queued.
                # Checked TWICE: here, and again INSIDE the lock below. The
                # single outer check was a hole - a worker already blocked on
                # _geo_repoint_lock (or already inside a re-point) had passed
                # it, so a cleanup() arriving a moment later cancelled
                # nothing and the thread went on installing its thousands of
                # routes with the teardown already under way.
                if _geo_install_cancel.is_set():
                    return
                with _geo_repoint_lock:
                    if _geo_install_cancel.is_set():
                        return
                    n = _repoint_geo_routes(old_iface, iface, gw)
                if n:
                    print(f"[+] geoip: {n} route(s) re-pointed to the new "
                          f"gateway.", flush=True)
                else:
                    print("[!] geoip: re-point moved no routes - the country "
                          "bypass may still be pinned to the old gateway.",
                          flush=True)
            except Exception as e:
                print(f"[!] geoip gateway re-point failed: "
                      f"{e.__class__.__name__}: {e}", flush=True)
        # Publish the handle so cleanup() can join it (see
        # _stop_geo_installer). The thread used to be fire-and-forget.
        _geo_repoint_thread = threading.Thread(
            target=_worker, name="geo-repoint", daemon=True)
        _geo_repoint_thread.start()
    # The metric lowering (if any) was applied to the OLD interface: put it
    # back, then re-arm on the new one (no-op without a connected VPN).
    try:
        restore_physical_metric()
        ensure_physical_metric_below_vpn(iface)
    except Exception:
        pass
    _live_mode["phys"] = (iface, gw)
    _live_mode["phys6"] = new6


def ensure_wintun_ipv4():
    """Ensure the Wintun IPv4 address (192.168.123.1/24) is present before
    pointing IPv4 routes at it. If it is missing, every IPv4 wintun route add
    fails and the 'TUN default route' check reports 'Wintun split-default
    routes missing'."""
    return _ensure_wintun_address("IPv4", TUN4, TUN4_MASK)


# The Wintun subnets are defined in tuntop.config.defaults
# (WINTUN4_NET / WINTUN6_NET); a bypass route that overlaps either would
# shadow the tunnel's own next-hop and break every Wintun route add.
_WINTUN4_NET = WINTUN4_NET
_WINTUN6_NET = WINTUN6_NET


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
    # PREFIX-LENGTH FLOOR - this is the rule that actually enforces "a country
    # range is never a default route", and it was MISSING: the /0 rejection
    # the README and SECURITY.md promise rested entirely on a hardcoded
    # six-string _skip set in the caller, so 0.0.0.0/1, ::/2, 2000::/3,
    # 32.0.0.0/3 and hundreds more sailed straight through. Installed at
    # metric=1 as store=active routes, a range this broad is more specific
    # than the tunnel's 0/0 + /1 (and ::/0 + ::/1 + 8000::/1) split-defaults
    # and therefore captures ALL traffic outside the tunnel - a hostile or
    # merely corrupt geoip.dat could exfiltrate the user's whole connection
    # while the dashboard still reported RUNNING.
    # Floors are deliberately conservative (no real country block is this
    # broad) so a legitimate large-country range is never dropped.
    if net.prefixlen < (8 if net.version == 4 else 16):
        return False
    return True


def _geo_overlaps_protected(cidr, protected):
    """True if geo CIDR `cidr` IS, or is INSIDE, one of `protected`'s prefixes.

    Protected prefixes are routes that must keep the egress THEY were given:
    the tunnel's own endpoint host routes (VLESS, proxy2 upstream, Windows VPN)
    and the user's explicit bypass entries.  A geoip country list routinely
    contains such addresses - a VLESS server hosted in the bypassed country, a
    CDN range the file lists, even an exact /32 identical to a bypass route.
    Installing the geo route for those - or worse, letting the pre-install
    conflict sweep delete the existing route with the same exact prefix and
    re-add it pointing at the geo egress - hijacks the transport into its own
    tunnel (the classic "changed the server with [U] and now every request to
    the server IP loops and fails") or silently moves user-bypassed traffic
    onto the geo egress instead of the egress the bypass entry names."""
    try:
        g = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    for p in protected or ():
        try:
            net = ipaddress.ip_network(str(p), strict=False)
        except ValueError:
            continue
        if g.version == net.version and g.subnet_of(net):
            return True
    return False


def collect_protected_geo_prefixes(server_v4=(), server_v6=(),
                                   bypass_v4=(), bypass_v6=(),
                                   vpn_v4=(), vpn_v6=(),
                                   proxy2_v4=(), proxy2_v6=(),
                                   cidr_entries=()):
    """Every prefix geoip must never own (install OR remove).

    Plain endpoint IPs become /32 (v4) / /128 (v6) host routes; `cidr_entries`
    (raw --bypass-ip / --proxy2-bypass-ip values that are already CIDRs) are
    taken as-is so even more-specific geo subnets INSIDE a user bypass range
    are skipped and the range keeps the egress the user chose for it."""
    prot = []

    def _reg(prefix):
        if prefix and prefix not in prot:
            prot.append(prefix)

    v4_all = list(server_v4 or ()) + list(bypass_v4 or ()) \
        + list(vpn_v4 or ()) + list(proxy2_v4 or ())
    v6_all = list(server_v6 or ()) + list(bypass_v6 or ()) \
        + list(vpn_v6 or ()) + list(proxy2_v6 or ())
    for ip in v4_all:
        _reg(f"{ip}/32")
    for ip in v6_all:
        _reg(f"{ip}/128")
    for entry in (cidr_entries or ()):
        e = str(entry).strip()
        if "/" not in e:
            continue
        try:
            ipaddress.ip_network(e, strict=False)
        except ValueError:
            continue
        _reg(e)
    return prot


# Geo install tuning (GEO_SUB_BATCH / GEO_MAX_WORKERS / GEO_SUB_TIMEOUT) is
# imported from tuntop.config.defaults - the sweep paths in the dashboard and
# the watchdog share the same script mechanism and must agree on it.


def _geo_remove_conflicts(cidrs, iface, fam):
    """Fast batched removal of any pre-existing route for our geo prefixes
    (on any real interface except wintun/wintun2).

    Two phases:
      1. ONE read-only Get-NetRoute scan that LISTS the matching
         (prefix, interface) pairs - no mutation happens in PowerShell.
      2. The actual deletes go through _remove_routes_bulk (concurrent
         `netsh -f` scripts) - the same fast path the installer and the exit
         cleanup use, milliseconds per route instead of ~50-100ms.

    Why not the old one-pipeline Remove-NetRoute sweep: the cmdlet costs
    ~50-100ms PER ROUTE, so after a hard close (Alt+F4 - the console dies,
    no cleanup runs) left ~3000 stale geo routes behind, the sweep needed
    MINUTES inside a run_ps(timeout=120) call. It was killed mid-sweep on
    every start, the table stayed half-cleaned, and the install that follows
    fought the leftovers - "opening the tun again takes forever to add geo".

    This drops BOTH routes a self-healing Windows VPN re-injected on a
    different interface AND stale routes left behind by a previous run on the
    SAME physical interface (the latter matters because pre-store=active
    builds installed geoip routes PERSISTENTLY; netsh delete clears BOTH
    stores, so those leftovers are caught too)."""
    if not cidrs:
        return
    af = "IPv4" if fam == "v4" else "IPv6"
    routes_lit = ",".join("'%s'" % ps_quote(r) for r in cidrs)
    # Read-only scan only: list "prefix|iface" for every route whose prefix is
    # one of ours and which does NOT live on a tunnel adapter (any
    # Wintun-driver adapter, ours or a foreign TUN: xray's 'xray_tun' etc.).
    # (geo-via-wintun mode installs ON the tunnel adapters - those must stay.)
    ps = (
        _tun_alias_powershell() +
        "$hs = [System.Collections.Generic.HashSet[string]]::new(); "
        "%s | ForEach-Object { $null = $hs.Add($_) }; "
        "Get-NetRoute -AddressFamily '%s' -ErrorAction SilentlyContinue | "
        "Where-Object { $hs.Contains($_.DestinationPrefix) -and "
        "$tunAliases -notcontains $_.InterfaceAlias } | "
        "ForEach-Object { \"$($_.DestinationPrefix)|$($_.InterfaceAlias)\" }"
    ) % (routes_lit, af)
    _code, out, _err = run_ps(ps, timeout=90)
    hits = _geo_sweep_hits(out, fam)
    if not hits:
        return
    print(f"[*] geo sweep ({fam}): {len(hits)} stale/conflicting route(s) "
          f"from an earlier run - bulk-removing before install...",
          flush=True)
    _remove_routes_bulk(hits)


def _geo_sweep_hits(out, fam):
    """Parse the conflict scan's "prefix|iface" lines into deduplicated
    (fam, dest, iface, "") tuples for _remove_routes_bulk.

    netsh delete route prefix + interface removes EVERY route for that prefix
    on that interface (any next-hop), so duplicate (prefix, iface) pairs
    collapse. Junk lines (blank, no '|', empty halves) are skipped. Pure
    string handling - unit-testable without Windows."""
    hits = []
    seen = set()
    for ln in (out or "").splitlines():
        ln = ln.strip()
        if "|" not in ln:
            continue
        dest, _sep, alias = ln.partition("|")
        dest, alias = dest.strip(), alias.strip()
        if not dest or not alias or (dest, alias) in seen:
            continue
        seen.add((dest, alias))
        hits.append((fam, dest, alias, ""))
    return hits


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


def add_geoip_bypass(code, cidrs, iface, gateway, v6iface=None, v6gw=None,
                     protected=(), reassert=()):
    """Install every CIDR in `cidrs` as a bypass route via the real (non-TUN)
    interface, so that country's traffic never enters the tunnel.

    protected: prefixes (strings like "1.2.3.4/32" or "5.0.0.0/16") that must
    keep their OWN egress - endpoint host routes and user bypass entries.  Any
    geo CIDR equal to or inside one of them is dropped from BOTH the conflict
    sweep and the install (without this, a geo range covering the VLESS server
    deletes + re-points the server's /32 and the transport loops; a user
    bypass range gets carved up by more-specific geo routes).

    reassert: (fam, dest, iface, gw) host routes re-installed idempotently
    AFTER the geo pass, so endpoint/bypass routes are provably back on their
    intended egress no matter what touched the table before.

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
        return []
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
        return []
    # PROTECTED PREFIXES OUTRANK GEOIP (endpoints + user bypass).  A geoip
    # country list can contain the VLESS/VPN server's own IP - even as an
    # exact /32 equal to the server's host route.  Without this guard the
    # conflict sweep below DELETES that /32 (exact-prefix match) and the geo
    # route for the same prefix is re-added pointing at the GEO egress, so
    # the proxy transport loops into its own tunnel: endless failing
    # connects to the server IP in the log (the classic "[U] server change
    # broke it" report).  The same guard keeps a user bypass entry on the
    # egress its entry names: geo CIDRs equal to or inside a bypass prefix
    # (host /32 or a whole range) are dropped here, so the more-specific-or-
    # equal bypass route always wins the lookup.
    if protected:
        _pre_prot = len(v4) + len(v6)
        v4 = [c for c in v4 if not _geo_overlaps_protected(c, protected)]
        v6 = [c for c in v6 if not _geo_overlaps_protected(c, protected)]
        _dropped = _pre_prot - (len(v4) + len(v6))
        if _dropped:
            _geo_diag(("skip_protected", code),
                      f"[!] geoip:{code} bypass: skipped {_dropped} CIDR(s) equal to or "
                      f"inside protected endpoint/bypass prefixes (those keep their own "
                      f"egress - geoip must never own them).")
        if not v4 and not v6:
            _geo_diag(("skip_allprotected", code),
                      f"[!] geoip:{code} bypass skipped (every CIDR overlaps a "
                      f"protected endpoint/bypass prefix).")
            return []
    # The parsed CIDR counts are NOT installation counts.  A machine can have
    # thousands of country IPv6 prefixes in geoip.dat but no usable native IPv6
    # egress (for example, a Wi-Fi link with only a link-local address and no
    # physical ::/0 route).  In that case v6iface/v6gw are None and the v6
    # batches are correctly omitted below.  Say that explicitly instead of
    # printing "Installing ... 1036 IPv6" and then scheduling only IPv4.
    v4_egress = bool(v4) and bool(iface) and gateway is not None
    v6_egress = bool(v6) and bool(v6iface) and v6gw is not None
    if v4_egress:
        gateway_msg = (f"gw={gateway}" if gateway else
                       "no gateway - on-link")
        v4_msg = f"{len(v4)} IPv4 via {iface} ({gateway_msg})"
    else:
        v4_msg = (f"{len(v4)} IPv4 skipped (no usable IPv4 egress - "
                  "no IPv4 default route/interface selected)")
    if v6_egress:
        v6_msg = f"{len(v6)} IPv6"
    elif v6:
        v6_msg = (f"{len(v6)} IPv6 skipped (no usable IPv6 egress - "
                  "no IPv6 default route/interface selected)")
    else:
        v6_msg = "0 IPv6"
    print(f"[*] Installing geoip:{code} bypass "
          f"({v4_msg}; {v6_msg})", flush=True)
    scheduled_total = ((len(v4) if v4_egress else 0)
                       + (len(v6) if v6_egress else 0))
    # Heartbeat BEFORE the slow pre-install passes below.  The dashboard's
    # startup watchdog extends its grace window while [GEO-LOAD] markers keep
    # arriving; without this early marker the metric fix + conflict sweep
    # (both PowerShell) run in total marker silence and a legitimate-but-slow
    # install gets killed at the plain startup timeout ("helper hung for 90s"
    # right after "Installing geoip..." - the exact report from the field).
    print(f"[GEO-LOAD] code={code} loaded=0 total={scheduled_total}", flush=True)
    # Direct (physical) geo case: a self-healing Windows VPN re-injects its own
    # routes for these exact CIDRs, so beating it requires the physical
    # interface metric to sit below the VPN's.  No-op when geo is routed via
    # wintun (--geoip-via-vpn) or the VPN itself (--geoip-via-win-vpn).
    if iface and not _is_wintun_alias(iface):
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
    # Heartbeat: the sweep above can take a while on a bloated route table -
    # tell the dashboard it is still alive before the sub-batch installs start
    # emitting their own markers.
    print(f"[GEO-LOAD] code={code} loaded=0 total={scheduled_total}", flush=True)

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
    # Registration is upfront (before any netsh runs) and lock-guarded, so a
    # cleanup() racing this install always SEES every route it is about to
    # install and can bulk-remove it - no untracked leftovers.
    with _geo_state_lock:
        registered = []
        for fam, subset, ifa, gw in (("v4", v4, iface, gateway),
                                     ("v6", v6, v6iface, v6gw)):
            if not subset or not ifa or gw is None:
                continue
            for i in range(0, len(subset), GEO_SUB_BATCH):
                grp = subset[i:i + GEO_SUB_BATCH]
                sub_batches.append((fam, grp, ifa, gw))
                for r in grp:
                    row = (fam, r, ifa, gw)
                    registered.append(row)
                    geoip_added.append(row)
    if not sub_batches:
        _geo_diag(("skip_noiface", code),
                  f"[!] geoip:{code} bypass skipped (no usable CIDRs / no interface + next-hop).")
        return []
    total = sum(len(g) for _, g, _, _ in sub_batches)
    loaded = 0
    geo_lock = threading.Lock()
    err_by_fam = {}
    if total:
        print(f"[GEO-LOAD] code={code} loaded=0 total={total}", flush=True)

    def _install_sub(fam, grp, ifa, gw):
        nonlocal loaded
        if _geo_install_cancel.is_set():
            # Teardown started mid-install: skip the remaining sub-batches
            # so we cannot add routes behind cleanup()'s bulk delete.
            return
        netsh_verb = "ipv4" if fam == "v4" else "ipv6"
        iface_dq = '"' + str(ifa).replace('"', '') + '"'
        # IPv6 on-link routes have gw='' (or '::', already normalized to ''
        # upstream).  netsh requires the gateway part to be omitted entirely
        # for on-link routes - a bare double-space token is rejected.
        gw_part = (" " + str(gw)) if gw else ""
        lines = ["interface %s add route %s %s%s metric=1 store=active"
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
                # NOTE: no print here. This runs on a ThreadPoolExecutor
                # worker; during a live [R] re-apply the dashboard's stdout
                # sink only intercepts the INSTALLING thread, so a print
                # here punches a raw "[GEO-LOAD] ..." line straight through
                # the TUI frame (the stray [GEO-LOAD] text burned into the
                # dashboard) AND the marker never reaches the progress
                # panel (bar stuck at 0%). The joining thread below emits
                # the marker after each future completes instead.

    with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(len(sub_batches), GEO_MAX_WORKERS)) as ex:
        futures = [ex.submit(_install_sub, fam, grp, ifa, gw)
                   for fam, grp, ifa, gw in sub_batches]
        for fut in concurrent.futures.as_completed(futures):
            try:
                fut.result()
            except Exception:
                pass
            # Progress marker on the INSTALLING (sink-owner) thread, once
            # per finished sub-batch: `loaded` is the geo_lock-guarded
            # total the workers advanced. The old code printed from the
            # worker threads themselves - during a live [R] re-apply those
            # writes bypassed the dashboard's stdout sink (it only
            # intercepts the installing thread), so the raw "[GEO-LOAD]"
            # text punched straight through the TUI frame AND the progress
            # panel never saw the markers (bar stuck at 0%).
            if total:
                with geo_lock:
                    cur = loaded
                print(f"[GEO-LOAD] code={code} loaded={cur} total={total}",
                      flush=True)
    for fam in ("v4", "v6"):
        if fam in err_by_fam:
            msg = f"[!] geoip:{code} {fam} batch had route failures (continuing)."
            diag = err_by_fam[fam]
            if diag:
                msg += f"  first error: {diag}"
            _geo_diag(("routefail", code, fam), msg)
    # Belt-and-braces: re-install the protected host routes the caller handed
    # us.  add_v4/add_v6 are idempotent (an identical route is kept, a drifted
    # one is replaced), so this is a cheap no-op when the table is already
    # right - and a self-repair when anything above (or another actor) left an
    # endpoint / user-bypass host route missing or on the wrong egress.
    # Without it, the moment a covering geo range outlives the /32, the
    # transport silently rides the country ranges and loops.
    for fam_r, dest_r, iface_r, gw_r in (reassert or ()):
        if not iface_r or gw_r is None:
            continue
        try:
            if fam_r == "v4":
                add_v4(dest_r, iface_r, gw_r, metric=1)
            else:
                add_v6(dest_r, iface_r, gw_r, 1)
        except Exception:
            pass
    # Signal the dashboard that this category's install pass is finished - even
    # if some routes failed (loaded < total).  Without this, the dashboard's
    # progress panel would stay on screen forever once any route failed, since
    # its "incomplete" condition never clears.  The dashboard starts a linger
    # window on this marker and then hides the panel.
    if total:
        print(f"[GEO-DONE] code={code} loaded={loaded} total={total}", flush=True)
    return registered


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
        # Skip, do not abort, a row we cannot even build a command from. One
        # malformed ledger row (a tuple of the wrong arity from a half-written
        # append, say) used to raise inside this comprehension and take the
        # whole GEO_SUB_BATCH-sized chunk with it - so up to 99 perfectly good
        # routes were never deleted, and because netsh delete clears both
        # stores and the dashboard's sweep only re-checks GEO cidrs, a lost
        # VPN-override or endpoint /32 in a mixed list could survive the
        # teardown. A route that is already gone is the desired end state;
        # a row we cannot parse is reported and skipped.
        lines = []
        for row in grp:
            try:
                fam, dest, iface, gw = row
            except (TypeError, ValueError):
                _say(f"[!] Skipping a malformed route row during bulk "
                     f"removal: {row!r}")
                continue
            if not dest:
                _say(f"[!] Skipping a route row with no destination: {row!r}")
                continue
            verb = "ipv4" if fam == "v4" else "ipv6"
            iface_dq = '"' + str(iface).replace('"', '') + '"'
            # Bare prefix / gateway tokens - quoting is rejected by netsh for
            # add (see _install_sub); delete follows the same rule.
            # On-link gateways are normalised away: "0.0.0.0" is a truthy
            # string and used to be appended as a next-hop token on delete,
            # where netsh treats it as a literal interface name.
            gw_tok = (" %s" % str(_norm_v4_gw(gw))) if _norm_v4_gw(gw) else ""
            lines.append("interface %s delete route %s %s%s"
                         % (verb, dest, iface_dq, gw_tok))
        if not lines:
            return
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
    # Guard against atexit/interpreter-shutdown: a ThreadPoolExecutor created
    # in an atexit callback can hit RuntimeError("cannot schedule new futures
    # after interpreter shutdown") if the interpreter is already tearing down
    # its internal threading state. Catch and fall back to a sequential drain.
    try:
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(len(chunks), GEO_MAX_WORKERS)) as ex:
            for _fut in concurrent.futures.as_completed(
                    [ex.submit(_drop_chunk, c) for c in chunks]):
                try:
                    _fut.result()
                except Exception:
                    pass
    except RuntimeError:
        # Interpreter shutting down: run remaining chunks sequentially.
        for c in chunks:
            try:
                _drop_chunk(c)
            except Exception:
                pass


def _say(msg):
    """Print a teardown line without ever raising.

    The helper's stdout is a PIPE owned by the dashboard. If the dashboard
    is gone (crash, Alt+F4, Task Manager), every print raises
    BrokenPipeError/OSError - and a raising print used to abort cleanup()
    outright, leaving stale /32s, the split-defaults, a lowered interface
    metric, a live tun2socks.exe and the catch-all NRPT DNS pin behind.
    Progress output is never worth a skipped teardown step."""
    try:
        print(msg, flush=True)
    except Exception:
        pass


def _step(label, fn):
    """Run one teardown phase, containing any failure to THAT phase.

    cleanup() must never abort part-way: whatever is left behind (stale
    routes, a live tun2socks, a pinned resolver) is exactly the state the
    exit sweeps and the detached watchdog exist to repair, and they can only
    do that if the small critical steps actually ran.

    BaseException, not Exception. This module is explicitly aware of the trap
    - it uses `except (Exception, SystemExit)` in the self-heal and
    `except BaseException` in the signal handler, because several platform
    helpers can sys.exit() - yet _step, the one chokepoint whose entire job
    is containment, kept the narrow clause. A KeyboardInterrupt (a second
    Ctrl+C, or an interruptible Thread.join) or a SystemExit raised inside
    any teardown helper therefore skipped EVERY remaining step, and because
    of the phase order the casualty is specifically the DNS guard: restoring
    the interface metric runs before removing the NRPT pin.
    """
    try:
        return fn()
    except (Exception, SystemExit, KeyboardInterrupt) as e:
        _say(f"[!] Cleanup step '{label}' failed: {e}")
        return None


def cleanup():
    global cleaned
    global _cleanup_in_progress
    if cleaned or _cleanup_in_progress:
        # Re-entrancy latch, INSIDE cleanup(). It used to be set only in
        # _on_signal, so `atexit.register(cleanup)` - a second entry point
        # with no guard at all - could re-enter: a Ctrl+C during the atexit
        # teardown saw _cleanup_in_progress still False, called cleanup()
        # again from INSIDE the running teardown, and then os._exit(0)'d out
        # of the outer pass, abandoning the remaining steps. That is exactly
        # the repeat-Ctrl+C-during-teardown case the flag was added to fix;
        # it was only fixed on the signal path. The teardown is also run
        # twice end-to-end that way - a second full netsh storm over the geo
        # ledger while the first is still in flight - which is what turns a
        # slow stop into the force-kill-mid-sweep the flag exists to avoid.
        # Every teardown step is idempotent, so latching (rather than
        # re-running) is both safe and correct.
        return
    _cleanup_in_progress = True
    # NOTE: `cleaned = True` moves to the END. Setting it first meant a
    # single failure in the first second permanently disabled cleanup for
    # the process (a later atexit/second-signal call returned immediately),
    # so a transient error turned into "no teardown at all".
    _step("drop control file", _drop_control_file)
    _step("restore physical interface metric", restore_physical_metric)
    # Drop the DNS leak guard right away: it rewrites system-wide name
    # resolution, so it must not outlive the tunnel even if the OS kills this
    # process during the longer route sweeps below.
    _step("remove DNS leak guard", _remove_dns_guard)
    # The geo install thread can still be adding routes; stop it and WAIT for
    # it before snapshotting the ledger, or a sub-batch that lands after the
    # snapshot installs routes nothing will ever track (uncleanable, and the
    # [Q] sweep has no receipts to match).
    _step("stop geo installer", _stop_geo_installer)

    # ORDER MATTERS (this was the Alt+F4 hole): cleanup() runs inside the
    # console-close window, and the OS may kill us mid-way when it expires.
    # The old order did the SLOW bulk geo delete FIRST, so everything after
    # it - the endpoint /32+/128 host routes, the VPN-override undo - never
    # ran, and "the servers I added stay in the routing table after Alt+F4"
    # was exactly that. Now every small, CRITICAL teardown runs before the
    # one long pole (the thousands-of-routes geo bulk delete) so a kill
    # mid-cleanup can only ever leave geo routes behind - those the exit
    # sweeps and the detached watchdog still remove by CIDR matching.
    _say("\n[*] Cleaning up routes...")
    # Remove the VPN-override routes we added to keep the tunnel the sole egress,
    # then restore the VPN's original injected routes we shadowed.
    #
    # BULK, not one netsh process per route (see _remove_routes_bulk). A VPN
    # client injects a whole table, and this loop was a process spawn per row
    # - the single largest contributor to a multi-second "Stopping tunnel
    # helper" step.
    if vpn_override_routes:
        _say(f"[*] Removing {len(vpn_override_routes)} VPN-override routes...")
        _step("remove VPN-override routes",
              lambda: _remove_routes_bulk(
                  list(reversed(list(vpn_override_routes)))))
        vpn_override_routes.clear()
    with _vpn_saved_lock:
        if vpn_saved_routes:
            _say(f"[*] Restoring {len(vpn_saved_routes)} VPN routes...")
            # Re-ADD, not delete: the batch helper only deletes, so these stay
            # on the (already batched) _raw_add_route path.
            _step("restore shadowed VPN routes", lambda: [
                _raw_add_route(fam, dest, iface, gateway, metric,
                               store="persistent")
                for fam, dest, iface, gateway, metric
                in reversed(vpn_saved_routes)])
            vpn_saved_routes.clear()
    # Remove every route this helper installed (endpoint /32+/128 bypasses,
    # LAN bypasses, TUN default/split routes) - CRITICAL, and now BULK.
    #
    # This was the teardown's worst offender: one `netsh` PROCESS per route,
    # serially. A typical session owns 25-35 rows here (6 TUN default/split,
    # ~10 LAN bypasses, the Wintun host routes, the VLESS /32s, the VPN
    # endpoint /32s), and a netsh spawn costs hundreds of ms - tens of
    # seconds of pure process-launch overhead before teardown even reached
    # the geo sweep. _remove_routes_bulk runs the identical
    # `interface <fam> delete route ...` lines through `netsh -f` in chunks
    # of GEO_SUB_BATCH, so this is typically ONE process instead of thirty.
    # It also swallows "already gone" errors, which is the desired end state
    # here, and the dashboard's exit sweep still re-checks the live table.
    _step("remove installed routes",
          lambda: _remove_routes_bulk(
              list(reversed(list(added_routes)))))
    added_routes.clear()

    _step("stop tun2socks", _stop_tun2socks)

    # Restore Wintun's original per-family interface metric (only the families
    # we actually lowered). Restore per AddressFamily so an IPv6 value never lands
    # on IPv4 and vice-versa. Robust to the legacy int/None shape so a stale
    # module state (or a test that sets the global to None) can't crash cleanup.
    _step("restore wintun interface metric", _restore_wintun_metric)

    # LAST: the long pole. Bulk-remove geoip bypass routes (can be thousands
    # of entries) - if the OS kills us during THIS, only geo routes survive,
    # and the dashboard's exit sweep / the watchdog remove those by CIDR.
    # Snapshot + clear under the state lock so a concurrently registering
    # install (or a gateway re-point rewrite) can never leak untracked rows.
    def _geo_sweep():
        with _geo_state_lock:
            geo_rows = list(geoip_added)
            geoip_added.clear()
        if geo_rows:
            _say(f"[*] Cleaning up {len(geo_rows)} geoip bypass routes...")
            _remove_routes_bulk(geo_rows)
    _step("remove geoip bypass routes", _geo_sweep)

    _say("[*] Done.")
    # Only now: cleanup is complete and a second call is genuinely redundant.
    cleaned = True
    # Release the re-entrancy latch. It exists to stop a CONCURRENT or
    # recursive call (a second Ctrl+C arriving mid-teardown, or atexit firing
    # inside the running pass) from executing a second full sweep - not to
    # disable cleanup() permanently. `cleaned` above is what makes a repeat
    # call redundant once this pass really finished; leaving the latch set
    # would also strand the flag on forever if this pass raised.
    _cleanup_in_progress = False


def _drop_control_file():
    """Drop the live-reconfig control file so a DNS choice made via [N] in
    THIS session can never leak into a future run (the next helper run also
    baselines the file's mtime - this just removes the stale state)."""
    global _control_mtime
    try:
        os.remove(CONTROL_FILE)
        _control_mtime = 0.0
    except OSError:
        pass


def _stop_geo_installer():
    """Cancel and JOIN the geo install / re-point threads.

    Only _on_signal used to do this. On a NORMAL exit (tun2socks dies, the
    monitor loop ends, main() returns, atexit fires) cleanup() raced the
    still-running daemon thread: it snapshotted and cleared the ledger, then
    the thread installed a batch AFTER the delete - routes in the table that
    no ledger and no later sweep could match.
    """
    # No `global` needed: the thread handles are READ here (via globals()),
    # never rebound - _check_gateway_change owns the assignment.
    _geo_install_cancel.set()
    for _name in ("_geo_install_thread", "_geo_repoint_thread"):
        t = globals().get(_name)
        if t is None or not t.is_alive() or t is threading.current_thread():
            continue
        # ESCALATE, do not give up. A single join(timeout=30) is a WAIT, not a
        # join, and it is sized far below the work it has to cover: the
        # tuner's own constants (GEO_SUB_BATCH=100, GEO_MAX_WORKERS=6,
        # GEO_SUB_TIMEOUT=90) put a 3000-CIDR country at 30 chunks over 6
        # workers - up to 5 waves of 90s. The join therefore timed out on
        # exactly the large geoip files the installer exists to handle, and
        # cleanup() went on to snapshot + clear the ledger while the thread
        # was still installing. The README claimed the threads are
        # "cancelled and joined before the route ledger is snapshotted";
        # that was only ever true for a small country.
        try:
            t.join(timeout=30)
            if t.is_alive():
                _say("[!] geo thread still busy after 30s - waiting for it "
                     "to finish so its routes stay tracked.")
                t.join(timeout=120)
            if t.is_alive():
                # Last resort. Say so loudly: cleanup() is about to snapshot
                # the ledger, and whatever this thread installs after that
                # point is untracked by construction.
                _say("[!] geo thread did not stop - any route it is still "
                     "installing will NOT be tracked or removed. Re-run "
                     "TunTop to sweep, or remove them by hand.")
        except Exception:
            pass


def _stop_tun2socks():
    for _name, _label in (("tun_proc", ""),
                          ("tun2_proc", " (second proxy pipe)")):
        p = globals().get(_name)
        if p is None or p.poll() is not None:
            continue
        _say(f"[*] Stopping tun2socks{_label}...")
        try:
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        except Exception as e:
            _say(f"[!] Could not stop tun2socks{_label}: {e}")


def _restore_wintun_metric():
    global wintun_saved_metric
    saved = wintun_saved_metric if isinstance(wintun_saved_metric, dict) else None
    if saved is None or not (saved.get("v4") is not None
                             or saved.get("v6") is not None):
        return
    for fam, key in (("IPv4", "v4"), ("IPv6", "v6")):
        val = saved.get(key)
        if val is None:
            continue
        try:
            run_ps(f"Set-NetIPInterface -InterfaceAlias '{TUN}' "
                   f"-AddressFamily {fam} -InterfaceMetric {val}")
        except Exception:
            pass
    wintun_saved_metric = {"v4": None, "v6": None}


def _probe_tunnel_once(url="https://api.ipify.org/", timeout=5):
    """One-shot verification that DNS resolves AND HTTPS fetches through the
    TUN. Returns (ok, message). Does NOT retry - the caller loops / self-heals.

    The host is derived from the URL WITHOUT its scheme or path, so a literal
    like "https://api.ipify.org/" is normalized to "api.ipify.org" before being
    handed to getaddrinfo (passing the scheme is exactly what produced the old
    "[Errno 11001] getaddrinfo failed" crash)."""
    import urllib.request
    # B310: every entry in _VERIFY_URLS is http(s). urlopen would happily take
    # file:, ftp: or data: as well, and this probe's verdict is what declares a
    # tunnel healthy, so a caller passing a non-http(s) URL is a bug that must
    # fail here rather than be "verified" by reading something local.
    if not url.startswith(("https://", "http://")):
        return False, f"probe URL is not http(s): {url[:48]}"
    # The urlopen below carries an inline bandit suppression for B310, whose
    # check is static (it flags every urlopen whose URL is not a string
    # literal) and cannot see this guard.
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
        with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310
            body = r.read(64).decode("utf-8", "replace").strip()
            status = getattr(r, "status", None) or r.getcode()
        if body:
            return True, f"{host} resolved -> {', '.join(addrs)}; public IP = {body}"
        # An empty body is only a failure for an endpoint that PROMISES one.
        # connectivitycheck.gstatic.com/generate_204 answers HTTP 204 No
        # Content by design - zero-length body, and urlopen does not raise for
        # a 204. It is the FIRST entry in _VERIFY_URLS precisely because it
        # answers in <100ms from almost anywhere, so scoring it as a failure
        # meant the fastest, most reliable endpoint could never succeed: five
        # retries burned the whole 8s round proving a working endpoint was
        # broken, and if the http:// fallbacks were blocked the round
        # returned False on a tunnel that stage 1 had just proven carries
        # packets -> a false "TUNNEL DEGRADED".
        if status in (204, 205, 304):
            return True, (f"{host} resolved -> {', '.join(addrs)}; "
                          f"HTTP {status} (no body, as expected)")
        return False, (f"{host} resolved ({', '.join(addrs)}) but empty body "
                       f"(HTTP {status})")
    except Exception as e:
        return False, f"{host} resolved ({', '.join(addrs)}) but fetch failed: {e}"


def _probe_tunnel_multi(timeout=4, urls=None):
    """Probe the tunnel against SEVERAL fast endpoints (see _VERIFY_URLS) and
    return (ok, message) on the FIRST success.

    All endpoints are probed CONCURRENTLY (one thread each, first success
    wins) - the same strategy wait_for_tunnel_stable() uses at startup. The
    monitor loop used to try the URLs ONE BY ONE, so a single slow/blocked
    endpoint (api.ipify.org's TLS handshake timing out through a congested
    tunnel) delayed the verdict by its full timeout AND could be the only
    message reported even though the faster endpoints also matter. Racing
    them all at once means a healthy tunnel is confirmed in <=timeout no
    matter how many endpoints are blocked, and a genuine outage collects
    every endpoint's error for the failure report.

    On total failure the message lists each endpoint's last error, so the
    operator can see WHICH endpoints disagreed rather than only the last
    one tried."""
    urls = list(urls or _VERIFY_URLS)
    if len(urls) == 1:
        return _probe_tunnel_once(urls[0], timeout=timeout)

    results: dict[str, str] = {}

    def _run(url):
        ok, msg = _probe_tunnel_once(url, timeout=timeout)
        host = _host_from_url(url) or url
        if ok:
            results[host] = ""          # success marker
        else:
            detail = msg.split(": ", 1)[-1] if ": " in msg else msg
            results[host] = detail

    # Every probe has its own `timeout`, so waiting for ALL of them costs at
    # most ~timeout seconds - exactly what ONE sequential failing probe used
    # to cost - while a healthy tunnel is confirmed by whichever endpoint
    # answers first. Bounded beyond that so a wedged getaddrinfo/urlopen
    # (they honour the socket timeout only loosely during DNS) cannot stall
    # the monitor loop.
    # NOT a `with ThreadPoolExecutor(...)` block. __exit__ calls
    # shutdown(wait=True), which blocks until EVERY worker thread finishes -
    # so the `timeout + 5` below would buy nothing and the bound this
    # function documents would be void. (That is exactly what a first attempt
    # at this fix did; the two sibling probes in this file, _probe_tunnel_no_dns
    # and wait_for_tunnel_stable's _run_round, both already use the explicit
    # shutdown form. This was the one straggler.)
    #
    # It matters: when plain UDP/53 cannot traverse the tunnel - the normal
    # state for a SOCKS5 client without a working UDP relay - Windows walks
    # every configured resolver with multi-second timeouts and getaddrinfo has
    # no timeout at all. One wedged probe froze the ENTIRE monitor loop: no
    # [MONITOR] lines, no SOCKS5-up recovery, no endpoint self-heal, no
    # gateway re-point, and the dashboard saw a dead helper.
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=len(urls))
    try:
        futs = [ex.submit(_run, u) for u in urls]
        concurrent.futures.wait(futs, timeout=timeout + 5)
        for f in futs:
            f.cancel()
    finally:
        ex.shutdown(wait=False, cancel_futures=True)

    # First success wins.
    winner = next((h for h, v in results.items() if v == ""), None)
    if winner is not None:
        return True, winner

    failures = [f"{h}: {d}" for h, d in results.items() if d]
    if not failures:
        return False, "no probe endpoint answered"
    return False, " | ".join(failures)


# ── Leak probe (monitor loop) ────────────────────────────────────────────────
# Proves that NO egress escapes the TUN, not just the verification probe's
# own HTTP: compares the DIRECT egress IP with the SOCKS-proxied egress IP.
# With the full-tunnel routes healthy, even a "direct" socket traverses
# wintun and exits at the SAME IP as the proxied request - so
#   direct == tunnel exit -> OK  (all traffic rides the TUN)
#   direct != tunnel exit -> LEAK (direct traffic escapes via the physical
#                                  NIC and reveals the real ISP IP)
# The mechanics (SOCKS5 client, endpoint racing, IP validation, verdicts)
# live in tuntop/network/leak_probe.py - a neutral stdlib leaf shared with
# the dashboard's monitor, so the two can never drift apart (a duplicated
# copy here is exactly how the inverted-verdict bug survived in the first
# place).  The leaf imports nothing from the UI/Monitor layers; the
# sys.path bootstrap below only makes the package importable when
# helper.py is launched as a standalone script (python helper.py puts
# tuntop/tunnel/ - not the package root - on sys.path).

def _import_leak_probe():
    """Import the shared leak-probe leaf, bootstrapping sys.path so this
    works whether helper.py runs as tuntop.tunnel.helper or standalone."""
    here = os.path.dirname(os.path.abspath(__file__))
    # tuntop/tunnel/ -> tuntop/ -> <package root> (the dir containing tuntop/)
    pkg_parent = os.path.dirname(os.path.dirname(here))
    if pkg_parent not in sys.path:
        sys.path.insert(0, pkg_parent)
    from tuntop.network import leak_probe
    return leak_probe


def _leak_probe(socks_port, timeout=5):
    """Compare DIRECT egress vs SOCKS-proxied egress concurrently.

    Returns (status, message) with status in
    {"ok", "same-exit", "leak", "no-proxy", "inconclusive", "no-network"} -
    see tuntop/network/leak_probe.py for the full verdict table."""
    status, message, _legs = _import_leak_probe().run_leak_probe(
        socks_port, timeout=timeout)
    return status, message


# Fast, reliable verification endpoints — tried in order.
# connectivitycheck.gstatic.com (Android check) and cp.cloudflare.com both
# respond in <100ms from almost anywhere; msftconnecttest.com (Windows' own
# NCSI probe) is another ultra-light fallback; api.ipify.org is LAST because
# it is slower and its TLS handshake through a congested tunnel can time out
# (which used to read as "tunnel broken" in the monitor even when the tunnel
# was fine).
_VERIFY_URLS = [
    "http://connectivitycheck.gstatic.com/generate_204",
    "http://cp.cloudflare.com/",
    "http://msftconnecttest.com/connecttest.txt",
    "https://api.ipify.org/",
]


_VERIFY_PRINT_LOCK = threading.Lock()

#: DNS-FREE tunnel liveness targets: LITERAL addresses, so no resolver is
#: consulted and nothing unbounded can be waited on. A TCP connect through the
#: TUN to one of these proves the tunnel forwards packets, which is the
#: question the URL round can only answer as a side effect.
_VERIFY_LITERAL_TCP = (("1.1.1.1", 443), ("8.8.8.8", 443), ("9.9.9.9", 443))
#: Per-connect ceiling. These are fat anycast edges: connected in ~100ms or
#: not at all, so this is generous.
_VERIFY_LITERAL_TIMEOUT = 3.0


def _probe_tunnel_no_dns(timeout=None):
    """(ok, msg) - can the TUN carry a TCP connection to a LITERAL address?

    This is the check that makes the start sequence fast and the log readable.
    The URL probes all begin with `getaddrinfo`, which has NO timeout: when
    plain UDP/53 cannot traverse the tunnel - the normal state for a SOCKS5
    client whose UDP relay does not work - Windows walks EVERY configured
    resolver (here 8.8.8.8 *and* an IPv6 one) with its own multi-second
    timeouts, so each of the four URLs cost 5-10s of pure resolver waiting to
    report the same thing, twice (plain round, then DoH round). That was the
    "Verifying the tunnel is stable..." spinner and the wall of
    "DNS resolve ... getaddrinfo failed" lines.

    Connecting to a literal IP skips the resolver entirely: it answers "is the
    tunnel forwarding packets?" in about a tenth of a second, which is the
    only question the start sequence actually needs answered. A failure here
    is a genuinely broken tunnel, and a success here means any later DNS
    failure is a RESOLVER problem - which the DoH escalation fixes, not more
    URL retries.

    Probed concurrently, first success wins."""
    import socket as _socket
    limit = _VERIFY_LITERAL_TIMEOUT if timeout is None else timeout
    if limit <= 0:
        return False, "no time left in the verification budget"

    def _one(host, port):
        try:
            with _socket.create_connection((host, port), timeout=limit):
                return True
        except Exception as e:
            return False, f"{host}:{port} {e}"

    ex = concurrent.futures.ThreadPoolExecutor(
        max_workers=len(_VERIFY_LITERAL_TCP))
    try:
        futs = [ex.submit(_one, h, p) for h, p in _VERIFY_LITERAL_TCP]
        concurrent.futures.wait(futs, timeout=limit)
        last = ""
        for (host, port), f in zip(_VERIFY_LITERAL_TCP, futs):
            if not f.done() or f.cancelled():
                continue
            res = f.result()
            if res is True:
                return True, f"TUN carries TCP to {host}:{port}"
            if isinstance(res, tuple):
                last = res[1]
        return False, last or "no literal endpoint answered"
    except Exception as e:
        return False, str(e)
    finally:
        ex.shutdown(wait=False, cancel_futures=True)


#: Wall-clock ceiling for the WHOLE start-sequence verification
#: (both rounds, including the DoH escalation). The tunnel is installed and
#: carrying traffic before this runs - it is a health signal, not a readiness
#: gate - so a bounded answer plus the monitor loop's re-probe is strictly
#: better than an unbounded wait on a resolver that may not answer for
#: minutes. Sizing: a healthy tunnel verifies in well under a second; a broken
#: one previously cost 20-30s of visible "Verifying the tunnel is stable...".
_VERIFY_BUDGET = 18.0
#: Per-round ceiling. The first round races 4 endpoints; the DoH round gets
#: whatever is left of the total budget.
_VERIFY_ROUND_BUDGET = 8.0
#: Once the tunnel is known to forward packets, this many consecutive
#: getaddrinfo failures mean the RESOLVER is the problem - not the tunnel.
#: Reaching it skips the remaining doomed round and goes straight to DoH.
_VERIFY_DNS_GIVEUP = 1


def _verify_worker(url, timeout, attempts, tag, shared):
    """Retry ONE verification URL until it succeeds or `attempts` run out.
    Runs on its own thread (all URLs are probed at the SAME time), so a dead
    endpoint can never delay the ones that work. First success anywhere wins.

    DNS-RESOLUTION failures (getaddrinfo/[Errno 11001] - plain UDP/53 through
    the TUN not working, e.g. a SOCKS client whose UDP relay is broken) give up
    after the FIRST try. They used to be retried twice with a 1s gap, which
    cost a second full resolve sweep - and getaddrinfo has no timeout, so
    against a configured-but-unreachable resolver (Windows walks every server
    with its own multi-second timeout) that is several more seconds of the
    start sequence burnt proving the resolver was still down, immediately
    before the DoH escalation that actually fixes it. The point of the
    failure is to trigger that escalation, so reach it in one step. Non-DNS
    failures (resolved, but the fetch failed) still get the full retry budget,
    since those can genuinely be transient."""
    dns_fails = 0
    for i in range(1, attempts + 1):
        ok, msg = _probe_tunnel_once(url, timeout=timeout)
        if ok:
            shared["ok"] = True
            shared["msg"] = msg
            return
        dns_fail = msg.startswith("DNS resolve")
        with _VERIFY_PRINT_LOCK:
            if shared["ok"]:
                return
            shared["last_err"] = msg.split(": ", 1)[-1] if ": " in msg else msg
            if dns_fail:
                # Every URL is racing the same broken resolver, so the
                # per-attempt line is pure repetition: the round already
                # speaks for itself with one line. The user's log used to
                # fill with a dozen identical "DNS resolve ... getaddrinfo
                # failed" entries, which said nothing except that the
                # resolver was down.
                shared["dns_seen"] = True
                shared["dns_urls"] = shared.get("dns_urls", 0) + 1
            else:
                print(f"    [{i}/{attempts}]{tag} {url}: {msg}", flush=True)
        if dns_fail:
            dns_fails += 1
            if dns_fails >= _VERIFY_DNS_GIVEUP:
                return   # give up on this URL - let the DoH escalation take over
        else:
            time.sleep(2)


def wait_for_tunnel_stable(timeout=5, budget=None):
    """Block until DNS + HTTP verification through the TUN succeeds.

    ALL _VERIFY_URLS are probed CONCURRENTLY (one worker thread each), so a
    blocked/unreachable endpoint no longer delays the working ones - the first
    success wins, in seconds, instead of waiting out 5 failed attempts per URL
    one by one. Each URL still retries up to 5 times with 2-second gaps.
    If every URL fails, auto-escalates to DoH DNS and retries the same way.

    Returns True if the tunnel is verified, False if all attempts fail.

    SPEED: the whole thing is bounded by `budget` wall-clock seconds
    (default _VERIFY_BUDGET). Two things used to make "Verifying the tunnel is
    stable..." the longest step in the entire start sequence:

      * socket.getaddrinfo has NO timeout parameter. With a resolver that is
        configured but unreachable - which is exactly the state plain UDP/53
        is in when it has to traverse a SOCKS5 tunnel - Windows walks every
        configured server (here 8.8.8.8 AND an IPv6 resolver) with its own
        multi-second timeouts, so one probe can burn 5-10s. `timeout` bounds
        the HTTP fetch, NOT the resolve, so nothing bounded the round.
      * `_run_round` waited on as_completed() with no deadline, so a single
        wedged resolve held the whole start open for the full retry budget,
        then paid it AGAIN for the DoH escalation round.

    A round now returns the moment its deadline passes or any endpoint
    verifies, and a failed start is not a dead tunnel: main() announces
    DEGRADED and the monitor loop re-probes (~5s later) and promotes to
    RUNNING on the first pass. So the budget trades a few seconds of a
    "Verifying..." spinner for a tunnel the user can actually use.
    """
    global _ACTIVE_DNS_MODE
    shared = {"ok": False, "msg": "", "last_err": "", "dns_seen": False}
    deadline = time.monotonic() + (budget if budget is not None
                                   else _VERIFY_BUDGET)

    def _remaining():
        return max(0.0, deadline - time.monotonic())

    # ── Stage 1: is the TUN forwarding packets AT ALL? ───────────────────
    # Answered with a LITERAL TCP connect, so no resolver is involved and
    # nothing unbounded can be waited on. This is what makes the start fast:
    # without it the four URL probes each pay an un-timed-out getaddrinfo
    # sweep (5-10s apiece when plain UDP/53 cannot cross the tunnel) to report
    # the same resolver failure, and then the DoH round pays it all again.
    if _remaining() > 0.5:
        _tcp_ok, _tcp_msg = _probe_tunnel_no_dns(
            timeout=min(_VERIFY_LITERAL_TIMEOUT, _remaining()))
        if not _tcp_ok:
            print(f"[!] Tunnel is not carrying traffic: a direct TCP connect "
                  f"through the TUN to a literal address failed ({_tcp_msg}). "
                  "This is a routing/tun2socks problem, not a DNS problem - "
                  "not retrying name resolution, the monitor will re-check.",
                  flush=True)
            return False
        # The tunnel forwards. From here on any failure is a RESOLVER failure,
        # which the DoH escalation below fixes - more URL retries would only
        # re-run the same doomed sweep.
        print(f"[*] TUN carries traffic ({_tcp_msg}) - verifying name "
              "resolution...", flush=True)

    def _run_round(tag="", round_budget=None):
        shared["ok"] = False
        shared["msg"] = ""
        shared["dns_seen"] = False
        stop_at = time.monotonic() + (round_budget if round_budget is not None
                                      else _VERIFY_ROUND_BUDGET)
        # NOT a `with ThreadPoolExecutor(...)` block. The context manager's
        # __exit__ calls shutdown(wait=True), which blocks until every worker
        # thread finishes - so a probe wedged inside an un-timed-out
        # getaddrinfo would hold the start sequence open for its full
        # duration and the round deadline below would buy nothing at all.
        # (That is exactly what a first attempt at this fix did.) Abandoning
        # the stuck resolve is the whole point; the thread finishes on its own
        # and is reaped by the executor.
        ex = concurrent.futures.ThreadPoolExecutor(max_workers=len(_VERIFY_URLS))
        try:
            futs = [ex.submit(_verify_worker, url, timeout, 5, tag, shared)
                    for url in _VERIFY_URLS]
            # Return as soon as ANY endpoint verifies the tunnel OR the round's
            # deadline passes - whichever comes first.
            while True:
                left = min(stop_at, deadline) - time.monotonic()
                if left <= 0:
                    break
                done, _ = concurrent.futures.wait(futs, timeout=min(0.25, left))
                if shared["ok"]:
                    with _VERIFY_PRINT_LOCK:
                        print(f"[+] Tunnel stable: {shared['msg']}", flush=True)
                    return True
                if done and all(f.done() for f in futs):
                    break
            return shared["ok"]
        finally:
            ex.shutdown(wait=False, cancel_futures=True)

    if _run_round():
        return True

    # The tunnel forwards packets (stage 1 proved it), so every URL failing on
    # getaddrinfo means the RESOLVER cannot be reached through it - the exact
    # state DoH over TCP/443 fixes. Say it once, in the terms the user can act
    # on, instead of the same "DNS resolve ... getaddrinfo failed" line four
    # more times.
    if shared.get("dns_seen"):
        print(f"[!] Name resolution through the TUN is not working (last: "
              f"{shared['last_err'] or 'getaddrinfo failed'}). The tunnel "
              "itself is fine; plain UDP/53 cannot cross it, so DNS is being "
              "escalated to DoH over TCP/443.", flush=True)
    else:
        print(f"[!] All verification endpoints failed (last: "
              f"{shared['last_err'] or 'no probe answered'}). "
              f"Routes are installed but egress through the TUN is not working yet.",
              flush=True)

    # Auto-escalate to DoH if plain DNS appears broken.
    if _ACTIVE_DNS_MODE == "auto" and _remaining() > 1.0:
        print("[*] Auto-switching wintun DNS to DoH (HTTPS) so name resolution "
              "rides over TCP/443...", flush=True)
        _ACTIVE_DNS_MODE = "doh"
        try:
            doh_on = configure_tun(_ACTIVE_DNS4, _ACTIVE_DNS6)
        except Exception as e:
            doh_on = False
            print(f"[!] DoH switch failed: {e}", flush=True)
        if not doh_on:
            # Nothing registered, so the adapter still carries the same plain
            # UDP/53 resolver that just failed to resolve through the tunnel.
            # A second probe round cannot succeed against it - it would spend
            # a full _VERIFY_ROUND_BUDGET of start latency to re-report the
            # same getaddrinfo failure. The monitor loop re-probes anyway, and
            # the state is announced DEGRADED below so the user sees the real
            # reason instead of a spinner.
            print("[!] DoH could not be registered, so resolution through the "
                  "TUN is still on plain UDP/53 - not re-probing a resolver "
                  "that just failed. Check the DoH lines above for why "
                  "(Windows build without DoH support, or a blocked "
                  "dns-query endpoint).", flush=True)
        else:
            # Flush the resolver cache so lookups stop hitting the broken
            # plain-UDP path and pick up the freshly registered DoH servers
            # immediately. Folded into ONE PowerShell call with the cache
            # clear: each psshell spawn costs hundreds of ms and this is on
            # the critical path.
            try:
                run_ps("Clear-DnsClientCache -ErrorAction SilentlyContinue; "
                       "ipconfig /flushdns | Out-Null")
            except Exception:
                pass
            if _run_round(" (DoH)"):
                return True
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
        # Self-heal implies the TUN routes are being re-asserted, so make sure
        # the DNS pin is still there too (a wipe of the NRPT rule is exactly
        # the kind of silent state loss this path exists to repair).
        #
        # INDIVIDUALLY GUARDED, and that is load-bearing rather than
        # decorative. The docstring above promises "one failing add cannot
        # abort the rest"; this call was NOT guarded, and a single cosmetic
        # bug inside it (an UnboundLocalError on the _dns_guard_state
        # bookkeeping) unwound out of the whole function - skipping every
        # Wintun address, the default and split-default routes, the entire
        # IPv6 stack and the LAN bypass re-apply. The self-heal did nothing at
        # all, the tunnel stayed broken, and the only visible symptom was one
        # "Self-heal failed" line naming a variable instead of the routes that
        # were never re-applied. Contain every step that is not a route add.
        try:
            _install_dns_guard(verbose=False)
        except (Exception, SystemExit) as e:
            print(f"[!] Self-heal: DNS leak guard re-assert failed ({e}); "
                  "continuing with the TUN routes.", flush=True)
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
        # get_ipv4_default() sys.exit()s when the IPv4 default route is
        # momentarily absent (a Wi-Fi roam / DHCP renewal / VPN flap - all
        # routine). SystemExit is a BaseException, so `except Exception` does
        # NOT catch it: it used to unwind out of this function, out of the
        # monitor loop, and tear the whole tunnel down over one blip. Use
        # RouteResult.unwrap, which treats the exit as "no result".
        try:
            _res = RouteResult.unwrap(get_ipv4_default)
            if _res.ok and _res.value:
                _add_lan_bypass(_res.value[0], _res.value[1])
        except Exception:
            pass
        print("[+] Self-heal applied.", flush=True)
    except (Exception, SystemExit) as e:
        print(f"[!] Self-heal failed: {e}")


def start_tun2socks_pipe(device_name, ip4, ip6, port, tun2socks_path,
                         dns4=None, dns6=None, fatal=True):
    """Bring up one TUN adapter + tun2socks process against one local SOCKS5
    port. Returns the Popen handle. Raises SystemExit on failure when
    ``fatal`` is True (the default); otherwise prints the same diagnostic and
    returns None so the caller can skip this optional pipe without taking the
    whole helper down.

    Extracted verbatim from main() so the second proxy pipe (TUN2, behind
    --proxy2-port) can reuse the exact same bring-up sequence. The PRIMARY
    pipe (device_name == TUN) additionally gets the full DNS delivery
    configuration (plain/DoH/NetBIOS via configure_tun); a secondary pipe
    only gets its interface addresses - DNS must stay on the primary
    adapter, or the two would fight over resolver settings."""
    def _fail(msg):
        if fatal:
            sys.exit(msg)
        print(f"[!] {msg}")
        return None

    print(f"[*] Checking local SOCKS5 proxy at 127.0.0.1:{port}...")
    if not test_local_socks(port):
        return _fail(
            f"127.0.0.1:{port} is not accepting TCP connections. Start your "
            "proxy client and verify its SOCKS5 inbound is listening on "
            "this port."
        )

    # Critical: no --interface.
    # This avoids the Windows UDP bind path that produced WSAEINVAL.
    cmd = [
        tun2socks_path,
        "--device", device_name,
        "--proxy", f"socks5://127.0.0.1:{port}",
    ]
    print("[*] Starting tun2socks without --interface:")
    print("    " + " ".join(cmd))

    proc = None

    def _fail(msg):
        # Kill the child we just spawned BEFORE giving up. _fail used to
        # return/exit while the tun2socks process was still running, and on
        # the fatal path `sys.exit` raised out of this function *before* the
        # caller's `tun_proc = start_tun2socks_pipe(...)` assignment
        # completed - so the global stayed None, cleanup() could never kill
        # it, and the orphan kept the Wintun adapter open (every later start
        # then failed with "Wintun adapter did not appear").
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
            except Exception:
                pass
        if fatal:
            sys.exit(msg)
        print(f"[!] {msg}")
        return None

    try:
        proc = subprocess.Popen(cmd, creationflags=_NO_WINDOW)
    except FileNotFoundError:
        return _fail(f"tun2socks not found: {tun2socks_path}")

    time.sleep(1)
    if proc.poll() is not None:
        return _fail(f"tun2socks exited immediately: {proc.returncode}")

    if not wait_for_tun(name=device_name):
        return _fail(f"Wintun adapter '{device_name}' did not appear.")

    if device_name == TUN:
        print(f"[*] Configuring Wintun: DNS4={dns4 or '(none)'}  "
              f"DNS6={dns6 or '(none)'}")
        configure_tun(dns4, dns6)
    else:
        # Secondary pipe: addresses only, never DNS (the primary owns it).
        _set_wintun_addresses_plain(dns4, dns6, device=device_name,
                                    ip4=ip4, ip6=ip6, set_dns=False)
    return proc


def main():
    global tun_proc, tun2_proc, _geo_install_thread

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--server", nargs="+", required=True,
                    help="VLESS server hostname or IP (repeatable: --server a b)")
    ap.add_argument("--port", type=int, default=DEFAULT_SOCKS_PORT,
                    help="Local SOCKS5 port of your proxy client (v2rayN, Xray, "
                         "sing-box, Clash, etc.)")
    ap.add_argument("--tun2socks", default="tun2socks.exe",
                    help="Path to tun2socks.exe")
    ap.add_argument("--vpn-server", action="append", default=[], metavar="HOST_OR_IP",
                    help="Windows VPN server to bypass (repeatable; needed for some third-party VPN clients)")
    ap.add_argument("--no-vpn-bypass", action="store_true",
                    help="Do not add bypass routes for connected Windows VPN endpoints")
    ap.add_argument("--proxy-over-vpn", "--vless-over-vpn", action="store_true",
                    dest="vless_over_vpn",
                    help="Send the proxy's own outbound connection through the "
                         "active Windows VPN (its server remains bypassed). "
                         "--vless-over-vpn is accepted as a legacy alias.")
    ap.add_argument("--vpn-interface", default=None, metavar="ALIAS",
                    help="Manually specify the Windows VPN adapter's InterfaceAlias for "
                         "--vless-over-vpn, if auto-detection via Get-VpnConnection fails")
    ap.add_argument("--dns-policy", choices=["availability", "strict"],
                    default="availability",
                    help="Resolution-fallback policy mirrored to the dashboard "
                         "(it is the fallback-resolver owner). 'strict': while "
                         "a tunnel is up the dashboard must not resolve via "
                         "direct UDP/53 or DoH - failures are reported instead "
                         "of leaking over the physical NIC.")
    ap.add_argument("--dns4", default=None, metavar="IP",
                    help=f"IPv4 DNS server to set on the Wintun adapter. Pass --dns4 "
                         f"(and/or --dns6) and the tunnel uses EXACTLY what you gave: a "
                         f"--dns4 without --dns6 sets IPv4 DNS only and leaves IPv6 DNS "
                         f"unset. With neither flag the defaults are used ({DNS4} + "
                         f"{DNS6}); --dns4 {DNS4} alone also counts as 'no choice' for "
                         f"backward compatibility. If DNS lookups fail even though the "
                         f"tunnel itself works, try a different resolver here - some "
                         f"networks block specific DNS IPs directly, and some VLESS "
                         f"configs route well-known DNS IPs 'direct' (outside the "
                         f"tunnel) by routing-rule default.")
    ap.add_argument("--dns6", default=None, metavar="IP",
                    help=f"IPv6 DNS server to set on the Wintun adapter. See --dns4 for "
                         f"the selection rules (default when nothing is chosen: {DNS6})")
    ap.add_argument("--dns-mode", choices=["plain", "doh", "auto"], default="auto",
                    help="Wintun DNS delivery: plain (UDP/53 - needs UDP relay through "
                         "the proxy), doh (DNS-over-HTTPS over TCP/443 - works whenever TCP "
                         "relays), or auto (start plain, escalate to DoH if resolution "
                         "through the TUN keeps failing). Default auto.")
    ap.add_argument("--doh-template", default=None, metavar="URL",
                    help="Override the DoH template URL (e.g. https://dns.google/dns-query). "
                         "Auto-selected from the DNS IP when omitted.")
    ap.add_argument("--dns-guard", action="store_true", dest="dns_guard",
                    default=True,
                    help="(Default) Install a catch-all NRPT rule for as long "
                         "as the tunnel is up, pinning the Windows DNS client "
                         "to the Wintun resolvers so a DHCP-assigned physical "
                         "resolver can never be queried in parallel (the real "
                         "DNS leak). A .local (mDNS) exemption is installed "
                         "alongside it; every teardown path removes the rule.")
    ap.add_argument("--no-dns-guard", action="store_false", dest="dns_guard",
                    help="Do not pin the OS DNS client (leave Windows free to "
                         "query every adapter's resolver in parallel - the "
                         "legacy behavior, leaks on multi-homed machines).")
    ap.add_argument("--dns-guard-exempt", action="append", default=[],
                    metavar="DOMAIN",
                    help="Extra domain that must stay resolvable by the LAN/"
                         "router resolver while the DNS guard is up (repeatable; "
                         ".local is always exempt).")
    ap.add_argument("--bypass-ip", action="append", default=[], metavar="HOST_OR_IP",
                    help="Additional IP(s) or hostname(s) to bypass the TUN (repeatable)")
    ap.add_argument("--proxy2-port", type=int, default=None, metavar="PORT",
                    help="SOCKS5 port of a SECOND local proxy (e.g. 10809). Presence "
                         "of this flag enables the second pipe: hosts marked for the "
                         "second hop (--proxy2-bypass-ip, or dashboard [A] -> proxy2) "
                         "are routed through it while everything else keeps using the "
                         "primary tunnel. Omit to disable entirely.")
    ap.add_argument("--proxy2-server", nargs="+", default=[], metavar="HOST_OR_IP",
                    help="The second proxy's own upstream server IP(s)/hostname(s) - "
                         "given direct (physical-NIC) bypass routes so its transport "
                         "does not loop back into either TUN adapter")
    ap.add_argument("--proxy2-bypass-ip", action="append", default=[], metavar="HOST_OR_IP",
                    help="IP(s) or hostname(s) to route through the SECOND proxy "
                         "(repeatable; requires --proxy2-port)")
    ap.add_argument("--geoip", default=None, metavar="PATH",
                    help="Path to an Xray-format geoip file (.dat OR .json; format "
                         "auto-detected - the same format is shared by v2rayN, "
                         "sing-box and Clash); "
                         "install bypass routes for every CIDR of --geoip-code "
                         "(e.g. cn = bypass mainland traffic through the TUN)")
    ap.add_argument("--geoip-code", default="", metavar="CC",
                     help="Country code inside the geoip file to bypass (required with --geoip)")
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
    ap.add_argument("--control-file", default=None, metavar="PATH",
                    help="Live-reconfig control file the dashboard writes (currently "
                         "DNS changes). Default: .tuntop_control.json next to this file. "
                         "The frozen exe passes an explicit shared path because each "
                         "onefile process extracts into its own temp dir.")
    args = ap.parse_args()

    # Explicit control-file handoff (frozen exe): must be applied BEFORE
    # _baseline_control_file() below baselines the file's mtime.
    if args.control_file:
        global CONTROL_FILE
        CONTROL_FILE = args.control_file

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
    global _ACTIVE_DNS_POLICY
    global _ACTIVE_DNS_GUARD, _ACTIVE_DNS_GUARD_EXEMPT
    global vpn_override_iface
    _ACTIVE_DNS_POLICY = args.dns_policy
    _ACTIVE_DNS4, _ACTIVE_DNS6 = _resolve_dns_choice(args.dns4, args.dns6)
    if _ACTIVE_DNS4 and _ACTIVE_DNS6:
        print(f"[*] DNS: IPv4 {_ACTIVE_DNS4} + IPv6 {_ACTIVE_DNS6}")
    elif _ACTIVE_DNS4:
        print(f"[*] DNS: IPv4 {_ACTIVE_DNS4} (v4 only - IPv6 DNS stays unset)")
    elif _ACTIVE_DNS6:
        print(f"[*] DNS: IPv6 {_ACTIVE_DNS6} (v6 only - IPv4 DNS stays unset)")
    else:
        print("[*] DNS: none set")
    _ACTIVE_DNS_MODE = args.dns_mode
    _ACTIVE_DOH_TEMPLATE = args.doh_template
    # DNS leak guard (--dns-guard / --no-dns-guard, --dns-guard-exempt): the
    # catch-all NRPT pin installed once the TUN routes are live.
    _ACTIVE_DNS_GUARD = bool(getattr(args, "dns_guard", True))
    _ACTIVE_DNS_GUARD_EXEMPT = [str(x).strip().lower()
                                for x in (getattr(args, "dns_guard_exempt", [])
                                          or []) if str(x).strip()]
    if not _ACTIVE_DNS_GUARD:
        print("[*] DNS leak guard: disabled by --no-dns-guard (Windows may "
              "query a physical adapter's resolver in parallel).")
    # Baseline the live-reconfig channel (see _baseline_control_file): only
    # control-file writes made while THIS run is up may change the DNS - a
    # leftover file from an earlier session must never override the launch
    # flags this run was started with.
    _baseline_control_file()

    if not is_admin():
        sys.exit("[!] Run this script as Administrator.")

    atexit.register(cleanup)
    # Also run cleanup() on termination signals so the routing is removed when
    # the tunnel is switched off / the process is signalled (e.g. the dashboard
    # sends CTRL_BREAK_EVENT) - not only on a clean interpreter exit. cleanup()
    # is idempotent, so a later atexit call is a harmless no-op.
    def _on_signal(signum, frame):
        # `global` is required: without it the flag below is a local, and
        # reading it on the first signal raises UnboundLocalError - out of a
        # signal handler, so the process would die immediately on Ctrl+C
        # without running cleanup() at all.
        global _cleanup_in_progress
        # A SECOND signal arriving while cleanup() is mid-teardown used to
        # re-enter here, find `cleaned` already True, return immediately
        # from cleanup() and then os._exit(0) - killing the process in the
        # middle of the route sweeps, leaving exactly the broken state
        # cleanup() exists to prevent. Ignore repeats instead: the
        # in-flight teardown will finish.
        if _cleanup_in_progress:
            return
        _cleanup_in_progress = True
        # Stop the background geo install FIRST and let it wind down
        # briefly: os._exit() mid-install leaves a half-installed country's
        # routes behind. The cancel flag makes the installer skip its
        # remaining netsh sub-batches; the join bounds the wait so the
        # signal handler never hangs.
        try:
            _geo_install_cancel.set()
            _t = _geo_install_thread
            if _t is not None and _t.is_alive():
                _t.join(timeout=3.0)
        except Exception:
            pass
        try:
            cleanup()
        except BaseException as e:
            # cleanup() is now internally guarded, but a BaseException
            # (Ctrl+C during a netsh wait) must still not skip the exit -
            # and the process must NOT exit 0 after a failed teardown, or
            # a parent watching the status sees a clean shutdown.
            _say(f"[!] Cleanup on signal {signum} failed: {e}")
            os._exit(1)
        os._exit(0)
    for _sig in (getattr(signal, "SIGINT", None),
                 getattr(signal, "SIGTERM", None),
                 getattr(signal, "SIGBREAK", None)):
        if _sig is not None:
            try:
                signal.signal(_sig, _on_signal)
            except (ValueError, OSError, AttributeError, RuntimeError):
                pass
    preflight_cleanup(tun2socks_path=getattr(args, "tun2socks", None))

    # Arm the live-mode args as early as any route decision exists: helpers
    # like ensure_physical_metric_below_vpn need to know whether THIS run is
    # in vless-over-vpn mode, and the geo install below already runs before
    # the tunnel is fully up (the later re-assignment at the monitor-loop
    # arm point is a harmless duplicate).
    _live_mode["args"] = args

    # A second Wintun program cannot coexist with this tunnel (see
    # reject_competing_tun): refuse to start when another TUN owns a default
    # route instead of letting the operator debug a broken routing state.
    reject_competing_tun()

    iface, gateway, ifindex = get_ipv4_default()
    print(f"[*] Physical interface: {iface}  IfIndex={ifindex}  Gateway={gateway}")
    vless_iface, vless_gateway = iface, gateway
    vpn_conn_name_for_check = None
    if args.vless_over_vpn:
        # The VPN lookup runs once per helper start. When --vless-over-vpn is
        # combined with auto-recovery, a start can land while the Windows VPN
        # is still RE-CONNECTING (its adapter/routes disappear for seconds
        # during the transport drop that killed the tunnel in the first
        # place) - a single immediate check then declares "no VPN" and the
        # helper exits, looping. Retry the lookup over a short window first.
        vpn_default = None
        for _attempt in range(4):
            vpn_default = get_vpn_ipv4_default(args.vpn_interface)
            if vpn_default:
                break
            if _attempt < 3:
                print(f"[*] No active Windows VPN route yet "
                      f"(attempt {_attempt + 1}/4) - waiting 3s and retrying...")
                time.sleep(3)
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
    _live_vpn_routes = []   # exact VPN bypass routes installed (live [Y] undo)
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

    tun_proc = start_tun2socks_pipe(TUN, TUN4, TUN6, args.port,
                                    args.tun2socks, _ACTIVE_DNS4, _ACTIVE_DNS6)

    # ── Install bypass routes NOW (before the tun2socks IPv6 restart) ──
    # Resolving the egress and adding the /32 (and /128) bypass routes here
    # makes them take effect the instant the Wintun adapter is up, instead of
    # only after the restart. They use the physical/VPN gateway and do not
    # depend on tun2socks, so doing them early is safe and removes the wait.
    # Install the bypass routes BEFORE the default TUN route.
    # These are more specific than 0/0, so your proxy's own outbound
    # connection remains on the physical network instead of entering
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
        # Clear any stale /32 (e.g. a previous direct-mode run, or a crash
        # that skipped the exit sweep) BEFORE resolving the egress: it would
        # otherwise out-match the VPN default in Find-NetRoute and pin the
        # route to the old egress again.
        _remove_host_routes_v4(f"{ip}/32")
        if args.vless_over_vpn:
            # Over-VPN mode is DETERMINISTIC: the /32 is pinned to the exact
            # VPN interface/next-hop resolved above (vpn_default), never to
            # whatever Find-NetRoute happens to rank first. The lookup path
            # (get_egress_for(exclude_vpn=False)) is NOT trusted here: its
            # candidate list drops tunnel-family adapters by DESCRIPTION, so
            # a VPN client whose adapter matches TUN_DRIVER_RE (SoftEther,
            # OpenVPN, WireGuard-based clients...) is excluded even in
            # over-VPN mode - and metric races can let the physical NIC win
            # too. Either way the /32 lands on Wi-Fi and the transport
            # silently stops riding the VPN ("VLESS server route via Wi-Fi"
            # while the VPN is Connected).
            #
            # This fallback to the validated (vless_iface, vless_gateway) is
            # what makes the behavioural TUN classifier (egress_scripts'
            # $tunAliases now also matches IfType 131 / Tunnel media) fail-safe
            # here: if that gate ever over-excludes a real egress, the None
            # from get_egress_for is absorbed and the /32 still pins to the
            # resolved VPN egress - never to a name-only guess.
            eg = (vless_iface, vless_gateway)
        else:
            eg = get_egress_for(ip, exclude_vpn=True) or (vless_iface, vless_gateway)
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
        _remove_host_routes_v4(f"{ip}/32")
        eg = get_egress_for(ip, exclude_vpn=not args.vless_over_vpn) or (vless_iface, vless_gateway)
        print(f"    bypass {ip} -> via {eg[0]} ({eg[1]})")
        if not add_v4(f"{ip}/32", eg[0], eg[1], metric=1):
            print(f"[!] Could not install bypass route for {ip}; continuing.")

    if vpn_v4:
        print("[*] Installing Windows VPN IPv4 bypass routes...")
        for ip in vpn_v4:
            # Physical adapter, always - see _direct_bypass_egress. A VPN
            # server reached via the VPN is a loop; the whole point of the
            # bypass is to keep that server OUTSIDE the tunnel.
            eg = _direct_bypass_egress(ip, (iface, gateway))
            if not eg:
                print(f"[!] No physical egress for VPN endpoint {ip}; not "
                      "installing its bypass (it must not ride the VPN).")
                continue
            if not add_v4(f"{ip}/32", eg[0], eg[1], metric=1):
                print(f"[!] Could not install VPN bypass route for {ip}; continuing.")
            else:
                _live_vpn_routes.append(("v4", f"{ip}/32", eg[0], eg[1]))

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
                _live_vpn_routes.append(("v6", f"{ip}/128",
                                         d6["InterfaceAlias"], d6["NextHop"]))
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
    # Rebuild the primary pipe's command line (start_tun2socks_pipe owns the
    # original build; the restart must be byte-identical to what it launched).
    cmd = [args.tun2socks, "--device", TUN,
           "--proxy", f"socks5://127.0.0.1:{args.port}"]
    tun_proc = subprocess.Popen(cmd, creationflags=_NO_WINDOW)
    time.sleep(1)
    if tun_proc.poll() is not None:
        sys.exit(f"[!] tun2socks exited after restart: {tun_proc.returncode}")
    if not wait_for_tun():
        sys.exit("[!] Wintun adapter did not reappear after restart.")
    configure_tun(_ACTIVE_DNS4, _ACTIVE_DNS6)

    # ── Second proxy pipe (optional, --proxy2-port) ──────────────────────────
    # A second TUN adapter + tun2socks against a second local SOCKS5 port.
    # The PRIMARY pipe keeps owning the default route; TUN2 NEVER gets one -
    # it only ever receives specific-destination /32+/128 host routes (the
    # ones below, plus live additions from the dashboard's proxy2 targeting).
    # Nothing in this block runs unless --proxy2-port was given.
    if args.proxy2_port is not None:
        # Pre-bind every proxy2 collection BEFORE the branch below. They were
        # only assigned inside the "wintun2 pipe active" else-branch, so a
        # --proxy2-port whose SOCKS5 is not listening left them UNBOUND - and
        # the geo background thread (which tests `args.proxy2_port is not
        # None`, not whether the pipe came up) hit NameError and installed
        # NO country bypass at all, with an error naming a variable instead
        # of the real cause.
        p2_v4, p2_v6, _p2b_v4, _p2b_v6 = [], [], [], []
        if args.proxy2_port == args.port:
            sys.exit(f"[!] --proxy2-port {args.proxy2_port} equals the primary "
                     "--port; a second pipe to the same proxy is pointless and "
                     "only adds a second adapter. Choose a different port.")
        if not args.proxy2_server:
            print("[!] --proxy2-port given without --proxy2-server: the second "
                  "proxy's own upstream connection has NO direct bypass route "
                  "and may loop into the TUN. Pass its server via "
                  "--proxy2-server.")
        print(f"[*] Starting second proxy pipe ({TUN2}) for "
              f"127.0.0.1:{args.proxy2_port}...")
        tun2_proc = start_tun2socks_pipe(TUN2, TUN2_IP4, TUN2_IP6,
                                         args.proxy2_port, args.tun2socks,
                                         fatal=False)
        if tun2_proc is None:
            # SOCKS5 not listening: skip the wintun2 pipe rather than killing
            # the whole helper (which would take the primary tunnel down too).
            print(f"[!] Second proxy at 127.0.0.1:{args.proxy2_port} is not "
                  "reachable - starting WITHOUT the wintun2 pipe. The primary "
                  "tunnel is unaffected; restart the tunnel once the second "
                  "proxy is listening to enable it.")
            print(f"[*] proxy2 pipe skipped - SOCKS5 not listening at "
                  f"127.0.0.1:{args.proxy2_port}")
        else:
            print(f"[*] proxy2 pipe active - wintun2 ready for "
                  f"127.0.0.1:{args.proxy2_port}")

            # The second proxy's own upstream server(s) get physical-NIC bypass
            # routes - same reasoning as the primary --server bypass above: without
            # them the proxy2 transport is captured by the TUN default route and
            # loops back into 127.0.0.1.
            for entry in (args.proxy2_server or []):
                ep4, ep6 = resolve_all_safe(entry, label=f"proxy2-server {entry}")
                if ep4 is None and ep6 is None:
                    continue
                p2_v4.extend(x for x in (ep4 or []) if x not in p2_v4)
                p2_v6.extend(x for x in (ep6 or []) if x not in p2_v6)
                if ep4 or ep6:
                    print(f"    [proxy2-server] {entry} -> "
                          f"{', '.join((ep4 or []) + (ep6 or []))}")
            for ip in p2_v4:
                eg = (get_egress_for(ip, exclude_vpn=not args.vless_over_vpn)
                      or (vless_iface, vless_gateway))
                print(f"    proxy2 server {ip} -> via {eg[0]} ({eg[1]})")
                if not add_v4(f"{ip}/32", eg[0], eg[1], metric=1):
                    print(f"[!] Could not install proxy2-server bypass route for "
                          f"{ip}; continuing.")
            d6 = get_ipv6_default()
            for ip in p2_v6:
                if d6:
                    add_v6(f"{ip}/128", d6["InterfaceAlias"], d6["NextHop"], 1)
                else:
                    print(f"[!] No native IPv6 gateway; proxy2-server bypass for "
                          f"{ip} not installed.")

            # Restart the second pipe so its tun2socks picks up the (now present)
            # wintun2 IPv6 address - same reason as the primary restart above.
            if tun2_proc is not None and tun2_proc.poll() is None:
                tun2_proc.terminate()
                try:
                    tun2_proc.wait(timeout=5)
                except Exception:
                    tun2_proc.kill()
            time.sleep(1)
            tun2_proc = subprocess.Popen([
                args.tun2socks, "--device", TUN2,
                "--proxy", f"socks5://127.0.0.1:{args.proxy2_port}",
            ], creationflags=_NO_WINDOW)
            time.sleep(1)
            if tun2_proc.poll() is not None:
                sys.exit(f"[!] tun2socks (proxy2) exited after restart: "
                         f"{tun2_proc.returncode}")
            if not wait_for_tun(name=TUN2):
                sys.exit(f"[!] Wintun adapter '{TUN2}' did not reappear after "
                         "restart.")
            _set_wintun_addresses_plain(None, None, device=TUN2, ip4=TUN2_IP4,
                                        ip6=TUN2_IP6, set_dns=False)

            # CLI-provided second-hop hosts get their TUN2 routes right away, so
            # the feature works headless; the dashboard can add more live.
            # Their prefixes are also collected so the geoip pass below never
            # removes/overrides them (a geo CIDR equal to one of these /32s would
            # otherwise be swept away and re-pointed at the geo egress).
            for entry in (args.proxy2_bypass_ip or []):
                ep4, ep6 = resolve_all_safe(entry, label=f"proxy2-bypass {entry}")
                if ep4 is None and ep6 is None:
                    continue
                print(f"    [proxy2-bypass] {entry} -> "
                      f"{', '.join((ep4 or []) + (ep6 or []))} via {TUN2}")
                for ip in (ep4 or []):
                    _p2b_v4.append(ip)
                    add_v4(f"{ip}/32", TUN2, TUN2_IP4, metric=1)
                for ip in (ep6 or []):
                    _p2b_v6.append(ip)
                    add_v6(f"{ip}/128", TUN2, TUN2_IP6, metric=1)

    # (Bypass routes are now installed right after the first Wintun config,
    #  before the tun2socks IPv6 restart, so they take effect instantly.)

    # ── geoip.dat bypass (route-level "bypass mainland" / geoip:cn) ─────────
    # Installs in a BACKGROUND thread (below): every geo prefix is more
    # specific than the TUN split-defaults, so the country ranges win the
    # lookup whenever they land - install order vs the default routes does
    # not matter, but NOT blocking "[+] TUNNEL ACTIVE" does.
    def _geo_install():
        # Runs in a BACKGROUND daemon thread (launched right below). The geo
        # install can legitimately take minutes (file decode + 3000+ route
        # adds); running it INLINE delayed "[+] TUNNEL ACTIVE" past the
        # dashboard's 90s startup watchdog, which then killed a HEALTHY helper
        # ("helper hung for 90s" right after "Installing geoip:ir bypass..." -
        # and geo never finished loading). Route ordering does not depend on
        # install order: every geo prefix is more specific than the /0-/1
        # split-defaults, so the country routes win the lookup whenever they
        # land. The tunnel comes up immediately; country routes stream in
        # behind it (watch the GEO panel fill up).
        code = (args.geoip_code or "").strip().lower()
        if not code:
            # The main path has already validated the --geoip/--geoip-code pair
            # BEFORE spawning this thread and printed the full advisory (it
            # even names the flag to add). Printing it again here produced the
            # identical warning twice in the log for one mistake.
            return
        print(f"[*] Loading geoip file bypass for code '{code}' from {args.geoip} ... (background)")
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
                # Endpoints + user bypass entries OUTRANK the country ranges:
                # geoip.dat can contain the VLESS/VPN server's own IP (even as
                # an exact /32 identical to its host route).  Without this, the
                # geo install's conflict sweep would delete the server's host
                # route and re-add it pointing at the GEO egress - the proxy
                # transport then loops into its own tunnel (endless failing
                # connects to the server IP in the log).
                _p2v4 = (p2_v4 + _p2b_v4) if args.proxy2_port is not None else []
                _p2v6 = (p2_v6 + _p2b_v6) if args.proxy2_port is not None else []
                add_geoip_bypass(
                    code, cidrs, g_iface, g_gw, v6iface, v6gw,
                    protected=collect_protected_geo_prefixes(
                        server_v4=v4, server_v6=v6,
                        bypass_v4=extra_bypass_v4, bypass_v6=extra_bypass_v6,
                        vpn_v4=vpn_v4, vpn_v6=vpn_v6,
                        proxy2_v4=_p2v4, proxy2_v6=_p2v6,
                    ),
                )
            except Exception as e:
                print(f"[!] geoip bypass install failed ({code}): {e}; continuing without it.")

    if args.geoip or args.geoip_code:
        # Validate the pair BEFORE spawning anything. The "[!] --geoip given
        # without --geoip-code" line used to live inside the thread that only
        # starts when --geoip is set, so passing --geoip-code ALONE produced
        # no message, no bypass and no hint that the flag was dropped.
        if args.geoip and not (args.geoip_code or "").strip():
            print("[!] --geoip given without --geoip-code - no country "
                  "bypass installed. Add --geoip-code <cc> (e.g. cn, ir) to "
                  "say WHICH country's ranges to bypass.")
        if args.geoip_code and not args.geoip:
            print("[!] --geoip-code given without --geoip - no country "
                  "bypass installed. Add --geoip <path to geoip.dat>, or "
                  "press [W] in the dashboard to download it.")
    if args.geoip:
        # Background daemon: never blocks the startup sequence (see the
        # docstring on _geo_install). Daemon because a Ctrl+C/[T] stop must
        # not be held up by a half-finished geo install - the exit cleanup
        # sweeps whatever routes actually made it into the table. The thread
        # handle is published so _on_signal can cancel + join it before
        # cleanup() (an os._exit mid-install leaves a half-installed country
        # in the table).
        _geo_install_thread = threading.Thread(target=_geo_install,
                                               name="geo-install",
                                               daemon=True)
        _geo_install_thread.start()

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

    # ── DNS leak guard (catch-all NRPT rule) ────────────────────────────────
    # Placed HERE, after the default/split routes are live and before the
    # tunnel is declared active: installing it from configure_tun would be
    # too early (that runs before these routes exist, and a catch-all rule
    # active while the endpoint / proxy2 / VPN resolutions of this same
    # startup still need the physical resolver would fail them).
    _install_dns_guard()

    # Arm the live [V]/[Y] channel with THIS run's route state (see
    # _live_mode): the monitor loop's poll_control_file can then re-point
    # these very endpoints when the dashboard toggles a mode at runtime -
    # without a tunnel restart.
    _live_mode["args"] = args
    _live_mode["vless_over_vpn"] = bool(args.vless_over_vpn)
    _live_mode["no_vpn_bypass"] = bool(args.no_vpn_bypass)
    _live_mode["v4"] = list(v4)
    _live_mode["v6"] = list(v6)
    _live_mode["vpn_v4"] = list(vpn_v4)
    _live_mode["vpn_v6"] = list(vpn_v6)
    # Validate before caching. get_ipv4_default()'s last-resort clause can
    # return "any non-wintun default route, may be the VPN" when a full-tunnel
    # VPN has replaced the physical default. Storing THAT under 'phys' made
    # every fallback below pin a bypass onto the VPN - including the VPN
    # endpoint's own /32, which is how a live [Y]/[U] install tried to add
    # '185.64.178.62/32 on Shirazu-VPN'. Store None instead: a missing cache
    # makes _direct_bypass_egress say "no physical egress" (visible and safe)
    # where a poisoned cache silently built broken routes. physical_egress()
    # re-validates on every read regardless, so this is belt and braces.
    _phys = physical_egress((iface, gateway))
    if _phys is None:
        print(f"[!] The reported IPv4 default ({iface} {gateway}) is not a "
              "physical adapter - not caching it as the physical egress. "
              "Bypass routes that need the physical adapter will be reported "
              "rather than pinned onto a VPN or tunnel.", flush=True)
    _live_mode["phys"] = _phys
    _live_mode["over"] = (vless_iface, vless_gateway)
    _live_mode["vpn_conn"] = vpn_conn_name_for_check
    _live_mode["vpn_routes"] = list(_live_vpn_routes)
    # Native IPv6 egress at startup - the gateway monitor compares against it
    # to re-point native-IPv6 endpoint /128s when the network changes.
    try:
        _d6 = get_ipv6_default()
        _live_mode["phys6"] = ((str(_d6["InterfaceAlias"]),
                                str(_d6.get("NextHop") or ""))
                               if _d6 else None)
    except Exception:
        _live_mode["phys6"] = None

    print(flush=True)
    print("[+] TUNNEL ACTIVE", flush=True)
    if ipv4_ok:
        print("[+] IPv4: system -> Wintun -> tun2socks -> local proxy (VPN-proof split default)")
    else:
        print("[#] IPv4: default/split routes did NOT all install - IPv4 may be partial or dead")
    if ipv6_ok:
        print("[+] IPv6: system -> Wintun -> tun2socks -> local proxy (VPN-proof split default)")
    else:
        print("[#] IPv6: split-default routes did NOT install - IPv6 is NOT tunneled (expected if the VLESS server has no IPv6 egress)")
    print(f"[+] VLESS endpoint(s): {'Windows VPN transport' if args.vless_over_vpn else 'physical adapter bypass'}")
    if vpn_v4 or vpn_v6:
        print("[+] Windows VPN endpoint(s): physical adapter bypass")
    print("[+] tun2socks --interface: OFF")

    # LOOP GUARD. Everything above installed the proxy transports' /32
    # bypasses BEFORE the default/split routes, which is the right order - but
    # order is not proof. Now that 0/0 and the /1 splits are live, prove the
    # server routes still bypass the TUN. If they do not, the proxy client's
    # own connection to its server is being swallowed by the tunnel we just
    # raised: it cannot reach the server, tun2socks has no upstream, and the
    # user's connection is gone - with the dashboard still showing a
    # perfectly healthy, fully installed tunnel. One PowerShell check now
    # beats an unexplainable blackout.
    endpoints_ok, endpoint_problems = (True, [])
    try:
        endpoints_ok, endpoint_problems = verify_endpoints_off_tun("startup")
    except Exception as e:
        print(f"[!] [LOOPGUARD] could not verify proxy endpoint routes: {e}",
              flush=True)

    # Verify the tunnel is actually carrying traffic before declaring success.
    # This retries until the tunnel stabilizes (it can still be "warming up"
    # right after the tun2socks restart) and fixes the old
    # "Could not resolve https://api.ipify.org/" failure, which was just the
    # full URL (scheme + path) being fed to getaddrinfo instead of a hostname.
    print("[*] Verifying the tunnel is stable...", flush=True)
    stable = wait_for_tunnel_stable()

    # The ready marker is the dashboard's ONLY cue for RUNNING, so it must not
    # be printed for a tunnel that never verified. The old code discarded
    # wait_for_tunnel_stable()'s verdict and announced readiness anyway, which
    # is how "everything says RUNNING and nothing works" was possible at all.
    # Announcing DEGRADED instead is both honest and recoverable: the first
    # successful monitor probe promotes it to RUNNING on its own, with no
    # restart and no user action.
    if stable and endpoints_ok:
        print("[*] Press Ctrl+C to stop.", flush=True)
    else:
        # Two DISTINCT markers, not one vague one: the dashboard maps each to
        # a different repair ladder (endpoint-route loop -> re-assert the
        # transport routes; unverified probe -> the egress/DNS ladder), so the
        # first thing a reader sees names the actual fault.
        if not endpoints_ok:
            print(f"[!] TUNNEL DEGRADED - proxy endpoint routes loop: "
                  f"{len(endpoint_problems)} endpoint(s) would be captured by "
                  f"the TUN just installed ({'; '.join(endpoint_problems)}).",
                  flush=True)
        else:
            print("[!] TUNNEL DEGRADED - traffic verification failed: the "
                  "TUN and its routes are installed but no traffic probe "
                  "succeeded through them.", flush=True)
        print("[*] The tunnel stays installed and promotes ITSELF to RUNNING "
              "as soon as a health probe passes - do not restart. Check the "
              "EVENT LOG above for the reason.", flush=True)
    print(flush=True)

    last_vpn_status = None
    last_probe = 0.0
    last_leak = None      # last leak verdict - report only on CHANGE
    last_gw_check = 0.0   # gateway-change poll clock (see _check_gateway_change)
    last_heal_check = 0.0  # endpoint-bypass self-heal clock (see _HEAL_EVERY)
    last_vpn_check = 0.0  # VPN transport status clock (see _VPN_STATUS_EVERY)
    last_socks_check = 0.0  # local SOCKS5 liveness clock (see _SOCKS_CHECK_EVERY)
    fails = 0
    proxy_up = test_local_socks(args.port, timeout=0.5)
    mon_interval = max(5, args.monitor_interval)
    mon_retries = max(1, args.monitor_retries)
    if not (stable and endpoints_ok):
        # A start that did not verify must not then sit silent for a whole
        # monitor interval before anyone looks at it again. Re-probe in ~5 s:
        # fast enough that a tunnel which is merely warming up is promoted to
        # RUNNING almost immediately, and a genuinely broken one is reported
        # quickly instead of half a minute later.
        last_probe = time.time() - mon_interval + 5
    try:
        while tun_proc.poll() is None:
            time.sleep(1)
            now = time.time()
            # Live-reconfig channel: pick up dashboard-written changes (DNS
            # etc.) without a tunnel restart. Cheap mtime check inside.
            #
            # DO NOT SWALLOW SILENTLY. poll_control_file is documented never to
            # raise, so anything arriving here is a genuine surprise - and a
            # bare `pass` made it invisible. A raise while applying, say, a
            # [V] switch would leave the mode half-applied with the user
            # pressing [N] and nothing happening and no log line explaining
            # why. Say it once per occurrence; the loop keeps running.
            try:
                poll_control_file()
            except Exception as e:
                _say(f"[!] live-config poll failed (the dashboard's next "
                     f"change will retry): {e.__class__.__name__}: {e}")
            # WiFi/network changed under the running tunnel? Re-point every
            # route pinned to the old gateway (endpoints, LAN, geo) so the
            # system keeps its internet. Cheap PowerShell poll, debounced.
            if not args.no_monitor and (now - last_gw_check) >= _GW_CHECK_EVERY:
                last_gw_check = now
                try:
                    _check_gateway_change()
                except Exception:
                    pass
            # Endpoint bypass self-heal (see _heal_endpoint_routes): a foreign
            # TUN (Throne's sing-tun owns 176.0.0.0/4) can steal or strip the
            # server /32s - the loop the connections panel shows as
            # '192.168.123.1 -> server:443'. Re-resolve + re-add when broken.
            if not args.no_monitor and (now - last_heal_check) >= _HEAL_EVERY:
                last_heal_check = now
                try:
                    for _heal_ln in _heal_endpoint_routes():
                        print(_heal_ln, flush=True)
                except Exception:
                    pass
            # Timestamp-based cadence (NOT int(now) % 10 == 0): a 1 s sleep
            # drifts, so the modulo can jump from 19.x to 21.x and silently
            # SKIP an entire VPN-status cycle - the exact window a flap can
            # happen in. The clock comparison can never skip a cycle.
            if args.vless_over_vpn and (now - last_vpn_check) >= _VPN_STATUS_EVERY:
                last_vpn_check = now
                # The transport may have been switched TO over-VPN live ([V]
                # toggle): then vpn_conn_name_for_check (the startup value)
                # is None and the live channel names the connection instead.
                _vpn_conn = vpn_conn_name_for_check or _live_mode.get("vpn_conn")
                if _vpn_conn:
                    status = get_vpn_connection_names_status().get(_vpn_conn)
                    if status != last_vpn_status:
                        last_vpn_status = status
                        if status and status != "Connected":
                            print(f"[!] Windows VPN '{_vpn_conn}' status changed: {status}",
                                  flush=True)
                            if _live_mode["vless_over_vpn"]:
                                # The VPN died under us: /32s pinned to its
                                # (now absent) gateway are blackholes - fall
                                # back to the physical egress so the tunnel
                                # keeps working, and ride the VPN again below
                                # when it reconnects.
                                print("[*] VPN down - VLESS transport falls back "
                                      "to the physical adapter.", flush=True)
                                try:
                                    _ok, _lines = _live_switch_vless(False)
                                    for _ln in _lines:
                                        print(_ln, flush=True)
                                    if _ok:
                                        _live_mode["vless_over_vpn"] = False
                                except Exception as _e:
                                    print(f"[!] VPN-down fallback failed: {_e}",
                                          flush=True)
                        elif status == "Connected" and not _live_mode["vless_over_vpn"]:
                            # args.vless_over_vpn (the DESIRED mode, this
                            # branch's guard) is True while the ROUTED mode
                            # fell back during the outage: re-ride the VPN.
                            print("[*] VPN back - re-pointing VLESS transport "
                                  "onto it.", flush=True)
                            try:
                                _ok, _lines = _live_switch_vless(True)
                                for _ln in _lines:
                                    print(_ln, flush=True)
                                if _ok:
                                    _live_mode["vless_over_vpn"] = True
                                else:
                                    print("[!] VPN re-point refused - staying "
                                          "on the physical adapter.", flush=True)
                            except Exception as _e:
                                print(f"[!] VPN reconnect re-point failed: {_e}",
                                      flush=True)
            # ── Upstream liveness (fast, independent cadence) ────────────
            # Is the local SOCKS5 inbound even listening? A proxy client that
            # is closed, crashed, or (the common case) has lost its own
            # connection to its server is the single most frequent cause of
            # "the tunnel is up but nothing works", and it must NOT be
            # reported as a DNS/route fault:
            #   * route self-heal cannot fix a closed port - it only churns the
            #     default route, and the user's connection with it;
            #   * restarting the helper CANNOT fix it either, because
            #     start_tun2socks_pipe exits when the port is refused - so
            #     escalating to a restart turns one proxy outage into a tunnel
            #     crash loop.
            # The tunnel itself is fine and stays installed; it heals by itself
            # the moment the port answers again, because tun2socks opens a
            # fresh upstream connection per request. This runs on its own
            # 5-second clock (not the 30 s probe interval) so the tunnel is
            # declared healthy again promptly after the proxy comes back.
            if not args.no_monitor and (now - last_socks_check) >= _SOCKS_CHECK_EVERY:
                last_socks_check = now
                socks_up = test_local_socks(args.port, timeout=0.5)
                if socks_up != proxy_up:
                    proxy_up = socks_up
                    if socks_up:
                        print(f"[MONITOR] proxy SOCKS5 is listening again on "
                              f"127.0.0.1:{args.port} - re-verifying the tunnel "
                              "now.", flush=True)
                        last_probe = 0.0     # verify on the very next probe tick
                        fails = 0
                    else:
                        print(f"[MONITOR] proxy SOCKS5 is NOT listening on "
                              f"127.0.0.1:{args.port} - the TUN and its routes "
                              "are installed and fine, but there is no upstream "
                              "to forward to, so nothing can pass. Start your "
                              "proxy client; the tunnel recovers by itself once "
                              "the port answers (no restart needed).",
                              flush=True)

            # Live monitor / debug loop: periodically verify the tunnel resolves
            # and carries traffic through the TUN. On repeated failure, self-heal
            # (re-apply Wintun DNS + default/split routes) instead of requiring a
            # manual restart. --no-monitor disables this entirely.
            if not args.no_monitor and (now - last_probe) >= mon_interval:
                last_probe = now
                if not proxy_up:
                    # No upstream: a traffic probe can only produce a useless
                    # failure, and the route self-heal below cannot help. Skip
                    # both until the port is back (checked every 5 s above).
                    last_leak = None
                    continue
                ok, msg = _probe_tunnel_multi(timeout=4)
                if ok:
                    fails = 0
                    print(f"[MONITOR] tunnel OK: {msg}", flush=True)
                    # Cheap guard re-assert: NRPT rules can be wiped
                    # mid-session (another VPN client's policy, a Group Policy
                    # refresh, a third-party cleanup) - without this check the
                    # DNS leak would silently come back while the tunnel still
                    # looks healthy. Only shells out when the rule is missing.
                    _dns_guard_reassert()
                    # Leak check - part of the regular monitor: prove that
                    # ALL egress (direct traffic included) still rides the
                    # TUN, not just the verification probe's own HTTP. Only
                    # meaningful when the tunnel itself just verified. The
                    # dashboard reacts to these markers: "LEAK DETECTED"
                    # marks the tunnel DEGRADED, a later "leak check OK"
                    # restores RUNNING. Verdict is reported only when it
                    # CHANGES, so the log stays quiet.
                    try:
                        leak_status, leak_msg = _leak_probe(args.port,
                                                            timeout=5)
                    except Exception as e:
                        leak_status, leak_msg = "inconclusive", f"probe error: {e}"
                    if leak_status != last_leak:
                        last_leak = leak_status
                        if leak_status in ("ok", "same-exit"):
                            print(f"[MONITOR] leak check OK: {leak_msg}",
                                  flush=True)
                        elif leak_status == "leak":
                            print(f"[MONITOR] LEAK DETECTED: {leak_msg}",
                                  flush=True)
                        else:
                            print(f"[MONITOR] leak check {leak_status}: "
                                  f"{leak_msg}", flush=True)
                else:
                    # Egress broken: re-arm the leak verdict so the first
                    # healthy cycle after recovery re-reports it once.
                    last_leak = None
                    fails += 1
                    print(f"[MONITOR] tunnel check failed ({fails}/{mon_retries}): {msg}", flush=True)
                    if fails >= mon_retries:
                        # Still in auto mode? Escalate DNS to DoH so resolution
                        # rides over TCP/443 instead of the broken UDP/53 path.
                        if _ACTIVE_DNS_MODE == "auto":
                            print("[*] Monitor: repeated DNS/egress failures; "
                                  "escalating wintun DNS to DoH.", flush=True)
                            _ACTIVE_DNS_MODE = "doh"
                        # Self-heal with the LIVE DNS values, not the
                        # launch-time ones - otherwise a DNS change applied
                        # via the dashboard's [N] would be reverted here.
                        self_heal_tunnel(_ACTIVE_DNS4, _ACTIVE_DNS6)
                        fails = 0
    except KeyboardInterrupt:
        pass

    # The loop above ends the moment tun2socks exits - normally because a
    # shutdown was requested, but also because tun2socks CRASHED. The old code
    # fell out of the loop silently in both cases, so the dashboard saw only a
    # generic "helper process exited" with no idea that the userspace forwarder
    # - the thing that actually moves packets - was gone. main() returns next
    # and cleanup() removes the routes, so the tunnel really is down; say so,
    # with the exit code, before that happens.
    if tun_proc is not None and tun_proc.poll() is not None:
        print(f"[!] tun2socks exited unexpectedly (code {tun_proc.returncode}) "
              "- the TUN had no userspace forwarder, so no traffic could pass "
              "through it. Tearing the tunnel down.", flush=True)


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

    # VALIDATE THE PHYSICAL EGRESS, exactly as main() does at startup. Taking
    # get_ipv4_default()'s return value raw is the bug: its "last resort"
    # clause can legitimately return "any non-wintun default route, MAY BE THE
    # VPN", and with the tunnel already up (which --live-bypass requires) the
    # enumeration can also surface a foreign tunnel-family adapter. main()
    # knows this and wraps the value in physical_egress(), refusing it when it
    # is not a validated physical egress - it does not, it used to, and a
    # user who asked for a DIRECT bypass got one pinned onto their corporate
    # VPN, printing "[+] bypass 1.2.3.4 -> via Shirazu-VPN" as if it worked.
    pe = physical_egress()
    if pe is None:
        sys.exit("[!] --live-bypass: no physical IPv4 egress could be "
                 "validated, so refusing to pin a bypass route onto a "
                 "VPN/tunnel adapter. Disconnect the VPN, or use the "
                 "dashboard's [A] key instead.")
    iface, gateway = pe
    print(f"[*] Live bypass: physical egress {iface} ({gateway}); "
          f"adding routes to the running TUN.")

    hosts = list(args.bypass_ip) + list(args.server)
    if not hosts:
        sys.exit("[!] --live-bypass needs at least one --bypass-ip or --server host.")

    d6 = get_ipv6_default()
    # Ride the VPN when the user explicitly asked for VLESS-over-VPN - every
    # sibling call site in main() passes exclude_vpn=not args.vless_over_vpn,
    # and ignoring the flag here silently contradicted [V] mode.
    over_vpn = bool(getattr(args, "vless_over_vpn", False))
    added = 0
    for h in hosts:
        v4, v6 = resolve_all_safe(h, label=f"bypass {h}")
        if v4 is None and v6 is None:
            continue
        for ip in (v4 or []):
            eg = get_egress_for(ip, exclude_vpn=not over_vpn) \
                or (iface, gateway)
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

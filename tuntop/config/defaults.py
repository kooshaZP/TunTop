"""Configuration defaults (Config layer).

THE single source of truth for every constant more than one module needs:
adapter names/addresses, DNS defaults, LAN bypass prefixes, the VPN
interface regex, geo batch tuning and the default ports. Other modules
IMPORT from here - a second literal copy of any of these values elsewhere
is a bug waiting to happen (the LAN list used to exist in three hand-synced
copies, the VPN regex in seven).

Kept free of any Windows imports.
"""
from __future__ import annotations

# ── DNS ──────────────────────────────────────────────────────────────────────
# Default resolvers used when the user has not chosen their own.
DNS4 = "8.8.8.8"
DNS6 = "2606:4700:4700::1111"

# Resolution-fallback policy. 'availability' (default): if the system
# resolver fails while the tunnel is up, fall back to direct UDP/53 + DoH
# queries - resolution beats perfection, but a half-broken tunnel CAN leak
# those lookups over the physical NIC. 'strict': while a tunnel is up,
# NEVER send DNS outside it - failed resolution is reported instead of
# silently escaped. Bootstrap (tunnel down/starting) always allows
# fallback; only a live-or-expected-live tunnel is fail-closed.
DNS_POLICIES = ("availability", "strict")
DEFAULT_DNS_POLICY = "availability"

# ── Wintun TUN adapters ──────────────────────────────────────────────────────
# Primary tunnel adapter (matches the project's Windows example).
TUN = "wintun"
TUN4 = "192.168.123.1"
TUN4_MASK = "255.255.255.0"
TUN6 = "fd00:dead:beef::1"
# Second proxy pipe (optional, --proxy2-port). Its adapter never gets a
# default route - only specific-destination host routes.
TUN2 = "wintun2"
TUN2_IP4 = "192.168.124.1"
TUN2_IP6 = "fd00:dead:beef:1::1"

# Tunnel adapter aliases as a tuple - "is this route on one of OUR adapters"
# checks everywhere (sweeps, conflict scans, snapshot filters) use this.
TUNNEL_ALIASES = (TUN, TUN2)

# Alias-prefix heuristic for the Wintun family ('wintun', 'wintun2',
# "Wintun Tunnel"). Python-side checks only: tools like v2rayN/xray name
# their own adapter freely ('xray_tun'), so PowerShell route lookups must
# exclude by DRIVER (InterfaceDescription -match 'Wintun') - see
# tunnel/helper.py:_tun_alias_powershell. Kept here so the heuristic
# itself still has exactly one definition.
WINTUN_FAMILY_RE = r"(?i)^wintun"

# The Wintun adapters own these subnets; a bypass route overlapping either
# would shadow the tunnel's own next-hop and break every Wintun route add.
import ipaddress as _ipaddress  # noqa: E402  (std-lib only, still no Windows)

WINTUN4_NET = _ipaddress.ip_network("192.168.123.0/24")
WINTUN6_NET = _ipaddress.ip_network("fd00:dead:beef::/64")

# ── LAN bypass prefixes ──────────────────────────────────────────────────────
# Installed EVERY run via the physical adapter so LAN traffic never enters
# the tunnel, and swept on every exit/startup path. Supernet prefixes
# Windows never creates on its own, so a route for one of these via a real
# gateway is always TunTop's (or a stale pin from a previous network).
LAN_BYPASS_PREFIXES = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "224.0.0.0/4",
    "255.255.255.255/32",
]

# ── VPN interface heuristic ──────────────────────────────────────────────────
# One regex, one place: connected-Windows-VPN adapter aliases are excluded
# from "physical egress" decisions everywhere (default-route lookup, geo
# egress, LAN sweeps) no matter what the user named the connection.
VPN_IFACE_RE = r"(?i)(pptp|l2tp|sstp|ikev2|vpn|wan miniport)"

# ── Geo route batch tuning ───────────────────────────────────────────────────
# Install: routes per `netsh -f` script, concurrent scripts, hard per-script
# timeout (a hung `netsh add route` must be killable). Sweep/delete uses the
# same script mechanism with its own (larger) chunk size.
GEO_SUB_BATCH = 100
GEO_MAX_WORKERS = 6
GEO_SUB_TIMEOUT = 90
SWEEP_CHUNK = 250
SWEEP_MAX_WORKERS = 6

# ── Ports ────────────────────────────────────────────────────────────────────
# Default SOCKS5 inbound port the dashboard expects v2rayN to expose.
DEFAULT_SOCKS_PORT = 10808
DEFAULT_ENDPOINT_PORT = 443

# ── Geoip ────────────────────────────────────────────────────────────────────
# Default geoip country code: NONE. Nothing is bypassed by country until
# the user picks a code ([F] Geo Manager / --geoip-code / a profile).
DEFAULT_GEOIP_CODE = ""

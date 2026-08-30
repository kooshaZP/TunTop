"""Configuration defaults (Config layer).

Centralised default values so the CLI, the dashboard and the profiles code
agree on them.  Kept free of any Windows imports.
"""
from __future__ import annotations

# Default DNS resolvers used when the user has not chosen their own.
DNS4 = "8.8.8.8"
DNS6 = "2606:4700:4700::1111"

# Wintun TUN interface addressing (matches the project's Windows example).
TUN = "wintun"
TUN4 = "192.168.123.1"
TUN4_MASK = "255.255.255.0"
TUN6 = "fd00:dead:beef::1"

# Default SOCKS5 inbound port the dashboard expects v2rayN to expose.
DEFAULT_SOCKS_PORT = 10808
DEFAULT_ENDPOINT_PORT = 443

# Default geoip country code to bypass through the physical adapter.
DEFAULT_GEOIP_CODE = "cn"

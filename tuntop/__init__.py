"""TunTop - route all of Windows through a VLESS proxy, beautifully.

One-line pitch: TunTop drives every byte your PC sends through a v2rayN
VLESS proxy over a Wintun TUN adapter, and gives you a live btop-style
terminal dashboard - throughput graphs, health checks, instant bypasses,
geo-splitting, profiles and leak tests - with zero pip dependencies.
"""

__version__ = "1.0.0"
__all__ = ["dashboard", "helper", "routing", "netdns", "geoip", "state",
           "recovery", "routes_txn", "startup_recovery", "integrity",
           "ui_text", "profiles"]

"""TunTop - route all of Windows through a VLESS proxy, beautifully.

One-line pitch: TunTop drives every byte your PC sends through a v2rayN
VLESS proxy over a Wintun TUN adapter, and gives you a live btop-style
terminal dashboard - throughput graphs, health checks, instant bypasses,
geo-splitting, profiles and leak tests - with zero pip dependencies.

Architecture (Phase 1) - strict downward dependency flow:

    UI  ->  Core  ->  Network / Tunnel  ->  Windows

The UI (``tuntop.ui``) must only ever drive ``tuntop.core`` (notably
``TunnelManager``); Core talks to the Network/Tunnel layers, which are the
only places that touch Windows.  Legacy top-level module names
(``tuntop.routing``, ``tuntop.helper``, ...) remain importable as aliases
for backward compatibility.
"""
from __future__ import annotations

__version__ = "1.0.0"

# Public, layered surface. Legacy flat names still resolve via shims.
__all__ = [
    "core", "network", "tunnel", "monitor", "config", "geo", "ui",
]

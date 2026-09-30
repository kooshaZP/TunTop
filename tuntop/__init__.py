"""TunTop - route all of Windows through any local SOCKS5 proxy, beautifully.

One-line pitch: TunTop drives every byte your PC sends through a local
SOCKS5 proxy (v2rayN, Xray, sing-box, Clash, ...) over a Wintun TUN
adapter, and gives you a live btop-style
terminal dashboard - throughput graphs, health checks, instant bypasses,
geo-splitting, profiles and leak tests - with zero pip dependencies.

Architecture (Phase 1) - aspirational, not enforced:

    UI  ->  Core  ->  Network / Tunnel  ->  Windows

The UI (``tuntop.ui``) reaches ``tuntop.core`` for only ``tunnel_manager``
and ``markers``; the rest arrives through the legacy top-level names
(``tuntop.routing``, ``tuntop.helper``, ...), which are ``sys.modules``
aliases for the very same objects.  ``core/tunnel_manager.py`` is a real
facade, but nothing stops the UI reaching around it - and it does.
"""
from __future__ import annotations

__version__ = "1.0.51"

# Public, layered surface. Legacy flat names still resolve via shims.
__all__ = [
    "core", "network", "tunnel", "monitor", "config", "geo", "ui",
]

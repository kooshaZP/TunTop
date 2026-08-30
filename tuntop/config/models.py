"""Configuration models (Config layer).

A typed view over the JSON profile snapshot defined in
``tuntop.config.profiles``. Secrets are never part of a model - they live in
the protected store (see ``tuntop.config.profiles.secret_store``).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Profile:
    """One shareable TunTop setup."""

    name: str = "default"
    server: list = field(default_factory=list)
    port: int = 10808
    dns4: str = "8.8.8.8"
    endpoint_port: int = 443
    bypass_ip: list = field(default_factory=list)
    geoip: Optional[str] = None
    geoip_code: str = "cn"
    vless_over_vpn: bool = False
    no_vpn_bypass: bool = False
    vpn_interface: Optional[str] = None
    secret_ref: Optional[str] = None   # key into the protected secret store

    @classmethod
    def from_snapshot(cls, name: str, snap: dict) -> "Profile":
        p = cls(name=name)
        for k, v in snap.items():
            if hasattr(p, k):
                setattr(p, k, v)
        return p

    def to_snapshot(self) -> dict:
        return {
            "server": list(self.server),
            "port": self.port,
            "dns4": self.dns4,
            "endpoint_port": self.endpoint_port,
            "bypass_ip": list(self.bypass_ip),
            "geoip": self.geoip,
            "geoip_code": self.geoip_code,
            "vless_over_vpn": self.vless_over_vpn,
            "no_vpn_bypass": self.no_vpn_bypass,
            "vpn_interface": self.vpn_interface,
        }

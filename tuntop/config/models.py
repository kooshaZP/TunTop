"""Configuration models (Config layer).

A typed view over the JSON profile snapshot defined in
``tuntop.config.profiles``. Secrets are never part of a model - they live in
the protected store (see ``tuntop.config.profiles.secret_store``).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from tuntop.config.defaults import (
    DEFAULT_ENDPOINT_PORT, DEFAULT_SOCKS_PORT, DNS4, DEFAULT_DNS_POLICY,
    DEFAULT_LOG_ADAPTER_ACTIVITY, DEFAULT_DNS_GUARD, DEFAULT_DNS_GUARD_EXEMPT,
)


@dataclass
class Profile:
    """One shareable TunTop setup."""

    name: str = "default"
    server: list = field(default_factory=list)
    port: int = DEFAULT_SOCKS_PORT
    dns4: str = DNS4
    dns6: Optional[str] = None   # None = not chosen (v4-only or defaults apply)
    dns_policy: str = DEFAULT_DNS_POLICY   # availability | strict (see defaults)
    endpoint_port: int = DEFAULT_ENDPOINT_PORT
    bypass_ip: list = field(default_factory=list)
    vpn_bypass_ip: list = field(default_factory=list)   # targets via Windows VPN
    proxy2_bypass_ip: list = field(default_factory=list)  # targets via proxy2
    proxy2_port: Optional[int] = None                     # None = feature off
    proxy2_server: list = field(default_factory=list)     # proxy2's own upstream
    geoip: Optional[str] = None
    geoip_code: str = ""   # empty = no country bypass
    geoip_target: Optional[str] = None  # direct | proxy2 | winvpn (None = legacy flags)
    vless_over_vpn: bool = False
    no_vpn_bypass: bool = False
    vpn_interface: Optional[str] = None
    log_adapter_activity: bool = DEFAULT_LOG_ADAPTER_ACTIVITY
    dns_guard: bool = DEFAULT_DNS_GUARD          # catch-all NRPT DNS pin
    # Extra exemptions beyond the always-on mDNS one. The field default comes
    # from DEFAULT_DNS_GUARD_EXEMPT (copied, not shared: a mutable default
    # must never be handed out by reference).
    dns_guard_exempt: list = field(
        default_factory=lambda: list(DEFAULT_DNS_GUARD_EXEMPT))
    secret_ref: Optional[str] = None   # key into the protected secret store

    #: Fields a snapshot may SET. An explicit allow-list, not hasattr(): the
    #: old loop let a hand-edited or shared snapshot overwrite `name` (the
    #: key the profile is stored under) and assign anything at all to any
    #: attribute, including the list fields with a plain string - which then
    #: iterated PER CHARACTER downstream.
    _SNAPSHOT_FIELDS = frozenset((
        "server", "port", "dns4", "dns6", "dns_policy", "endpoint_port",
        "bypass_ip", "vpn_bypass_ip", "proxy2_bypass_ip", "proxy2_port",
        "proxy2_server", "geoip", "geoip_code", "geoip_target",
        "vless_over_vpn", "no_vpn_bypass", "vpn_interface",
        "log_adapter_activity", "dns_guard", "dns_guard_exempt",
        "secret_ref",
    ))

    #: List-typed fields: a string must never be assigned straight in, and a
    #: non-list becomes an empty list rather than a per-character iterable.
    _SNAPSHOT_LISTS = frozenset((
        "server", "bypass_ip", "vpn_bypass_ip", "proxy2_bypass_ip",
        "proxy2_server", "dns_guard_exempt",
    ))

    @classmethod
    def from_snapshot(cls, name: str, snap: dict) -> "Profile":
        p = cls(name=name)
        for k, v in (snap or {}).items():
            if k not in cls._SNAPSHOT_FIELDS:
                continue
            if k in cls._SNAPSHOT_LISTS:
                if v is None:
                    v = []
                elif isinstance(v, str):
                    v = [v]
                elif not isinstance(v, (list, tuple)):
                    continue
                else:
                    v = list(v)
            setattr(p, k, v)
        return p

    def to_snapshot(self) -> dict:
        return {
            "server": list(self.server),
            "port": self.port,
            "dns4": self.dns4,
            "dns6": self.dns6,
            "dns_policy": self.dns_policy,
            "endpoint_port": self.endpoint_port,
            "bypass_ip": list(self.bypass_ip),
            "vpn_bypass_ip": list(self.vpn_bypass_ip),
            "proxy2_bypass_ip": list(self.proxy2_bypass_ip),
            "proxy2_port": self.proxy2_port,
            "proxy2_server": list(self.proxy2_server),
            "geoip": self.geoip,
            "geoip_code": self.geoip_code,
            "geoip_target": self.geoip_target,
            "vless_over_vpn": self.vless_over_vpn,
            "no_vpn_bypass": self.no_vpn_bypass,
            "vpn_interface": self.vpn_interface,
            "log_adapter_activity": self.log_adapter_activity,
            "dns_guard": self.dns_guard,
            "dns_guard_exempt": list(self.dns_guard_exempt),
            # secret_ref MUST round-trip. Profile.secret_ref exists precisely
            # so a profile points at the protected (DPAPI) store; dropping it
            # here silently detached a profile from its stored credential on
            # the first save/load cycle, and the orphaned secret was never
            # cleaned up.
            "secret_ref": self.secret_ref,
        }

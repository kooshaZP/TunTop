"""Profile persistence - save/load named setups as plain JSON.

This is the CONFIG layer of the dashboard's [O] profile feature: what a
profile contains, how it is stored, and how a stored snapshot is written
back onto the runtime options. It deliberately knows NOTHING about the
TUI - no overlays, no log lines, no key handling (those stay in
dashboard.py); the caller supplies any host normalisation callback.

Storage: a single profiles.json next to the package, keyed by profile
name. JSON-safe, human-editable, and (Phase 15 note) contains NO secrets
- only server addresses, ports, DNS, geo and bypass settings.

Pure stdlib, zero pip dependencies.
"""
from __future__ import annotations

import json
import os


def profile_file(package_dir: str) -> str:
    """Where the profiles store lives (next to the package)."""
    return os.path.join(package_dir, "profiles.json")


def snapshot_from_args(ns) -> dict:
    """Capture everything that defines a setup from the argparse
    namespace. Only settings - never credentials (VLESS auth lives in
    v2rayN; this file must stay shareable)."""
    return {
        "server": list(getattr(ns, "server", []) or []),
        "port": getattr(ns, "port", 10808),
        "dns4": getattr(ns, "dns4", "8.8.8.8"),
        "endpoint_port": getattr(ns, "endpoint_port", 443),
        "bypass_ip": list(getattr(ns, "bypass_ip", []) or []),
        "geoip": getattr(ns, "geoip", None),
        "geoip_code": getattr(ns, "geoip_code", "cn"),
        "vless_over_vpn": bool(getattr(ns, "vless_over_vpn", False)),
        "no_vpn_bypass": bool(getattr(ns, "no_vpn_bypass", False)),
        "vpn_interface": getattr(ns, "vpn_interface", None),
    }


def load_store(path: str) -> tuple:
    """Read the whole profiles store. Returns (data, error) where data is
    a dict (possibly empty) and error is None, 'missing', or an error
    string - so the UI can show the right message without try/except."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return (data if isinstance(data, dict) else {}), None
    except FileNotFoundError:
        return {}, "missing"
    except Exception as e:
        return {}, str(e)


def save_snapshot(path: str, name: str, snapshot: dict) -> tuple:
    """Store one named profile (merging into the existing store).
    Returns (ok, message) - the message is UI-ready."""
    name = (name or "").strip()
    if not name:
        return False, "[!] Empty profile name - not saved."
    try:
        data, err = load_store(path)
        if err and err != "missing":
            return False, f"[!] Could not read profiles.json: {err}"
        data[name] = snapshot
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        return False, f"[!] Could not write profiles.json: {e}"
    return True, (f"[+] Profile '{name}' saved "
                  f"({len(data)} profile(s) total).")


def apply_to_args(ns, snap: dict, normalise_host=None) -> list:
    """Write a stored snapshot back onto the runtime argparse namespace.
    `normalise_host` (optional) is applied to every bypass entry - the
    dashboard passes its _host_from_url so URLs/ports never sneak into a
    route. Returns the list of scalar attributes applied (for logging)."""
    applied = []
    for attr in ("port", "dns4", "endpoint_port", "geoip",
                 "geoip_code", "vpn_interface"):
        if attr in snap:
            setattr(ns, attr, snap[attr])
            applied.append(attr)
    ns.server = list(snap.get("server") or [])
    ns.bypass_ip = [_host_from_url(x) for x in (snap.get("bypass_ip") or [])
                    if _host_from_url(x)] if normalise_host \
        else list(snap.get("bypass_ip") or [])
    ns.vless_over_vpn = bool(snap.get("vless_over_vpn"))
    ns.no_vpn_bypass = bool(snap.get("no_vpn_bypass"))
    return applied

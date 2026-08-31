"""Profile persistence - save/load named setups as plain JSON.

This is the CONFIG layer of the dashboard's [O] profile feature: what a
profile contains, how it is stored, and how a stored snapshot is written
back onto the runtime options. It deliberately knows NOTHING about the
TUI - no overlays, no log lines, no key handling (those stay in
tuntop/ui/dashboard.py); the caller supplies any host normalisation callback.

Storage: a single profiles.json next to the package, keyed by profile
name. JSON-safe, human-editable, and (Phase 15 note) contains NO secrets
- only server addresses, ports, DNS, geo and bypass settings.

Pure stdlib, zero pip dependencies.
"""
from __future__ import annotations

import json
import os


#: Default profile-store filename (Phase 15 - portable, branded).
PROFILE_FILENAME = "MyTunTopProfile.json"


def profile_file(package_dir: str) -> str:
    """Where the profiles store lives (next to the package)."""
    return os.path.join(package_dir, PROFILE_FILENAME)


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
        "vpn_bypass_ip": list(getattr(ns, "vpn_bypass_ip", []) or []),
        "proxy2_bypass_ip": list(getattr(ns, "proxy2_bypass_ip", []) or []),
        "proxy2_port": getattr(ns, "proxy2_port", None),
        "proxy2_server": list(getattr(ns, "proxy2_server", []) or []),
        "geoip": getattr(ns, "geoip", None),
        "geoip_code": getattr(ns, "geoip_code", "cn"),
        "geoip_target": getattr(ns, "geoip_target", None),
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
                 "geoip_code", "geoip_target", "vpn_interface"):
        if attr in snap:
            setattr(ns, attr, snap[attr])
            applied.append(attr)
    ns.server = list(snap.get("server") or [])
    if normalise_host:
        ns.bypass_ip = [h for h in (normalise_host(x)
                                    for x in (snap.get("bypass_ip") or []))
                        if h]
        ns.proxy2_bypass_ip = [h for h in (normalise_host(x)
                                           for x in (snap.get("proxy2_bypass_ip")
                                                     or []))
                               if h]
        ns.vpn_bypass_ip = [h for h in (normalise_host(x)
                                        for x in (snap.get("vpn_bypass_ip")
                                                  or []))
                            if h]
    else:
        ns.bypass_ip = list(snap.get("bypass_ip") or [])
        ns.proxy2_bypass_ip = list(snap.get("proxy2_bypass_ip") or [])
        ns.vpn_bypass_ip = list(snap.get("vpn_bypass_ip") or [])
    if "proxy2_port" in snap:
        ns.proxy2_port = snap["proxy2_port"]
        applied.append("proxy2_port")
    ns.proxy2_server = list(snap.get("proxy2_server") or [])
    ns.vless_over_vpn = bool(snap.get("vless_over_vpn"))
    ns.no_vpn_bypass = bool(snap.get("no_vpn_bypass"))
    return applied


def export_profile(path: str, name: str, snapshot: dict) -> tuple:
    """Write a single profile to a standalone .json file for sharing.

    The file is self-contained: it wraps the snapshot under a top-level
    ``{"name": ..., "snapshot": ...}`` envelope so ``import_profile``
    can validate it.  Returns (ok, message)."""
    name = (name or "").strip()
    if not name:
        return False, "[!] Empty profile name - not exported."
    try:
        envelope = {"name": name, "snapshot": snapshot}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(envelope, f, indent=2)
    except Exception as e:
        return False, f"[!] Could not write profile: {e}"
    return True, f"[+] Profile '{name}' exported to {os.path.basename(path)}."


def import_profile(path: str) -> tuple:
    """Read a standalone profile file previously created by ``export_profile``.

    Returns (name, snapshot, error) where error is None on success,
    or a human-readable error string."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return None, None, f"File not found: {path}"
    except Exception as e:
        return None, None, f"Could not read file: {e}"

    if not isinstance(data, dict):
        return None, None, "Invalid profile file (not a JSON object)."
    name = data.get("name", "").strip()
    snap = data.get("snapshot")
    if not name:
        return None, None, "Profile file missing 'name' field."
    if not isinstance(snap, dict):
        return None, None, "Profile file missing or invalid 'snapshot' field."
    return name, snap, None


# ── Protected secret storage (Phase 15) ────────────────────────────────────
# A profile must NEVER embed a password/UUID/key in plaintext JSON (that
# file is meant to be shareable). Anything sensitive is kept in the OS
# protected store instead, and the profile references it by key.
#
# On Windows that is the Windows Credential Manager (DPAPI-backed, per-user,
# never written to disk as plaintext via our code). On every other platform
# the store is unavailable and any attempt to persist a secret raises
# SecretStoreError - deliberately, so a secret can never leak into a JSON
# file by accident.


class SecretStoreError(Exception):
    """Raised when a protected secret cannot be stored/retrieved."""


class SecretStore:
    """Protected, OS-backed secret storage.

    Reference it from a profile snapshot as
    ``{"secret_ref": "my-vless-key"}`` rather than embedding the value.
    """

    TARGET_PREFIX = "TunTop:"

    def __init__(self):
        self._api = _WinCred() if (os.name == "nt" and _HAS_WINCRED) else None

    def available(self) -> bool:
        """Whether a protected backend exists on this platform."""
        return self._api is not None

    def put(self, key: str, secret: str) -> None:
        if self._api is None:
            raise SecretStoreError(
                "protected secret store unavailable on this platform - "
                "secrets were NOT saved (kept out of the profile file "
                "on purpose)")
        if not key or secret is None:
            raise SecretStoreError("secret key and value are required")
        self._api.write(self.TARGET_PREFIX + key, secret)

    def get(self, key: str):
        if self._api is None:
            raise SecretStoreError("protected secret store unavailable")
        return self._api.read(self.TARGET_PREFIX + key)

    def delete(self, key: str) -> bool:
        if self._api is None:
            raise SecretStoreError("protected secret store unavailable")
        return self._api.delete(self.TARGET_PREFIX + key)


#: Module-level flags so SecretStore.__init__ can read them safely even on
#: non-Windows (where the ctypes block below never runs).
_HAS_WINCRED = False
_WinCred = None


# ── Windows Credential Manager backend (ctypes, zero pip deps) ──────────────
# Only loaded on Windows; on other platforms _HAS_WINCRED stays False and the
# ctypes/advapi32 code below is never executed (so import is safe anywhere).

if os.name == "nt":
    try:
        import ctypes
        from ctypes import wintypes

        _CRED_TYPE_GENERIC = 0x1
        _CRED_PERSIST_LOCAL_MACHINE = 0x2

        class _CREDENTIALW(ctypes.Structure):
            _fields_ = [
                ("Flags", wintypes.DWORD),
                ("Type", wintypes.DWORD),
                ("TargetName", wintypes.LPWSTR),
                ("Comment", wintypes.LPWSTR),
                ("LastWritten", wintypes.FILETIME),
                ("CredentialBlobSize", wintypes.DWORD),
                ("CredentialBlob", ctypes.POINTER(ctypes.c_byte)),
                ("Persist", wintypes.DWORD),
                ("AttributeCount", wintypes.DWORD),
                ("Attributes", ctypes.c_void_p),
                ("TargetAlias", wintypes.LPWSTR),
                ("UserName", wintypes.LPWSTR),
            ]

        _advapi = ctypes.windll.advapi32
        _advapi.CredWriteW.argtypes = [ctypes.POINTER(_CREDENTIALW), wintypes.DWORD]
        _advapi.CredWriteW.restype = wintypes.BOOL
        _advapi.CredReadW.argtypes = [wintypes.LPWSTR, wintypes.DWORD,
                                      wintypes.DWORD,
                                      ctypes.POINTER(ctypes.POINTER(_CREDENTIALW))]
        _advapi.CredReadW.restype = wintypes.BOOL
        _advapi.CredDeleteW.argtypes = [wintypes.LPWSTR, wintypes.DWORD,
                                        wintypes.DWORD]
        _advapi.CredDeleteW.restype = wintypes.BOOL
        _advapi.CredFree.argtypes = [ctypes.POINTER(_CREDENTIALW)]
        _advapi.CredFree.restype = None

        class _WinCred:
            """Thin wrapper over the CREDENTIAL API."""

            def write(self, target: str, secret: str) -> None:
                blob = secret.encode("utf-16-le")
                buf = (ctypes.c_byte * len(blob)).from_buffer_copy(blob)
                cred = _CREDENTIALW()
                cred.Type = _CRED_TYPE_GENERIC
                cred.TargetName = target
                cred.CredentialBlobSize = len(blob)
                cred.CredentialBlob = ctypes.cast(buf,
                                                  ctypes.POINTER(ctypes.c_byte))
                cred.Persist = _CRED_PERSIST_LOCAL_MACHINE
                if not _advapi.CredWriteW(ctypes.byref(cred), 0):
                    raise SecretStoreError("CredWriteW failed")

            def read(self, target: str):
                pptr = ctypes.POINTER(_CREDENTIALW)()
                if not _advapi.CredReadW(target, _CRED_TYPE_GENERIC, 0,
                                         ctypes.byref(pptr)):
                    raise SecretStoreError(f"no such secret: {target!r}")
                try:
                    cred = pptr.contents
                    size = cred.CredentialBlobSize
                    raw = bytes(ctypes.cast(cred.CredentialBlob,
                                            ctypes.POINTER(ctypes.c_byte))[0:size])
                    return raw.decode("utf-16-le")
                finally:
                    _advapi.CredFree(pptr)

            def delete(self, target: str) -> bool:
                return bool(_advapi.CredDeleteW(target, _CRED_TYPE_GENERIC, 0))

        _HAS_WINCRED = True
    except Exception:
        # Any failure to bind the API -> behave as "no protected store".
        _HAS_WINCRED = False


#: Shared instance - import this rather than constructing your own.
secret_store = SecretStore()

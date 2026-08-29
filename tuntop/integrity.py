"""Binary integrity verification - trust the bytes you run as ADMIN.

TunTop launches `tun2socks.exe` (and loads `wintun.dll`) from an
Administrator process that rewrites the system routing table. If either
binary is swapped, corrupted, or half-downloaded, that is arbitrary code
execution in an elevated process - not a glitch.

So every launch verifies the binaries against SHA-256 pins recorded in
this file:

    verify -> hash matches pin? -yes-> start the tunnel
                        |
                        no  -> REFUSE to start, print expected vs actual
                               (an explicit --trust-binaries escape hatch
                                exists for deliberate rebuilds)

Upgrading a binary is therefore a deliberate act: replace the file AND
update its pin in PINNED_BINARIES (the unit test that checks the vendored
files against the pins will fail loudly if the two ever drift apart).

Pure stdlib, zero pip dependencies; hash computation is chunked so the
multi-MB tun2socks binary never loads whole into memory.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Optional

# -- The pins ---------------------------------------------------------------
# sha256 of the exact vendored files this repo ships. Update BOTH the file
# and its pin together (see module docstring).

PINNED_BINARIES = {
    "tun2socks-windows-amd64-v3.exe":
        "f08d327819f722da3ee3f591cb7e9e36b06640a92b3f63f5073a454be29be35f",
    "wintun.dll":
        "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",
}

# -- Results ----------------------------------------------------------------

STATUS_OK = "ok"
STATUS_MISSING = "missing"
STATUS_MISMATCH = "mismatch"


@dataclass
class BinaryReport:
    """One binary's verification outcome."""

    name: str
    path: str
    status: str                    # OK | MISSING | MISMATCH
    expected: str = ""
    actual: str = ""
    size: int = 0

    @property
    def ok(self) -> bool:
        return self.status == STATUS_OK


def sha256_of(path: str, chunk_size: int = 1024 * 1024) -> str:
    """SHA-256 of a file, streamed in chunks (never loads it whole)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def verify_file(path: str, expected_sha256: str) -> BinaryReport:
    """Check one file against an expected SHA-256 (case-insensitive)."""
    name = os.path.basename(path) if path else "(none)"
    if not path or not os.path.isfile(path):
        return BinaryReport(name=name, path=path or "(not given)",
                            status=STATUS_MISSING,
                            expected=expected_sha256.lower())
    try:
        actual = sha256_of(path)
        size = os.path.getsize(path)
    except OSError as e:
        return BinaryReport(name=name, path=path, status=STATUS_MISMATCH,
                            expected=expected_sha256.lower(),
                            actual=f"unreadable ({e})")
    status = STATUS_OK if actual.lower() == expected_sha256.lower() \
        else STATUS_MISMATCH
    return BinaryReport(name=name, path=path, status=status,
                        expected=expected_sha256.lower(), actual=actual,
                        size=size)


def locate_wintun(tun2socks_path: str) -> Optional[str]:
    """Find wintun.dll the same way tun2socks finds it: next to the
    tun2socks binary first, then the package directory, then the CWD.
    Returns None when it is nowhere (reported as MISSING)."""
    candidates = []
    if tun2socks_path:
        candidates.append(os.path.join(os.path.dirname(os.path.abspath(
            tun2socks_path)), "wintun.dll"))
    candidates.append(os.path.join(os.path.dirname(os.path.abspath(
        __file__)), "wintun.dll"))
    candidates.append(os.path.join(os.getcwd(), "wintun.dll"))
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def verify_for_launch(tun2socks_path: str, wintun_path: Optional[str] = None,
                      trust: bool = False,
                      expected: Optional[dict] = None) -> tuple:
    """Verify the binaries the tunnel is about to run.

    Returns (ok, reports, messages): `ok` is False when the launch must be
    refused - a MISSING or MISMATCHED binary, unless `trust=True` (the
    documented escape hatch for deliberately rebuilt binaries).
    `expected` overrides the pins (used by tests and by callers verifying
    a differently-named binary).
    """
    pins = expected if expected is not None else PINNED_BINARIES
    t_name = os.path.basename(tun2socks_path) if tun2socks_path else \
        "tun2socks"
    t_pin = pins.get(t_name) or pins.get(
        "tun2socks-windows-amd64-v3.exe", "")
    t_report = verify_file(tun2socks_path or "", t_pin)

    if not wintun_path:
        wintun_path = locate_wintun(tun2socks_path)
    w_pin = pins.get("wintun.dll", "")
    if wintun_path:
        w_report = verify_file(wintun_path, w_pin)
    else:
        w_report = BinaryReport(name="wintun.dll", path="(not found)",
                                status=STATUS_MISSING, expected=w_pin)

    reports = [t_report, w_report]
    ok = all(r.ok for r in reports)
    messages = []
    for r in reports:
        if r.status == STATUS_OK:
            messages.append(f"[+] {r.name}: integrity verified "
                            f"(sha256 {r.actual[:16]}...)")
        elif r.status == STATUS_MISSING:
            messages.append(f"[!] {r.name}: NOT FOUND at {r.path}")
        else:
            messages.append(f"[!] {r.name}: SHA-256 MISMATCH at {r.path}")
            messages.append(f"    expected: {r.expected}")
            messages.append(f"    actual:   {r.actual}")
    if not ok and trust:
        messages.append("[!] Launching anyway (--trust-binaries): the "
                        "binaries above are UNVERIFIED.")
        ok = True
    if not ok:
        messages.append("[!] Refusing to start with unverified binaries. "
                        "Restore the files above (they ship with the "
                        "repo), or override with --trust-binaries if you "
                        "rebuilt them yourself.")
    return ok, reports, messages


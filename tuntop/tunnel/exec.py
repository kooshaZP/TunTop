"""Subprocess / PowerShell execution primitives for the tunnel layer.

Moved out of helper.py (Phase 4 split): these are STATE-FREE platform
primitives every tunnel subsystem needs (installer, geo engine, monitor).
No tuntop state is read or written here - only processes are spawned.

`run` enforces a hard timeout: Windows networking cmdlets can block
indefinitely when the RasMan service is busy or the routing table is
mid-change, and a hung child must never freeze the tunnel loop.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import tempfile

# Windows caps a whole CreateProcess command line at 32767 chars; the encoded
# form of a big bulk-removal script exceeds it, so run_ps() falls back to
# executing such scripts from a temp .ps1 file (mirrors tuntop/routing.py).
_PS_CMDLINE_SAFE = 20000


def run(cmd, check=False, timeout=15):
    """Run a command and return (returncode, stdout, stderr).

    A timeout is enforced so a hung child cannot freeze the whole script.
    Windows networking cmdlets (Get-VpnConnection / Find-NetRoute /
    Get-NetRoute) can block indefinitely when the RasMan service is busy or
    the routing table is mid-change - without a timeout this stalls the
    helper forever ("not crashed but unresponsive"). On timeout the child is
    killed and a nonzero code is returned, letting callers fall back instead
    of stalling.

    15s is chosen as a bound: these cmdlets are normally sub-second, so a
    real hang is caught quickly without cutting off a legitimately slow one.
    Hot-path callers (e.g. get_egress_for, called once per server) pass a
    shorter timeout so N servers can't multiply the stall into minutes.
    """
    try:
        p = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except (FileNotFoundError, OSError) as e:
        msg = str(e)
        if check:
            print(f"[!] Command failed to start: {' '.join(cmd)}")
            if msg:
                print(f"    {msg}")
        return 1, "", msg
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            p.kill()
        except Exception:
            pass
        # Bound the post-kill read too: if a child (e.g. netsh) inherited the
        # stdout pipe and is still alive, a bare communicate() could hang again.
        try:
            out, err = p.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            out, err = "", ""
        if check:
            print(f"[!] Command timed out ({timeout}s): {' '.join(cmd)}")
        return 124, (out or "").strip(), f"timed out after {timeout}s"
    if check and p.returncode:
        msg = (err or "").strip() or (out or "").strip()
        print(f"[!] Command failed: {' '.join(cmd)}")
        if msg:
            print(f"    {msg}")
    return p.returncode, (out or "").strip(), (err or "").strip()


def ps_json(script, timeout=15):
    # -EncodedCommand (UTF-16LE, base64) instead of raw -Command text.
    # -Command re-parses the string as if typed at a console, which can
    # mis-split scripts containing nested single quotes, braces, or
    # pipes. All the VPN-detection PowerShell above relies on this being
    # reliable, so encode it rather than risk a silent parse failure.
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    code, out, _ = run([
        "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-EncodedCommand", encoded
    ], timeout=timeout)
    if code or not out:
        return None
    try:
        return json.loads(out)
    except Exception:
        return None


def run_ps(script, timeout=15):
    """Run a PowerShell script and return its raw stdout, for callers that
    don't need ps_json's JSON parsing.

    Small scripts use -EncodedCommand as before. Scripts whose encoded command
    line would approach the Windows 32767-char CreateProcess cap - notably
    the multi-hundred-statement geoip teardown batches, which silently NEVER
    STARTED over the limit (why geoip routes survived every cleanup) - are
    written to a temp .ps1 file and run with -File instead."""
    base_cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass"]
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    if len(encoded) + 80 > _PS_CMDLINE_SAFE:
        fd, path = tempfile.mkstemp(suffix=".ps1", prefix="TunTop_helper_")
        try:
            with os.fdopen(fd, "w", encoding="utf-8-sig") as f:
                f.write(script)
            return run(base_cmd + ["-File", path], timeout=timeout)
        finally:
            try:
                os.unlink(path)
            except Exception:
                pass
    return run(base_cmd + ["-EncodedCommand", encoded], timeout=timeout)


def _clean_err(err):
    """Pull a human-readable line out of a PowerShell stderr blob, skipping
    the '#< CLIXML' progress/telemetry records PowerShell wraps around errors
    so the geo-install failure reason is actually readable."""
    for line in (err or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#<"):
            continue
        return line
    return ""

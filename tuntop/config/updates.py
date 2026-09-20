"""GitHub release auto-update for TunTop (CONFIG layer).

Fetches the latest stable GitHub release of kooshaZP/TunTop, verifies the
TunTop.exe artifact against the published checksums.txt (SHA-256), and
stages the new version NEXT TO the running one under its versioned name
(TunTop-<version>.exe). The running executable is never touched or
launched - the staged file is picked up on the next manual start.

Pure stdlib, zero pip dependencies, no subprocess, no elevation.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.request

__all__ = [
    "UpdateError", "StagedUpdate", "check_latest", "download_release",
    "prepare_update", "expected_exe_name",
]

_API_URL = "https://api.github.com/repos/kooshaZP/TunTop/releases/latest"
_ASSET_BASE = "https://github.com/kooshaZP/TunTop/releases/download/"
_EXE_NAME = "TunTop.exe"
_CHECKSUM_NAME = "checksums.txt"
_MAX_EXE_BYTES = 64 * 1024 * 1024
_MAX_CHECKSUM_BYTES = 64 * 1024
_TIMEOUT = 20
_UA = {"User-Agent": "TunTop-Updater"}
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_SHA256_RE = re.compile(r"^([0-9a-fA-F]{64})\s+\*?(.+)$")


class UpdateError(Exception):
    pass


class UpdateErrorTyped(UpdateError):
    pass


class StagedUpdate:
    """A verified TunTop-<version>.exe staged next to the running exe."""

    __slots__ = ("version", "path", "sha256")

    def __init__(self, version, path, sha256):
        self.version = version
        self.path = path
        self.sha256 = sha256

    def __repr__(self):
        return f"StagedUpdate(version={self.version!r}, path={self.path!r})"


def expected_exe_name(version: str) -> str:
    return f"TunTop-{version}.exe"


def _bigger_then_strip(data: bytes, limit: int) -> bytes:
    if len(data) > limit:
        raise UpdateError("response exceeds size limit")
    return data


def _fetch(url: str, limit: int) -> bytes:
    req = urllib.request.Request(url, headers=_UA)
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        if getattr(resp, "status", 200) != 200:
            raise UpdateError(f"HTTP {resp.status} for {url}")
        return _bigger_then_strip(resp.read(limit + 1), limit)


def _parse_version(tag: str) -> str:
    v = (tag or "").strip()
    if v[:1].lower() == "v":
        v = v[1:]
    if not _VERSION_RE.match(v):
        raise UpdateError(f"unsupported release tag {tag!r}")
    return v


def _version_gt(a: str, b: str) -> bool:
    ka = tuple(int(x) for x in a.split("."))
    kb = tuple(int(x) for x in b.split("."))
    return ka > kb


def _asset_url(tag: str, name: str) -> str:
    if not re.match(r"^[\w.\-]+$", name):
        raise UpdateError(f"unexpected asset name {name!r}")
    return (_ASSET_BASE + tag + "/" + name)


def check_latest(current_version: str) -> dict:
    """Query the latest stable release. Returns a dict with keys:
    version, exe_url, checksum_url. Raises UpdateError on anything
    unexpected (draft/prerelease, malformed tag, wrong asset set)."""
    current = _parse_version(current_version)
    raw = _fetch(_API_URL, 1024 * 1024)
    try:
        rel = json.loads(raw.decode("utf-8"))
    except Exception as e:
        raise UpdateError(f"release metadata is not JSON: {e}")
    if not isinstance(rel, dict):
        raise UpdateError("release metadata is not an object")
    if rel.get("draft") or rel.get("prerelease"):
        raise UpdateError("latest release is draft/prerelease - skipping")
    version = _parse_version(str(rel.get("tag_name") or ""))
    assets = rel.get("assets") or []
    urls = {a.get("name"): a.get("browser_download_url") for a in assets
            if isinstance(a, dict)}
    exe_url = urls.get(_EXE_NAME)
    sum_url = urls.get(_CHECKSUM_NAME)
    if not exe_url or not sum_url:
        raise UpdateError("release is missing TunTop.exe or checksums.txt")
    if not str(exe_url).startswith(_ASSET_BASE):
        raise UpdateError("asset URL is not on the release download host")
    if not str(sum_url).startswith(_ASSET_BASE):
        raise UpdateError("checksum URL is not on the release download host")
    return {
        "version": version,
        "current": current,
        "update_available": _version_gt(version, current),
        "exe_url": exe_url,
        "checksum_url": sum_url,
    }


def _parse_checksums(data: bytes) -> dict:
    """Parse `sha256  filename  (N bytes)` lines (build_release.write_checksums
    format) plus the classic `sha256 *filename` form."""
    out = {}
    for line in data.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2 and len(parts[0]) == 64 and \
                all(c in "0123456789abcdefABCDEF" for c in parts[0]):
            name = parts[1].lstrip("*")
            out[name] = parts[0].lower()
        else:
            m = _SHA256_RE.match(line)
            if m:
                out[m.group(2).strip().lstrip("*")] = m.group(1).lower()
    return out


def _verify_pe_header(blob: bytes) -> None:
    if len(blob) < 0x40 or blob[:2] != b"MZ":
        raise UpdateError("downloaded file is not a PE executable")
    pe_off = int.from_bytes(blob[0x3C:0x40], "little")
    if pe_off <= 0 or pe_off + 6 > len(blob) or blob[pe_off:pe_off + 4] != b"PE\0\0":
        raise UpdateError("downloaded file has no PE header")
    machine = int.from_bytes(blob[pe_off + 4:pe_off + 6], "little")
    if machine != 0x8664:
        raise UpdateError("downloaded exe is not x64")


def download_release(info: dict, directory: str) -> StagedUpdate:
    """Download TunTop.exe + checksums.txt, verify the SHA-256 and the PE
    header, then stage the exe as TunTop-<version>.exe inside `directory`
    (atomically, never overwriting a different file)."""
    version = info["version"]
    target = os.path.join(directory, f"TunTop-{version}.exe")
    fd, tmp = tempfile_name(directory)
    try:
        blob = _fetch(info["exe_url"], _MAX_EXE_BYTES)
        _verify_pe_header(blob)
        sums = _parse_checksums(_fetch(info["checksum_url"], _MAX_CHECKSUM_BYTES))
        expected = sums.get(_EXE_NAME)
        if not expected:
            raise UpdateError("checksums.txt has no entry for TunTop.exe")
        actual = hashlib.sha256(blob).hexdigest()
        if actual != expected:
            raise UpdateError(
                f"checksum mismatch (got {actual[:12]}..., want {expected[:12]}...)")
        if os.path.exists(target):
            with open(target, "rb") as f:
                same = hashlib.sha256(f.read()).hexdigest() == actual
            # The temp file may still hold our open fd here (the reuse
            # path never enters the fdopen block) - close it BEFORE the
            # unlink or Windows refuses (WinError 32).
            if fd is not None:
                try:
                    os.close(fd)
                except Exception:
                    pass
                fd = None
            if same:
                os.unlink(tmp)
                return StagedUpdate(version, target, actual)
            raise UpdateError(
                f"{os.path.basename(target)} already exists with different content")
        with os.fdopen(fd, "wb") as f:
            fd = None
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, target)
        return StagedUpdate(version, target, actual)
    except Exception:
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass
        try:
            os.unlink(tmp)
        except Exception:
            pass
        raise


def tempfile_name(directory: str):
    import tempfile
    return tempfile.mkstemp(prefix="tuntop_upd_", suffix=".part", dir=directory)


def prepare_update(current_version: str, directory: str) -> StagedUpdate | None:
    """End-to-end: check the latest release, download + verify + stage it.
    Returns None when already up to date or the check is inconclusive
    (offline); raises UpdateError for verification failures."""
    try:
        info = check_latest(current_version)
    except UpdateError as e:
        if "unsupported release tag" in str(e) or "draft/prerelease" in str(e):
            return None
        raise
    except OSError:
        return None
    if not info["update_available"]:
        return None
    os.makedirs(directory, exist_ok=True)
    return download_release(info, directory)

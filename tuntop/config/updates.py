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
import io
import json
import os
import re
import shutil
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from typing import Optional

__all__ = [
    "UpdateError", "StagedUpdate", "check_latest", "download_release",
    "prepare_update", "expected_exe_name",
]

_API_URL = "https://api.github.com/repos/kooshaZP/TunTop/releases/latest"
_ASSET_BASE = "https://github.com/kooshaZP/TunTop/releases/download/"
_EXE_NAME = "TunTop.exe"
_CHECKSUM_NAME = "checksums.txt"
#: The standalone zip is the only self-contained artifact, and it is the whole
#: collected tree - so the cap has to cover it (14.7 MB at 1.0.51) with room to
#: grow, while still refusing an absurd response.
_MAX_ZIP_BYTES = 128 * 1024 * 1024
_MAX_CHECKSUM_BYTES = 64 * 1024
_TIMEOUT = 20
_UA = {"User-Agent": "TunTop-Updater"}
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_SHA256_RE = re.compile(r"^([0-9a-fA-F]{64})\s+\*?(.+)$")

#: Hosts every request (and every redirect hop) must stay on. The release
#: API is api.github.com; artifact URLs are served from github.com under
#: _ASSET_BASE and legitimately 302 to release-assets.githubusercontent.com
#: (GitHub's own asset CDN) for the actual bytes. That last one is part of
#: the same trust boundary, so it is allowed by name; anything else - a
#: typosquat, a proxy, a hijacked DNS answer - is refused.
_ALLOWED_HOSTS = (
    "github.com",
    "api.github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
)

#: TLS floor, pinned explicitly. Without it the module inherits whatever the
#: interpreter's default context allows, and nothing in this file proves the
#: protocol is 1.2+.
_SSL_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_SSL_CONTEXT.load_default_certs()
_SSL_CONTEXT.check_hostname = True
_SSL_CONTEXT.verify_mode = ssl.CERT_REQUIRED
if hasattr(ssl, "TLSVersion"):
    _SSL_CONTEXT.minimum_version = ssl.TLSVersion.TLSv1_2


class _SameHostRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse a 30x that leaves the expected hosts or downgrades to http.

    urlopen() installs the DEFAULT redirect handler, which follows a 302 to
    ANY host and ANY scheme. check_latest() verified the URLs it was GIVEN
    start with _ASSET_BASE, then handed them straight to urlopen - so a
    redirect was followed transparently and whatever the redirector served
    was treated as the release asset. The checksums file came over the same
    redirectable transport, so it validated the redirector's copy too.

    The SCHEME half was checked only after the fact: _fetch re-validates
    resp.url, so an http:// hop was caught before any byte was used - but
    only once the plaintext request had already left the machine, and only
    if the response carried a usable URL. A 30x to ``http://github.com/...``
    was accepted by this handler, which is what its own docstring said it
    refused. checksums.txt arrives from the same release, so the SHA-256
    only proves the bytes were not corrupted in transit: an attacker who can
    answer for the release can answer for both files and the checksum will
    agree. Requiring https here is what makes the host allow-list mean
    something.

    Re-raise instead of following, so the caller sees the real failure.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            parts = urllib.parse.urlsplit(newurl)
            scheme = (parts.scheme or "").lower()
            host = parts.hostname or ""
        except ValueError:
            raise urllib.error.HTTPError(
                newurl, code, f"malformed redirect target: {msg}",
                headers, fp)
        if scheme != "https":
            raise urllib.error.HTTPError(
                newurl, code,
                f"refusing redirect that is not https ({scheme or 'no scheme'})",
                headers, fp)
        if host.lower() not in _ALLOWED_HOSTS:
            raise urllib.error.HTTPError(
                newurl, code,
                f"refusing redirect to an unexpected host ({host})",
                headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(
    _SameHostRedirectHandler(),
    urllib.request.HTTPSHandler(context=_SSL_CONTEXT),
)


def _assert_allowed_url(url: str) -> None:
    """Fail closed on a URL that is not HTTPS on an expected host."""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError as e:
        raise UpdateError(f"malformed asset URL: {e}")
    if parts.scheme != "https":
        raise UpdateError(f"asset URL is not https: {url}")
    if (parts.hostname or "").lower() not in _ALLOWED_HOSTS:
        raise UpdateError(f"asset URL is not on an expected host: {url}")


class UpdateError(Exception):
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


def _fetch(url: str, limit: int, timeout: Optional[int] = None) -> bytes:
    """GET `url`, capped at `limit` bytes.

    `timeout` overrides the module default so a CALLER can bound the wait:
    the startup check runs inline, before the dashboard opens, and a
    20-second network stall there would look like a hung app (it passes a
    short one; the background download keeps the full default).

    Goes through _OPENER, not urlopen: the opener carries the explicit
    TLS 1.2+ floor and the same-host redirect policy, both of which
    urlopen() would bypass. The FINAL url is re-checked after the response
    arrives, so a redirect that slipped through is caught before a single
    byte is used."""
    _assert_allowed_url(url)
    req = urllib.request.Request(url, headers=_UA)
    with _OPENER.open(
            req, timeout=_TIMEOUT if timeout is None else timeout) as resp:
        final = getattr(resp, "url", None) or url
        _assert_allowed_url(final)
        if getattr(resp, "status", 200) != 200:
            raise UpdateError(f"HTTP {resp.status} for {final}")
        return _bigger_then_strip(resp.read(limit + 1), limit)


def _parse_version(tag: str) -> str:
    v = (tag or "").strip()
    if v[:1].lower() == "v":
        v = v[1:]
    if not _VERSION_RE.match(v):
        raise UpdateError(f"unsupported release tag {tag!r}")
    return v


def _standalone_zip_name(version: str) -> str:
    """The ONE self-contained artifact a release publishes.

    It has to be this, and not the exe, because of what the onedir layout is.
    A collected PyInstaller build is not relocatable: `TunTop.exe` is a small
    launcher (2.8 MB) and its interpreter, DLLs and the vendored binaries live in
    the sibling `_internal/` tree (34 MB). Downloading the exe alone yields a
    program that cannot start - verified on the published v1.0.51 asset, which
    dies with "Failed to load Python DLL '.../_internal/python312.dll'". The zip
    is the whole directory, so it is the only artifact that works on its own.

    That is also why the exe is no longer published: it was on the release page
    as a download that could not run, and the updater fetched it by name, which
    is the one thing keeping a broken file in the set. Both lists changed
    together - see build_release.published_asset_paths."""
    return f"TunTop-{version}-x64-standalone.zip"


def _version_gt(a: str, b: str) -> bool:
    ka = tuple(int(x) for x in a.split("."))
    kb = tuple(int(x) for x in b.split("."))
    return ka > kb


def check_latest(current_version: str,
                 timeout: Optional[int] = None) -> dict:
    """Query the latest stable release. Returns a dict with keys:
    version, exe_url, checksum_url. Raises UpdateError on anything
    unexpected (draft/prerelease, malformed tag, wrong asset set).

    `timeout` bounds the network wait (see _fetch) - the inline startup check
    passes a short one so a stalled feed cannot hold up the launch."""
    current = _parse_version(current_version)
    raw = _fetch(_API_URL, 1024 * 1024, timeout=timeout)
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
    zip_name = _standalone_zip_name(version)
    zip_url = urls.get(zip_name)
    sum_url = urls.get(_CHECKSUM_NAME)
    if not zip_url or not sum_url:
        raise UpdateError(
            f"release is missing {zip_name} or {_CHECKSUM_NAME}")
    if not str(zip_url).startswith(_ASSET_BASE):
        raise UpdateError("asset URL is not on the release download host")
    if not str(sum_url).startswith(_ASSET_BASE):
        raise UpdateError("checksum URL is not on the release download host")
    return {
        "version": version,
        "current": current,
        "update_available": _version_gt(version, current),
        "zip_name": zip_name,
        "zip_url": zip_url,
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


def _safe_extract(zf: zipfile.ZipFile, dest: str) -> None:
    """Extract `zf` into `dest`, refusing any member that would land outside.

    Zip-slip is the whole risk of extracting an archive here: a member named
    `../../Windows/System32/...` or an ABSOLUTE path escapes `dest` on the
    next `extract`, and this is a network download that has only been checked
    by HASH - which proves the bytes are the ones the release published, not
    that the archive is well-formed. So every member is resolved against dest
    and rejected if it is not a descendant, BEFORE anything is written.

    Symlinks are refused outright: a member marked as one could otherwise point
    anywhere, and PyInstaller's payload has no reason to contain one."""
    root = os.path.realpath(dest)
    for info_ in zf.infolist():
        name = info_.filename
        if name.startswith("/") or name.startswith("\\") or \
                (len(name) > 1 and name[1] == ":"):
            raise UpdateError(f"archive member has an absolute path: {name}")
        target = os.path.realpath(os.path.join(root, name))
        if target != root and not target.startswith(root + os.sep):
            raise UpdateError(f"archive member escapes the target: {name}")
        # 0xA000 is the symlink bit in the external_attr high half.
        if (info_.external_attr >> 16) & 0xA000 == 0xA000:
            raise UpdateError(f"archive member is a symlink: {name}")


def download_release(info: dict, directory: str,
                     timeout: Optional[int] = None) -> StagedUpdate:
    """Download the standalone ZIP + checksums.txt, verify the ZIP's SHA-256
    against the published line, then extract it into `directory` as
    TunTop-<version>/ and stage the exe inside it.

    WHY A DIRECTORY AND NOT A SWAPPED EXE
    ------------------------------------
    This used to download `TunTop.exe`, verify it, and stage it next to the
    running executable for the user to run instead. That only ever worked for a
    self-contained build. Since 1.0.51 the shipped layout is onedir, where the
    exe is a launcher whose interpreter and DLLs live in a sibling
    `_internal/` - so the "verified" download was a file that could not start on
    its own, and the published asset was the same broken thing offered to
    users. The zip is the whole directory and is the only artifact that runs
    standalone, so it is what gets verified and what gets unpacked.

    The result is a NEW FOLDER rather than a replaced file: that is inherent to
    a multi-file install, and it is why the caller has to say so plainly
    instead of "run that exe to apply it".

    Extraction is into a sibling temp directory and moved into place, so a
    failure part-way through cannot leave a half-written TunTop-<version>/ that
    the next run would treat as already staged."""
    version = info["version"]
    zip_name = info.get("zip_name") or _standalone_zip_name(version)
    target_dir = os.path.join(directory, f"TunTop-{version}")
    staged_exe = os.path.join(target_dir, "TunTop", "TunTop.exe")

    blob = _fetch(info["zip_url"], _MAX_ZIP_BYTES, timeout=timeout)
    sums = _parse_checksums(_fetch(info["checksum_url"], _MAX_CHECKSUM_BYTES,
                                   timeout=timeout))
    expected = sums.get(zip_name)
    if not expected:
        raise UpdateError(f"checksums.txt has no entry for {zip_name}")
    actual = hashlib.sha256(blob).hexdigest()
    if actual != expected:
        raise UpdateError(
            f"checksum mismatch (got {actual[:12]}..., want {expected[:12]}...)")

    # Already staged from a previous attempt? Reuse it only if the exe inside
    # is still a real x64 PE. A folder that fails that is not "already applied" -
    # it is a truncated or corrupted extraction, so it is discarded and the
    # archive is unpacked again rather than reported as done.
    if os.path.isfile(staged_exe):
        try:
            with open(staged_exe, "rb") as f:
                _verify_pe_header(f.read(0x200))
            return StagedUpdate(version, staged_exe, actual)
        except UpdateError:
            _rmtree(target_dir)

    staging = os.path.join(directory, f".tuntop-{version}.staging")
    _rmtree(staging)
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            _safe_extract(zf, staging)
            zf.extractall(staging)
        found = None
        for base, _dirs, files in os.walk(staging):
            if "TunTop.exe" in files:
                found = os.path.join(base, "TunTop.exe")
                break
        if not found:
            raise UpdateError("the archive contains no TunTop.exe")
        with open(found, "rb") as f:
            _verify_pe_header(f.read(0x200))
        _rmtree(target_dir)
        os.replace(staging, target_dir)
    except Exception:
        _rmtree(staging)
        raise
    return StagedUpdate(version, staged_exe, actual)


def _rmtree(path: str) -> None:
    """Best-effort recursive delete. Used only on paths this module created."""
    try:
        shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass


def tempfile_name(directory: str):
    import tempfile
    return tempfile.mkstemp(prefix="tuntop_upd_", suffix=".part", dir=directory)


def prepare_update(current_version: str, directory: str,
                   timeout: Optional[int] = None) -> StagedUpdate | None:
    """End-to-end: check the latest release, download + verify + stage it.
    Returns None when already up to date or the check is inconclusive
    (offline); raises UpdateError for verification failures."""
    try:
        info = check_latest(current_version, timeout=timeout)
    except UpdateError as e:
        if "unsupported release tag" in str(e) or "draft/prerelease" in str(e):
            return None
        raise
    except urllib.error.HTTPError as e:
        # HTTPError is a subclass of OSError, so the old `except OSError`
        # swallowed it: a 403 rate-limit, a 404 (release renamed) and a 500
        # were all indistinguishable from "offline", so the updater silently
        # never updated and logged nothing at all. Surface the code - the
        # caller shows it to the user.
        raise UpdateError(
            f"update check failed: HTTP {e.code} from "
            f"{getattr(e, 'url', 'the release feed')}"
            + (" (rate limited - try again later)"
               if e.code in (403, 429) else "")) from e
    except (urllib.error.URLError, socket.timeout, TimeoutError):
        # Offline / timed out. "Cannot check" is not "up to date" and not
        # "update available" - the caller decides what None means.
        return None
    if not info["update_available"]:
        return None
    os.makedirs(directory, exist_ok=True)
    return download_release(info, directory, timeout=timeout)

"""Offline regression tests for tuntop.config.updates (GitHub release
auto-update, 1.0.33).

No network: every fetch is intercepted at updates._OPENER.open, so the
verification pipeline (version gating, asset selection, checksum parse,
SHA-256 match, PE header, staging semantics) is exercised in isolation.

Run:  python -m unittest tests.unit.test_updates -v
"""
import hashlib
import io
import json
import os
import shutil
import ssl
import tempfile
import unittest
from unittest import mock

import urllib.error
import urllib.parse
import urllib.request
import zipfile

from tuntop.config import updates


def _exe_blob():
    # Minimal but real x64 PE: 'MZ' + e_lfanew at 0x3C -> 'PE\0\0' + machine
    # 0x8664 at offset+4.
    blob = bytearray(b"MZ" + b"\x00" * 0x3A)
    blob += (0x40).to_bytes(4, "little")
    blob += b"PE\0\0" + (0x8664).to_bytes(2, "little") + b"\x00" * 8
    return bytes(blob)


def _zip_blob(exe=None, extra=None, name="evil"):
    """A standalone-style archive: TunTop/TunTop.exe plus a sibling tree.

    Mirrors what build_release.zip_onedir produces - a top-level folder holding
    the launcher and its _internal/ payload - because the layout is the whole
    reason the updater takes a zip rather than an exe."""
    if exe is None:
        exe = _exe_blob()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("TunTop/TunTop.exe", exe)
        zf.writestr("TunTop/_internal/python312.dll", b"\x00" * 32)
        for member, data in (extra or {}).items():
            zf.writestr(member, data)
    return buf.getvalue()


def _zip_name(version):
    return f"TunTop-{version}-x64-standalone.zip"


def _release(version="9.9.9"):
    tag = "v" + version
    return {
        "tag_name": tag,
        "draft": False,
        "prerelease": False,
        "assets": [
            {"name": _zip_name(version),
             "browser_download_url": "https://github.com/kooshaZP/TunTop/"
                                     f"releases/download/{tag}/"
                                     + _zip_name(version)},
            {"name": "checksums.txt",
             "browser_download_url": "https://github.com/kooshaZP/TunTop/"
                                     f"releases/download/{tag}/checksums.txt"},
        ],
    }


def _checksums(blob, name=None):
    # The EXACT line format build_release.write_checksums emits:
    # "<sha256>  <name>  (<size> bytes)"
    return (f"{hashlib.sha256(blob).hexdigest()}  {name or 'TunTop.exe'}  "
            f"({len(blob):,} bytes)\n").encode()


class _FakeResp:
    def __init__(self, payload, status=200, url=None):
        self._buf = io.BytesIO(payload)
        self.status = status
        self.url = url or ""

    def read(self, n=-1):
        return self._buf.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestCheckLatest(unittest.TestCase):
    def test_newer_release_reports_update(self):
        rel = _release("9.9.9")
        body = json.dumps(rel).encode()

        def fake_open(req, timeout=None):
            # Parse the URL and compare the HOST - never a substring check:
            # "api.github.com" can appear at an arbitrary position in a URL
            # (CodeQL py/incomplete-url-substring-sanitization).
            if urllib.parse.urlparse(req.full_url).hostname == "api.github.com":
                return _FakeResp(body)
            raise AssertionError("unexpected fetch " + req.full_url)

        with mock.patch.object(updates._OPENER, "open", fake_open):
            info = updates.check_latest("1.0.32")
        self.assertTrue(info["update_available"])
        self.assertEqual(info["version"], "9.9.9")
        self.assertTrue(info["zip_url"].endswith(_zip_name("9.9.9")))

    def test_the_updater_no_longer_asks_for_a_bare_exe(self):
        """An onedir exe cannot run on its own, so a release must not be asked
        for one. This is the selection half of the defect: the published asset
        existed only because the updater looked it up by that name."""
        body = json.dumps(_release("9.9.9")).encode()
        with mock.patch.object(updates._OPENER, "open",
                               lambda req, timeout=None: _FakeResp(body)):
            info = updates.check_latest("1.0.32")
        self.assertNotIn("exe_url", info)
        self.assertIn("zip_url", info)

    def test_a_release_offering_only_a_bare_exe_is_rejected(self):
        """Without the zip there is nothing that can actually be installed, so
        the check must fail loudly rather than fall back to the broken exe."""
        rel = _release("9.9.9")
        rel["assets"] = [a for a in rel["assets"] if "standalone" not in a["name"]]
        rel["assets"].append({
            "name": "TunTop.exe",
            "browser_download_url": "https://github.com/kooshaZP/TunTop/"
                                    "releases/download/v9.9.9/TunTop.exe"})
        body = json.dumps(rel).encode()
        with mock.patch.object(updates._OPENER, "open",
                               lambda req, timeout=None: _FakeResp(body)):
            self.assertRaises(updates.UpdateError, updates.check_latest, "1.0.32")

    def test_same_or_older_version_is_no_update(self):
        body = json.dumps(_release("1.0.32")).encode()
        with mock.patch.object(updates._OPENER, "open",
                               lambda req, timeout=None: _FakeResp(body)):
            info = updates.check_latest("1.0.32")
        self.assertFalse(info["update_available"])
        self.assertEqual(info["version"], "1.0.32")

    def test_v_prefixed_tag_is_accepted(self):
        body = json.dumps(_release("2.0.1")).encode()
        with mock.patch.object(updates._OPENER, "open",
                               lambda req, timeout=None: _FakeResp(body)):
            info = updates.check_latest("1.0.32")
        self.assertEqual(info["version"], "2.0.1")

    def test_prerelease_is_rejected(self):
        rel = _release("9.9.9")
        rel["prerelease"] = True
        body = json.dumps(rel).encode()
        with mock.patch.object(updates._OPENER, "open",
                               lambda req, timeout=None: _FakeResp(body)):
            self.assertRaises(updates.UpdateError, updates.check_latest, "1.0.32")

    def test_missing_checksum_asset_is_rejected(self):
        rel = _release()
        rel["assets"] = rel["assets"][:1]
        body = json.dumps(rel).encode()
        with mock.patch.object(updates._OPENER, "open",
                               lambda req, timeout=None: _FakeResp(body)):
            self.assertRaises(updates.UpdateError, updates.check_latest, "1.0.32")

    def test_bad_current_version_is_rejected(self):
        self.assertRaises(updates.UpdateError, updates.check_latest, "abc")


class TestDownloadRelease(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="tuntop_upd_test_")
        self.blob = _zip_blob()
        self.addCleanup(os.rmdir_guard if False else self._cleanup)

    def _cleanup(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _install(self, blob=None, sums=None):
        blob = self.blob if blob is None else blob
        sums = (_checksums(blob, _zip_name("9.9.9")) if sums is None
                else sums)
        rel = _release("9.9.9")

        def fake_open(req, timeout=None):
            url = req.full_url
            if url.endswith("releases/latest"):
                return _FakeResp(json.dumps(rel).encode())
            if url.endswith(_zip_name("9.9.9")):
                return _FakeResp(blob)
            if url.endswith("/checksums.txt"):
                return _FakeResp(sums)
            raise AssertionError("unexpected fetch " + url)

        return fake_open

    def test_stages_a_complete_verified_install(self):
        """The result is a FOLDER, because a folder is the only thing that
        runs: the launcher is meaningless without its sibling _internal/."""
        with mock.patch.object(updates._OPENER, "open",
                               self._install()):
            staged = updates.prepare_update("1.0.32", self.tmp)
        self.assertIsNotNone(staged)
        self.assertEqual(staged.version, "9.9.9")
        self.assertTrue(os.path.basename(staged.path) == "TunTop.exe")
        install = os.path.dirname(os.path.dirname(staged.path))
        self.assertEqual(os.path.basename(install), "TunTop-9.9.9")
        # The payload the exe needs must be there, or the staged install is
        # the same broken 2 MB artifact this change exists to stop shipping.
        self.assertTrue(os.path.isfile(os.path.join(
            install, "TunTop", "_internal", "python312.dll")))
        self.assertEqual(hashlib.sha256(self.blob).hexdigest(), staged.sha256)
        self.assertEqual([n for n in os.listdir(self.tmp)
                          if n.startswith("tuntop_upd_")
                          or n.startswith(".tuntop-")], [])

    def test_up_to_date_returns_none(self):
        rel = _release("1.0.32")
        body = json.dumps(rel).encode()
        with mock.patch.object(updates._OPENER, "open",
                               lambda req, timeout=None: _FakeResp(body)):
            self.assertIsNone(updates.prepare_update("1.0.32", self.tmp))

    def test_checksum_mismatch_leaves_nothing_behind(self):
        bad_sums = (f"{'0' * 64}  {_zip_name('9.9.9')}\n").encode()
        with mock.patch.object(updates._OPENER, "open",
                               self._install(sums=bad_sums)):
            self.assertRaises(updates.UpdateError,
                              updates.prepare_update, "1.0.32", self.tmp)
        self.assertEqual(os.listdir(self.tmp), [])

    def test_a_checksum_naming_the_old_exe_does_not_satisfy_the_zip(self):
        """The exact line that shipped on v1.0.51. If this passed, the updater
        would accept a zip nobody vouched for."""
        sums = _checksums(self.blob, "TunTop.exe")
        with mock.patch.object(updates._OPENER, "open",
                               self._install(sums=sums)):
            self.assertRaises(updates.UpdateError,
                              updates.prepare_update, "1.0.32", self.tmp)
        self.assertEqual(os.listdir(self.tmp), [])

    def test_not_a_pe_inside_the_archive_is_rejected(self):
        with mock.patch.object(updates._OPENER, "open",
                               self._install(blob=_zip_blob(exe=b"nope"))):
            self.assertRaises(updates.UpdateError,
                              updates.prepare_update, "1.0.32", self.tmp)
        self.assertEqual(os.listdir(self.tmp), [])

    def test_32bit_pe_inside_the_archive_is_rejected(self):
        blob = bytearray(_exe_blob())
        off = int.from_bytes(blob[0x3C:0x40], "little")
        blob[off + 4:off + 6] = (0x014C).to_bytes(2, "little")
        with mock.patch.object(updates._OPENER, "open",
                               self._install(blob=_zip_blob(exe=bytes(blob)))):
            self.assertRaises(updates.UpdateError,
                              updates.prepare_update, "1.0.32", self.tmp)
        self.assertEqual(os.listdir(self.tmp), [])

    def test_an_archive_with_no_exe_is_rejected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("TunTop/readme.txt", b"no exe here")
        with mock.patch.object(updates._OPENER, "open",
                               self._install(blob=buf.getvalue())):
            self.assertRaises(updates.UpdateError,
                              updates.prepare_update, "1.0.32", self.tmp)
        self.assertEqual(os.listdir(self.tmp), [])

    def test_oversized_archive_is_rejected(self):
        with mock.patch.object(updates, "_MAX_ZIP_BYTES", 16):
            with mock.patch.object(updates._OPENER, "open",
                                   self._install()):
                self.assertRaises(updates.UpdateError,
                                  updates.prepare_update, "1.0.32", self.tmp)

    def test_a_traversing_member_is_refused_before_anything_is_written(self):
        """Zip-slip: a verified archive can still be malformed, and a member
        escaping the target would write outside it."""
        for member in ("../escaped.txt", "TunTop/../../escaped.txt",
                       "/abs/escaped.txt"):
            blob = _zip_blob(extra={member: b"x"})
            stage = tempfile.mkdtemp(prefix="tuntop_slip_")
            self.addCleanup(shutil.rmtree, stage, True)
            with mock.patch.object(updates._OPENER, "open",
                                   self._install(blob=blob)):
                self.assertRaises(updates.UpdateError,
                                  updates.prepare_update, "1.0.32", stage)
            self.assertEqual(os.listdir(stage), [],
                             f"{member} was extracted")

    def test_existing_identical_stage_is_reused(self):
        with mock.patch.object(updates._OPENER, "open",
                               self._install()):
            first = updates.prepare_update("1.0.32", self.tmp)
            second = updates.prepare_update("1.0.32", self.tmp)
        self.assertEqual(first.path, second.path)

    def test_existing_conflicting_stage_is_replaced_not_trusted(self):
        """A staged folder whose exe is not a real PE - a truncated extraction,
        say - must not be reported as an already-applied update."""
        with mock.patch.object(updates._OPENER, "open",
                               self._install()):
            staged = updates.prepare_update("1.0.32", self.tmp)
        with open(staged.path, "wb") as f:
            f.write(b"corrupt")
        with mock.patch.object(updates._OPENER, "open",
                               self._install()):
            again = updates.prepare_update("1.0.32", self.tmp)
        with open(again.path, "rb") as f:
            self.assertEqual(f.read()[:2], b"MZ",
                             "the corrupt staged exe was accepted as complete")

    def test_offline_returns_none(self):
        def offline(req, timeout=None):
            raise urllib.error.URLError("no network")

        with mock.patch.object(updates._OPENER, "open", offline):
            self.assertIsNone(updates.prepare_update("1.0.32", self.tmp))


class TestTransportPolicy(unittest.TestCase):
    """The updater installs a binary. Transport policy is security policy."""

    def test_tls_floor_is_pinned(self):
        self.assertEqual(updates._SSL_CONTEXT.minimum_version,
                         ssl.TLSVersion.TLSv1_2)
        self.assertTrue(updates._SSL_CONTEXT.check_hostname)
        self.assertEqual(updates._SSL_CONTEXT.verify_mode,
                         ssl.CERT_REQUIRED)

    def test_https_and_known_host_are_required(self):
        with self.assertRaises(updates.UpdateError):
            updates._assert_allowed_url("http://github.com/evil.exe")
        with self.assertRaises(updates.UpdateError):
            updates._assert_allowed_url("https://evil.example/x.exe")
        # The real release CDN hop must keep working.
        updates._assert_allowed_url(
            "https://release-assets.githubusercontent.com/x")

    def test_a_redirect_off_the_allowlist_is_refused(self):
        """urlopen()'s default handler follows a 30x to ANY host, so a
        302 was followed transparently and whatever the redirector served
        was treated as the release asset - with checksums.txt fetched over
        the same redirectable transport, validating the redirector's copy
        too. The host allow-list must be enforced on every hop.

        Called the way HTTPRedirectHandler.http_error_302 really calls it:
        with the ORIGINAL Request in hand. Passing req=None is a shape
        urlopen never produces, and it let a handler that reasoned about
        `req` (a scheme change, a dropped header, a same-host re-issue)
        pass here and break every real user.

        An HTTPError IS a file-like object wrapping the 302 response, so it
        has to be closed; left open it is collected later as a ResourceWarning
        - "Implicitly cleaning up <HTTPError 302: 'refusing redirect to an
        unexpected host ...'>" - which is noise landing in the middle of an
        unrelated run, and a real leaked socket on the production path."""
        handler = updates._SameHostRedirectHandler()
        req = urllib.request.Request(
            "https://github.com/kooshaZP/TunTop/releases/download/v1/x.exe")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            handler.redirect_request(
                req, None, 302, "Found", {},
                "https://evil.example/TunTop.exe")
        self.addCleanup(ctx.exception.close)
        self.assertIn("unexpected host", str(ctx.exception))

    def test_a_redirect_inside_the_allowlist_is_followed(self):
        handler = updates._SameHostRedirectHandler()
        req = urllib.request.Request(
            "https://github.com/kooshaZP/TunTop/releases/download/v1/x.exe")
        out = handler.redirect_request(
            req, None, 302, "Found", {},
            "https://release-assets.githubusercontent.com/x")
        self.assertIsNotNone(out)

    def test_http_error_is_not_reported_as_offline(self):
        """HTTPError subclasses OSError, so `except OSError` swallowed every
        403/404/500 and the updater silently never updated - with no log
        line at all. A rate limit must be distinguishable from offline."""
        def rate_limited(req, timeout=None):
            raise urllib.error.HTTPError(
                req.full_url, 403, "rate limited", {}, None)

        with mock.patch.object(updates._OPENER, "open", rate_limited):
            with self.assertRaises(updates.UpdateError) as ctx:
                updates.prepare_update("1.0.32", tempfile.mkdtemp())
        self.assertIn("403", str(ctx.exception))
        self.assertIn("rate limited", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()

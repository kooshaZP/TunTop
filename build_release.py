"""Build a distributable TunTop release.

Usage:  python build_release.py
        python build_release.py --version 1.0.0
        python build_release.py --with-exe        # also build TunTop.exe (needs pyinstaller)
        python build_release.py --with-exe --onefile   # single self-extracting exe (NOT default)
        python build_release.py --with-exe --defender-exclude

ONEDIR IS THE DEFAULT (1.0.51)
------------------------------
`--with-exe` builds the onedir layout - dist/TunTop/ with the exe plus its
support files - and publishes it as TunTop-<version>-x64-standalone.zip.

That is a change from 1.0.50, where `--with-exe` produced the single
self-extracting onefile unless `--onedir` was passed. It is no longer a
taste question. The onefile bootloader unpacks an unsigned payload to a temp
dir on every start, which is the exact behaviour profile Defender's ML model
keys on, and the flag had become reliably reproducible rather than occasional:
a local 1.0.50 build was quarantined as Trojan:Win32/Bearfoos.A!ml mid-session,
with the parent exe AND four child processes flagged. `TunTop.spec` already
documented onefile as "the single most AV-false-positive-prone PyInstaller
layout"; this just stops shipping it by default.

The alternative fix - an AV exclusion - is NOT the default and should not be.
TunTop rewrites the host's routing table, so a blanket repo exclusion is a
broad hole in the one tool the user is relying on. Changing the LAYOUT removes
the actual trigger and needs no exclusion at all. `--defender-exclude` remains
available for a one-off local build, and says so.

`--onefile` still builds the old layout for anyone who needs a single file to
hand around; `--onedir` is accepted and is now a no-op, so existing scripts and
instructions do not break.

Produces dist/TunTop-x64.zip containing everything needed to run TunTop from
source (the vendored binaries are included so the download is fully
self-contained), plus dist/TunTop-<version>-x64-standalone.zip for the onedir
build, plus dist/checksums.txt with a SHA-256 for every PUBLISHED artifact.
The vendored binaries ship inside the zip but are not release assets, so they
are not checksummed on their own.

Pure stdlib, no pip dependencies (PyInstaller is optional and only used for
the --with-exe step).
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import os
import re
import shutil
import subprocess
import sys
import time
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(ROOT, "dist")

# Files and directories to include in the release zip
INCLUDE_FILES = [
    "Run_Helper.ps1",
    # The launcher the README shipped INSIDE this same zip tells users to
    # double-click. It exists only to strip the Mark-of-the-Web and run under
    # -ExecutionPolicy Bypass - the two blockers that make a bare
    # Run_Helper.ps1 unusable straight out of the download. Omitting it ships
    # instructions to a file that is not there.
    "Start_TunTop.bat",
    "Run_Monitor.ps1",
    # Run_Monitor.ps1:52 executes this by path next to itself, so shipping the
    # launcher without it produces an immediate "can't open file" traceback.
    "monitor_windows2.py",
    "check_dns_leak.ps1",
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
    "FAQ.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
]

# Directories copied wholesale into the release zip. Every entry is walked by
# build_zip() with the SAME rules (EXCLUDE_PATTERNS applied to both file and
# directory names), so adding one here cannot silently bypass the filters.
INCLUDE_DIRS = [
    "tuntop",
    "assets",      # TunTop.spec's icon source
]

# Files/dirs to exclude from every INCLUDE_DIRS entry in the zip (matched
# against both file and directory names while walking)
EXCLUDE_PATTERNS = {
    "__pycache__",
    "*.pyc",
    ".pyc",
    "MyTunTopProfile.json",   # saved profiles (settings only, no secrets)
    "profiles.json",          # legacy profile-store name (pre-rename)
    "diagnostics_*.txt",
    "*.log",
    "crash_*.txt",
    ".last_run.json",
    ".cleanup_watchdog_state.json",
    "tuntop_version_info.txt",   # PyInstaller resource spec, not runtime
    ".geo_cache",
}

# Vendored binaries shipped alongside the app so the zip is self-contained.
BINARIES = [
    "tun2socks-windows-amd64-v3.exe",
    "wintun.dll",
]


def get_version() -> str:
    """Read version from tuntop/__init__.py."""
    init_path = os.path.join(ROOT, "tuntop", "__init__.py")
    with open(init_path, encoding="utf-8") as f:
        content = f.read()
    m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', content)
    return m.group(1) if m else "0.0.0"


def sha256_file(path: str) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def should_exclude(name: str) -> bool:
    """Check if a filename matches any exclusion pattern (fnmatch, so
    mid-name wildcards like diagnostics_*.txt actually match - the old
    endswith/exact-match logic could never match them and a diagnostics
    export would silently ship inside the release zip)."""
    return any(fnmatch.fnmatch(name, pat) for pat in EXCLUDE_PATTERNS)


def _clean_onedir_output(onedir: bool = True) -> None:
    """Remove build output that a previous run left in dist/ and that this run
    will NOT rebuild. Extracted so it is directly testable - the two artifacts
    it clears are both dangerous to leave next to a fresh release:

    * dist/TunTop/ - PyInstaller's COLLECT merges into an existing directory,
      so a file dropped from the spec (or left by an older build) survives into
      the new tree. The whole directory is digested as part of the release
      artifact, so a stale file would ship INSIDE the published hash with no
      way to tell it was not in the build.
    * dist/TunTop.exe - a previous release's self-extracting onefile. This run
      does not rebuild it, and it is the larger of the two files named
      TunTop.exe, so a user reaching into dist/ for this release can pick the
      quarantinable one without any signal that they did.

    No-op when onedir=False: that path DOES rebuild dist/TunTop.exe, and
    deleting it there would make the opt-out layout unbuildable. Never raises -
    a locked file is a nuisance, not a build failure."""
    if not onedir:
        return
    stale_tree = os.path.join(DIST, "TunTop")
    if os.path.isdir(stale_tree):
        shutil.rmtree(stale_tree, ignore_errors=True)
    stale_onefile = os.path.join(DIST, "TunTop.exe")
    if os.path.isfile(stale_onefile):
        try:
            os.remove(stale_onefile)
            print("  ~ removed a stale onefile dist/TunTop.exe - this release "
                  "ships the onedir layout, not that binary")
        except OSError as e:
            print(f"  ! could not remove the stale onefile dist/TunTop.exe "
                  f"({e}) - DELETE IT BY HAND so it is not mistaken for this "
                  "release's artifact")


def build_exe(onedir: bool = True) -> str | None:
    """Build TunTop with PyInstaller. onedir=True (the DEFAULT since 1.0.51)
    produces dist/TunTop/ (exe + support files) and is then zipped for
    release; onedir=False produces the classic single dist/TunTop.exe (onefile),
    which is now opt-in because its temp-dir self-extraction is what gets the
    unsigned build quarantined. Returns the built EXE path in BOTH layouts: the
    onedir FOLDER is the release artifact (main() takes dirname() of this to
    zip it), but _guard_exe() exists to watch one file through the scanner's
    verdict window, and handing it a directory made os.path.isfile() false for
    every copy - so a perfectly healthy onedir build reported itself
    quarantined. None if PyInstaller is unavailable. Raises on build failure."""
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("  ! PyInstaller not installed - skipping TunTop.exe "
              "(pip install pyinstaller to enable)")
        return None
    spec = os.path.join(ROOT, "TunTop.spec")
    if not os.path.isfile(spec):
        print("  ! TunTop.spec missing - cannot build TunTop.exe")
        return None
    if onedir:
        # Clear whatever a previous run left that this one will not rebuild.
        _clean_onedir_output(onedir=True)
    print("  * Building TunTop.exe with PyInstaller ("
          + ("onedir" if onedir else "onefile") + ") ...")
    cmd = [sys.executable, "-m", "PyInstaller", "--clean", "--noconfirm"]
    env = dict(os.environ)
    if onedir:
        # The spec reads TUNTOP_SPEC_ONEDIR (NOT the --onedir CLI flag:
        # onefile/onedir are makespec options and are rejected together
        # with a .spec file).
        env["TUNTOP_SPEC_ONEDIR"] = "1"
    cmd.append(spec)
    subprocess.run(cmd, check=True, cwd=ROOT, env=env)
    exe = os.path.join(DIST, "TunTop.exe")
    if onedir:
        exe = os.path.join(DIST, "TunTop", "TunTop.exe")
    version = get_version()
    keep = os.path.join(DIST, f"TunTop-{version}.exe")
    fallback = os.path.join(ROOT, f"TunTop-{version}.standalone.exe")
    # AV/Defender routinely eats a freshly-written unsigned onefile within
    # seconds - it can vanish BETWEEN PyInstaller exiting and our first
    # check. Poll briefly for it to appear (it may still be mid-write), and
    # mirror it the MOMENT it lands so a protected copy exists before the
    # scanner's verdict arrives.
    deadline = time.time() + 8.0
    while not os.path.isfile(exe) and time.time() < deadline:
        time.sleep(0.25)
    if not os.path.isfile(exe):
        if _restore_all([exe], [keep, fallback]):
            print("  ~ dist/TunTop.exe was already removed (AV?) - restored "
                  "from a protected copy.")
        else:
            print(_AV_HELP)
            return None
    if onedir:
        # The directory build has no self-extracting image - the #1 AV
        # false-positive trigger - so it does not need the onefile mirrors.
        # They must NOT be overwritten here: the versioned backup /
        # standalone names belong to the ONEFILE variant, and clobbering
        # them with the (much smaller) onedir exe would corrupt the backup
        # set. The onedir FOLDER is the artifact, but the EXE is what this
        # function returns: _guard_exe() exists to watch one file through the
        # scanner's verdict window, and handing it a directory made
        # os.path.isfile() false for every copy - so the onedir build reported
        # itself quarantined even when it was sitting there. main() takes the
        # directory from dirname() of this when it needs to zip it.
        print("  * onedir artifact: " + exe)
        return exe
    # Two protected copies, written IMMEDIATELY (before the scan completes):
    # a second on-disk artifact under a different name often survives the
    # scan that takes the original, and the copy OUTSIDE dist/ survives even
    # a purge of everything inside dist/.
    _mirror(exe, keep)
    _mirror(keep if os.path.isfile(keep) else exe, fallback)
    print(f"  * Protected copies: {os.path.basename(keep)}, "
          f"{os.path.basename(fallback)}")
    return exe


def zip_onedir(folder: str, version: str) -> str | None:
    """Zip a built onedir directory into the distributable release asset.

    A directory cannot be published as a GitHub Release asset, and it cannot
    sensibly be checksummed as one file either - so the zip IS the artifact
    users download, and its bytes are what checksums.txt promises.

    Deliberately applies NO EXCLUDE_PATTERNS. Those are a SOURCE-tree hygiene
    list (no __pycache__, no .pyc, no saved profiles, no diagnostic dumps) and
    they are correct for build_zip(), which walks the repo. This walks
    PyInstaller's own output, where `_internal/` legitimately contains
    __pycache__ directories and compiled modules that the app REQUIRES at
    runtime. Filtering them here would produce a zip that installs and then
    fails to start - the worst possible outcome for the one layout we ship
    precisely because it is meant to work.
    """
    if not folder or not os.path.isdir(folder):
        return None
    os.makedirs(DIST, exist_ok=True)
    name = f"TunTop-{version}-x64-standalone.zip"
    path = os.path.join(DIST, name)
    base = os.path.dirname(folder.rstrip("\\/"))
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for dirpath, dirnames, filenames in os.walk(folder):
            dirnames.sort()
            for fname in sorted(filenames):
                full = os.path.join(dirpath, fname)
                arc = os.path.relpath(full, base).replace("\\", "/")
                zf.write(full, arc)
    print(f"  = {name}")
    return path


def _mirror(src: str, dst: str) -> bool:
    """copy2 with short retries (a fresh destination can be locked for a
    moment by the scanner). Never raises; True when dst exists afterwards."""
    for _ in range(3):
        try:
            if (os.path.isfile(dst)
                    and os.path.getsize(dst) == os.path.getsize(src)):
                return True
            shutil.copy2(src, dst)
            return True
        except OSError:
            time.sleep(0.4)
    return os.path.isfile(dst)


def _first_surviving(paths) -> str | None:
    """The first path that exists on disk (None when every copy is gone)."""
    for p in paths:
        if p and os.path.isfile(p):
            return p
    return None


def _restore_all(targets, sources) -> int:
    """Re-create every missing target from the first surviving source.
    Returns how many copies were restored."""
    src = _first_surviving(sources)
    if src is None:
        return 0
    n = 0
    for dst in targets:
        if (os.path.normcase(dst) == os.path.normcase(src)
                or os.path.isfile(dst)):
            continue
        if _mirror(src, dst):
            n += 1
    return n


_AV_HELP = (
    "  ! The built exe did not survive: an AV (Defender) most likely\n"
    "    quarantined it. The path checked is named above.\n"
    "    BEST FIX - change the layout, no AV configuration required:\n"
    "      python build_release.py --with-exe\n"
    "    (onedir is the default since 1.0.51; the self-extracting onefile is\n"
    "    what gets flagged, and only --onefile asks for it back.)\n"
    "    If you already built onefile, recover the quarantined file:\n"
    "      Windows Security -> Virus & threat protection -> Protection history\n"
    "      -> the exe -> Actions -> Restore\n"
    "    LAST RESORT - an AV exclusion. This is a broad hole: TunTop rewrites\n"
    "    the host routing table, so excluding the build directory also stops\n"
    "    Defender watching every future artifact written into it. Prefer the\n"
    "    layout change.\n"
    "      Add-MpPreference -ExclusionPath '<repo>\\dist'\n"
    "    The published GitHub-Release artifacts are built on CI.")


def _guard_exe(exe: str, version: str, timeout: float = 45.0,
               protect: bool = True) -> str | None:
    """Watch the freshly-built exe through the AV quarantine window.

    Defender keys on the just-written onefile image and often takes the
    original seconds (sometimes a minute) after it lands - far longer than
    a single quick check. With protect=True (onefile) ALL THREE copies
    (dist/TunTop.exe, the versioned backup, the outside-dist fallback) are
    restored from whichever copy survives, repeatedly, until the window
    closes. protect=False (onedir) guards only `exe` - the versioned /
    standalone names belong to the onefile variant and must never receive
    a onedir binary. Returns the best surviving artifact (the original
    preferred) - or None only when the AV ate every copy."""
    if protect:
        keep = os.path.join(DIST, f"TunTop-{version}.exe")
        fallback = os.path.join(ROOT, f"TunTop-{version}.standalone.exe")
        copies = [exe, keep, fallback]
    else:
        copies = [exe]
    deadline = time.time() + timeout
    while time.time() < deadline:
        n = _restore_all(copies, copies)
        if n:
            print(f"  ~ re-copied {n} artifact(s) an AV had removed")
        if all(os.path.isfile(p) for p in copies):
            # Settle window: AV verdicts frequently land 5-30 s AFTER the
            # write, not instantly - hold everything through one, then
            # re-verify before declaring victory.
            time.sleep(5.0)
            _restore_all(copies, copies)
            if all(os.path.isfile(p) for p in copies):
                return exe
        else:
            time.sleep(1.0)
    # Window closed with something still being eaten. Restore once more and
    # return the best surviving artifact instead of a bare None.
    _restore_all(copies, copies)
    for p in copies:
        if os.path.isfile(p):
            if p != exe:
                print(f"  ~ dist/TunTop.exe did not survive; the protected "
                      f"copy did: {p}")
            return p
    print(_AV_HELP)
    return None


def try_defender_exclusion(paths=None) -> bool:
    """OPT-IN, LAST RESORT, best effort: add `paths` (default: repo root +
    dist/) to Defender's exclusion list so a freshly-built unsigned onefile is
    not quarantined DURING the build. Needs an elevated shell - without one the
    manual PowerShell is printed and nothing is changed. Never raises.

    Read this before using it. A folder exclusion is not scoped to this build:
    it tells Defender to stop watching every file created under that path,
    from now on, including anything a later compromised build drops there. For
    a tool whose whole job is rewriting the host's routing table and DNS, that
    is a worse trade than the quarantine it prevents. The layout fix -- the
    onedir build, which does not self-extract -- removes the trigger without
    any exclusion at all, and is now the default. This exists for the
    deliberate one-off case where someone genuinely needs a single-file exe and
    is building it locally.
    """
    if paths is None:
        # dist/ ONLY, not the repo root. The root exclusion was the broader of
        # the two and bought nothing extra: the build writes only to dist/.
        paths = [DIST]
    ps = ("; ".join(f"Add-MpPreference -ExclusionPath '{p}'" for p in paths)
          + "; if ($?) { 'TUNTOP_EXCLUSION_OK' }")
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, text=True, timeout=60)
        if "TUNTOP_EXCLUSION_OK" in (r.stdout or ""):
            print("  + Defender exclusions added: " + ", ".join(paths))
            return True
    except Exception:
        pass
    print("  ! Could not add Defender exclusions (need an elevated shell). "
          "Do it manually BEFORE rebuilding:\n"
          "      Add-MpPreference -ExclusionPath '<repo>'   (admin "
          "PowerShell)\n"
          "      Add-MpPreference -ExclusionPath '<repo>\\dist'")
    return False


def build_zip(version: str) -> str:
    """Build the release zip (self-contained: includes vendored binaries)."""
    os.makedirs(DIST, exist_ok=True)
    zip_name = "TunTop-x64.zip"
    zip_path = os.path.join(DIST, zip_name)

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Top-level files
        for fname in INCLUDE_FILES:
            src = os.path.join(ROOT, fname)
            if os.path.isfile(src):
                zf.write(src, fname)
                print(f"  + {fname}")
            else:
                print(f"  ! {fname} not found, skipping")

        # INCLUDE_DIRS - walk every listed directory, not a hardcoded path, so
        # the constant above is authoritative. The same EXCLUDE_PATTERNS rules
        # apply to each of them (a new entry must not start shipping
        # __pycache__/.geo_cache or saved-profile state).
        for dname in INCLUDE_DIRS:
            pkg_dir = os.path.join(ROOT, dname)
            if not os.path.isdir(pkg_dir):
                print(f"  ! {dname}/ not found, skipping")
                continue
            for dirpath, dirnames, filenames in os.walk(pkg_dir):
                dirnames[:] = [d for d in dirnames if not should_exclude(d)]
                rel = os.path.relpath(dirpath, ROOT)
                for fname in filenames:
                    if should_exclude(fname):
                        continue
                    src = os.path.join(dirpath, fname)
                    arc = os.path.join(rel, fname).replace("\\", "/")
                    zf.write(src, arc)
                    print(f"  + {arc}")

        # geofil/ as an empty directory entry (never the geoip.dat itself): the
        # geo-bypass path is where Run_Helper.ps1:193-195 drops/looks for it
        # next to itself, so shipping the folder makes that first-run location
        # discoverable instead of something the user has to discover.
        geodir = zipfile.ZipInfo("geofil/")
        geodir.external_attr = 0x10 << 16   # FILE_ATTRIBUTE_DIRECTORY
        zf.writestr(geodir, b"")
        print("  + geofil/")

        # Vendored binaries - shipped in the package dir because that is where
        # the app looks: tuntop/ui/dashboard.py's app_dir() resolves to
        # <root>/tuntop in a source run, and sys._MEIPASS when frozen.
        # Run_Helper.ps1 resolves them independently and used to look only at
        # the zip ROOT, so an extracted release missed these bundled copies
        # and re-downloaded them; it now searches the root first and falls
        # back to this 'tuntop/' location, so both consumers are satisfied by
        # a single copy in the archive.
        for b in BINARIES:
            src = os.path.join(ROOT, b)
            if os.path.isfile(src):
                zf.write(src, os.path.join("tuntop", b).replace("\\", "/"))
                print(f"  + tuntop/{b}")
            else:
                print(f"  ! {b} not found - release will auto-download it")

    print(f"  = {zip_name}")
    return zip_path


def dir_digest(path: str) -> tuple:
    """A stable SHA-256 over a DIRECTORY's contents, plus its total byte count.

    Needed because the onedir artifact is a directory. `write_checksums` used
    to gate on `os.path.isfile(ap)`, so a directory was SKIPPED SILENTLY and
    the published standalone build shipped with no checksum line at all - the
    one claim in the whole release process that users are told to verify, gone
    for exactly the artifact that replaced the quarantined exe.

    The digest covers each file's path AND its content, with paths sorted and
    separators normalised to '/', so it is reproducible across machines and
    does not depend on directory-walk order. Renaming, adding, removing or
    editing any file changes the digest.
    """
    entries = []
    total = 0
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames.sort()
        for fname in sorted(filenames):
            full = os.path.join(dirpath, fname)
            rel = os.path.relpath(full, path).replace("\\", "/")
            size = os.path.getsize(full)
            total += size
            entries.append(f"{rel} {sha256_file(full)} {size}")
    h = hashlib.sha256()
    for line in entries:
        h.update(line.encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest(), total, len(entries)


def write_checksums(version: str, artifacts: list[str]) -> str:
    """Write SHA-256 checksums for every shipped artifact."""
    path = os.path.join(DIST, "checksums.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"SHA-256 checksums for TunTop {version}\n")
        f.write("=" * 50 + "\n")
        for ap in artifacts:
            if os.path.isdir(ap):
                # A directory cannot be hashed as one file, so the line is a
                # CONTENT digest over the whole tree (see dir_digest). Say so
                # explicitly, or a user running `certutil -hashfile` on the
                # folder name gets nothing back and assumes the file is corrupt.
                h, size, n = dir_digest(ap)
                f.write(f"{h}  {os.path.basename(ap)}/  "
                        f"({n} files, {size:,} bytes - content digest: hash "
                        f"the packaged zip instead)\n")
            elif os.path.isfile(ap):
                h = sha256_file(ap)
                size = os.path.getsize(ap)
                f.write(f"{h}  {os.path.basename(ap)}  ({size:,} bytes)\n")
            else:
                # Never reached in practice (main() only ever appends paths
                # that were just built), but a silently-skipped artifact is
                # the failure mode that produced a checksum file promising
                # less than the release page offered.
                print(f"  ! artifact missing, not checksummed: {ap}")
    return path


def published_asset_paths(zip_path: str, exe: str | None,
                          onedir: bool) -> list[str]:
    """Every path this release PUBLISHES, in the order they are checksummed.

    ONE function because two lists must not exist independently: the checksum
    file and release.yml's upload list. An asset published with no checksum
    line is a download nobody can verify; a path in the checksum file that is
    never uploaded is a promise nobody can check. Both have shipped.

    They drifted for exactly one release. When onedir became the default,
    `artifacts` gained the packaged zip and the collected tree but NOT the exe
    itself - while release.yml kept uploading `dist/TunTop/TunTop.exe`. So every
    release since has advertised an unverifiable binary, and
    `config.updates.download_release`, which requires a `TunTop.exe` line
    before it will stage anything, failed on EVERY user with
    "checksums.txt has no entry for TunTop.exe". The in-app updater has been
    dead since the layout change and nothing said so, because the updater's
    own tests encode the onefile world (they synthesise the TunTop.exe line)
    and no test ever compared them against what the build actually writes.

    WHY THE EXE IS NOT IN THIS LIST
    -------------------------------
    It used to be, and that was wrong twice over. `release.yml` uploaded
    `dist/TunTop/TunTop.exe`, but an onedir exe is a 2.8 MB launcher whose
    interpreter, DLLs and the vendored binaries live in the sibling
    `_internal/` tree (34 MB across 63 files) - so the release page offered a
    download that could not start. Verified on the published v1.0.51 asset:
    downloaded alone it dies with "Failed to load Python DLL
    '.../_internal/python312.dll'". And `config.updates` fetched that same file
    by name, which is the only thing keeping a broken artifact in the set: the
    exe was checksummed only so the updater could "verify" a file that still
    could not run.

    The standalone zip IS the whole directory, is already in this list, and
    does run on its own - so it is what release.yml publishes and what the
    updater now fetches, verifies and extracts. One list, no broken member.
    """
    paths = [zip_path]
    if exe:
        if onedir:
            folder = os.path.dirname(exe)
            zipped = zip_onedir(folder, get_version())
            if not zipped:
                print("ERROR: the onedir build produced no "
                      "distributable zip.", file=sys.stderr)
                raise SystemExit(1)
            paths.append(zipped)
            # The directory, as a content digest - it is not itself an
            # uploadable asset, but it is what the zip contains and the one
            # way to state what the tree's own integrity is.
            paths.append(folder)
    return paths


def build_parser() -> argparse.ArgumentParser:
    """The CLI. Extracted from main() so the flag semantics are testable
    without building anything - the default layout in particular is a
    behavioural contract (see the module docstring), not an implementation
    detail, and it has to be assertable."""
    ap = argparse.ArgumentParser(description="Build TunTop release")
    ap.add_argument("--version", default=None,
                    help="Version string (default: read from __init__.py)")
    ap.add_argument("--with-exe", action="store_true",
                    help="Also build TunTop via PyInstaller (optional). "
                         "Builds the ONEDIR layout by default and publishes "
                         "it as TunTop-<version>-x64-standalone.zip")
    # Mutually exclusive so the contradiction is rejected BY THE PARSER, with
    # a usage message, instead of by a branch in main() that a future edit can
    # drop. Silently preferring one flag is how a user ends up shipping the
    # layout they were trying to avoid.
    layout = ap.add_mutually_exclusive_group()
    layout.add_argument("--onedir", action="store_true",
                        help="(no-op since 1.0.51 - onedir is now the "
                             "default. Accepted so existing scripts and "
                             "instructions keep working)")
    layout.add_argument("--onefile", action="store_true",
                        help="Build the single SELF-EXTRACTING exe instead. "
                             "This is what gets quarantined: the onefile "
                             "bootloader unpacks an unsigned payload to a temp "
                             "dir on every start, which is the profile "
                             "Defender's ML model keys on. Opt in only if you "
                             "need one file to hand around")
    ap.add_argument("--defender-exclude", action="store_true",
                    help="LAST RESORT, best effort: add dist/ to Defender's "
                         "exclusion list before building (needs an elevated "
                         "shell; otherwise the manual command is printed). A "
                         "folder exclusion stops Defender watching every "
                         "future file written there, so prefer the default "
                         "onedir layout, which needs no exclusion")
    return ap


def main():
    ap = build_parser()
    args = ap.parse_args()

    # onedir unless onefile was explicitly asked for.
    onedir = not args.onefile
    if args.onedir:
        print("  i --onedir is the default since 1.0.51; nothing to do.")

    version = args.version or get_version()
    print(f"Building TunTop {version} release ...")

    if args.defender_exclude:
        try_defender_exclusion()

    zip_path = build_zip(version)
    # Only files that are actually PUBLISHED as release assets get a
    # checksum line. These three used to be added here and must not be again:
    #   - tun2socks-windows-amd64-v3.exe and wintun.dll: gitignored, fetched
    #     by CI, and shipped only INSIDE the zip. release.yml uploads neither.
    #   - TunTop-<version>.standalone.exe: written to the repo ROOT by
    #     _guard_exe as an AV-protection mirror. Never uploaded.
    # A checksum line for a file no downloader can fetch from the release is a
    # promise that cannot be checked, and it made checksums.txt list assets
    # the release page did not have.
    artifacts = [zip_path]
    exe_built = False

    if args.with_exe:
        exe = build_exe(onedir=onedir)
        if exe:
            # Defender routinely quarantines a freshly-written unsigned exe
            # within seconds (much more reliably for onefile); keep every copy
            # alive through the scan window and return the best surviving one.
            exe = _guard_exe(exe, version, protect=not onedir)
            if exe:
                artifacts = published_asset_paths(zip_path, exe, onedir)
                exe_built = True

    if args.with_exe and not exe_built:
        # build_exe() returns None for three different failures - PyInstaller
        # not importable, TunTop.spec missing, or an AV that ate every copy -
        # and main() used to exit 0 for all of them. CI therefore recorded a
        # "successful" release build and only failed later, in the upload
        # step, with an opaque file-not-found from the publishing action.
        # --with-exe was explicitly requested, so producing no exe is a build
        # failure, not a warning.
        print("ERROR: --with-exe was requested but no exe artifact was "
              "produced (PyInstaller unavailable, TunTop.spec missing, or an "
              "AV quarantined every copy). The default layout is onedir - if "
              "you passed --onefile, drop it; that layout is the one AVs "
              "quarantine.", file=sys.stderr)
        raise SystemExit(1)

    checksum_path = write_checksums(version, artifacts)

    print(f"\nRelease built: {zip_path}")
    print(f"Checksums:     {checksum_path}")
    with open(checksum_path, encoding="utf-8") as f:
        print(f.read())


if __name__ == "__main__":
    main()

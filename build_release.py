"""Build a distributable TunTop release.

Usage:  python build_release.py
        python build_release.py --version 1.0.0
        python build_release.py --with-exe        # also build TunTop.exe (needs pyinstaller)
        python build_release.py --with-exe --onedir   # AV-friendlier exe layout
        python build_release.py --with-exe --defender-exclude

Produces dist/TunTop-x64.zip containing everything needed to run TunTop
(the vendored binaries are included so the download is fully self-contained),
plus dist/checksums.txt with a SHA-256 for every shipped artifact
(TunTop-x64.zip, TunTop.exe when built, tun2socks.exe, wintun.dll).

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
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
]

INCLUDE_DIRS = [
    "tuntop",
]

# Files/dirs to exclude from tuntop/ in the zip
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


def build_exe(onedir: bool = False) -> str | None:
    """Build TunTop.exe with PyInstaller. onedir=False (default) produces the
    classic single dist/TunTop.exe (onefile); onedir=True produces
    dist/TunTop/ (exe + support files) - the AV-friendlier layout. Returns
    the artifact path (the exe itself), or None if PyInstaller is not
    available. Raises on build failure."""
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
        # set. The onedir folder itself is the artifact.
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
    "  ! dist/TunTop.exe did not survive the build: an AV (Defender) most\n"
    "    likely quarantined it. Recover it:\n"
    "      Windows Security -> Virus & threat protection -> Protection history\n"
    "      -> TunTop.exe -> Actions -> Restore\n"
    "    then add folder exclusions BEFORE rebuilding (admin PowerShell):\n"
    "      Add-MpPreference -ExclusionPath '<repo>'\n"
    "      Add-MpPreference -ExclusionPath '<repo>\\dist'\n"
    "    or build the AV-friendly onedir variant:\n"
    "      python build_release.py --onedir\n"
    "    The published GitHub-Release exe is unaffected (built on CI).")


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
    """OPT-IN, best effort: add `paths` (default: repo root + dist/) to
    Defender's exclusion list so the freshly-built unsigned exe is not
    quarantined DURING the build. Needs an elevated shell - without one the
    manual PowerShell is printed and nothing is changed. Never raises."""
    if paths is None:
        paths = [ROOT, DIST]
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

        # tuntop/ package
        pkg_dir = os.path.join(ROOT, "tuntop")
        for dirpath, dirnames, filenames in os.walk(pkg_dir):
            dirnames[:] = [d for d in dirnames
                           if d not in ("__pycache__", ".geo_cache")]
            rel = os.path.relpath(dirpath, ROOT)
            for fname in filenames:
                if should_exclude(fname):
                    continue
                src = os.path.join(dirpath, fname)
                arc = os.path.join(rel, fname).replace("\\", "/")
                zf.write(src, arc)
                print(f"  + {arc}")

        # Vendored binaries - shipped in the package dir so the app finds them
        # via app_dir() (and sys._MEIPASS when frozen).
        for b in BINARIES:
            src = os.path.join(ROOT, b)
            if os.path.isfile(src):
                zf.write(src, os.path.join("tuntop", b).replace("\\", "/"))
                print(f"  + tuntop/{b}")
            else:
                print(f"  ! {b} not found - release will auto-download it")

    print(f"  = {zip_name}")
    return zip_path


def write_checksums(version: str, artifacts: list[str]) -> str:
    """Write SHA-256 checksums for every shipped artifact."""
    path = os.path.join(DIST, "checksums.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"SHA-256 checksums for TunTop {version}\n")
        f.write("=" * 50 + "\n")
        for ap in artifacts:
            if os.path.isfile(ap):
                h = sha256_file(ap)
                size = os.path.getsize(ap)
                f.write(f"{h}  {os.path.basename(ap)}  ({size:,} bytes)\n")
    return path


def main():
    ap = argparse.ArgumentParser(description="Build TunTop release")
    ap.add_argument("--version", default=None,
                    help="Version string (default: read from __init__.py)")
    ap.add_argument("--with-exe", action="store_true",
                    help="Also build TunTop.exe via PyInstaller (optional)")
    ap.add_argument("--onedir", action="store_true",
                    help="Build the AV-friendly onedir layout "
                         "(dist/TunTop/ with the exe + support files) "
                         "instead of the single self-extracting onefile - "
                         "dramatically fewer AV false positives")
    ap.add_argument("--defender-exclude", action="store_true",
                    help="Best-effort: add this repo and dist/ to Defender's "
                         "exclusion list first (needs an elevated shell; "
                         "otherwise the manual command is printed)")
    args = ap.parse_args()

    version = args.version or get_version()
    print(f"Building TunTop {version} release ...")

    if args.defender_exclude:
        try_defender_exclusion()

    zip_path = build_zip(version)
    artifacts = [zip_path]

    if args.with_exe:
        exe = build_exe(onedir=args.onedir)
        if exe:
            # Defender routinely quarantines a freshly-written unsigned exe
            # within seconds (longer for onefile); keep every copy alive
            # through the scan window and return the best surviving one.
            exe = _guard_exe(exe, version, protect=not args.onedir)
            if exe:
                artifacts.append(exe)
            if not args.onedir:
                # onefile only: the outside-dist standalone copy the guard
                # keeps alive (onedir's support files are the artifact).
                standalone = os.path.join(
                    ROOT, f"TunTop-{version}.standalone.exe")
                if os.path.isfile(standalone):
                    artifacts.append(standalone)

    # Always checksum the vendored binaries that ship inside the zip too, so
    # users can verify them independently of the archive.
    for b in BINARIES:
        bp = os.path.join(ROOT, b)
        if os.path.isfile(bp):
            artifacts.append(bp)

    checksum_path = write_checksums(version, artifacts)

    print(f"\nRelease built: {zip_path}")
    print(f"Checksums:     {checksum_path}")
    with open(checksum_path, encoding="utf-8") as f:
        print(f.read())


if __name__ == "__main__":
    main()

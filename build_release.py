"""Build a distributable TunTop release.

Usage:  python build_release.py
        python build_release.py --version 1.0.0
        python build_release.py --with-exe        # also build TunTop.exe (needs pyinstaller)

Produces dist/TunTop-x64.zip containing everything needed to run TunTop
(the vendored binaries are included so the download is fully self-contained),
plus dist/checksums.txt with a SHA-256 for every shipped artifact
(TunTop-x64.zip, TunTop.exe when built, tun2socks.exe, wintun.dll).

Pure stdlib, no pip dependencies (PyInstaller is optional and only used for
the --with-exe step).
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
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
    "profiles.json",
    "diagnostics_*.txt",
    "*.log",
    "crash_*.txt",
    ".last_run.json",
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
    """Check if a filename matches any top-level exclusion pattern."""
    for pattern in EXCLUDE_PATTERNS:
        if pattern.startswith("*"):
            if name.endswith(pattern[1:]):
                return True
        elif name == pattern:
            return True
    return False


def build_exe() -> str | None:
    """Build TunTop.exe with PyInstaller (onefile). Returns the exe path, or
    None if PyInstaller is not available. Raises on build failure."""
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
    print("  * Building TunTop.exe with PyInstaller ...")
    subprocess.run([sys.executable, "-m", "PyInstaller", "--clean",
                    "--noconfirm", spec], check=True, cwd=ROOT)
    exe = os.path.join(DIST, "TunTop.exe")
    return exe if os.path.isfile(exe) else None


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
    args = ap.parse_args()

    version = args.version or get_version()
    print(f"Building TunTop {version} release ...")

    zip_path = build_zip(version)
    artifacts = [zip_path]

    if args.with_exe:
        exe = build_exe()
        if exe:
            artifacts.append(exe)

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

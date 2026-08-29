"""Build a distributable TunTop release zip.

Usage:  python build_release.py
        python build_release.py --version 1.0.0

Creates dist/TunTop-<version>.zip containing everything needed to run TunTop
(except the vendored binaries, which are auto-downloaded on first run).

Pure stdlib, no pip dependencies.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
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
    "tun2socks-windows-amd64-v3.exe",
    "wintun.dll",
    "profiles.json",
    "diagnostics_*.txt",
    "*.log",
    "crash_*.txt",
    ".last_run.json",
    ".geo_cache",
}

# Test files to exclude from the release (users don't need them)
EXCLUDE_TUNTOP = {
    "__pycache__",
    ".geo_cache",
}


def get_version() -> str:
    """Read version from tuntop/__init__.py."""
    init_path = os.path.join(ROOT, "tuntop", "__init__.py")
    with open(init_path, encoding="utf-8") as f:
        content = f.read()
    m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', content)
    if m:
        return m.group(1)
    return "0.0.0"


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
    """Check if a filename matches any exclusion pattern."""
    for pattern in EXCLUDE_PATTERNS:
        if pattern.startswith("*"):
            if name.endswith(pattern[1:]):
                return True
        elif name == pattern:
            return True
    return False


def build_zip(version: str) -> str:
    """Build the release zip and return its path."""
    os.makedirs(DIST, exist_ok=True)
    zip_name = f"TunTop-{version}.zip"
    zip_path = os.path.join(DIST, zip_name)

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Add top-level files
        for fname in INCLUDE_FILES:
            src = os.path.join(ROOT, fname)
            if os.path.isfile(src):
                zf.write(src, fname)
                print(f"  + {fname}")
            else:
                print(f"  ! {fname} not found, skipping")

        # Add tuntop/ package
        pkg_dir = os.path.join(ROOT, "tuntop")
        if os.path.isdir(pkg_dir):
            for dirpath, dirnames, filenames in os.walk(pkg_dir):
                # Remove excluded dirs in-place so os.walk skips them
                dirnames[:] = [d for d in dirnames
                               if d not in EXCLUDE_TUNTOP and d != "__pycache__"]
                rel = os.path.relpath(dirpath, ROOT)
                for fname in filenames:
                    if should_exclude(fname):
                        continue
                    src = os.path.join(dirpath, fname)
                    arc = os.path.join(rel, fname).replace("\\", "/")
                    zf.write(src, arc)
                    print(f"  + {arc}")

    return zip_path


def main():
    parser = argparse.ArgumentParser(description="Build TunTop release zip")
    parser.add_argument("--version", default=None,
                        help="Version string (default: read from __init__.py)")
    args = parser.parse_args()

    version = args.version or get_version()
    print(f"Building TunTop {version} release...")

    zip_path = build_zip(version)

    # Write checksums
    checksum_path = os.path.join(DIST, "checksums.txt")
    with open(checksum_path, "w") as f:
        f.write(f"SHA-256 checksums for TunTop {version}\n")
        f.write(f"{'=' * 50}\n")
        h = sha256_file(zip_path)
        size = os.path.getsize(zip_path)
        f.write(f"{h}  TunTop-{version}.zip  ({size:,} bytes)\n")

    print(f"\nRelease built: {zip_path}")
    print(f"Checksums:     {checksum_path}")
    with open(checksum_path) as f:
        print(f.read())


if __name__ == "__main__":
    main()

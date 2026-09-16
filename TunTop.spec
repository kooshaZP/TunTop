# PyInstaller spec for building the standalone TunTop.exe.
#
#   pyinstaller --clean --noconfirm TunTop.spec
#
# Produces dist/TunTop.exe (onefile). The vendored binaries
# (tun2socks-windows-amd64-v3.exe, wintun.dll) are collected next to the
# executable, and dashboard.app_dir() resolves them correctly at runtime via
# sys._MEIPASS (onefile) or the executable directory.
import os

ROOT = os.path.dirname(os.path.abspath(SPEC))
BINARIES = [
    os.path.join(ROOT, "tun2socks-windows-amd64-v3.exe"),
    os.path.join(ROOT, "wintun.dll"),
]
binaries = [(b, ".") for b in BINARIES if os.path.isfile(b)]

block_cipher = None

a = Analysis(
    [os.path.join(ROOT, "tuntop", "ui", "dashboard.py")],
    pathex=[ROOT],
    binaries=binaries,
    datas=[],
    hiddenimports=["tuntop",
                   # Spawned as child PROCESSES of the exe (via the
                   # --helper-child / --watchdog-child re-entry flags in
                   # dashboard.main()), not imported on the dashboard's
                   # static import graph - without these pins PyInstaller
                   # may leave them out of the bundle entirely.
                   "tuntop.tunnel.helper",
                   "tuntop.core.cleanup_watchdog"],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# ONEFILE vs ONEDIR
#
# onefile (default): single TunTop.exe, self-extracting. Clean to ship, but
# it is ALSO the single most AV-false-positive-prone PyInstaller layout: the
# bootloader unpacks an unsigned payload to a temp dir at every start - the
# exact behavior profile ML detectors flag, which is why Defender keeps
# deleting the artifact seconds after each build.
#
# onedir (--onedir): TunTop.exe next to its support files in dist/TunTop/.
# No self-extraction, no temp-dir payload drop - dramatically fewer AV
# detections, and a quarantine can be restored file-by-file instead of
# killing the whole artifact. Ship this variant when AV interference is a
# problem (zip dist/TunTop/ with the same INCLUDE/BINARY set).
import os
import sys
# onedir is selected via TUNTOP_SPEC_ONEDIR=1 (set by build_release.py):
# --onedir/--onefile are MAKESPEC options - PyInstaller rejects them when a
# .spec file is given, so the flag must travel outside sys.argv.
ONE_DIR = os.environ.get("TUNTOP_SPEC_ONEDIR") == "1"

exe = EXE(
    pyz,
    a.scripts,
    ([] if ONE_DIR else a.binaries),   # onedir: binaries ride in COLLECT
    ([] if ONE_DIR else a.zipfiles),
    ([] if ONE_DIR else a.datas),
    [],
    name="TunTop",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,   # UPX packing is the #1 AV false-positive trigger for
                 # onefile builds; keep the payload unpacked.
    console=True,
    icon="assets/tuntop.ico",
    version="tuntop_version_info.txt",
    exclude_binaries=ONE_DIR,          # onedir: EXE excludes, COLLECT owns
)

if ONE_DIR:
    coll = COLLECT(
        exe,
        a.binaries,
        a.zipfiles,
        a.datas,
        strip=False,
        upx=False,
        name="TunTop",
    )

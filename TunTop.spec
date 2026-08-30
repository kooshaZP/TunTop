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
    hiddenimports=["tuntop"],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="TunTop",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    runtime_tmpdir=None,
    console=True,
    icon=None,
)

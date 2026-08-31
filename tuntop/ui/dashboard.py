#!/usr/bin/env python3
"""btop-style dashboard for v2ray TUN monitoring.

A separate, self-contained TUI inspired by btop/btop+ - panel-based layout,
Unicode box-drawing borders, block-element progress bars, gradient graphs,
active/inactive panel styling, and a clean dark theme.

DOES NOT MODIFY ANY EXISTING FILE.  All helper logic is re-implemented locally.

Usage:  python tuntop/ui/dashboard.py --server IP [--port PORT] [--tun2socks PATH] [MODE FLAGS]
Run via Run_Helper.ps1 for admin elevation.
"""

import argparse
import atexit
import base64
import concurrent.futures
import ctypes
import json
import os
import queue
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

import os as _os
import sys as _sys
_PKG_PARENT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _PKG_PARENT not in _sys.path:
    _sys.path.insert(0, _PKG_PARENT)


def app_dir() -> str:
    """Directory that holds TunTop's runtime assets (tun2socks.exe / wintun.dll).

    When frozen by PyInstaller (``--onefile``) the script runs from a temp
    extraction dir, so the real assets live under ``sys._MEIPASS``; when run
    from source they ship inside the ``tuntop`` package (this file lives in
    ``tuntop/ui/``, so the assets are one level up). Always resolves to the
    directory the *assets* are shipped in, never the temp sandbox.
    """
    if getattr(_sys, "frozen", False):
        return getattr(_sys, "_MEIPASS", _os.path.dirname(_sys.executable))
    here = _os.path.dirname(_os.path.abspath(__file__))
    if _os.path.basename(here) == "ui":
        return _os.path.dirname(here)
    return here

from tuntop.routing import (          # noqa: E402
    _ps, _netsh, _teardown_wintun,
    _add_route_v4, _del_route_v4, _add_route_v6, _del_route_v6,
    _route_exists_v4, _route_exists_v6,
    _get_ipv4_default, _get_ipv6_default,
    _get_egress_for, _get_vpn_ipv4_default, _get_vpn_ipv6_default,
)
from tuntop.netdns import (           # noqa: E402
    _host_from_url, _resolve, _resolve_cached, _resolve_detail,
    _dns_cache_clear, _dns_build_query, _dns_parse_answers,
    _dns_query_udp, _dns_query_doh,
)
from tuntop.state import (            # noqa: E402
    TunnelState, TunnelStateMachine,
)
from tuntop.recovery import (         # noqa: E402
    FailureKind, RecoveryAction, RecoveryEngine,
)
from tuntop.routes_txn import RouteTransaction   # noqa: E402
from tuntop import startup_recovery              # noqa: E402
from tuntop import integrity                     # noqa: E402
from tuntop import ui_text                       # noqa: E402
from tuntop import profiles                      # noqa: E402
from tuntop.structured_log import (              # noqa: E402
    LogRing, INFO as _LOG_INFO, WARNING as _LOG_WARNING,
    ERROR as _LOG_ERROR,
)
from tuntop.health_report import (              # noqa: E402
    format_panel as _health_format_panel,
    format_compact as _health_compact,
)


# Crash log written next to this script. main() catches anything that gets
# past the per-frame draw() guard, writes the traceback here, prints it to
# the console, and waits for a keypress instead of letting the window just
# vanish (the classic "it crashes when I try to open it" symptom, which is
# usually really "it crashed and closed before I could read why").
CRASH_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "TunTop_crash.log")

# Where a downloaded geoip database lands when none is configured ([W] key /
# missing-file auto-download on start). Next to the package so it survives
# alongside the .geo_cache that keys off the file's mtime+size.
_DEFAULT_GEOIP_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "geoip.dat")


def _snap_parse_done(geo_parse, code):
    """Snap one country code's stale [GEO-PARSE] value (loaded < total) up to
    complete, so a File bar that never received its final 100% marker doesn't
    stay frozen next to the moving Routes bar."""
    p = geo_parse.get(code)
    if p and p[0] < p[1]:
        geo_parse[code] = (p[1], p[1])

# Reference to the console-control callback registered with
# SetConsoleCtrlHandler.  The ctypes function pointer must be kept alive for
# the life of the program; if it is garbage-collected, the OS calling into it
# on window close / logoff / Ctrl+Break (exactly the events it exists to catch
# for cleanup) is undefined behaviour.  Stored at module scope so it is never
# reclaimed while the dashboard runs.
_CTRL_HANDLER_REF = None

# ─── Windows console input structures (mouse + keyboard, no extra deps) ──────
# Used for click support. All of this is best-effort: if any of it fails to
# initialize on a given terminal host, the dashboard falls back to the
# original keyboard-only msvcrt polling and nothing breaks.

STD_INPUT_HANDLE = -10
ENABLE_EXTENDED_FLAGS = 0x0080
ENABLE_MOUSE_INPUT = 0x0010
ENABLE_QUICK_EDIT_MODE = 0x0040
ENABLE_PROCESSED_INPUT = 0x0001
KEY_EVENT = 0x0001
MOUSE_EVENT = 0x0002
FROM_LEFT_1ST_BUTTON = 0x0001


class _COORD(ctypes.Structure):
    _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]


class _KEY_EVENT_RECORD(ctypes.Structure):
    _fields_ = [
        ("bKeyDown", ctypes.c_int),
        ("wRepeatCount", ctypes.c_ushort),
        ("wVirtualKeyCode", ctypes.c_ushort),
        ("wVirtualScanCode", ctypes.c_ushort),
        ("uChar", ctypes.c_wchar),
        ("dwControlKeyState", ctypes.c_uint32),
    ]


class _MOUSE_EVENT_RECORD(ctypes.Structure):
    _fields_ = [
        ("dwMousePosition", _COORD),
        ("dwButtonState", ctypes.c_uint32),
        ("dwControlKeyState", ctypes.c_uint32),
        ("dwEventFlags", ctypes.c_uint32),
    ]


class _INPUT_RECORD_EVENT(ctypes.Union):
    _fields_ = [
        ("KeyEvent", _KEY_EVENT_RECORD),
        ("MouseEvent", _MOUSE_EVENT_RECORD),
    ]


class _INPUT_RECORD(ctypes.Structure):
    _fields_ = [
        ("EventType", ctypes.c_ushort),
        ("Event", _INPUT_RECORD_EVENT),
    ]


# ─── Colours ─────────────────────────────────────────────────────────────────

DIM = "\033[2m"
BRIGHT = "\033[1m"
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
WHITE = "\033[97m"
PURPLE = "\033[95m"
GRAY = "\033[90m"

# Panel borders ─ light active, heavy inactive
P_LIGHT   = "\033[38;2;100;140;200m"   # panel border (active)
P_INACT   = "\033[38;2;60;75;100m"     # panel border (inactive / dim)
P_ACTIVE  = "\033[38;2;140;190;255m"    # bright accent line
BG_DARK   = "\033[48;2;15;17;22m"      # subtle bg fill

# ─── Themes ──────────────────────────────────────────────────────────────────
# Swappable named palettes. Each palette provides a default border set
# (light/active/inact) plus a distinct *accent* colour per panel so the
# dashboard no longer reuses one blue for every border. Selected at runtime
# with [M]; built on top of the colour constants above. The first entry is the
# cool default, the second a high-contrast amber "degraded" theme, the third a
# muted low-colour theme for weak terminals; matrix/ice are monochrome-accent
# variants and dracula/nord are popular pastel community palettes.
THEMES = [
    {  # 0 - cool (default)
        "name": "cool",
        "light":   "\033[38;2;100;140;200m",
        "active":  "\033[38;2;140;190;255m",
        "inact":   "\033[38;2;60;75;100m",
        "metrics":     "\033[38;2;120;200;255m",
        "endpoint":   "\033[38;2;120;230;200m",
        "throughput": "\033[38;2;140;255;170m",
        "health":     "\033[38;2;190;160;255m",
        "log":        "\033[38;2;210;200;150m",
    },
    {  # 1 - amber / high-contrast "degraded"
        "name": "amber",
        "light":   "\033[38;2;180;130;40m",
        "active":  "\033[38;2;255;190;80m",
        "inact":   "\033[38;2;110;80;25m",
        "metrics":     "\033[38;2;255;200;90m",
        "endpoint":   "\033[38;2;255;170;60m",
        "throughput": "\033[38;2;255;210;120m",
        "health":     "\033[38;2;255;150;40m",
        "log":        "\033[38;2;235;185;95m",
    },
    {  # 2 - muted / low-colour
        "name": "muted",
        "light":   "\033[38;2;120;120;120m",
        "active":  "\033[38;2;185;185;185m",
        "inact":   "\033[38;2;80;80;80m",
        "metrics":     "\033[38;2;170;170;170m",
        "endpoint":   "\033[38;2;150;150;150m",
        "throughput": "\033[38;2;160;160;160m",
        "health":     "\033[38;2;195;195;195m",
        "log":        "\033[38;2;140;140;140m",
    },
    {  # 3 - matrix / green phosphor
        "name": "matrix",
        "light":   "\033[38;2;60;150;90m",
        "active":  "\033[38;2;120;255;140m",
        "inact":   "\033[38;2;35;90;55m",
        "metrics":     "\033[38;2;90;230;120m",
        "endpoint":   "\033[38;2;120;255;150m",
        "throughput": "\033[38;2;60;220;120m",
        "health":     "\033[38;2;160;255;180m",
        "log":        "\033[38;2;110;210;120m",
    },
    {  # 4 - ice / cyan
        "name": "ice",
        "light":   "\033[38;2;90;170;200m",
        "active":  "\033[38;2;150;230;255m",
        "inact":   "\033[38;2;55;105;125m",
        "metrics":     "\033[38;2;120;220;255m",
        "endpoint":   "\033[38;2;140;235;255m",
        "throughput": "\033[38;2;110;215;245m",
        "health":     "\033[38;2;180;240;255m",
        "log":        "\033[38;2;150;210;235m",
    },
    {  # 5 - dracula / purple-pastel
        "name": "dracula",
        "light":   "\033[38;2;98;114;164m",
        "active":  "\033[38;2;189;147;249m",
        "inact":   "\033[38;2;68;71;90m",
        "metrics":     "\033[38;2;189;147;249m",
        "endpoint":   "\033[38;2;255;121;198m",
        "throughput": "\033[38;2;139;233;253m",
        "health":     "\033[38;2;241;250;140m",
        "log":        "\033[38;2;255;184;108m",
    },
    {  # 6 - nord / frosty blue-green
        "name": "nord",
        "light":   "\033[38;2;76;86;106m",
        "active":  "\033[38;2;136;192;208m",
        "inact":   "\033[38;2;46;52;64m",
        "metrics":     "\033[38;2;129;161;193m",
        "endpoint":   "\033[38;2;163;190;140m",
        "throughput": "\033[38;2;235;203;139m",
        "health":     "\033[38;2;180;142;173m",
        "log":        "\033[38;2;208;135;112m",
    },
]
ACTIVE_THEME = 0  # index into THEMES; switched with [M]


def theme():
    """Return the currently active palette dict."""
    return THEMES[ACTIVE_THEME]

# ─── Terminal-safe glyphs ───────────────────────────────────────────────────
# Classic cmd.exe can still render Unicode as '?' even after switching to
# UTF-8, depending on the console host/font. The old check only lit up the
# Unicode glyph set inside a handful of terminals it knew about in advance
# (Windows Terminal, ConEmu, ANSICON, VS Code) - so a plain cmd.exe window, a
# plain PowerShell console, and Git Bash's mintty (none of which set any of
# those variables) all silently fell back to '+'/'-'/'#' and never looked
# like btop. _apply_glyphs()/_probe_unicode_support() below replace that with
# real capability probing, run once main() has had a chance to fix the
# console codepage/font up (see _enable_ansi()/_set_unicode_font()).

def _apply_glyphs(unicode_on):
    """Set every glyph/box-drawing global at once, so the Unicode/ASCII
    decision only ever lives in one place instead of being duplicated at
    import time and again in main()."""
    global USE_UNICODE, BOX_LC, BOX_RC, BOX_BL, BOX_BR, BOX_MID, BOX_V, BOX_BS
    global PROGRESS_EMPTY, PROGRESS_MED, PROGRESS_FULL, PROGRESS_W
    global SPLINE, DOT_GLYPH, DOT_OK, DOT_WARN, DOT_FAIL, DOT_IDLE
    USE_UNICODE = unicode_on
    # Top corners (╭/╮) and a distinct bottom-corner pair (╰/╯) so the bottom
    # border never reuses the top-right glyph. The names mirror the top pair so
    # any future glyph set that forgets the bottom pair will fail loudly.
    if unicode_on:
        BOX_LC, BOX_RC, BOX_BL, BOX_BR, BOX_MID, BOX_V, BOX_BS = "╭", "╮", "╰", "╯", "─", "│", "━"
        PROGRESS_EMPTY, PROGRESS_MED, PROGRESS_FULL, PROGRESS_W = "░", "▒", "▓", "█"
        DOT_GLYPH = "●"
    else:
        BOX_LC, BOX_RC, BOX_BL, BOX_BR, BOX_MID, BOX_V, BOX_BS = "+", "+", "+", "+", "-", "|", "="
        PROGRESS_EMPTY, PROGRESS_MED, PROGRESS_FULL, PROGRESS_W = "-", "=", "#", "#"
        DOT_GLYPH = "o"
    SPLINE = " .:-=+*#@"
    DOT_OK   = GREEN + DOT_GLYPH + RESET
    DOT_WARN = YELLOW + DOT_GLYPH + RESET
    DOT_FAIL = RED + DOT_GLYPH + RESET
    DOT_IDLE = GRAY + DOT_GLYPH + RESET


def _detect_terminal_host():
    """Best-effort label for the terminal host we're running inside. Only
    used to decide how cautious to be about Unicode glyphs below - every
    other behaviour is identical no matter which host this returns, so a
    wrong guess just means a possibly-unnecessary ASCII fallback, never a
    crash."""
    if os.environ.get("WT_SESSION"):
        return "windows-terminal"
    if os.environ.get("ConEmuANSI") == "ON":
        return "conemu"
    if os.environ.get("ANSICON"):
        return "ansicon"
    if os.environ.get("TERM_PROGRAM"):
        return os.environ["TERM_PROGRAM"]
    if os.environ.get("MSYSTEM"):
        return "mintty"       # Git Bash / MSYS2
    if os.environ.get("TERM"):
        return "posix-term"   # any other bash-family shell on a pty
    return "conhost"          # plain cmd.exe / powershell.exe console


_unicode_setup_ok = True  # updated by _set_unicode_font() once it actually runs


def _probe_unicode_support():
    """Decide whether Unicode box/block glyphs are safe to use. Defaults to
    yes almost everywhere: mintty (Git Bash), Windows Terminal, ConEmu, and
    VS Code all render them natively, and _enable_ansi()/_set_unicode_font()
    already switch a classic conhost (plain cmd.exe or PowerShell console) to
    a UTF-8 codepage and a TrueType font before this is called. Only falls
    back to ASCII automatically when output isn't an interactive terminal at
    all, or that conhost font/codepage fix-up is confirmed to have failed."""
    if os.environ.get("BTOP_ASCII"):
        return False
    if not sys.stdout.isatty():
        return False
    if _detect_terminal_host() == "conhost":
        return _unicode_setup_ok
    return True


_apply_glyphs(False)  # safe placeholder until main() probes the real terminal


# ─── Helpers (re-implemented, never touch original files) ────────────────────

def _admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _set_unicode_font():
    """Switch the console to a TrueType font (Consolas/...) that can actually
    draw the Unicode box/block glyphs. With an elevated cmd.exe the default
    Raster font cannot render them, so the screen shows '?' even though the
    text buffer already holds the correct Unicode (that's why a copy/paste of
    the screen still contains the real box characters).

    Sets the module-level _unicode_setup_ok flag so _probe_unicode_support()
    knows whether this actually worked on a plain conhost (cmd.exe/PowerShell)
    - other hosts (mintty, Windows Terminal, ...) don't need this fix-up and
    ignore the flag entirely."""
    global _unicode_setup_ok
    try:
        k32 = ctypes.windll.kernel32

        class CONSOLE_FONT_INFOEX(ctypes.Structure):
            _fields_ = [
                ("cbSize", ctypes.c_ulong),
                ("nFont", ctypes.c_ulong),
                ("dwFontSize", ctypes.COORD),
                ("FontFamily", ctypes.c_uint),
                ("FontWeight", ctypes.c_uint),
                ("FaceName", ctypes.c_wchar * 32),
            ]

        k32.GetCurrentConsoleFontEx.argtypes = [
            ctypes.c_void_p, ctypes.c_bool, ctypes.POINTER(CONSOLE_FONT_INFOEX)]
        k32.GetCurrentConsoleFontEx.restype = ctypes.c_bool
        k32.SetCurrentConsoleFontEx.argtypes = [
            ctypes.c_void_p, ctypes.c_bool, ctypes.POINTER(CONSOLE_FONT_INFOEX)]
        k32.SetCurrentConsoleFontEx.restype = ctypes.c_bool

        h = k32.GetStdHandle(-11)
        cur = CONSOLE_FONT_INFOEX()
        cur.cbSize = ctypes.sizeof(cur)
        if not k32.GetCurrentConsoleFontEx(h, False, ctypes.byref(cur)):
            _unicode_setup_ok = False
            return
        # The only thing that actually prevents box/block glyphs from rendering
        # on a conhost is a *Raster* (bitmap) font, whose cells can't hold the
        # Unicode codepoints. If the active font is already TrueType we're done:
        # glyphs will render regardless of whether our later Set* call "succeeds".
        # This is the fix for the false-negative - a default Consolas face would
        # previously fall through to the ASCII fallback if SetCurrentConsoleFontEx
        # didn't return exactly True, even though it was perfectly capable.
        if cur.FontFamily & 0x04:  # TMPF_TRUETYPE
            _unicode_setup_ok = True
            return
        # Keep the current size; if it's unset, pick a sane default.
        if cur.dwFontSize.Y == 0:
            cur.dwFontSize = ctypes.COORD(0, 16)
        # Iterating family bits too: SetCurrentConsoleFontEx silently keeps the
        # current (Raster) font unless a TrueType family bit is requested, so the
        # named font must be paired with a TrueType-capable FontFamily value.
        for family in (0x36, 0x04):
            for face in ("Consolas", "Lucida Console", "DejaVu Sans Mono", "Courier New"):
                new = CONSOLE_FONT_INFOEX()
                new.cbSize = ctypes.sizeof(new)
                new.nFont = 0
                new.dwFontSize = cur.dwFontSize
                new.FontFamily = family
                new.FontWeight = 400
                new.FaceName = face
                if k32.SetCurrentConsoleFontEx(h, False, ctypes.byref(new)):
                    # Re-read the *now-active* font and trust its TrueType bit,
                    # not the return value of the call. If it's TrueType, glyphs
                    # will render - otherwise keep looking / fall back.
                    chk = CONSOLE_FONT_INFOEX()
                    chk.cbSize = ctypes.sizeof(chk)
                    if k32.GetCurrentConsoleFontEx(h, False, ctypes.byref(chk)):
                        if chk.FontFamily & 0x04:
                            _unicode_setup_ok = True
                            return
        _unicode_setup_ok = False  # every candidate face/family failed
    except Exception:
        _unicode_setup_ok = False


def _enable_ansi():
    """Enable VT processing, force the console into UTF-8 (codepage 65001), and
    switch to a Unicode-capable TrueType font, so the box-drawing glyphs render
    instead of turning into '?'. An elevated cmd.exe otherwise defaults to an
    OEM codepage (437/850) and a Raster font, neither of which can show them."""
    try:
        k32 = ctypes.windll.kernel32
        h = k32.GetStdHandle(-11)
        m = ctypes.c_uint32()
        if k32.GetConsoleMode(h, ctypes.byref(m)):
            k32.SetConsoleMode(h, m.value | 0x0004)
        # Output + input codepage to UTF-8 so Python's UTF-8 bytes are shown
        # correctly and typed input is decoded as UTF-8.
        k32.SetConsoleOutputCP(65001)
        k32.SetConsoleCP(65001)
    except Exception:
        pass
    _set_unicode_font()
    try:
        for stream in (sys.stdout, sys.stderr):
            if hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    # Make any child process (the helper) emit UTF-8 as well, so its log
    # lines decode cleanly instead of becoming '?'.
    os.environ.setdefault("PYTHONUTF8", "1")
    os.environ["PYTHONIOENCODING"] = "utf-8"


def _resize_console(cols=120, rows=3000):
    """Size the console *buffer* so the dashboard can fill whatever window
    height the user chooses.

    CRITICAL: only the buffer *height* is grown. The buffer *width* is left at
    (or reset to) the current visible window width. `shutil.get_terminal_size()`
    returns the buffer width on Windows, so if we grew the buffer width to 512
    the layout would believe the terminal is 512 cols wide and emit 512-col
    lines into a ~119-col window - they wrap and interleave into garbage. By
    keeping buffer width == window width, every width source (get_terminal_size
    and the srWindow rectangle) agrees with what's actually on screen.

    The window itself is deliberately left to the user: cmd/PowerShell can be
    dragged taller/wider freely (conhost auto-grows the buffer to match a wider
    window), and the dashboard adapts to that size. We only grow the backing
    buffer tall enough that the fixed top sections plus the expanding event-log
    panel are never clipped, however tall the user makes the window.

    Best-effort: any failure (non-console host, driver/size limits) is
    ignored so the dashboard still runs at whatever size it inherits."""
    try:
        k32 = ctypes.windll.kernel32

        class COORD(ctypes.Structure):
            _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]

        class SMALL_RECT(ctypes.Structure):
            _fields_ = [("Left", ctypes.c_short), ("Top", ctypes.c_short),
                        ("Right", ctypes.c_short), ("Bottom", ctypes.c_short)]

        class CONSOLE_SCREEN_BUFFER_INFO(ctypes.Structure):
            _fields_ = [("dwSize", COORD), ("dwCursorPosition", COORD),
                        ("wAttributes", ctypes.c_uint16),
                        ("srWindow", SMALL_RECT),
                        ("dwMaximumWindowSize", COORD)]

        h = k32.GetStdHandle(-11)
        info = CONSOLE_SCREEN_BUFFER_INFO()
        info.cbSize = ctypes.sizeof(info)
        if k32.GetConsoleScreenBufferInfo(h, ctypes.byref(info)):
            # Visible window width (srWindow), falling back to the current
            # buffer width. Never grow the buffer wider than the window.
            if info.srWindow.Right > info.srWindow.Left:
                win_w = int(info.srWindow.Right) - int(info.srWindow.Left) + 1
            else:
                win_w = int(info.dwSize.X)
            cols = max(40, win_w)
        # Grow the buffer height generously but keep its width at the window
        # width - never resize the visible window beyond what the user set.
        k32.SetConsoleScreenBufferSize(h, COORD(cols, rows))
    except Exception:
        pass


def _get_window_size():
    """Return the *visible console window* size (cols, rows).

    `shutil.get_terminal_size()` can report the console *buffer* width on
    Windows (which _resize_console deliberately grows), not the viewport the
    user is actually looking at. Using the buffer width for layout makes the
    `>140` wide-column decision fire incorrectly and every panel line wider
    than the real window, so the lines wrap and interleave into garbage. We
    read the window rectangle (srWindow) directly instead. Returns None when
    there is no real console (piped output), so the caller can fall back."""
    try:
        k32 = ctypes.windll.kernel32

        class COORD(ctypes.Structure):
            _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]

        class SMALL_RECT(ctypes.Structure):
            _fields_ = [("Left", ctypes.c_short), ("Top", ctypes.c_short),
                        ("Right", ctypes.c_short), ("Bottom", ctypes.c_short)]

        class CONSOLE_SCREEN_BUFFER_INFO(ctypes.Structure):
            _fields_ = [("dwSize", COORD), ("dwCursorPosition", COORD),
                        ("wAttributes", ctypes.c_uint16),
                        ("srWindow", SMALL_RECT),
                        ("dwMaximumWindowSize", COORD)]

        h = k32.GetStdHandle(-11)
        info = CONSOLE_SCREEN_BUFFER_INFO()
        info.cbSize = ctypes.sizeof(info)
        if k32.GetConsoleScreenBufferInfo(h, ctypes.byref(info)):
            cols = int(info.srWindow.Right) - int(info.srWindow.Left) + 1
            rows = int(info.srWindow.Bottom) - int(info.srWindow.Top) + 1
            if cols > 0 and rows > 0:
                return cols, rows
    except Exception:
        pass
    return None


def _tcp(host, port, timeout=4):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"{host}:{port} reachable"
    except OSError as e:
        return False, str(e)


def _socks_greeting(port):
    try:
        with socket.create_connection(("127.0.0.1", port), 4) as s:
            s.settimeout(4)
            s.sendall(b"\x05\x01\x00")
            reply = s.recv(2)
            return reply == b"\x05\x00", "No-auth method accepted" if reply == b"\x05\x00" else f"Reply: {reply!r}"
    except OSError as e:
        return False, str(e)


def _recv_exact(sock, size):
    """Read exactly *size* bytes unless the peer closes the socket."""
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            return b""
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _recv_socks5_reply(sock):
    """Read a complete SOCKS5 reply, including IPv6/domain bind addresses."""
    head = _recv_exact(sock, 4)
    if len(head) != 4:
        return b""
    atyp = head[3]
    if atyp == 1:  # IPv4 + port
        tail = _recv_exact(sock, 4 + 2)
    elif atyp == 4:  # IPv6 + port
        tail = _recv_exact(sock, 16 + 2)
    elif atyp == 3:  # domain length + domain + port
        length = _recv_exact(sock, 1)
        if len(length) != 1:
            return b""
        tail = length + _recv_exact(sock, length[0] + 2)
    else:
        return b""
    return head + tail


def _socks_connect_domain(port, domain="www.gstatic.com", tport=443, timeout=6):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"\x05\x01\x00")
            if s.recv(2) != b"\x05\x00":
                return False, "SOCKS authentication was not accepted"
            dom = domain.encode("ascii")
            addr = b"\x03" + bytes((len(dom),)) + dom + tport.to_bytes(2, "big")
            s.sendall(bytes((5, 1, 0)) + addr)
            reply = _recv_socks5_reply(s)
            ok = len(reply) >= 2 and reply[1] == 0
            return ok, f"CONNECT {domain}:{tport} accepted" if ok else f"Reply: {reply!r}"
    except OSError as e:
        return False, str(e)


def _socks_request(port, command, target_ip="1.1.1.1"):
    """SOCKS5 CONNECT (command=1) or UDP ASSOCIATE (command=3) to a raw IP."""
    try:
        with socket.create_connection(("127.0.0.1", port), 5) as s:
            s.settimeout(5)
            s.sendall(b"\x05\x01\x00")
            if s.recv(2) != b"\x05\x00":
                return False, "SOCKS authentication was not accepted"
            address = (b"\x01" + socket.inet_aton(target_ip) + b"\x01\xbb"
                       if command == 1 else b"\x01\x00\x00\x00\x00\x00")
            s.sendall(bytes((5, command, 0)) + address)
            reply = _recv_socks5_reply(s)
            ok = len(reply) >= 2 and reply[1] == 0
            return ok, "SOCKS request accepted" if ok else f"Reply: {reply!r}"
    except OSError as e:
        return False, str(e)


def _socks_request_v6(port, target_ip="2606:4700:4700::1111", target_port=53):
    """SOCKS5 CONNECT to a raw IPv6 literal through 127.0.0.1:port.

    This isolates whether the VLESS server itself provides IPv6 egress.
    If this fails, the tunnel's IPv6 breakage is server-side (no client
    routing change can fix it); if it succeeds while curl -6 via Wintun
    still fails, the problem is tun2socks IPv6 forwarding."""
    try:
        with socket.create_connection(("127.0.0.1", port), 5) as s:
            s.settimeout(5)
            s.sendall(b"\x05\x01\x00")
            if s.recv(2) != b"\x05\x00":
                return False, "SOCKS authentication was not accepted"
            addr = (b"\x04" + socket.inet_pton(socket.AF_INET6, target_ip)
                    + target_port.to_bytes(2, "big"))
            s.sendall(bytes((5, 1, 0)) + addr)
            reply = _recv_socks5_reply(s)
            ok = len(reply) >= 2 and reply[1] == 0
            return ok, ("IPv6 SOCKS CONNECT accepted (server has IPv6 egress)"
                       if ok else f"Reply: {reply!r}")
    except OSError as e:
        return False, str(e)



def _socks_udp_assoc(port, timeout=6):
    try:
        ctrl = socket.create_connection(("127.0.0.1", port), timeout)
    except OSError as e:
        return None, f"cannot reach SOCKS5 at 127.0.0.1:{port}: {e}"
    try:
        ctrl.settimeout(timeout)
        ctrl.sendall(b"\x05\x01\x00")
        if ctrl.recv(2) != b"\x05\x00":
            return None, "SOCKS5 authentication was not accepted"
        ctrl.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        rep = _recv_socks5_reply(ctrl)
        if len(rep) < 7 or rep[1] != 0:
            return None, f"UDP ASSOCIATE rejected (reply {rep!r})"
        atyp = rep[3]
        host = "127.0.0.1"
        rport = 0
        if atyp == 1:
            host = socket.inet_ntoa(rep[4:8])
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, rep[4:20])
        rport = int.from_bytes(rep[-2:], "big")
        return (host, rport, ctrl), f"UDP ASSOCIATE ok (relay {host}:{rport})"
    except OSError as e:
        try:
            ctrl.close()
        except Exception:
            pass
        return None, f"UDP ASSOCIATE error: {e}"


def _check_udp_assoc(port):
    relay, msg = _socks_udp_assoc(port)
    if relay is None:
        return False, msg + " - enable UDP on the v2rayN SOCKS inbound"
    _, _, ctrl = relay
    try:
        ctrl.close()
    except Exception:
        pass
    return True, msg


def _dns_query_via_socks(port, server="1.1.1.1", tcp_mode=False, timeout=6):
    txid = os.urandom(2)
    question = b"".join(bytes((len(x),)) + x.encode("ascii") for x in "cloudflare.com".split(".")) + b"\0\0\1\0\1"
    packet = txid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question
    try:
        if tcp_mode:
            with socket.create_connection(("127.0.0.1", port), timeout) as s:
                s.settimeout(timeout)
                s.sendall(b"\x05\x01\x00")
                if s.recv(2) != b"\x05\x00":
                    return False, "SOCKS5 authentication was not accepted"
                addr = b"\x01" + socket.inet_aton(server) + (53).to_bytes(2, "big")
                s.sendall(b"\x05\x01\x00" + addr)
                rep = _recv_socks5_reply(s)
                if len(rep) < 7 or rep[1] != 0:
                    return False, f"SOCKS5 CONNECT {server}:53 rejected: {rep!r}"
                s.sendall(len(packet).to_bytes(2, "big") + packet)
                n = int.from_bytes(s.recv(2), "big")
                reply = s.recv(n)
        else:
            relay, msg = _socks_udp_assoc(port, timeout)
            if relay is None:
                return False, msg
            host, rport, ctrl = relay
            try:
                udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp.settimeout(timeout)
                header = b"\x00\x00\x00\x01" + socket.inet_aton(server) + (53).to_bytes(2, "big")
                udp.sendto(header + packet, (host, rport))
                data, _ = udp.recvfrom(4096)
                reply = data[10:] if len(data) > 10 and data[:2] == b"\x00\x00" else data
            finally:
                try:
                    udp.close()
                except Exception:
                    pass
                try:
                    ctrl.close()
                except Exception:
                    pass
        if len(reply) < 12 or reply[:2] != txid:
            head = reply[:64]
            if b"HTTP" in head or b"TP/1" in head or b"<html" in head.lower():
                return False, ("resolver intercepted - v2rayN routing direct; "
                               "send DNS IPs through proxy or use DoH")
            return False, "Invalid DNS reply via proxy"
        rcode = reply[3] & 15
        answers = int.from_bytes(reply[6:8], "big")
        return rcode == 0 and answers > 0, f"DNS SOCKS {'TCP' if tcp_mode else 'UDP'}: {answers} ans, rcode {rcode}"
    except OSError as e:
        msg = str(e)
        if "timed out" in msg:
            if tcp_mode:
                return False, f"{msg}; send DNS IPs through proxy or use DoH"
            return False, f"{msg} - server does not relay UDP; DNS falls back to TCP"
        return False, msg


def _dns_tunnel_verdict(dns, port):
    """Run both UDP and TCP DNS-through-the-tunnel probes and return a single,
    unambiguous verdict so the dashboard isn't alarmist when only the TCP
    fallback fails.

    Normal resolver traffic is UDP/53. A failed *TCP* probe while UDP still
    works is harmless (the OS simply won't use the TCP fallback), so we report
    it as OK. Only when *both* fail is the DNS server genuinely unreachable
    through the tunnel and the operator must change --dns4."""
    ok_udp, msg_udp = _dns_query_via_socks(port, dns, False)
    ok_tcp, msg_tcp = _dns_query_via_socks(port, dns, True)
    if ok_udp and ok_tcp:
        return True, f"UDP+TCP OK via {dns}"
    if ok_udp and not ok_tcp:
        return True, f"UDP OK via {dns}; TCP fallback failed (harmless - resolver uses UDP)"
    if not ok_udp and ok_tcp:
        return True, f"TCP OK via {dns}; UDP failed (harmless - resolver can use TCP)"
    return False, f"both UDP+TCP failed via {dns}: {msg_udp}"


def _https(proxy=False, v6=False, port=10808,
           url="https://www.cloudflare.com/cdn-cgi/trace"):
    cmd = ["curl.exe", "--silent", "--show-error", "--max-time", "15",
           "--output", "NUL", "--write-out", "%{http_code}"]
    if proxy:
        cmd += ["--socks5-hostname", f"127.0.0.1:{port}"]
    cmd.append("-6" if v6 else "-4")
    cmd.append(url)
    last = (False, "")
    for _ in range(2):
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=18)
            out = (p.stdout or "").strip() or (p.stderr or "").strip()
            last = (p.returncode == 0 and out.startswith("2"), out)
            if last[0]:
                return last
        except Exception as e:
            last = (False, str(e))
    return last


def _ipv6_tun_verdict(port, url="https://www.cloudflare.com/cdn-cgi/trace"):
    """Distinguish 'IPv6 simply isn't routed through the tunnel' (harmless /
    expected) from 'IPv6 IS routed but the tunnel is broken' (a real error).

    The helper only installs the Wintun IPv6 route when its `::/0` add
    succeeds; otherwise it prints '[!] IPv6 default route failed; IPv4 remains
    active.' and IPv6 is never tunneled. In that state a failed `curl -6` is
    expected and must NOT be reported as a tunnel fault. Only when a Wintun
    IPv6 route exists AND `curl -6` still fails do we flag a genuine IPv6
    tunnel failure.

    Uses an explicit stdout marker (not `_ps`'s `ok`, which can be polluted by
    stderr noise) so the verdict can never disagree with the 'Default IPv6
    route' check."""
    ok, out = _ps(
        "$r = Get-NetRoute -AddressFamily IPv6 -ErrorAction SilentlyContinue | "
        "Where-Object {$_.InterfaceAlias -eq 'wintun' -and "
        "$_.DestinationPrefix -in '::/0','::/1','8000::/1'} | Select-Object -First 1; "
        "if ($r) { Write-Output 'WINTUN_IPV6_PRESENT' } else { Write-Output 'NO_WINTUN_IPV6' }")
    routed = 'WINTUN_IPV6_PRESENT' in out
    if not routed:
        return True, ("IPv6 not routed through Wintun (no ::/0 or ::/1 route) - "
                      "expected if the helper skipped/failed the IPv6 route install; "
                      "IPv4 tunnel is unaffected")
    ok2, code = _https(False, True, port, url)
    if ok2:
        return True, f"IPv6 via Wintun OK (HTTP {code})"
    return False, (f"IPv6 IS routed through Wintun but request failed "
                   f"(curl -6 -> {code}); IPv6 tunnel is broken")


def _teardown_wintun():
    """Best-effort teardown of stale tunnel state: removes routes from BOTH
    tunnel adapters ('wintun' + optional 'wintun2' second pipe) and kills
    orphaned tun2socks processes. Mirrors tuntop.network.routing's version."""
    try:
        for _adapter in ("wintun", "wintun2"):
            _ps(f"Get-NetRoute -InterfaceAlias '{_adapter}' -ErrorAction SilentlyContinue | "
                "Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue")
        _ps("Get-Process -ErrorAction SilentlyContinue | Where-Object {$_.ProcessName -like 'tun2socks*'} | "
            "ForEach-Object { Stop-Process -Force -Id $_.Id -ErrorAction SilentlyContinue }")
    except Exception:
        pass


# ─── Live route helpers (for in-dashboard bypass-IP editing) ─────────────────
# Re-implemented locally rather than imported from tuntop/helper.py, same
# as everything else in this file - these mirror get_ipv4_default() and
# get_vpn_ipv4_default() there closely enough to pick the same interface.

def _get_ipv4_default():
    """IPv4 default route used to reach the Internet (interface + gateway).

    Mirrors tuntop.helper get_ipv4_default(): never returns a connected
    Windows VPN as the "physical" gateway (so geo/bypass traffic is not routed
    into the VPN), and recovers the physical NIC's configured gateway via CIM
    when a full-tunnel VPN has deleted the Wi-Fi default route.  The VPN
    gateway is only used as an absolute last resort."""
    ps = r"""
$vpnAliases = @(
    @(Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue) +
    @(Get-VpnConnection -ErrorAction SilentlyContinue) |
    Where-Object { $_.ConnectionStatus -eq 'Connected' } |
    Select-Object -ExpandProperty Name -Unique |
    ForEach-Object {
        $n = $_
        $_
        Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -InterfaceAlias $n -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty InterfaceAlias -Unique
        Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -InterfaceAlias $n -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty InterfaceAlias -Unique
    }
)
Get-NetRoute -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceAlias -match '(?i)(pptp|l2tp|sstp|ikev2|vpn|wan miniport)' } |
    Select-Object -ExpandProperty InterfaceAlias -Unique | ForEach-Object { $vpnAliases += $_ }
$vpnAliases = @($vpnAliases | Where-Object { $_ } | Select-Object -Unique)
$r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Where-Object {
        $_.NextHop -ne '0.0.0.0' -and $_.State -eq 'Alive' -and
        $_.InterfaceAlias -ne 'wintun' -and
        ($vpnAliases.Count -eq 0 -or -not ($vpnAliases -contains $_.InterfaceAlias))
    } |
    Sort-Object RouteMetric, InterfaceMetric |
    Select-Object -First 1 NextHop, InterfaceAlias
if ($null -eq $r) {
    $r = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction SilentlyContinue |
        Where-Object { $_.DefaultIPGateway } |
        ForEach-Object {
            $gw = @($_.DefaultIPGateway) | Where-Object { $_ -and $_ -ne '0.0.0.0' -and $_ -ne '::' } | Select-Object -First 1
            if ($gw) {
                $na = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue
                [PSCustomObject]@{
                    NextHop = $gw
                    InterfaceAlias = if ($na) { $na.InterfaceAlias } else { $_.Description }
                }
            }
        } |
        Where-Object { $_.InterfaceAlias -ne 'wintun' -and ($vpnAliases.Count -eq 0 -or -not ($vpnAliases -contains $_.InterfaceAlias)) } |
        Select-Object -First 1
}
if ($null -eq $r) {
    $r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Where-Object {$_.NextHop -ne '0.0.0.0' -and $_.State -eq 'Alive' -and $_.InterfaceAlias -ne 'wintun'} |
        Sort-Object RouteMetric, InterfaceMetric |
        Select-Object -First 1 NextHop, InterfaceAlias
}
if ($null -eq $r) { exit 1 }
$r | ConvertTo-Json -Compress
"""
    ok, out = _ps(ps)
    if not ok:
        return None
    try:
        d = json.loads(out)
        return d["InterfaceAlias"], d["NextHop"]
    except Exception:
        return None


def _get_egress_for(ip):
    """Return (interface, gateway) Windows would actually use to reach `ip`
    over its real (non-wintun) path. Respects split-tunnel VPNs (a destination
    reachable only via the VPN gets that gateway), unlike _get_ipv4_default()
    which only knows the system default route. Prefers the most-specific
    non-wintun route, then falls back to the real default route."""
    ps = rf"""
$r = Find-NetRoute -RemoteIPAddress '{ip}' -ErrorAction SilentlyContinue
if ($r) {{
    $r = @($r) | Where-Object {{ $_.InterfaceAlias -ne 'wintun' }} |
        Sort-Object {{ ($_.DestinationPrefix -split '/')[1] -as [int] }} -Descending, RouteMetric, InterfaceMetric |
        Select-Object -First 1
}}
if (-not $r) {{
    $r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Where-Object {{ $_.InterfaceAlias -ne 'wintun' -and $_.NextHop -ne '0.0.0.0' }} |
        Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
}}
if ($null -eq $r) {{ exit 1 }}
$r | Select-Object InterfaceAlias, NextHop | ConvertTo-Json -Compress
"""
    ok, out = _ps(ps)
    if not ok:
        return None
    try:
        d = json.loads(out)
    except Exception:
        return None
    iface = str(d.get("InterfaceAlias", ""))
    gw = str(d.get("NextHop", "") or "")
    if not iface:
        return None
    return iface, (gw or "0.0.0.0")


def _get_vpn_ipv4_default(vpn_interface=None):
    """Connected Windows VPN's IPv4 default route (for --vless-over-vpn)."""
    if vpn_interface:
        ps = rf"""
$r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -InterfaceAlias '{vpn_interface}' -ErrorAction SilentlyContinue |
    Sort-Object RouteMetric, InterfaceMetric |
    Select-Object -First 1 NextHop, InterfaceAlias
if ($null -eq $r) {{ exit 1 }}
$r | ConvertTo-Json -Compress
"""
    else:
        ps = r"""
$names = @(
    @(Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue) +
    @(Get-VpnConnection -ErrorAction SilentlyContinue) |
    Where-Object {$_.ConnectionStatus -eq 'Connected'} |
    Select-Object -ExpandProperty Name -Unique
)
$best = $null
foreach ($n in $names) {
    $r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -InterfaceAlias $n -ErrorAction SilentlyContinue |
        Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
    if ($r) { $best = $r; break }
}
if ($null -eq $best) { exit 1 }
$best | Select-Object NextHop, InterfaceAlias | ConvertTo-Json -Compress
"""
    ok, out = _ps(ps)
    if not ok:
        return None
    try:
        d = json.loads(out)
        return d["InterfaceAlias"], d["NextHop"]
    except Exception:
        return None


def _get_vpn_ipv6_default(vpn_interface=None):
    """IPv6 counterpart of _get_vpn_ipv4_default for --vless-over-vpn."""
    if vpn_interface:
        ps = rf"""
$r = Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -InterfaceAlias '{vpn_interface}' -ErrorAction SilentlyContinue |
    Where-Object {{$_.NextHop -ne '::'}} |
    Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1 NextHop, InterfaceAlias
if ($null -eq $r) {{ exit 1 }}
$r | ConvertTo-Json -Compress
"""
    else:
        ps = r"""
$names = @(
    @(Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue) +
    @(Get-VpnConnection -ErrorAction SilentlyContinue) |
    Where-Object {$_.ConnectionStatus -eq 'Connected'} |
    Select-Object -ExpandProperty Name -Unique
)
$best = $null
foreach ($n in $names) {
    $r = Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -InterfaceAlias $n -ErrorAction SilentlyContinue |
        Where-Object {$_.NextHop -ne '::'} |
        Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
    if ($r) { $best = $r; break }
}
if ($null -eq $best) { exit 1 }
$best | Select-Object NextHop, InterfaceAlias | ConvertTo-Json -Compress
"""
    ok, out = _ps(ps)
    if not ok:
        return None
    try:
        d = json.loads(out)
        return d["InterfaceAlias"], d["NextHop"]
    except Exception:
        return None


def _netsh(args_list, timeout=10):
    try:
        p = subprocess.run(["netsh"] + args_list, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=timeout)
        return p.returncode == 0, (p.stdout or p.stderr or "").strip()
    except Exception as e:
        return False, str(e)


def _add_route_v4(dest, iface, gateway, metric=1):
    ok, msg = _netsh(["interface", "ipv4", "add", "route", dest, iface, gateway, f"metric={metric}", "store=active"])
    # "The object already exists" just means the bypass route is already
    # installed (e.g. by the helper at startup, or a previous live add) - that
    # is a successful bypass, not a failure. Treating it as success is what
    # lets a live [A] add report correctly without needing a tunnel restart.
    if ok:
        return True
    if "already exists" in msg.lower():
        # Persistent leftover from an older build (registry) - convert to
        # active-store-only so it does not survive the next reboot.
        _netsh(["interface", "ipv4", "delete", "route", dest, iface, gateway])
        ok2, msg2 = _netsh(["interface", "ipv4", "add", "route", dest, iface, gateway, f"metric={metric}", "store=active"])
        return ok2 or "already exists" in msg2.lower()
    return False


def _route_exists_v4(dest):
    """True if any IPv4 route with exactly this prefix is in the live table."""
    ok, out = _ps(
        f"if (Get-NetRoute -DestinationPrefix '{dest}' -AddressFamily IPv4 "
        f"-ErrorAction SilentlyContinue) {{ 'yes' }}")
    return ok and "yes" in out


def _route_exists_v6(dest):
    ok, out = _ps(
        f"if (Get-NetRoute -DestinationPrefix '{dest}' -AddressFamily IPv6 "
        f"-ErrorAction SilentlyContinue) {{ 'yes' }}")
    return ok and "yes" in out


def _del_route_v4(dest, iface, gateway):
    """Delete an IPv4 route. Robust against parameter drift: netsh only
    removes the route when iface AND next-hop BOTH match what was recorded at
    install time. If the egress changed since then (Wi-Fi switch, DHCP renew,
    on-link <-> gateway form), netsh answers 'element not found' - which looks
    identical to 'route was never there'. Left alone, that silently KEEPS the
    /32 route alive and traffic keeps flowing DIRECT after [X] remove."""
    ok, msg = _netsh(["interface", "ipv4", "delete", "route", dest, iface, gateway])
    low = msg.lower()
    if ok:
        return True
    claims_gone = "not found" in low or "element" in low
    # Ambiguous failure: either genuinely absent, or our parameters don't
    # match the installed route. Check the live table before believing it...
    if claims_gone and not _route_exists_v4(dest):
        return True
    # ...and fall back to a prefix-wide delete that ignores iface/nexthop.
    _ps(f"Remove-NetRoute -DestinationPrefix '{dest}' -AddressFamily IPv4 "
        f"-Confirm:$false -ErrorAction SilentlyContinue | Out-Null")
    return not _route_exists_v4(dest)


def _del_route_v6(dest, iface, gateway):
    cmd = ["interface", "ipv6", "delete", "route", dest, iface]
    if gateway:
        cmd.append(gateway)
    ok, msg = _netsh(cmd)
    low = msg.lower()
    if ok:
        return True
    claims_gone = "not found" in low or "element" in low
    if claims_gone and not _route_exists_v6(dest):
        return True
    _ps(f"Remove-NetRoute -DestinationPrefix '{dest}' -AddressFamily IPv6 "
        f"-Confirm:$false -ErrorAction SilentlyContinue | Out-Null")
    return not _route_exists_v6(dest)


def _add_route_v6(dest, iface, gateway, metric=1):
    cmd = ["interface", "ipv6", "add", "route", dest, iface]
    if gateway:
        cmd.append(gateway)
    cmd.append(f"metric={metric}")
    cmd.append("store=active")
    ok, msg = _netsh(cmd)
    if ok:
        return True
    if "already exists" in msg.lower():
        # Persistent leftover from an older build (registry) - convert to
        # active-store-only so it does not survive the next reboot.
        del_cmd = ["interface", "ipv6", "delete", "route", dest, iface]
        if gateway:
            del_cmd.append(gateway)
        _netsh(del_cmd)
        ok2, msg2 = _netsh(cmd)
        return ok2 or "already exists" in msg2.lower()
    return False


def _get_ipv6_default(vpn_interface=None):
    """IPv6 default route (next hop) used to send a bypass entry's IPv6
    address directly. Mirrors the VPN-exclusion fix in
    tuntop.helper get_ipv6_default() so a connected Windows VPN is never
    picked as the "safe" native gateway."""
    if vpn_interface:
        ps = rf"""
$r = Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -InterfaceAlias '{vpn_interface}' -ErrorAction SilentlyContinue |
    Where-Object {{$_.NextHop -ne '::'}} |
    Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1 NextHop, InterfaceAlias
if ($null -eq $r) {{ exit 1 }}
$r | ConvertTo-Json -Compress
"""
    else:
        ps = r"""
$vpnAliases = @(
    @(Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue) +
    @(Get-VpnConnection -ErrorAction SilentlyContinue) |
    Where-Object { $_.ConnectionStatus -eq 'Connected' } |
    Select-Object -ExpandProperty Name -Unique |
    ForEach-Object {
        $n = $_
        $_
        Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -InterfaceAlias $n -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty InterfaceAlias -Unique
    }
)
Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceAlias -match '(?i)(pptp|l2tp|sstp|ikev2|vpn|wan miniport)' } |
    Select-Object -ExpandProperty InterfaceAlias -Unique | ForEach-Object { $vpnAliases += $_ }
$vpnAliases = @($vpnAliases | Where-Object { $_ } | Select-Object -Unique)
$r = Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue |
    Where-Object {
        $_.NextHop -ne '::' -and $_.State -eq 'Alive' -and
        $_.InterfaceAlias -ne 'wintun' -and
        ($vpnAliases.Count -eq 0 -or -not ($vpnAliases -contains $_.InterfaceAlias))
    } |
    Sort-Object RouteMetric, InterfaceMetric |
    Select-Object -First 1 NextHop, InterfaceAlias
if ($null -eq $r) {
    $r = Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -ne '::' -and $_.State -eq 'Alive' -and $_.InterfaceAlias -ne 'wintun' } |
        Sort-Object RouteMetric, InterfaceMetric |
        Select-Object -First 1 NextHop, InterfaceAlias
}
if ($null -eq $r) { exit 1 }
$r | ConvertTo-Json -Compress
"""
    ok, out = _ps(ps)
    if not ok:
        return None
    try:
        d = json.loads(out)
        return d["InterfaceAlias"], d["NextHop"]
    except Exception:
        return None


def _get_active_connections(limit=15):
    """Established TCP connections (excluding loopback) joined with owning
    process name, for the event log's [net] entries. Best-effort: returns []
    on any failure rather than raising.

    The -First cap was removed on purpose: on any machine with more than a
    handful of concurrent established connections (a browser plus this very
    proxy), Get-NetTCPConnection's enumeration order is not stable/sorted by
    recency, so a connection that fell out of a -First 15 window one poll and
    reappeared the next was logged again as "new", defeating the dedup set.
    We now return every established connection and let _poll_connections()'
    order-preserving dedup map absorb the churn instead of sampling by an
    unstable -First cutoff."""
    ps = rf"""
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
  Where-Object {{ $_.RemoteAddress -notlike '127.*' -and $_.RemoteAddress -ne '::1' -and $_.RemoteAddress -ne '0.0.0.0' }} |
  Select-Object OwningProcess, RemoteAddress, RemotePort -Unique |
  ForEach-Object {{
    $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{{ Proc = if ($p) {{ $p.ProcessName }} else {{ 'pid-' + $_.OwningProcess }}; Pid = $_.OwningProcess; Remote = $_.RemoteAddress; Port = $_.RemotePort }}
  }} | ConvertTo-Json -Compress
 """
    ok, out = _ps(ps, timeout=6)
    if not ok:
        return []
    try:
        data = json.loads(out)
    except Exception:
        return []
    return data if isinstance(data, list) else [data]


# ─── Health checks ──────────────────────────────────────────────────────────

def build_checks(ns):
    """Return list of (label, check_fn) - health-check suite."""
    p = ns.port
    servers = ns.server
    dns = ns.dns4
    ep = getattr(ns, "endpoint_port", 443)

    def q(label, code):
        return (label, lambda: _ps(code))

    checks = [
        # Routing REQUIRES elevation - a "Not Administrator" pass here is
        # misleading; the user would read green while every route add fails.
        q("Windows administrator status",
          "if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {'Administrator'} else {Write-Output 'Not Administrator - route changes will fail'; exit 1}"),
        q("Windows version",
          "(Get-CimInstance Win32_OperatingSystem).Caption + ' ' + (Get-CimInstance Win32_OperatingSystem).Version"),
        q("Network adapters",
          "@(Get-NetAdapter | ? Status -eq 'Up').Count | % { if ($_ -gt 0) {'Active adapters: ' + $_} else {throw 'No active adapters'} }"),
        q("IPv4 addresses",
          "@(Get-NetIPAddress -AddressFamily IPv4 | ? IPAddress -notlike '127.*').Count | % {if ($_ -gt 0) {'IPv4 addresses: ' + $_} else {throw 'None'}}"),
        q("IPv6 addresses",
          "@(Get-NetIPAddress -AddressFamily IPv6 | ? IPAddress -notlike '::1').Count | % {if ($_ -gt 0) {'IPv6 addresses: ' + $_} else {throw 'None'}}"),
        q("Default IPv4 route",
          "$r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1; "
          "if ($r) { 'via ' + $r.InterfaceAlias + ' metric ' + $r.RouteMetric } else { Write-Output 'no IPv4 default route'; exit 1 }"),
        # Require the Wintun IPv6 routes the helper installs (::/0 on wintun,
        # or the more reliable ::/1 + 8000::/1 split-default). Do NOT pass just
        # because some other adapter happens to own ::/0 - that proves nothing
        # about IPv6 being tunneled. Use -ErrorAction SilentlyContinue and never
        # `throw` so a missing entry does not emit CLIXML error text.
        q("Default IPv6 route",
          "$s = @(Get-NetRoute -AddressFamily IPv6 -ErrorAction SilentlyContinue | Where-Object {$_.InterfaceAlias -eq 'wintun' -and $_.DestinationPrefix -in '::/0','::/1','8000::/1'}); "
          "if ($s.Count -ge 1) { 'IPv6 via wintun (' + $s.Count + ' route(s): ' + ($s.DestinationPrefix -join ', ') + ')'; exit 0 }; "
          "Write-Output 'no IPv6 default or wintun split route'; exit 1"),
        q("DNS configuration",
          "@(Get-DnsClientServerAddress | ? {$_.ServerAddresses}).Count | % {if ($_ -gt 0) {'DNS configured'} else {throw 'No DNS servers'}}"),
        q("MTU",
          "Get-NetIPInterface -AddressFamily IPv4 | ? {$_.NlMtu -ge 1280} | select -First 1 | % {'MTU ' + $_.NlMtu}"),
        # wintun may be absent (tunnel not yet up); never use -ErrorAction
        # Stop here or the check dumps raw CLIXML into the dashboard.
        q("Wintun adapter",
          "$a = Get-NetAdapter -Name wintun -ErrorAction SilentlyContinue; if ($a -and $a.Status -eq 'Up') {'Up, ifIndex ' + $a.ifIndex} else {Write-Output 'wintun not present / not Up'; exit 1}"),
        q("Wintun IPv4",
          "$x = Get-NetIPAddress -InterfaceAlias wintun -AddressFamily IPv4 -ErrorAction SilentlyContinue | ? {$_.IPAddress -eq '192.168.123.1'}; if ($x) {$x.IPAddress} else {Write-Output '192.168.123.1 not on wintun'; exit 1}"),
        q("Wintun IPv6",
          "$x = Get-NetIPAddress -InterfaceAlias wintun -AddressFamily IPv6 -ErrorAction SilentlyContinue | ? {$_.IPAddress -like 'fd00:dead:beef*'}; if ($x) {$x.IPAddress} else {Write-Output 'no fd00:dead:beef::/64 on wintun'; exit 1}"),
        ("v2rayN SOCKS TCP", lambda: _tcp("127.0.0.1", p)),
        ("SOCKS5 authentication", lambda: _socks_greeting(p)),
        ("SOCKS5 CONNECT by hostname (proxy relay)", lambda: _socks_connect_domain(p)),
        ("SOCKS5 TCP CONNECT to DNS IP", lambda: _socks_request(p, 1, dns)),
        # Directly tests whether the VLESS SERVER provides IPv6 egress. This
        # isolates the IPv6 tunnel failure: if this fails, the server has no
        # IPv6 (client routing can't fix it); if it passes while curl -6 via
        # Wintun fails, the problem is tun2socks IPv6 forwarding.
        ("IPv6 egress via SOCKS5 (server IPv6 support)", lambda: _socks_request_v6(p)),
        ("SOCKS5 UDP ASSOCIATE", lambda: _check_udp_assoc(p)),
        ("Direct TCP test", lambda: _tcp(dns, 443)),
        # VALIDITY NOTE: UDP is connectionless - this can only prove the LOCAL
        # socket stack queues packets. It is deliberately labelled as such;
        # the REAL UDP-relay test is "SOCKS5 UDP ASSOCIATE" above.
        ("Local UDP send (stack sanity)",
         lambda: _ps(f"$u=New-Object Net.Sockets.UdpClient; $u.Connect('{dns}',53); "
                     f"[void]$u.Send([byte[]](0),1); $u.Close(); "
                     f"'UDP packet queued locally to {dns}:53 (no ack possible)'")),
        ("DNS (via SOCKS tunnel)", lambda: _dns_tunnel_verdict(dns, p)),
        ("IPv4 HTTPS end-to-end (via Wintun)", lambda: _https(False, False, p)),
        # IPv6 rows use _ipv6_tun_verdict so a missing Wintun IPv6 route
        # (expected when the helper's ::/0 install is skipped/failed) is
        # reported as informational, not as a tunnel fault.
        ("IPv6 HTTPS (via Wintun)", lambda: _ipv6_tun_verdict(p)),
        ("Google IPv4 (via Wintun)", lambda: _https(False, False, p, "https://www.google.com")),
        ("Google IPv6 (via Wintun)", lambda: _ipv6_tun_verdict(p, "https://www.google.com")),
        q("HTTP/3 / QUIC",
          "$v = @(curl.exe -V 2>$null); if ($v.Count -eq 0) {throw 'curl.exe not available'}; "
          "$feats = ''; foreach ($l in $v) { if ($l -match '^Features:') {$feats = $l} }; "
          "if ($feats -match 'HTTP3') {'local curl HAS HTTP/3 (' + $feats.Trim() + ')'} "
          "else {'Local curl has NO HTTP/3 support (' + $v[0] + ') - QUIC is NOT testable with it. A checker using --http3-only will falsely report Blocked (it fails at argument parsing, before any packet). Real QUIC needs UDP relay through the core (see SOCKS5 UDP ASSOCIATE).'}"),
        # Per-server endpoint checks are appended below (after the static list).
        q("Route-table conflicts",
          "@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0').Count | % {if ($_ -le 5) {'Default routes: ' + $_} else {throw 'Too many IPv4 default routes: ' + $_}}"),
        q("Duplicate routes",
          "@(Get-NetRoute -AddressFamily IPv4 | Group DestinationPrefix,InterfaceIndex,NextHop | ? Count -gt 1).Count | % {if ($_ -eq 0) {'No duplicate IPv4 routes'} else {throw ('Duplicate groups: ' + $_)}}"),
        q("TUN default route",
          "$r = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | ? {$_.InterfaceAlias -eq 'wintun' -and $_.DestinationPrefix -in '0.0.0.0/0','0.0.0.0/1','128.0.0.0/1'}); if ($r.Count -ge 2) {'Wintun routes: ' + $r.Count} else {Write-Output 'Wintun split-default routes missing'; exit 1}"),
        # (Proxy loop detection per server is appended below.)
        # VALIDITY NOTE: firewall state is a policy choice and says nothing
        # about tunnel health - report it, never fail on it.
        q("Firewall profiles (info)",
          "'Profiles enabled: ' + @(Get-NetFirewallProfile | ? Enabled -eq 'True').Count + ' of 3'"),
        q("Wintun packet activity",
          "$s = Get-NetAdapterStatistics -Name wintun -ErrorAction SilentlyContinue; if ($s) {$n=$s.ReceivedBytes + $s.SentBytes; if ($n -gt 0) {'Wintun bytes observed: ' + $n} else {Write-Output 'No Wintun bytes yet'; exit 1}} else {Write-Output 'wintun statistics unavailable'; exit 1}"),
        # VALIDITY NOTE: ICMP echo is blocked on many networks/cores, so BOTH
        # probes below are tolerance-aware: a filtered reply is reported as
        # INCONCLUSIVE (pass-with-info), not a red cross. Tunnel health is
        # proven by the HTTPS-over-wintun rows above, not by ping.
        q("MTU / fragmentation probe",
          f"$l = ping.exe -n 1 -f -l 1200 {dns} 2>$null | Select-String 'Reply from'; "
          f"if ($l) {{$l.Line}} else {{'No ICMP reply (filtered?) - inconclusive'}}; exit 0"),
        q("ICMP loss to resolver (info)",
          f"$p = ping.exe -n 4 {dns} 2>$null; $t = $p -join ' '; "
          f"if ($t -match 'Lost = (\\d+)') {{'ICMP loss ' + $Matches[1] + ' of 4'}} "
          f"else {{'No ICMP replies (filtered?) - inconclusive'}}; exit 0"),
        # VALIDITY NOTE: retransmit RATE alone can't pass/fail (it depends on
        # load); report the real number as info instead of a content-free PASS.
        q("TCP retransmissions (info)",
          "$c = Get-Counter '\\TCPv4\\Segments Retransmitted/sec' -ErrorAction SilentlyContinue; "
          "if ($c) {'Retransmitted: {0:N2}/s' -f $c.CounterSamples[0].CookedValue} "
          "else {'Counter unavailable'}; exit 0"),
        q("tun2socks process",
          "$p = Get-Process -ErrorAction SilentlyContinue | ? ProcessName -like 'tun2socks*' | select -First 1; if ($p) {'PID ' + $p.Id} else {Write-Output 'tun2socks not running'; exit 1}"),
        q("Wintun traffic counters",
          "$s = Get-NetAdapterStatistics -Name wintun -ErrorAction SilentlyContinue; if ($s) {'RX ' + $s.ReceivedBytes + ', TX ' + $s.SentBytes} else {Write-Output 'wintun statistics unavailable'; exit 1}"),
        ("IPv4 HTTPS through SOCKS5", lambda: _https(True, False, p)),
        q("v2rayN core process",
          "Get-Process -ErrorAction SilentlyContinue | ? {$_.ProcessName -match '^(xray|v2ray|sing-box|mihomo|clash)'} | select -First 1 | % {$_.ProcessName + ' PID ' + $_.Id}"),
    ]

    # Geoip database presence - Python-side closure (clean path quoting) rather
    # than PowerShell Test-Path. A configured-but-missing file is a real,
    # actionable failure now that [W] can download it.
    _geo = getattr(ns, "geoip", None)
    if _geo:
        _geo_code = getattr(ns, "geoip_code", "cn")
        def _geo_check(g=_geo, c=_geo_code):
            if os.path.isfile(g):
                try:
                    sz = os.path.getsize(g) / 1048576
                    return True, f"geoip:{c} file ready ({sz:.1f} MiB)"
                except OSError as e:
                    return False, f"unreadable: {e}"
            return False, f"{g} missing - press [W] to download it"
        checks.append((f"Geoip database ({_geo_code})", _geo_check))

    if getattr(ns, "vless_over_vpn", False):
        checks.append(q("Windows VPN (vless-over-vpn)",
            "$c = @(@(Get-VpnConnection -AllUserConnection -EA SilentlyContinue) + @(Get-VpnConnection -EA SilentlyContinue)) | "
            "? ConnectionStatus -eq 'Connected' | select -First 1; "
            "if ($c) {$c.Name + ': Connected'} else {throw 'No connected Windows VPN found'}"))

    if getattr(ns, "bypass_ip", None):
        for entry in ns.bypass_ip:
            # Domains are resolved to their current IPs so the health check
            # tests the actual route(s) that were installed (not the raw
            # domain string, which Get-NetRoute cannot parse). Cache-ONLY: this
            # runs on the UI thread (every checks rebuild), so it must never do
            # a lookup. The background bypass resolver fills the cache and
            # rebuilds the checks once an entry resolves.
            host = _host_from_url(entry) or entry
            ep4, ep6 = _resolve_cached(host)
            if not ep4 and not ep6:
                checks.append(q(f"Bypass {host}",
                    f"throw 'not resolved yet: {host} (the resolver keeps retrying)'"))
                continue
            for ip in ep4 + ep6:
                prefix = f"{ip}/32" if ":" not in ip else f"{ip}/128"
                label = host if host == ip else f"{host} ({ip})"
                checks.append(q(f"Bypass {label}",
                    f"Get-NetRoute -DestinationPrefix '{prefix}' -ErrorAction SilentlyContinue | % {{'routed'}}"))

    # Per-server endpoint checks: one set of TCP / route / proxy-loop checks
    # for every configured --server value.
    for _s in (servers or []):
        checks.append((f"Configured endpoint TCP/{ep} ({_s})",
                       lambda _s=_s, ep=ep: _tcp(_s, ep, 8)))
        checks.append(q(f"VLESS server route ({_s})",
                        f"$r = Find-NetRoute -RemoteIPAddress '{_s}' -ErrorAction SilentlyContinue | select -First 1; if ($r) {{'via ' + $r.InterfaceAlias}} else {{Write-Output 'no route found'; exit 1}}"))
        checks.append(q(f"Proxy loop detection ({_s})",
                        f"$r = Find-NetRoute -RemoteIPAddress '{_s}' -ErrorAction SilentlyContinue | select -First 1; if ($r -and $r.InterfaceAlias -ne 'wintun') {{'VLESS endpoint bypassed through ' + $r.InterfaceAlias}} else {{Write-Output 'VLESS endpoint NOT bypassed (loops into tunnel!)'; exit 1}}"))

    return checks


# ─── Telemetry helpers ──────────────────────────────────────────────────────

def get_wintun_speed(state_ref):
    """Sample Wintun RX/TX byte counters and return each in KiB/s.

    state_ref is a one-element list holding (rx_total, tx_total, ts) from the
    previous sample, or None on the first call. Returns
    (rx_kib, tx_kib, rx_total, tx_total). On failure returns
    (0.0, 0.0, None, None) so callers can tell success from failure."""
    ok, out = _ps(
        "Get-NetAdapterStatistics -Name wintun -ErrorAction SilentlyContinue | "
        "Select ReceivedBytes,SentBytes | ConvertTo-Json -Compress")
    if not ok:
        return 0.0, 0.0, None, None
    try:
        d = json.loads(out)
        rx = int(d["ReceivedBytes"])
        tx = int(d["SentBytes"])
        now = time.time()
        if state_ref[0] is None:
            state_ref[0] = (rx, tx, now)
            return 0.0, 0.0, rx, tx
        dt = now - state_ref[0][2]
        rx_speed = max(0, (rx - state_ref[0][0])) / max(dt, 0.1) / 1024.0
        tx_speed = max(0, (tx - state_ref[0][1])) / max(dt, 0.1) / 1024.0
        state_ref[0] = (rx, tx, now)
        return round(rx_speed, 3), round(tx_speed, 3), rx, tx
    except Exception:
        return 0.0, 0.0, None, None


def get_ping(port, dns):
    """Rolling-average TCP latency via SOCKS5."""
    ms = None
    txid = os.urandom(2)
    question = b"".join(bytes((len(x),)) + x.encode("ascii") for x in "cloudflare.com".split(".")) + b"\0\0\1\0\1"
    packet = txid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question
    t0 = time.time()
    try:
        with socket.create_connection(("127.0.0.1", port), 4) as s:
            s.settimeout(5)
            s.sendall(b"\x05\x01\x00")
            if s.recv(2) != b"\x05\x00":
                return None
            addr = b"\x01" + socket.inet_aton(dns) + (53).to_bytes(2, "big")
            s.sendall(b"\x05\x01\x00" + addr)
            rep = _recv_socks5_reply(s)
            if len(rep) < 7 or rep[1] != 0:
                return None
            s.sendall(len(packet).to_bytes(2, "big") + packet)
            n = int.from_bytes(s.recv(2), "big")
            s.recv(n)
        dt = (time.time() - t0) * 1000.0
        ms = dt if dt > 0 else None
    except OSError:
        pass
    return ms


def get_vpn_status():
    ok, out = _ps(
        "@(@(Get-VpnConnection -AllUserConnection -EA SilentlyContinue) + "
        "@(Get-VpnConnection -EA SilentlyContinue)) | "
        "? ConnectionStatus -eq 'Connected' | Select-Object -First 1 | % {$_.Name}")
    return out.strip() if ok else None


# ─── Drawing primitives ─────────────────────────────────────────────────────

def _console_safe(text):
    """Keep child-process messages printable (see ui_text.console_safe)."""
    return ui_text.console_safe(text, USE_UNICODE)


def _pad(text, width):
    """Right-pad to visible width (see ui_text.pad)."""
    return ui_text.pad(text, width)


def _hslice(text, start, width):
    """ANSI-aware horizontal window (see ui_text.hslice)."""
    return ui_text.hslice(text, start, width)


def _hpad(text, width, start=0):
    """ANSI-aware scroll + right-pad (see ui_text.hpad)."""
    return ui_text.hpad(text, width, start)


def _split_hostport(s):
    """Split 'host:port' / '[ipv6]:port' / 'host' into (host, port)."""
    return ui_text.split_hostport(s)


def _format_log_line(raw):
    """Render an event-log line. Plain tag lines ([*], [!], [+], [net], ...)
    pass through unchanged; JSON connection records (either with explicit
    proto/src/dst keys, or with the data inside a `msg` string such as
    "[TCP] 1.2.3.4:5 <-> 6.7.8.9:9") are reformatted into aligned proto /
    src / dst / port columns, coloured by protocol (TCP green, UDP cyan,
    ICMP purple, blocked/dropped red).

    Defensive: if the line isn't a recognised JSON connection record it is
    returned verbatim, so any other helper output is unaffected."""
    s = str(raw).strip()
    if not s:
        return raw
    tag = ""
    body = s
    m = re.match(r'^\[([^\]]+)\]\s*(.*)$', s)
    if m:
        tag = m.group(1)
        body = m.group(2).strip()

    proto = src = dst = sport = dport = ""
    blocked = False

    if body.startswith("{") and body.endswith("}"):
        try:
            d = json.loads(body)
        except Exception:
            d = None
        if isinstance(d, dict):
            # Explicit key form.
            proto = str(d.get("proto") or d.get("protocol")
                        or d.get("ip_proto") or "").upper()
            src = str(d.get("src") or d.get("source") or d.get("saddr")
                     or d.get("src_addr") or "")
            dst = str(d.get("dst") or d.get("dest") or d.get("daddr")
                     or d.get("dst_addr") or "")
            sport = str(d.get("sport") or d.get("src_port") or "")
            dport = str(d.get("dport") or d.get("dst_port") or "")
            action = str(d.get("action") or d.get("verdict") or "").upper()
            blocked = (action in ("BLOCK", "DROP", "REJECT", "DENY")
                       or str(d.get("blocked") or d.get("drop") or "").lower() == "true")
            # msg form, e.g. {"msg":"[TCP] 1.2.3.4:5 <-> 6.7.8.9:9"}
            msg = d.get("msg")
            if not (proto or (src and dst)) and isinstance(msg, str):
                mm = re.match(r'^\[\s*([A-Za-z0-9]+)\s*\]\s*(.*)$', msg.strip())
                if mm:
                    proto = mm.group(1).upper()
                    rest = mm.group(2)
                    if "<->" in rest:
                        lhs, rhs = rest.split("<->", 1)
                    elif "->" in rest:
                        lhs, rhs = rest.split("->", 1)
                    else:
                        lhs = rhs = rest
                    sh, sp = _split_hostport(lhs)
                    dh, dp = _split_hostport(rhs)
                    src, sport, dst, dport = sh, sp, dh, dp
                    if re.search(r"block|deny|drop|reject", rest, re.I):
                        blocked = True

    if proto or (src and dst):
        if proto == "TCP":
            col = GREEN
        elif proto == "UDP":
            col = CYAN
        elif proto in ("ICMP", "ICMPV6"):
            col = PURPLE
        else:
            col = DIM
        if blocked:
            col = RED
        proto_disp = f"{proto:<5}" if proto else "?????    "
        src_disp = f"{src}:{sport}" if sport else src
        dst_disp = f"{dst}:{dport}" if dport else dst
        parts = []
        if tag:
            parts.append(f"{DIM}[{tag}]{RESET} ")
        parts.append(f"{col}{proto_disp}{RESET}")
        parts.append(f" {DIM}{src_disp:>21}{RESET}")
        parts.append(f" {DIM}->{RESET} ")
        parts.append(f"{DIM}{dst_disp:>21}{RESET}")
        return "".join(parts)

    # Plain tagged helper lines ("[+] ...", "[!] ...", "[*] ...", "[MONITOR] ..",
    # "[dns] .."): colour the leading tag as a CHIP so the event log scans
    # visually - green = success, red = problem, cyan = action/info, purple =
    # monitor heartbeat. Untagged lines still fall through unchanged (the log
    # panel dims them).
    if tag:
        tcol = {"+": GREEN, "!": RED, "*": CYAN,
                "i": GRAY, "-": YELLOW}.get(tag[:1])
        if tcol is None:
            upper = tag.upper()
            if upper == "MONITOR":
                tcol = PURPLE
            elif upper in ("DNS", "NET"):
                tcol = CYAN
            elif upper.startswith("GEO"):
                tcol = YELLOW
        if tcol:
            if body:
                return f"{BRIGHT}{tcol}[{tag}]{RESET} {body}"
            return f"{BRIGHT}{tcol}[{tag}]{RESET}"
    return raw


# Green -> yellow -> red, the same ramp btop uses for its CPU/mem/net meters.
_GRAD_STOPS = ui_text.GRAD_STOPS


def _gradient_color(frac):
    """24-bit ANSI ramp colour (see ui_text.gradient_color)."""
    return ui_text.gradient_color(frac, _GRAD_STOPS)


def _rgb(r, g, b):
    """24-bit ANSI foreground escape (see ui_text.rgb)."""
    return ui_text.rgb(r, g, b)


def _bar_stops(frac, width, stops, full=None, empty=None):
    """Custom-ramp meter (see ui_text.bar_stops); glyphs resolved at call
    time so glyph-set changes are always reflected."""
    return ui_text.bar_stops(frac, width, stops,
                             full if full is not None else PROGRESS_FULL,
                             empty if empty is not None else PROGRESS_EMPTY,
                             P_INACT, RESET)


def _bar(frac, width, full=None, empty=None, gradient=True):
    """Render a horizontal meter (see ui_text.bar). Glyphs are read at
    call time (rather than as stale default-argument values captured once
    at import) so a later glyph-set change - e.g. --unicode/--ascii, or
    the real terminal probe in main() - is always reflected."""
    return ui_text.bar(frac, width,
                       full if full is not None else PROGRESS_FULL,
                       empty if empty is not None else PROGRESS_EMPTY,
                       P_INACT, RESET, gradient)


def _spark(values, width, mode=None):
    """Gradient sparkline (see ui_text.spark)."""
    return ui_text.spark(values, width, mode, USE_UNICODE)


def _panel(lines, title=None, width=60, active=True):
    """Render a panel with box borders."""
    border = P_ACTIVE if active else P_INACT
    pad_border = P_LIGHT if active else P_INACT
    L = []

    sep = BOX_BS * max(1, width - 2)
    hsep = BOX_MID * max(1, width - 2)

    # Top
    if title:
        centre = f" {title} "
        L.append(f"{pad_border}{BOX_LC}{centre.center(width - 2, BOX_MID)}{BOX_RC}{RESET}")
    else:
        L.append(f"{pad_border}{BOX_LC}{sep}{BOX_RC}{RESET}")

    # Body
    for row in lines:
        text = str(row).replace("\033[", "ESC[")  # protect embedded ANSI
        # Strip ANSI to get visible width
        visible = len(re.sub(r'\x1b\[[^m]*m', '', str(row)))
        L.append(f"{pad_border}{BOX_V} {_pad(text, width - 2)} {BOX_V}{RESET}")

    # Bottom
    L.append(f"{pad_border}{BOX_BL}{hsep}{BOX_BS}{BOX_BR}{RESET}")
    return "\n".join(L)


# ─── TUI class ──────────────────────────────────────────────────────────────

class _GeoLogSink:
    """A write-only stdout replacement that feeds each line the helper module
    prints during a live [R] geo re-apply to the dashboard's dispatcher, so the
    geo progress panel stays live (the same way the [S] subprocess reader feeds
    [GEO-LOAD]/[GEO-DONE] markers into the panel). Buffers partial writes until
    a newline arrives, then routes the complete line through the TUI callback."""

    def __init__(self, tui):
        self._tui = tui
        self._buf = ""

    def write(self, data):
        self._buf += (data or "")
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            self._tui._route_geo_helper_line(line)

    def flush(self):
        pass


class BTopTui:
    # Geo-leftover sweep tuning (exit cleanup): routes are removed in parallel
    # chunks so quitting after a geoip load takes seconds, not tens of seconds.
    _SWEEP_CHUNK = 250
    _SWEEP_WORKERS = 6

    def __init__(self, args):
        self.ns = args
        self.proc = None
        self.logs = queue.Queue()

        # Tunnel state machine (tuntop/state.py): the single source of
        # truth for what the tunnel is doing - far beyond the old
        # "helper process alive => RUNNING" boolean. Phases of the start
        # sequence, degradation, self-heal and teardown are all explicit
        # states now; every transition is mirrored into the event log (see
        # _on_tunnel_state_change) so a stuck or failing start is visible
        # in the UI instead of a dashboard that just keeps saying RUNNING.
        self.tunnel = TunnelStateMachine()
        self.tunnel.observe(self._on_tunnel_state_change)

        # Recovery engine (tuntop/recovery.py): bounded, backoff-based
        # repair policy on top of the state machine. A dead helper gets
        # auto-restarted (max 3 attempts, 1s/2s/4s backoff, crash-loop
        # protection); persistent DEGRADED escalates to a restart only
        # after the helper's own self-heal had 90s to work. Disabled with
        # --no-auto-recover (the engine then stays paused).
        self.recovery = RecoveryEngine(
            self.tunnel, log=lambda msg: self.logs.put(msg),
            max_attempts=3, give_up_after=3)
        self.recovery.register(FailureKind.PROCESS, [RecoveryAction(
            "restart the tunnel helper", repair=self._recover_restart_tunnel,
            verify=lambda: bool(self.proc and self.proc.poll() is None))])
        # DNS/proxy failures: the helper's own monitor/self-heal loop gets
        # 90s (its retries + self-heal) before the engine escalates to a
        # full restart - never fight the helper's own repair.
        self.recovery.register(FailureKind.DNS, [RecoveryAction(
            "restart the tunnel helper", repair=self._recover_restart_tunnel,
            verify=lambda: bool(self.proc and self.proc.poll() is None))],
            first_delay=90)
        self.recovery.register(FailureKind.PROXY, [RecoveryAction(
            "restart the tunnel helper", repair=self._recover_restart_tunnel,
            verify=lambda: bool(self.proc and self.proc.poll() is None))],
            first_delay=90)
        # Opt-out: --no-auto-recover keeps the engine paused forever (the
        # state machine still tracks phases; nothing is auto-repaired).
        if getattr(self.ns, "no_auto_recover", False):
            self.recovery.pause("disabled by --no-auto-recover")
        else:
            self.recovery.start()

        self.results = []
        self.checking = False
        self.running = True

        # Structured event log (tuntop/structured_log.py): every significant
        # event goes through here with timestamp, severity, component and
        # state — used by the event panel, diagnostics export, and
        # (eventually) JSON bug reports.
        self.event_log = LogRing(capacity=500)

        # [Q] shutdown-with-progress state. While `_shutting_down` is True the
        # dashboard runs a blocking, single-threaded route-clearing sequence and
        # draws a dedicated progress bar; it does NOT exit until every route is
        # gone. `_cleanup_done` gates stop()/atexit so the same cleanup is never
        # run twice (the [Q] path does the full job with progress reporting).
        self._shutting_down = False      # True while the progress-bar cleanup runs
        self._shutdown_stage = ""        # current cleanup step label
        self._shutdown_progress = 0.0    # 0.0..1.0 overall cleanup progress
        self._cleanup_done = False       # True once routes are fully cleared
        self.speed_hist = []           # combined (RX+TX) KiB/s, for the SPEED card
        self.rx_hist = []              # download KiB/s, for the graph
        self.tx_hist = []              # upload KiB/s, for the graph
        self.ping_samples = []
        self.page = 0
        self.last_checked = None
        self.baseline_bytes = [None]   # mutable ref for get_wintun_speed: (rx,tx,ts)
        self._last_raw_rx = None       # previous absolute Wintun RX byte total
        self._last_raw_tx = None       # previous absolute Wintun TX byte total
        self.total_traffic = 0

        # Render loop tuning - keep the frame cheap and flicker-free.
        self._last_frame = ""          # last rendered screen, to skip no-op redraws
        self._frame_interval = 0.04     # seconds between scheduled redraws (~25 fps)
        self._full_repaint = True       # force a full clear+repaint next frame
        self._prev_lines = []           # previous frame's line list (for diff paint)
        self._prev_w = 0                # previous frame width (resize detection)
        self._flash = None              # (row, x0, x1, expiry) of the last clicked region

        # Graph resolution mode. "auto" (default) picks braille on modern hosts
        # (Windows Terminal / mintty / VS Code - all render the U+2800 block
        # natively), half-block doubling on a plain Unicode conhost, and falls
        # back to the classic block fill when Unicode is off. The user can cycle
        # with [G]; non-Unicode hosts can only use "block".
        self.graph_mode = "auto"       # auto | block | half | braille

        # Telemetry cache (avoid redundant PS calls)
        self._speed_ts = 0
        self._ping_ts = 0
        self._vpn_cache_ts = 0
        self._vpn_status = None
        # Tunnel state watcher (loop()): None until the first check primes
        # it, then the machine's state string - it announces tunnel DOWN
        # (terminal state) transitions; every other transition is already
        # announced by _on_tunnel_state_change.
        self._last_seen_state = None
        self._mouse_retry_done = False

        # Background telemetry thread flag (started/stopped by loop()).
        self._telemetry_running = True
        # Guards the history lists, which the telemetry thread mutates and the
        # main (draw) thread reads concurrently. Also guards the geo-progress
        # dicts (geo_progress / geo_parse) which the helper-reader thread mutates
        # while draw() snapshots them on the main thread (see _update_geo_progress
        # and the geo panel in draw()).
        self._tel_lock = threading.Lock()
        self._geo_lock = threading.Lock()

        self.checks = build_checks(args)
        self.log_lines = []
        self._log_scroll = 0        # lines scrolled back from the newest log entry
        self._hscroll = 0           # horizontal scroll column for logs/health rows
        self._log_visible = 10      # how many log lines fit in the event-log panel
        self._show_help = True      # footer key/action guide; toggle with [H]
        self._hidden = set()         # section ids hidden via [1]-[5],[B]; [0] shows all
        self._bypass_res_cache = {}   # entry -> (v4_list, v6_list) last good result
        # Second-hop (proxy2) resolver state - a SEPARATE dict, not a field on
        # the direct one, so a target can never leak across (2.4 design rule).
        self._proxy2_res_cache = {}
        self._proxy2_res_state = {}
        # Third routing target: "vpn" (egress through a CONNECTED Windows VPN).
        # Separate store, same isolation rule as direct/proxy2.
        self._vpn_res_cache = {}
        self._vpn_res_state = {}
        # Per-entry resolution state for the extra bypass list. Owned by the
        # background resolver thread; read (under the lock) by the draw thread.
        #   status : pending | ok | fail
        #   ips    : last resolved IPs        err   : last failure reason
        #   tries  : consecutive failures     next  : earliest next attempt (ts)
        #   routed : a live bypass route is installed for these IPs
        self._bypass_res_state = {}
        self._bypass_res_lock = threading.Lock()
        self._bypass_res_thread = None
        self.page_size = 9
        # Resolve every configured server (repeatable --server) and combine
        # the resulting IPs for display and endpoint health checks.
        self.endpoint_v4, self.endpoint_v6 = [], []
        for _srv in (args.server or []):
            _v4, _v6 = _resolve(_srv)
            for ip in _v4:
                if ip not in self.endpoint_v4:
                    self.endpoint_v4.append(ip)
            for ip in _v6:
                if ip not in self.endpoint_v6:
                    self.endpoint_v6.append(ip)

        # Click-map / mouse support (populated each draw(), consumed by
        # _poll_input()). See _init_mouse() for the console-mode setup.
        self._click_map = []
        self._mouse_queue = []   # buffered actionable input events (keys/clicks)
        self._mouse_ok = False
        self._kbd_ok = True     # flips False if msvcrt polling proves unusable
        self._stdin_handle = None
        self._orig_console_mode = None
        self._dash_mode = None  # console mode the dashboard runs in (set in _init_mouse)
        self._live_geo_added = []  # geo routes this dashboard process installed live (for cleanup on stop)
        self._live_bypass_added = []  # live [A] bypass-IP routes (for cleanup on stop)
        self._geo_dl_active = False   # a background geoip download is running
        self._geo_applied_target = None  # egress target the live geo routes currently point at

        # Adaptive layout: the panels shrink FIRST, the help footer is removed
        # LAST (short windows / 16:9 screens). _fixed_rows is the previous
        # frame's height of everything above the event log; the shrink budget
        # for this frame is derived from it, so it converges one frame (~40 ms)
        # after a resize. All three are recomputed at the top of draw().
        self._fixed_rows = None
        self._checks_cap = None      # max health-check rows shown this frame
        self._graph_cap = None       # min graph rows per direction this frame
        self._help_rows = 4          # help footer rows this frame (4 / 2 / 0)
        self._shrink_size = None     # (h, w) the shrink budget was computed for

        # Bypass add mode. False (default) = INSTANT: [A]/[X] resolve and
        # install/remove the /32 - /128 routes live in a background thread, so
        # the tunnel keeps running and traffic never drops. True = [A] instead
        # fully STOPs and re-STARTs the tunnel so the helper re-applies the
        # whole --bypass-ip list cleanly at startup. _bypass_restart_active /
        # _restart_lock serialise overlapping restarts (a running restart already
        # reads the latest ns.bypass_ip, so a second one is skipped, not queued).
        self._bypass_restart_active = False
        self._restart_lock = threading.Lock()

        # Live-reconfiguration support
        self._iface_cache = None        # cached (interface, gateway) for live bypass-route adds
        # Dedup map for [net] connection log lines: key -> last-seen timestamp.
        # A plain set has no order, so its list()[-300:] eviction kept an
        # ARBITRARY subset and could drop a still-open, long-lived connection's
        # key, causing it to re-log as "new" forever. An ordered dict lets us
        # evict the genuinely-oldest entries (and re-seen connections are moved
        # to the end so they survive), so the dedup actually holds.
        self._seen_conns = {}
        self._conn_poll_ts = 0

        # Geo bypass load progress. Two phases feed it:
        #   * geo_parse  - the helper decoding the geoip file (fed by [GEO-PARSE]
        #                  markers while the file is being read), so the panel
        #                  shows the *file load* itself instead of sitting at 0%.
        #   * geo_progress - the helper installing the bypass routes (fed by
        #                  [GEO-LOAD] markers during the install).
        # (code, loaded, total); keyed by code so repeated runs don't clobber
        # each other. _geo_progress_done_ts marks when the last install finished
        # so the panel lingers briefly, then hides.
        self.geo_progress = {}
        self.geo_parse = {}
        self._geo_progress_done_ts = None
        # Generalized per-session deduplication for geoip diagnostics (the
        # "skipped N non-routable CIDR(s)" note, the "bypass skipped (no ...)"
        # notes, and the "batch had route failures" warning). Keyed stably so a
        # repeated *kind* of diagnostic from the helper collapses to one logged
        # line across [S]/[T]→[S] cycles AND [R] re-applies instead of spamming
        # the event log verbatim every time.
        self._seen_geo_diag = set()
        # Throttle the catch-all draw-error log so one failure can't append the
        # identical "[!] Draw error: ..." string every frame (~25/s).
        self._last_draw_err = None
        self._last_draw_err_ts = 0.0
        # Smoothed (eased) loaded count for the widget.  The helper only emits
        # a marker when each ~400-route chunk finishes, and all chunks start
        # together so those markers arrive in a short burst - sampling them at
        # the draw rate would make the bar snap 0 -> 100%.  Easing the shown
        # value toward the real target each frame keeps the percentage (and
        # bar) visibly animating across the whole load instead of jumping.
        self._geo_disp_loaded = 0.0

    # ── Telemetry (throttled) ────────────────────────────────────────────

    def _telemetry(self):
        now = time.time()

        # Speed - sampled ~10x/s for a smooth, responsive graph/reading.
        # Runs in the background thread, so the PowerShell call never blocks
        # the UI. The list mutations below are guarded by _tel_lock because
        # draw() reads the same lists from the main thread.
        if now - self._speed_ts >= 0.1:
            self._speed_ts = now
            rx_kib, tx_kib, rx_total, tx_total = get_wintun_speed(self.baseline_bytes)
            with self._tel_lock:
                # Combined (RX+TX) history drives the SPEED metric card.
                self.speed_hist.append(rx_kib + tx_kib)
                if len(self.speed_hist) > 120:
                    self.speed_hist.pop(0)
                # Separate RX/TX histories drive the download/upload graph.
                self.rx_hist.append(rx_kib)
                self.tx_hist.append(tx_kib)
                if len(self.rx_hist) > 120:
                    self.rx_hist.pop(0)
                if len(self.tx_hist) > 120:
                    self.tx_hist.pop(0)
                # Accumulate total traffic from consecutive absolute byte counters.
                if rx_total is not None and tx_total is not None:
                    if self._last_raw_rx is not None:
                        self.total_traffic = max(
                            0, self.total_traffic
                            + max(0, rx_total - self._last_raw_rx)
                            + max(0, tx_total - self._last_raw_tx))
                    self._last_raw_rx = rx_total
                    self._last_raw_tx = tx_total

        # Ping - every 3 s
        if now - self._ping_ts >= 2.5:
            self._ping_ts = now
            ms = get_ping(self.ns.port, self.ns.dns4)
            if ms is not None:
                with self._tel_lock:
                    self.ping_samples.append(round(ms))
                    if len(self.ping_samples) > 8:
                        self.ping_samples.pop(0)

        # VPN - every 5 s
        if getattr(self.ns, "vless_over_vpn", False) and now - self._vpn_cache_ts >= 4.0:
            self._vpn_cache_ts = now
            self._vpn_status = get_vpn_status()

    def _telemetry_worker(self):
        """Background loop: sample speed/ping/vpn off the main thread so the
        UI never stalls on a slow PowerShell/subprocess or proxy call. Runs
        until self._telemetry_running is cleared (in loop()'s finally)."""
        while self._telemetry_running:
            try:
                self._telemetry()
                self._poll_connections()
            except Exception as e:
                # NEVER silently swallow here: telemetry dying is what makes
                # speed/ping/graph freeze at zero with no clue why. Log the
                # first failure immediately, then repeat every ~30s so the
                # log isn't spammed but the problem stays visible.
                now = time.time()
                if e != getattr(self, "_tel_last_err", None) or \
                        now - getattr(self, "_tel_last_err_ts", 0) > 30:
                    self._tel_last_err = repr(e)
                    self._tel_last_err_ts = now
                    try:
                        self.logs.put(f"[!] Telemetry error (speed/ping/graph "
                                      f"frozen): {e}")
                    except Exception:
                        pass
            time.sleep(0.1)

    @property
    def current_speed(self):
        return self.speed_hist[-1] if self.speed_hist else 0.0

    @property
    def avg_speed(self):
        h = self.speed_hist
        return (sum(h) / len(h)) if h else 0.0

    @property
    def peak_speed(self):
        return (max(self.speed_hist)) if self.speed_hist else 0.0

    @property
    def current_rx(self):
        return self.rx_hist[-1] if self.rx_hist else 0.0

    @property
    def current_tx(self):
        return self.tx_hist[-1] if self.tx_hist else 0.0

    @property
    def peak_rx(self):
        return (max(self.rx_hist)) if self.rx_hist else 0.0

    @property
    def peak_tx(self):
        return (max(self.tx_hist)) if self.tx_hist else 0.0

    @property
    def avg_ping(self):
        s = self.ping_samples
        return round(sum(s) / len(s)) if s else None

    def _on_tunnel_state_change(self, tr):
        """TunnelStateMachine observer: mirror every state transition into
        the event log so the user sees exactly which phase the tunnel is
        in - and, when things go wrong, exactly which phase failed. Runs on
        whichever thread made the transition (UI, helper reader or
        telemetry); self.logs is a thread-safe queue drained by loop()."""
        try:
            self.logs.put(f"[*] TUNNEL: {tr.source.value} -> "
                          f"{tr.target.value}" + (f" - {tr.reason}"
                                                  if tr.reason else ""))
            # Feed the recovery engine: a verified RUNNING closes any open
            # incident; an unexpected helper death opens one (user-initiated
            # stop paths pause the engine first, so their STOPPED
            # transitions are absorbed, not treated as crashes).
            if tr.target is TunnelState.RUNNING:
                self.recovery.report_success()
            elif tr.target is TunnelState.STOPPED and \
                    (tr.reason or "").startswith("helper process"):
                self.recovery.report_failure(FailureKind.PROCESS,
                                             tr.reason or "helper died")
        except Exception:
            pass

    def _recover_restart_tunnel(self):
        """Recovery-engine repair: full stop + start of the tunnel helper -
        the only dashboard-owned repair for a dead or unfixable helper.
        Serialised against bypass restarts; refuses to run while a user
        shutdown is in progress. Returns True when a helper process is
        alive again (the machine reaches RUNNING when the helper itself
        announces stability)."""
        if not getattr(self.ns, "server", None):
            return False
        if self._shutting_down or self._cleanup_done:
            return False
        with self._restart_lock:
            if self._bypass_restart_active:
                return True      # a restart is already in flight
            self._bypass_restart_active = True
        try:
            self._blog("[*] Recovery: restarting the tunnel...")
            try:
                self.stop()
            except Exception as e:
                self._blog(f"[!] stop during recovery restart failed: {e}")
            try:
                self.launch()
            except Exception as e:
                self._blog(f"[!] launch during recovery restart failed: {e}")
            return bool(self.proc and self.proc.poll() is None)
        finally:
            with self._restart_lock:
                self._bypass_restart_active = False

    @property
    def state(self):
        """The tunnel state as a plain string ("RUNNING", "STOPPED",
        "VERIFYING", ...), backed by the state machine.

        Reconciled against the helper process on every read: if the machine
        thinks the tunnel is up (or starting) but the helper process is
        gone, the machine is driven down right here. The helper-output
        reader thread normally handles that first; this is the belt to its
        braces, covering a dead reader thread too. A dead helper can
        therefore never leave the dashboard claiming RUNNING."""
        st = self.tunnel.current
        if (st.is_operational or st is TunnelState.STARTING) and \
                not (self.proc and self.proc.poll() is None):
            self.tunnel.try_transition(TunnelState.STOPPING,
                                       "helper process is gone")
            self.tunnel.try_transition(TunnelState.STOPPED,
                                       "helper process is gone")
            st = self.tunnel.current
        return st.value

    # ── Graph resolution mode ────────────────────────────────────────────

    def _is_modern_host(self):
        """A terminal host that reliably renders the U+2800 braille block and
        half-block glyphs (Windows Terminal, mintty/Git Bash, ConEmu, VS Code)."""
        if os.environ.get("WT_SESSION"):
            return True
        if os.environ.get("TERM_PROGRAM") in ("vscode", "code"):
            return True
        if os.environ.get("MSYSTEM"):           # mintty / MSYS2 / Git Bash
            return True
        if os.environ.get("ConEmuANSI") == "ON":
            return True
        return False

    def _resolve_graph_mode(self):
        """Resolve the effective graph mode. Non-Unicode hosts can only use the
        plain block fill; otherwise honour an explicit choice or, in 'auto',
        pick braille on a modern host and half-block elsewhere."""
        if self.graph_mode == "auto":
            if not USE_UNICODE:
                return "block"
            return "braille" if self._is_modern_host() else "half"
        if self.graph_mode in ("half", "braille", "line") and not USE_UNICODE:
            return "block"
        return self.graph_mode

    def _cycle_graph_mode(self):
        order = ["block", "half", "braille", "line"] if USE_UNICODE else ["block"]
        cur = self._resolve_graph_mode()
        # When in auto, start cycling from the resolved default's next option.
        idx = order.index(cur) if cur in order else 0
        self.graph_mode = order[(idx + 1) % len(order)]

    def _cycle_theme(self):
        """Cycle to the next named palette (cool -> amber -> muted -> ...)."""
        global ACTIVE_THEME
        ACTIVE_THEME = (ACTIVE_THEME + 1) % len(THEMES)
        return THEMES[ACTIVE_THEME]["name"]

    # ── Mouse / console input ──────────────────────────────────────────────

    def _init_mouse(self):
        """Enable Windows console mouse-click reporting. Best-effort, but no
        longer SILENT: every failure mode is reported to the event log with
        the reason, so "the mouse doesn't work" becomes diagnosable."""
        try:
            k32 = ctypes.windll.kernel32
            h = k32.GetStdHandle(STD_INPUT_HANDLE)
            if h in (0, -1, None):
                self.logs.put("[i] Mouse off: no console input handle "
                              "(stdin redirected?).")
                return
            mode = ctypes.c_uint32()
            if not k32.GetConsoleMode(h, ctypes.byref(mode)):
                self.logs.put(f"[i] Mouse off: GetConsoleMode failed "
                              f"(WinError {ctypes.GetLastError()}).")
                return
            self._orig_console_mode = mode.value
            new_mode = (mode.value | ENABLE_EXTENDED_FLAGS | ENABLE_MOUSE_INPUT | ENABLE_PROCESSED_INPUT)
            new_mode &= ~ENABLE_QUICK_EDIT_MODE
            if not k32.SetConsoleMode(h, new_mode):
                self.logs.put(f"[i] Mouse off: SetConsoleMode failed "
                              f"(WinError {ctypes.GetLastError()}).")
                return
            self._stdin_handle = h
            self._mouse_ok = True
            self._dash_mode = new_mode
        except Exception as e:
            self._mouse_ok = False
            try:
                self.logs.put(f"[i] Mouse off: {e}")
            except Exception:
                pass

    def _restore_console_mode(self):
        try:
            if self._stdin_handle is not None and self._orig_console_mode is not None:
                ctypes.windll.kernel32.SetConsoleMode(self._stdin_handle, self._orig_console_mode)
        except Exception:
            pass

    def _resolve_action(self, action):
        if action == "toggle":
            return 't' if (self.proc and self.proc.poll() is None) else 's'
        return action

    def _flash_wrap(self, row, x0, x1, text):
        """If (row, x0, x1) is the region the user just clicked (and the brief
        highlight window hasn't expired), wrap `text` in reverse video so the
        key/badge visibly reacts to the mouse click."""
        f = self._flash
        if f and f[0] == row and f[1] <= x0 and f[2] >= x1 and time.time() < f[3]:
            return f"\033[7m{text}\033[27m"
        return text

    def _poll_input(self):
        """Non-blocking unified keyboard+mouse poll via ReadConsoleInputW.
        Only used once _init_mouse() has succeeded; returns a single logical
        lowercase key (from either a keypress or a click on a mapped region),
        or None if nothing actionable happened.

        Actionable events are buffered in self._mouse_queue and drained
        one-per-frame, so a fast second keypress (or a click that lands in the
        same console input batch as a keypress) is never silently dropped - the
        old code only ever returned the LAST event of the whole batch, which is
        exactly what made rapid input feel like "the mouse / keys don't work"."""
        try:
            n = ctypes.c_uint32()
            if not ctypes.windll.kernel32.GetNumberOfConsoleInputEvents(self._stdin_handle, ctypes.byref(n)):
                return None
            if n.value == 0:
                return None
            buf = (_INPUT_RECORD * n.value)()
            read = ctypes.c_uint32()
            if not ctypes.windll.kernel32.ReadConsoleInputW(self._stdin_handle, buf, n.value, ctypes.byref(read)):
                return None
            vmap = {0x25: "left", 0x27: "right",
                    0x26: "up", 0x28: "down", 0x21: "pgup",
                    0x22: "pgdn", 0x24: "home", 0x23: "end"}
            for i in range(read.value):
                rec = buf[i]
                if rec.EventType == KEY_EVENT and rec.Event.KeyEvent.bKeyDown:
                    ch = rec.Event.KeyEvent.uChar
                    if ch and ch != '\x00':
                        self._mouse_queue.append(('key', ch.lower()))
                    else:
                        v = vmap.get(rec.Event.KeyEvent.wVirtualKeyCode)
                        if v:
                            self._mouse_queue.append(('key', v))
                elif rec.EventType == MOUSE_EVENT:
                    me = rec.Event.MouseEvent
                    if me.dwEventFlags == 0 and (me.dwButtonState & FROM_LEFT_1ST_BUTTON):
                        y = me.dwMousePosition.Y
                        x = me.dwMousePosition.X
                        for (row, x0, x1, action) in self._click_map:
                            if row == y and x0 <= x < x1:
                                # Briefly remember the clicked region so draw()
                                # can highlight it (reverse video) for ~0.4s.
                                self._flash = (row, x0, x1, time.time() + 0.4)
                                self._mouse_queue.append(
                                    ('click', self._resolve_action(action)))
                                break
            if not self._mouse_queue:
                return None
            kind, val = self._mouse_queue.pop(0)
            return val
        except Exception:
            self._mouse_ok = False
            self._mouse_queue = []
            return None

    def _next_key(self):
        """Return one logical key for this frame, or None. Handles keyboard
        (incl. arrow/PageUp/PageDown) and mouse clicks uniformly. Falls back
        from the mouse-capable Win32 console path to plain msvcrt polling;
        if neither is usable (e.g. a bash host with no real console attached
        - some Git Bash/MSYS setups without winpty/ConPTY) this degrades to
        "no keyboard input" once and stays there, instead of raising on
        every single frame."""
        if self._mouse_ok:
            return self._poll_input()
        if not self._kbd_ok:
            return None
        try:
            import msvcrt
            if not msvcrt.kbhit():
                return None
            ch = msvcrt.getwch()
        except Exception:
            self._kbd_ok = False
            self.log_lines.append(
                "[!] No usable console keyboard input on this host - mouse "
                "only, if available. Try running from cmd.exe, PowerShell, "
                "or Windows Terminal directly.")
            return None
        if ch == '\x1b':
            return 'esc'
        if ch in ('\x00', '\xe0'):
            # Extended key: the scan code is the next char.
            try:
                sc = msvcrt.getwch()
            except Exception:
                return None
            return {'H': 'up', 'P': 'down', 'K': 'left', 'M': 'right',
                    'I': 'pgup', 'Q': 'pgdn', 'G': 'home', 'O': 'end'}.get(sc)
        if ch.isprintable():
            return ch.lower()
        return None

    def _read_char(self):
        """Blocking read of a single character from the console input buffer.

        Uses ReadConsoleInputW - the SAME handle the dashboard already owns -
        so it keeps working while the console is in raw/mouse-reporting mode.
        msvcrt.getwch() can silently drop keystrokes under ENABLE_MOUSE_INPUT,
        which is exactly what made the [A]/[X] live-bypass prompts appear to do
        nothing. Falls back to msvcrt only when no managed handle exists (no
        real console attached). Returns one character (incl. '\\r', '\\x1b',
        '\\x08'), or None on error."""
        h = self._stdin_handle
        if h is not None:
            while True:
                # Read a SINGLE record per call so a fast second keypress
                # (e.g. typing "12") is never discarded by batch-draining.
                try:
                    n = ctypes.c_uint32()
                    if (not ctypes.windll.kernel32.GetNumberOfConsoleInputEvents(
                            h, ctypes.byref(n))):
                        return None
                    if n.value == 0:
                        time.sleep(0.02)
                        continue
                    rec = _INPUT_RECORD()
                    read = ctypes.c_uint32()
                    if (not ctypes.windll.kernel32.ReadConsoleInputW(
                            h, ctypes.byref(rec), 1, ctypes.byref(read))):
                        return None
                    if read.value == 0:
                        time.sleep(0.02)
                        continue
                    if rec.EventType != KEY_EVENT:
                        continue
                    ke = rec.Event.KeyEvent
                    if not ke.bKeyDown:
                        continue
                    # A real character (or a control char we handle:
                    # Enter/\r, Esc/\x1b, Backspace/\x08). Extended keys
                    # (arrows, F-keys) report uChar == '\x00' and are skipped.
                    if ke.uChar:
                        return ke.uChar
                except Exception:
                    return None
        # No managed handle (non-console host): fall back to msvcrt.
        try:
            import msvcrt
            return msvcrt.getwch()
        except Exception:
            return None

    def _read_nav_key(self):
        """Blocking read of a single NAVIGATION key for list-selection overlays
        (the [X] remove-bypass picker). Like _read_char but also reports arrow
        keys (whose uChar is NUL in _read_char) as 'up'/'down'/'pgup'/'pgdn'/
        'home'/'end', plus 'enter'/'esc'/'space' and printable chars."""
        h = self._stdin_handle
        if h is not None:
            vmap = {0x26: "up", 0x28: "down", 0x21: "pgup",
                    0x22: "pgdn", 0x24: "home", 0x23: "end"}
            while True:
                try:
                    n = ctypes.c_uint32()
                    if (not ctypes.windll.kernel32.GetNumberOfConsoleInputEvents(
                            h, ctypes.byref(n))):
                        return None
                    if n.value == 0:
                        time.sleep(0.02)
                        continue
                    rec = _INPUT_RECORD()
                    read = ctypes.c_uint32()
                    if (not ctypes.windll.kernel32.ReadConsoleInputW(
                            h, ctypes.byref(rec), 1, ctypes.byref(read))):
                        return None
                    if read.value == 0:
                        time.sleep(0.02)
                        continue
                    if rec.EventType != KEY_EVENT:
                        continue
                    ke = rec.Event.KeyEvent
                    if not ke.bKeyDown:
                        continue
                    ch = ke.uChar
                    if ch == '\r' or ch == '\n':
                        return "enter"
                    if ch == '\x1b':
                        return "esc"
                    if ch == '\x20':
                        return "space"
                    vk = ke.wVirtualKeyCode
                    if vk in vmap:
                        return vmap[vk]
                    if ch and ch.isprintable():
                        return ch
                except Exception:
                    return None
        # No managed handle (non-console host): fall back to msvcrt.
        try:
            import msvcrt
            ch = msvcrt.getwch()
            if ch == '\r' or ch == '\n':
                return "enter"
            if ch == '\x1b':
                return "esc"
            if ch == '\x20':
                return "space"
            if ch in ('\x00', '\xe0'):
                sc = msvcrt.getwch()
                return {'H': 'up', 'P': 'down', 'I': 'pgup', 'Q': 'pgdn',
                        'G': 'home', 'O': 'end'}.get(sc)
            if ch.isprintable():
                return ch
            return None
        except Exception:
            return None

    def _read_line(self, prompt, title="INPUT", examples=None):
        """Blocking single-line prompt rendered as a styled centred BOX:
        accent title bar, the question, a live `>` input line with a block
        cursor, optional example rows, and key-chip hints ([Enter]/[Esc]/
        right-click paste). Re-rendered on every keystroke so backspace/paste
        always looks right. Returns the entered text, or None on Esc.

        Leaves the full-screen dashboard temporarily; the next loop()
        iteration repaints it. Character input goes through _read_char()
        (ReadConsoleInputW) so it works even with mouse reporting enabled.

        While the prompt is up we re-enable console QuickEdit mode so the user
        can right-click / Shift+Ins paste (the dashboard normally disables it
        for its own click handling). The previous mode is always restored."""
        # Invalidate the cached frame so the dashboard is guaranteed to repaint
        # (and clear this prompt) on the next draw, even if nothing else changed.
        self._last_frame = ""
        self._prev_lines = []
        self._full_repaint = True

        size = _get_window_size() or (80, 24)
        w = max(52, min(size[0] - 6, 86))
        pal = theme()
        acc = pal["active"]

        def _center(text, width, fill=BOX_MID):
            vis = len(re.sub(r"\x1b\[[^m]*m", "", text))
            if vis >= width:
                return text
            pad = width - vis
            return fill * (pad // 2) + text + fill * (pad - pad // 2)

        def _row(content):
            return f"{acc}{BOX_V} {_hpad(content, w - 3)}{acc}{BOX_V}{RESET}"

        def _frame(buf):
            typed = "".join(buf)
            lines = [
                f"{acc}{BOX_LC}{BRIGHT}{_center(f' {title} ', w - 2)}{BOX_RC}{RESET}",
                _row(""),
                _row(f"  {BRIGHT}{prompt}{RESET}"),
                _row(f"  {GREEN}>{RESET} {typed}{WHITE}\u2588{RESET}"),
                _row(""),
            ]
            for ex in (examples or []):
                lines.append(_row(f"  {GRAY}e.g.{RESET} {DIM}{ex}{RESET}"))
            if examples:
                lines.append(_row(""))
            chips = "   ".join(
                f"{GREEN}[{k}]{RESET} {GRAY}{v}{RESET}"
                for k, v in (("Enter", "confirm"), ("Esc", "cancel"),
                             ("right-click", "paste")))
            lines.append(_row(f"  {chips}"))
            lines.append(f"{pal['inact']}{BOX_BL}{BOX_BS * (w - 2)}{BOX_BR}{RESET}")
            return "\033[?25l\033[2J\033[H" + "\n".join(lines)

        sys.stdout.write(_frame([]))
        sys.stdout.flush()
        # Temporarily enable QuickEdit so paste works; restore on exit.
        saved_mode = None
        if self._stdin_handle is not None and self._dash_mode is not None:
            try:
                saved_mode = ctypes.c_uint32()
                ctypes.windll.kernel32.GetConsoleMode(
                    self._stdin_handle, ctypes.byref(saved_mode))
                ctypes.windll.kernel32.SetConsoleMode(
                    self._stdin_handle, self._dash_mode | ENABLE_QUICK_EDIT_MODE)
            except Exception:
                saved_mode = None
        buf = []
        try:
            while True:
                ch = self._read_char()
                if ch is None:
                    self.log_lines.append(
                        "[!] No usable console keyboard input on this host - "
                        "cancelled this prompt.")
                    return None
                if ch in ('\r', '\n'):
                    return "".join(buf).strip()
                elif ch == '\x1b':
                    return None
                elif ch == '\x08':
                    if buf:
                        buf.pop()
                        sys.stdout.write(_frame(buf))
                        sys.stdout.flush()
                elif ch in ('\x00', '\xe0'):
                    # Extended key (arrows/F-keys): nothing to insert.
                    pass
                elif ord(ch) >= 0x20:
                    buf.append(ch)
                    sys.stdout.write(_frame(buf))
                    sys.stdout.flush()
        finally:
            if saved_mode is not None:
                try:
                    ctypes.windll.kernel32.SetConsoleMode(
                        self._stdin_handle, saved_mode.value)
                except Exception:
                    pass

    # ── Live reconfiguration ─────────────────────────────────────────────

    def _get_vless_iface_gateway(self):
        """Cached (interface, gateway) used to bypass the VLESS endpoint -
        detected the same way tuntop/helper.py does, so a live-added
        bypass route lands on the same interface. Cached for the life of the
        dashboard; restart the dashboard if the active network path changes."""
        if self._iface_cache:
            return self._iface_cache
        if getattr(self.ns, "vless_over_vpn", False):
            result = _get_vpn_ipv4_default(getattr(self.ns, "vpn_interface", None))
        else:
            result = _get_ipv4_default()
        if result:
            self._iface_cache = result
        return result

    def _get_vless_iface_gateway_v6(self):
        """IPv6 (interface, gateway) for live IPv6 bypass routes - mirrors
        _get_vless_iface_gateway() but for the IPv6 default next hop."""
        if getattr(self.ns, "vless_over_vpn", False):
            return _get_vpn_ipv6_default(getattr(self.ns, "vpn_interface", None))
        return _get_ipv6_default()

    # Windows loopback pseudo-interface. Used as a "blackhole" next-hop for the
    # IPv6 fallback below: a /128 pointed here has nowhere real to go, so the
    # TCP connect fails and Happy Eyeballs falls back to the IPv4 /32.
    _LOOPBACK_IFACE = "Loopback Pseudo-Interface 1"

    def _ipv6_is_local(self, addr):
        """True if `addr` is assigned to any local adapter. Safety guard so the
        IPv6-blackhole fallback never blackholes one of our own addresses."""
        try:
            ok, out = _ps(
                f"@(Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue "
                f"| Where-Object {{$_.IPAddress -eq '{addr}'}}).Count -gt 0")
            return ok and out.strip().strip('"').lower() in ("true", "1")
        except Exception:
            return False

    # ── Extra bypass entries: add / remove / resolve (background) ─────────
    #
    # Design note (this is what fixed the "-> (unresolved)" forever bug):
    #   * every entry is normalised to a bare host/IP FIRST, so a pasted URL
    #     like https://www.whatismyip.com/ is resolvable at all;
    #   * resolution happens in a background thread with retry + backoff, so a
    #     transient DNS failure is retried instead of being cached as "dead"
    #     for the rest of the session;
    #   * the UI thread NEVER does DNS - it only reads the cached state, so the
    #     panel and the [A]/[X] keys stay instant;
    #   * as soon as an entry resolves, its bypass route is installed live and
    #     the result is logged, with no tunnel restart needed.

    _BYPASS_RETRY_MAX = 60.0        # cap for the retry backoff (seconds)
    _BYPASS_REFRESH = 300.0         # re-resolve a healthy entry this often

    def _blog(self, msg):
        """Log from either thread (the loop drains self.logs every frame)."""
        try:
            self.logs.put(msg)
        except Exception:
            self.log_lines.append(msg)
        # Mirror into the structured ring for diagnostics and the event panel.
        sev = _LOG_ERROR if msg.startswith("[!]") else (
            _LOG_WARNING if msg.startswith("[*]") else _LOG_INFO)
        self.event_log.log(sev, "DASHBOARD", msg)

    def _geo_diag_suppress(self, line):
        """Return True if this geoip diagnostic has already been logged this
        session (across [S]/[T]→[S] cycles and [R] re-applies) and must be
        dropped, otherwise record it and return False.

        The helper add_geoip_bypass() also deduplicates these
        within a single process, but each [S] spawn is a fresh subprocess, so
        the per-session state that survives tunnel restarts lives here. Keys are
        derived stably so the *kind* of diagnostic collapses to one log line even
        if a volatile counter (e.g. "skipped N") or per-run error detail changes."""
        m = re.match(r'\[!\]\s+geoip:(\S+)\s+(\S+)\s+batch had route failures', line)
        if m:
            key = ("routefail", m.group(1), m.group(2))
        elif re.match(r'\[!\]\s+geoip:\S+\s+bypass', line):
            # Normalize the volatile count so it's one entry per code.
            key = ("bypass", re.sub(r'\d+', 'N', line))
        else:
            return False
        if key in self._seen_geo_diag:
            return True
        self._seen_geo_diag.add(key)
        return False

    def _route_geo_helper_line(self, raw_line):
        """Dispatch one line emitted by the helper module during a live [R]
        geo re-apply. Mirrors the [S] subprocess path in _read(): GEO markers
        drive the progress panel, repeated geoip diagnostics are deduplicated,
        and everything else is surfaced to the event log. Called from the [R]
        worker thread, so it must only touch thread-safe state (_update_geo_progress
        under _geo_lock, _blog via the queue)."""
        s = (raw_line or "").rstrip("\r\n")
        if not s:
            return
        if (s.startswith("[GEO-PARSE]") or s.startswith("[GEO-LOAD]")
                or s.startswith("[GEO-DONE]")):
            self._update_geo_progress(s)
            return
        if self._geo_diag_suppress(s):
            return
        self._blog(s)

    def _bypass_new_state(self):
        return {"status": "pending", "ips": [], "err": None, "tries": 0,
                "next": 0.0, "routed": False, "source": None, "last": 0.0}

    def _tun2_constants(self):
        """(TUN2, TUN2_IP4, TUN2_IP6) from the helper module - imported lazily
        the same way _reapply_geo_bypass_worker does, so the UI layer keeps its
        import graph pointing at Core/Tunnel facades only."""
        import importlib
        here = os.path.dirname(os.path.abspath(__file__))
        pkg_dir = os.path.dirname(here)   # tuntop/ package
        if pkg_dir not in sys.path:
            sys.path.insert(0, pkg_dir)
        helper = importlib.import_module("tuntop.tunnel.helper")
        return helper.TUN2, helper.TUN2_IP4, helper.TUN2_IP6

    def _install_bypass_routes(self, entry, ep4, ep6, log=True, target="direct"):
        """Install /32 + /128 routes for one entry. Returns the list of IPs
        that are now routed. Safe to call from any thread: it only shells out
        and logs through the queue.

        target="direct" (default): bypass routes via the physical NIC - the
        traffic stays OUT of the tunnel entirely.
        target="proxy2": routes point at the SECOND TUN adapter (wintun2, only
        present when --proxy2-port is set) - the traffic exits through the
        second proxy instead of the primary one.

        TRANSACTIONAL (tuntop/routes_txn.py): every route of the entry is
        applied as ONE all-or-nothing unit - each add is verified against the
        real routing table, and any failure rolls back the routes already
        applied. A half-installed bypass (IPv4 direct while IPv6 still dies
        inside the TUN) can no longer happen."""
        if target == "proxy2":
            t2, t2_ip4, t2_ip6 = self._tun2_constants()
            iface_gw = (t2, t2_ip4)      # wintun2's own address = its next hop,
            v6_target = (t2, t2_ip6)     # exactly how the primary TUN is used
        elif target == "vpn":
            # Egress through a CONNECTED Windows VPN (same egress the geoip
            # "via Windows VPN" mode uses). No VPN default route -> nothing
            # planned; the resolver retries with backoff and reports why.
            v4d = _get_vpn_ipv4_default(getattr(self.ns, "vpn_interface", None))
            iface_gw = (v4d[0], v4d[1]) if v4d else None
            v6d = _get_vpn_ipv6_default(getattr(self.ns, "vpn_interface", None))
            v6_target = (v6d[0], v6d[1]) if v6d else None
        else:
            iface_gw = self._get_vless_iface_gateway()
            v6_target = None
        # ── Plan ────────────────────────────────────────────────────────
        planned = []                   # (ip, RouteOp) in apply order
        for ip in ep4:
            if target in ("proxy2", "vpn"):
                eg = iface_gw
            else:
                # Route via the interface/gateway Windows would really use to
                # reach this IP (correct for split-tunnel VPNs), not the bare
                # default.
                eg = _get_egress_for(ip) or iface_gw
            if not eg:
                if log:
                    self._blog(f"[!] No egress found for {ip} ({entry}); bypass route "
                               "not installed yet - will retry.")
                continue
            planned.append(
                (ip, ("v4", f"{ip}/32", eg[0], eg[1])))
        if ep6:
            if target in ("proxy2", "vpn"):
                if not v6_target:
                    if log:
                        self._blog("[i] No IPv6 gateway on the target egress - "
                                   "IPv6 bypass routes are not installed live; "
                                   "they apply on tunnel restart.")
                else:
                    v6iface, v6gateway = v6_target
                    for ip in ep6:
                        planned.append(
                            (ip, ("v6", f"{ip}/128", v6iface, v6gateway)))
            else:
                v6gw = self._get_vless_iface_gateway_v6()
                if not v6gw:
                    if log:
                        self._blog("[i] No usable IPv6 gateway - IPv6 bypass routes are "
                                   "not installed live; they apply on tunnel restart.")
                else:
                    v6iface, v6gateway = v6gw
                    for ip in ep6:
                        planned.append(
                            (ip, ("v6", f"{ip}/128", v6iface, v6gateway)))
        if not planned:
            return []
        # ── Apply (all-or-nothing) ──────────────────────────────────────
        txn = RouteTransaction(log=self._blog if log else None)
        for _ip, (fam, dest, iface, gw) in planned:
            if fam == "v4":
                txn.add_v4(dest, iface, gw, metric=1)
            else:
                txn.add_v6(dest, iface, gw, metric=1)
        result = txn.commit()
        if not result.ok:
            # The table was rolled back: traffic path is UNCHANGED, so this
            # is a clean "not applied" - the resolver retries later.
            if log:
                self._blog(f"[!] Bypass routes for {entry} FAILED - "
                           "transaction rolled back, traffic path unchanged.")
                for op, err in result.failed:
                    self._blog(f"[!]   {op.dest} via {op.iface}: {err}")
            return []
        applied = []
        for ip, (fam, dest, iface, gw) in planned:
            applied.append(ip)
            # Bookkeeping for stop()/exit sweeps (same tuples as before).
            self._live_bypass_added.append((fam, dest, iface, gw))
        return applied

    def _bypass_stores(self, target):
        """(state_dict, cache_dict) for a routing target. Deliberately SEPARATE
        stores per target (never one dict with a target field): a direct entry
        and a proxy2 entry with the same name cannot collide, and no code path
        can accidentally install one target's route for the other's entry."""
        if target == "proxy2":
            return self._proxy2_res_state, self._proxy2_res_cache
        if target == "vpn":
            return self._vpn_res_state, self._vpn_res_cache
        return self._bypass_res_state, self._bypass_res_cache

    def _bypass_resolve_entry(self, entry, log=True, target="direct"):
        """Resolve ONE entry (full fallback stack) and install its routes if it
        resolved. Updates the shared state. Returns the state dict copy."""
        ep4, ep6, err, src = _resolve_detail(entry, use_cache=False, fallback=True)
        now = time.time()
        ips = list(ep4) + list(ep6)
        state, cache = self._bypass_stores(target)
        with self._bypass_res_lock:
            st = state.setdefault(entry, self._bypass_new_state())
            prev_ips = list(st.get("ips") or [])
            prev_status = st.get("status")
            st["last"] = now
        if ips:
            changed = (ips != prev_ips) or not prev_ips
            applied = []
            if changed or not prev_ips:
                applied = self._install_bypass_routes(entry, ep4, ep6, log=log,
                                                      target=target)
            with self._bypass_res_lock:
                st = state.setdefault(entry, self._bypass_new_state())
                st.update(status="ok", ips=ips, err=None, tries=0, source=src,
                          next=now + self._BYPASS_REFRESH)
                if applied:
                    st["routed"] = True
                elif changed:
                    st["routed"] = False
                out = dict(st)
            cache[entry] = (list(ep4), list(ep6))
            if changed:
                # The health checks probe the routes for the *resolved* IPs, so
                # rebuild them now that we know what those are.
                try:
                    self.checks = build_checks(self.ns)
                except Exception:
                    pass
            if log and changed:
                via = f" via {src}" if src and src not in ("system", "literal") else ""
                if target == "proxy2":
                    route_note = (f"; routed via proxy2: {', '.join(applied)}"
                                  if applied else
                                  "; proxy2 route not installed yet (will retry)")
                else:
                    route_note = (f"; routed direct: {', '.join(applied)}"
                                  if applied else
                                  "; route not installed yet (will retry)")
                if prev_status == "fail":
                    self._blog(f"[+] Bypass '{entry}' resolved again{via} -> "
                               f"{', '.join(ips)}{route_note}")
                else:
                    self._blog(f"[+] Bypass '{entry}' -> {', '.join(ips)}{via}{route_note}")
            elif log and not out["routed"]:
                # Resolved, same IPs, but the route never made it in - retry it.
                applied = self._install_bypass_routes(entry, ep4, ep6, log=False,
                                                      target=target)
                if applied:
                    with self._bypass_res_lock:
                        state[entry]["routed"] = True
                    self._blog(f"[+] Bypass route(s) installed for {entry}: "
                               f"{', '.join(applied)}")
            return out
        # Failure: schedule an exponential-backoff retry (3, 6, 12, 24, 48, 60s).
        with self._bypass_res_lock:
            st = state.setdefault(entry, self._bypass_new_state())
            st["tries"] = int(st.get("tries") or 0) + 1
            delay = min(self._BYPASS_RETRY_MAX, 3.0 * (2 ** (st["tries"] - 1)))
            st.update(status="fail", err=err or "could not resolve",
                      next=now + delay, source=None)
            tries = st["tries"]
            out = dict(st)
        if log and (tries == 1 or tries % 10 == 0):
            self._blog(f"[!] Bypass '{entry}' did not resolve ({out['err']}); "
                       f"retrying every {int(min(self._BYPASS_RETRY_MAX, delay))}s "
                       f"in the background (attempt {tries}).")
        return out

    def _bypass_normalise_list(self, target="direct"):
        """Make sure every entry in the target's bypass list is a bare host/IP.
        Entries can arrive as URLs from --bypass-ip/--proxy2-bypass-ip too, not
        just from the [A] key."""
        if target == "proxy2":
            current = list(getattr(self.ns, "proxy2_bypass_ip", []) or [])
        elif target == "vpn":
            current = list(getattr(self.ns, "vpn_bypass_ip", []) or [])
        else:
            current = list(getattr(self.ns, "bypass_ip", []) or [])
        fixed, changed = [], False
        for raw in current:
            host = _host_from_url(raw)
            if not host:
                changed = True
                self._blog(f"[!] Dropping unusable bypass entry {raw!r}.")
                continue
            if host != raw:
                changed = True
                self._blog(f"[i] Bypass entry {raw!r} normalised to '{host}' "
                           "(a route needs a host/IP, not a URL).")
            if host not in fixed:
                fixed.append(host)
            else:
                changed = True
        if changed:
            if target == "proxy2":
                self.ns.proxy2_bypass_ip = fixed
            elif target == "vpn":
                self.ns.vpn_bypass_ip = fixed
            else:
                self.ns.bypass_ip = fixed
            self.checks = build_checks(self.ns)
        return fixed

    def _bypass_resolve_tick(self):
        """One pass over the extra bypass entries: resolve whatever is due.
        Called by the background thread (and directly by the tests)."""
        now = time.time()
        for target in ("direct", "proxy2", "vpn"):
            if target == "proxy2" and not getattr(self.ns, "proxy2_port", None):
                continue   # second hop disabled: nothing to resolve for it
            if target == "vpn" and not getattr(self.ns, "vpn_bypass_ip", None):
                continue   # nothing was ever pointed at the VPN egress
            entries = self._bypass_normalise_list(target)
            state, cache = self._bypass_stores(target)
            with self._bypass_res_lock:
                for gone in [e for e in state if e not in entries]:
                    state.pop(gone, None)
                    cache.pop(gone, None)
                due = []
                for entry in entries:
                    st = state.get(entry)
                    if st is None:
                        state[entry] = self._bypass_new_state()
                        due.append(entry)
                    elif st.get("next", 0.0) <= now:
                        due.append(entry)
            for entry in due:
                self._bypass_resolve_entry(entry, target=target)

    def _ensure_bypass_resolver(self):
        """Start (or restart) the background bypass resolver. Called from
        loop() and from [A], so an entry added before/without a running worker
        still gets resolved - without ever blocking the UI thread."""
        th = self._bypass_res_thread
        if th is not None and th.is_alive():
            return th
        self._telemetry_running = True
        th = threading.Thread(target=self._bypass_resolver_worker, daemon=True)
        self._bypass_res_thread = th
        th.start()
        return th

    def _bypass_resolver_worker(self):
        """Background loop: keep every bypass entry resolved and routed. Runs
        until the dashboard exits. All DNS/route work happens here so the UI
        thread can never stall on a slow lookup."""
        while self._telemetry_running and self.running:
            try:
                self._bypass_resolve_tick()
            except Exception as e:
                self._blog(f"[!] Bypass resolver error: {e}")
            time.sleep(0.5)

    def _add_bypass_ip(self, raw, target="direct"):
        """[A] - add an entry to a bypass list. Accepts an IP, a hostname or
        a full URL. The entry is resolved + routed live in the background and
        the tunnel keeps running. target="proxy2" adds it to the second-hop
        list (routes point at wintun2 instead of the physical NIC)."""
        entry = _host_from_url(raw)
        if not entry:
            self.log_lines.append(f"[!] {raw!r} is not a usable IP/hostname.")
            return
        norm_note = ""
        if entry != str(raw).strip():
            norm_note = (f" (normalised from '{str(raw).strip()}' - a bypass route "
                         "needs a host/IP, not a URL)")
        if target == "proxy2":
            current = list(getattr(self.ns, "proxy2_bypass_ip", []) or [])
        elif target == "vpn":
            current = list(getattr(self.ns, "vpn_bypass_ip", []) or [])
        else:
            current = list(getattr(self.ns, "bypass_ip", []) or [])
        already = entry in current
        if not already:
            current.append(entry)
            if target == "proxy2":
                self.ns.proxy2_bypass_ip = current
            elif target == "vpn":
                self.ns.vpn_bypass_ip = current
            else:
                self.ns.bypass_ip = current
            self.checks = build_checks(self.ns)
        state, _cache = self._bypass_stores(target)
        with self._bypass_res_lock:
            st = state.get(entry)
            if st is None or st.get("status") != "ok":
                state[entry] = self._bypass_new_state()
        target_note = " (second hop: proxy2)" if target == "proxy2" else (
            " (egress: Windows VPN)" if target == "vpn" else "")
        if already:
            self.log_lines.append(
                f"[i] '{entry}' is already in the {target} bypass list - "
                "re-applying now.")
        else:
            self.log_lines.append(f"[+] Added '{entry}'{norm_note} to the "
                                  f"{target} bypass list{target_note}.")
        self.log_lines.append(
            "    (resolving + installing the route live in the background "
            "- no restart needed)")
        self._ensure_bypass_resolver()

    def _remove_bypass_ip(self, entry, target="direct"):
        entry = _host_from_url(entry) or entry
        if target == "proxy2":
            current = list(getattr(self.ns, "proxy2_bypass_ip", []) or [])
        elif target == "vpn":
            current = list(getattr(self.ns, "vpn_bypass_ip", []) or [])
        else:
            current = list(getattr(self.ns, "bypass_ip", []) or [])
        if entry not in current:
            self.log_lines.append(f"[!] '{entry}' is not in the current {target} "
                                  f"bypass list: "
                                  f"{', '.join(current) if current else '(empty)'}")
            return
        # Capture the IPs we already know for this entry BEFORE dropping its
        # state/cache, so the live-route delete (used when auto-restart is off)
        # actually has something to remove. The background resolver stores the
        # resolved IPs in <state>[entry]["ips"] and the per-target cache.
        state, cache = self._bypass_stores(target)
        with self._bypass_res_lock:
            st = state.get(entry) or {}
            known = list(st.get("ips") or [])
        if not known:
            k4, k6 = cache.get(entry, ([], []))
            known = list(k4) + list(k6)
        if not known:
            k4, k6 = _resolve_cached(entry)
            known = list(k4) + list(k6)
        # Drop the entry from the active list + per-entry state now (cheap,
        # main-thread). The actual netsh/Find-NetRoute deletion is deferred to a
        # background thread so the keypress never blocks the UI (a hung RasMan /
        # netsh call could otherwise freeze the whole dashboard for seconds).
        current.remove(entry)
        if target == "proxy2":
            self.ns.proxy2_bypass_ip = current
        elif target == "vpn":
            self.ns.vpn_bypass_ip = current
        else:
            self.ns.bypass_ip = current
        cache.pop(entry, None)
        with self._bypass_res_lock:
            state.pop(entry, None)
        self.checks = build_checks(self.ns)
        self.log_lines.append(f"[-] Removed '{entry}' from the {target} bypass list.")
        # Removal is ALWAYS a live, backgrounded route delete - it must never
        # restart the tunnel (that would reload geo and briefly drop traffic for
        # no reason). The entry is already gone from the bypass list, so the next
        # tunnel start/restart simply won't re-apply it. The [A] key is the only
        # one gated by the auto-restart ([Z]) toggle.
        self._remove_bypass_routes_async(entry, known, target=target)

    def _remove_bypass_routes_async(self, entry, known, target="direct"):
        """Delete an entry's live routes off the UI thread. `known` is the
        list of IPs captured by _remove_bypass_ip (or [] if none were known
        yet). `target` must match the target the routes were installed with:
        proxy2 routes live on the wintun2 adapter, direct ones on the egress
        the physical lookup picks. Logs results through _blog()."""
        if not known:
            k4, k6 = _resolve_cached(entry)
            known = list(k4) + list(k6)
        if not known:
            self._blog(f"[-] Removed '{entry}' from the {target} bypass list "
                       "(no resolved IPs - nothing to delete).")
            return

        if target == "proxy2":
            t2, t2_ip4, t2_ip6 = self._tun2_constants()

        def _worker():
            ep4 = [ip for ip in known if ":" not in ip]
            ep6 = [ip for ip in known if ":" in ip]
            removed, failed = [], []
            if target == "vpn":
                # VPN egress detected in the background thread (PowerShell -
                # never on the UI thread).
                vg = _get_vpn_ipv4_default(getattr(self.ns, "vpn_interface", None))
                vg6 = _get_vpn_ipv6_default(getattr(self.ns, "vpn_interface", None))
            for ip in ep4:
                if target == "proxy2":
                    if _del_route_v4(f"{ip}/32", t2, t2_ip4):
                        removed.append(ip)
                    else:
                        failed.append(ip)
                    continue
                if target == "vpn":
                    if vg:
                        ok = _del_route_v4(f"{ip}/32", vg[0], vg[1])
                    else:
                        ok = _del_route_v4(f"{ip}/32", "", "")
                    (removed if ok else failed).append(ip)
                    continue
                eg = _get_egress_for(ip) or self._get_vless_iface_gateway()
                if not eg:
                    # No egress info - try a prefix-wide delete anyway; the
                    # robust _del_route_v4 verifies the result either way.
                    if not _del_route_v4(f"{ip}/32", "", ""):
                        failed.append(ip)
                    else:
                        removed.append(ip)
                    continue
                if _del_route_v4(f"{ip}/32", eg[0], eg[1]):
                    removed.append(ip)
                else:
                    failed.append(ip)
            if ep6:
                if target == "proxy2":
                    for ip in ep6:
                        if _del_route_v6(f"{ip}/128", t2, t2_ip6):
                            removed.append(ip)
                        else:
                            failed.append(ip)
                elif target == "vpn":
                    for ip in ep6:
                        if vg6:
                            ok = _del_route_v6(f"{ip}/128", vg6[0], vg6[1])
                        else:
                            ok = _del_route_v6(f"{ip}/128", "", "")
                        (removed if ok else failed).append(ip)
                else:
                    v6gw = self._get_vless_iface_gateway_v6()
                    for ip in ep6:
                        ok = False
                        # Prefer a targeted delete when we know the gateway it
                        # was installed with.
                        if v6gw:
                            ok = _del_route_v6(f"{ip}/128", v6gw[0], v6gw[1])
                        if ok:
                            removed.append(ip)
                            continue
                        # No gateway detected (or the targeted delete missed):
                        # fall back to a prefix-wide Remove-NetRoute that ignores
                        # iface/nexthop, so a route installed earlier (when a
                        # gateway existed) is still removed even if the gateway
                        # is no longer detected - mirrors the IPv4 path.
                        if _del_route_v6(f"{ip}/128", "", ""):
                            removed.append(ip)
                        else:
                            failed.append(ip)
            if removed:
                self._blog(f"[-] Removed bypass route(s): {', '.join(removed)}")
            elif not failed:
                self._blog(f"[-] No matching live route found to delete for "
                           f"'{entry}' (already gone?).")
            if failed:
                self._blog(f"[!] Could NOT remove route(s) for: {', '.join(failed)} "
                           f"- traffic to them still bypasses the tunnel. "
                           f"Try [S] stop + start once.")
            if removed or failed:
                # Flush the OS DNS cache so the next lookup isn't answered from
                # a stale entry, and warn about browser connection pooling:
                # Chrome/Firefox keep ESTABLISHED sockets on the old direct
                # path, so tabs must be reloaded before they ride the tunnel.
                _ps("Clear-DnsClientCache -ErrorAction SilentlyContinue | Out-Null")
                self._blog(
                    f"[i] '{entry}' now routes through the TUN for NEW connections "
                    f"(reload the site's tabs - open connections stay direct until closed).")
        threading.Thread(target=_worker, daemon=True).start()

    def _draw_list_overlay(self, title, labels, sel, top, avail):
        """Full-screen list picker (its own 'page', so it never fights with the
        main dashboard). Rendered as a styled centred BOX: accent title bar
        with an entry counter, numbered rows, the highlighted row filled with
        a background chip, and a key-chip footer."""
        size = _get_window_size() or (80, 24)
        w = max(56, min(size[0] - 6, 92))
        pal = theme()
        acc = pal["active"]

        def _center(text, width, fill=BOX_MID):
            vis = len(re.sub(r"\x1b\[[^m]*m", "", text))
            if vis >= width:
                return text
            pad = width - vis
            return fill * (pad // 2) + text + fill * (pad - pad // 2)

        def _row(content):
            return f"{acc}{BOX_V} {_hpad(content, w - 3)}{acc}{BOX_V}{RESET}"

        sys.stdout.write("\033[?25l\033[2J\033[H")
        lines = [
            f"{acc}{BOX_LC}{BRIGHT}{_center(f' {title} ', w - 2)}{BOX_RC}{RESET}",
            _row(f"{GRAY}  {len(labels)} entr{'y' if len(labels) == 1 else 'ies'}"
                 f"{RESET}{GRAY} - highlight one, press Enter{RESET}"),
            _row(BOX_MID * (w - 5)),
        ]
        visible = labels[top:top + avail]
        for i, lab in enumerate(visible):
            idx = top + i
            num = f"{idx + 1:>2}."
            if idx == sel:
                # Filled background chip + bright text for the selected row.
                lines.append(_row(
                    f"\033[48;2;45;70;110m{WHITE}{BRIGHT} \u25b8 {num} {lab}"
                    f"{' ' * 2}\033[49m"))
            else:
                lines.append(_row(f"{GRAY}{num}{RESET}  {lab}"))
        for _ in range(max(0, avail - len(visible))):
            lines.append(_row(""))
        lines.append(_row(BOX_MID * (w - 5)))
        chips = "   ".join(
            f"{GREEN}[{k}]{RESET} {GRAY}{v}{RESET}"
            for k, v in (("\u2191/\u2193 PgUp/PgDn", "move"),
                         ("Home/End", "first/last"),
                         ("Enter", "remove"),
                         ("Esc", "cancel")))
        lines.append(_row(f"  {chips}"))
        lines.append(f"{pal['inact']}{BOX_BL}{BOX_BS * (w - 2)}{BOX_BR}{RESET}")
        sys.stdout.write("\n".join(lines))
        sys.stdout.flush()

    def _select_bypass(self):
        """Interactive removal: show the current extra bypass entries as a
        scrollable list; the user highlights one and presses Enter to remove it
        (Esc cancels). Replaces the old 'type the exact entry' prompt so there
        is no guessing or spelling of long hostnames."""
        items = list(getattr(self.ns, "bypass_ip", []) or [])
        # Combined picker: direct entries first, then proxy2/vpn ones (tagged).
        targets = ["direct"] * len(items)
        if getattr(self.ns, "proxy2_port", None):
            p2 = list(getattr(self.ns, "proxy2_bypass_ip", []) or [])
            items = items + p2
            targets = targets + ["proxy2"] * len(p2)
        vp = list(getattr(self.ns, "vpn_bypass_ip", []) or [])
        items = items + vp
        targets = targets + ["vpn"] * len(vp)
        if not items:
            self.log_lines.append("[i] No extra bypass entries to remove.")
            return
        labels = self._bypass_labels()
        size = _get_window_size() or (80, 24)
        avail = max(5, min(20, size[1] - 6))
        sel = 0
        try:
            while True:
                top = max(0, min(sel - avail // 2, max(0, len(items) - avail)))
                self._draw_list_overlay(
                    "REMOVE BYPASS", labels, sel, top, avail)
                k = self._read_nav_key()
                if k is None:
                    return
                if k == "esc":
                    self.log_lines.append("[*] Remove cancelled.")
                    return
                if k == "enter":
                    entry = items[sel]
                    self._remove_bypass_ip(entry, target=targets[sel])
                    return
                if k == "up":
                    sel = max(0, sel - 1)
                elif k == "down":
                    sel = min(len(items) - 1, sel + 1)
                elif k == "pgup":
                    sel = max(0, sel - avail)
                elif k == "pgdn":
                    sel = min(len(items) - 1, sel + avail)
                elif k == "home":
                    sel = 0
                elif k == "end":
                    sel = len(items) - 1
        finally:
            # Force the dashboard to fully repaint on the next frame (the overlay
            # cleared the screen, so a per-line diff would leave stale rows).
            self._last_frame = ""
            self._prev_lines = []
            self._full_repaint = True

    def _bypass_resolved_list(self, target="direct"):
        """Snapshot of every extra bypass entry for the UI:
        [{entry, ips, status, detail}, ...].

        Pure state read - NO DNS happens here, so the panel cannot stall the
        frame and an unresolved entry always shows *why* plus when it will be
        retried (the background resolver keeps trying)."""
        out = []
        now = time.time()
        state, _cache = self._bypass_stores(target)
        if target == "proxy2":
            entries = list(getattr(self.ns, "proxy2_bypass_ip", []) or [])
        else:
            entries = list(getattr(self.ns, "bypass_ip", []) or [])
        with self._bypass_res_lock:
            states = {k: dict(v) for k, v in state.items()}
        for entry in entries:
            st = states.get(entry)
            if st is None:
                out.append({"entry": entry, "ips": [], "status": "pending",
                            "detail": "(resolving...)"})
                continue
            ips = list(st.get("ips") or [])
            status = st.get("status", "pending")
            if status == "ok" and ips:
                tag = " [routed]" if st.get("routed") else " [route pending]"
                src = st.get("source")
                via = f" (via {src})" if src and src not in ("system", "literal", "cache") else ""
                detail = ", ".join(ips) + via + tag
            elif status == "fail":
                wait = max(0, int(round(st.get("next", now) - now)))
                detail = (f"(unresolved: {st.get('err') or 'lookup failed'}; "
                          f"retry in {wait}s, attempt {st.get('tries', 0)})")
            else:
                detail = "(resolving...)"
            if target == "proxy2":
                detail += " [proxy2]"
            elif target == "vpn":
                detail += " [vpn]"
            out.append({"entry": entry, "ips": ips, "status": status, "detail": detail})
        return out

    def _bypass_labels(self):
        """Rows for the [X] remove picker - same non-blocking state as the panel."""
        rows = (self._bypass_resolved_list("direct")
                + self._bypass_resolved_list("proxy2")
                + self._bypass_resolved_list("vpn"))
        return [f"{it['entry']}  ->  {it['detail']}" for it in rows]

    def _apply_launch_change(self, reason):
        """A setting that shapes the helper's COMMAND LINE was edited at
        runtime (server list / VPN mode / VPN bypass). Restart stop+start in
        the background so it takes effect - the relaunch reads ns.* fresh."""
        self._schedule_bypass_restart(reason)

    def _toggle_vless_over_vpn(self):
        cur = bool(getattr(self.ns, "vless_over_vpn", False))
        self.ns.vless_over_vpn = not cur
        if not cur:
            # When enabling VLESS-over-VPN, also enable VPN bypass so the
            # VPN endpoint stays direct (required for this mode to work).
            self.ns.no_vpn_bypass = True
            self.log_lines.append(
                "[*] VPN endpoint bypass: ENABLED (auto-set for VLESS-over-VPN).")
        try:
            self.checks = build_checks(self.ns)
        except Exception as e:
            self.log_lines.append(f"[!] Health-check rebuild failed: {e}")
        self.log_lines.append(
            f"[*] vless-over-vpn: {'OFF' if cur else 'ON'} "
            f"({'direct transport' if cur else 'VLESS rides the Windows VPN'}).")
        self._apply_launch_change("vless-over-vpn toggled")

    def _toggle_vpn_bypass(self):
        cur = bool(getattr(self.ns, "no_vpn_bypass", False))
        self.ns.no_vpn_bypass = not cur
        try:
            self.checks = build_checks(self.ns)
        except Exception as e:
            self.log_lines.append(f"[!] Health-check rebuild failed: {e}")
        self.log_lines.append(
            f"[*] VPN endpoint bypass: {'ENABLED' if cur else 'DISABLED'} "
            f"({'VPN traffic IS tunneled' if cur else 'VPN endpoints stay direct'}).")
        self._apply_launch_change("vpn-bypass toggled")

    def _edit_servers(self):
        val = self._read_line(
            "VLESS server IP(s)/hostname(s), comma or space separated:",
            title="EDIT SERVERS",
            examples=[f"current: {', '.join(self.ns.server)}",
                      "1.2.3.4, example.com   (multiple are fine)",
                      "applies on the next tunnel start"])
        if not val:
            return
        hosts = []
        for part in re.split(r"[,\s]+", val.strip()):
            h = _host_from_url(part)
            if h and h not in hosts:
                hosts.append(h)
        if not hosts:
            self.log_lines.append(f"[!] No usable host in {val!r} - servers unchanged.")
            return
        old_v4, old_v6 = list(self.endpoint_v4), list(self.endpoint_v6)
        self.ns.server = hosts
        # Re-resolve the endpoints for display/health immediately (best effort).
        self.endpoint_v4, self.endpoint_v6 = [], []
        for srv in hosts:
            v4, v6 = _resolve(srv)
            for ip in v4:
                if ip not in self.endpoint_v4:
                    self.endpoint_v4.append(ip)
            for ip in v6:
                if ip not in self.endpoint_v6:
                    self.endpoint_v6.append(ip)
        try:
            self.checks = build_checks(self.ns)
        except Exception as e:
            self.log_lines.append(f"[!] Health-check rebuild failed: {e}")
        self.log_lines.append(f"[*] Servers set to: {', '.join(hosts)}.")
        # LIVE apply - the VLESS transport is reached by IP, so NO TUN restart
        # is needed: drop the old endpoints' host routes and install ones for
        # the new servers (keeps the proxy's own connection out of the TUN).
        self._rehost_endpoint_routes(old_v4 + old_v6, hosts)

    def _rehost_endpoint_routes(self, old_ips, hosts):
        """Live server change: delete the old VLESS endpoints' /32-/128 host
        routes and install fresh ones for the new servers - all off the UI
        thread. Only a display/health refresh happens on the main thread."""
        def _worker():
            gone = []
            for ip in old_ips:
                ok = (_del_route_v4(f"{ip}/32", "", "") if ":" not in ip
                      else _del_route_v6(f"{ip}/128", "", ""))
                if ok:
                    gone.append(ip)
            if gone:
                self._blog(f"[-] Old server host routes removed: {', '.join(gone)}")
            for srv in hosts:
                v4, v6 = _resolve(srv)
                if not v4 and not v6:
                    self._blog(f"[!] Could not resolve new server '{srv}' - "
                               "its host route will be retried automatically.")
                    continue
                applied = self._install_bypass_routes(srv, v4, v6,
                                                      log=True, target="direct")
                if applied:
                    self._blog(f"[+] Server '{srv}' now bypassed direct "
                               f"({', '.join(applied)}) - no TUN restart needed.")
        threading.Thread(target=_worker, daemon=True).start()

    def _edit_geo(self):
        new_code = self._read_line(
            f"Geo bypass country code (current "
            f"{getattr(self.ns, 'geoip_code', 'cn') or 'none'}):",
            title="GEOIP SETTINGS",
            examples=["ir = Iran   cn = China   ru = Russia   pk = Pakistan",
                      "or enter any ISO country code",
                      "leave empty to cancel"])
        if not new_code:
            return
        self.ns.geoip_code = new_code.strip().lower()
        self.log_lines.append(f"[*] Geo bypass code set to '{self.ns.geoip_code}'.")
        # Egress target - same "direct / proxy2 / vpn" choice as [A], and it
        # can be changed while the app is running (routes are re-pointed live).
        t = self._read_line(
            "Route geoip country traffic via: [Enter]=keep current, "
            "1=direct, 2=proxy2, 3=vpn (Windows VPN):",
            title="GEOIP  -  CHOOSE EGRESS",
            examples=[f"current: {self._geo_target()}",
                      "2 needs proxy2 configured (press [Z])",
                      "the choice applies live - no tunnel restart"])
        t = (t or "").strip()
        target = self._geo_target()
        if t == "1":
            target = "direct"
        elif t == "2":
            if getattr(self.ns, "proxy2_port", None):
                target = "proxy2"
            else:
                self.log_lines.append(
                    "[!] proxy2 is not configured (press [Z] to add it) - "
                    "keeping the current egress.")
        elif t == "3":
            target = "winvpn"
        if target != self._geo_target():
            self._set_geo_target(target)
            self.log_lines.append(f"[*] Geo egress target: {target}.")
        if getattr(self.ns, "geoip", None):
            # A geo file is configured - re-apply the ranges LIVE, no restart.
            self._reapply_geo_bypass(target=target)
        else:
            path = self._read_line(
                "Path to v2rayN geoip.dat (empty = cancel):",
                title="GEOIP FILE PATH",
                examples=["C:\\Program Files\\v2rayN\\bin\\geoip.dat"])
            if path and os.path.isfile(path):
                self.ns.geoip = path
                self.log_lines.append(f"[*] Geoip file set: {path}.")
                self._apply_launch_change("geoip file added")
            elif path:
                self.log_lines.append(
                    f"[!] File not found: {path} - geoip unchanged. "
                    "(Tip: press [W] to download geoip.dat automatically.)")

    # ── Profiles ([O] save / [I] load) ──────────────────────────────────────
    # Presets of everything that shapes the helper's command line, stored in
    # profiles.json next to the script. Loading applies to ns.* and restarts
    # the tunnel so it takes effect - one key to switch setups.

    def _profile_file(self):
        return profiles.profile_file(os.path.dirname(os.path.abspath(__file__)))

    def _profile_snapshot(self):
        """Everything that defines a setup (see profiles.snapshot_from_args)."""
        return profiles.snapshot_from_args(self.ns)

    def _save_profile(self):
        name = self._read_line("Profile name to SAVE current settings as:",
                               title="SAVE PROFILE",
                               examples=["home", "work-vpn", "ir-geo"])
        if not name:
            return
        ok, msg = profiles.save_snapshot(self._profile_file(), name,
                                         self._profile_snapshot())
        self.log_lines.append(msg)

    def _load_profile(self):
        data, err = profiles.load_store(self._profile_file())
        if err == "missing":
            self.log_lines.append("[i] No profiles yet - save one with [O].")
            return
        if err:
            self.log_lines.append(f"[!] Could not read profiles.json: {err}")
            return
        if not data:
            self.log_lines.append("[i] profiles.json is empty - save one with [O].")
            return
        names = list(data.keys())
        labels = [
            f"{n}  {GRAY}({data[n].get('server') and ', '.join(data[n]['server'])}"
            f" · :{data[n].get('port')}){RESET}"
            for n in names
        ]
        size = _get_window_size() or (80, 24)
        avail = max(5, min(20, size[1] - 6))
        sel, top = 0, 0
        try:
            while True:
                top = max(0, min(sel - avail // 2, max(0, len(names) - avail)))
                self._draw_list_overlay("LOAD PROFILE", labels, sel, top, avail)
                k = self._read_nav_key()
                if k is None or k == "esc":
                    self.log_lines.append("[*] Load cancelled.")
                    return
                if k == "enter":
                    break
                if k == "up":
                    sel = max(0, sel - 1)
                elif k == "down":
                    sel = min(len(names) - 1, sel + 1)
                elif k == "pgup":
                    sel = max(0, sel - avail)
                elif k == "pgdn":
                    sel = min(len(names) - 1, sel + avail)
                elif k == "home":
                    sel = 0
                elif k == "end":
                    sel = len(names) - 1
        finally:
            # Force the dashboard to fully repaint on the next frame (the overlay
            # cleared the screen, so a per-line diff would leave stale rows).
            self._last_frame = ""
            self._prev_lines = []
            self._full_repaint = True
        name = names[sel]
        snap = data[name]
        profiles.apply_to_args(self.ns, snap, normalise_host=_host_from_url)
        self.endpoint_v4, self.endpoint_v6 = [], []
        for srv in self.ns.server:
            v4, v6 = _resolve(srv)
            for ip in v4 + v6:
                bucket = self.endpoint_v4 if ":" not in ip else self.endpoint_v6
                if ip not in bucket:
                    bucket.append(ip)
        try:
            self.checks = build_checks(self.ns)
        except Exception as e:
            self.log_lines.append(f"[!] Health-check rebuild failed: {e}")
        self.log_lines.append(f"[+] Profile '{name}' loaded "
                              f"(servers: {', '.join(self.ns.server) or '-'}).")
        self._apply_launch_change(f"profile '{name}' loaded")

    # ── Leak test ([L]) ─────────────────────────────────────────────────────
    # One-key proof of what the tunnel actually does: compares the DIRECT
    # egress IP with the SOCKS-proxied egress IP and measures both latencies.
    #   direct == proxied -> traffic LEAKS outside the tunnel
    #   direct != proxied -> OK, the tunnel carries your traffic

    def _leak_test(self):
        port = getattr(self.ns, "port", 10808)

        def _curl(args):
            try:
                p = subprocess.run(
                    ["curl.exe", "-4", "--silent", "--max-time", "8"] + args,
                    capture_output=True, text=True, timeout=12)
                return p.stdout.strip()
            except Exception:
                return ""

        def _worker():
            self._blog("[*] Leak test running (direct vs proxied exit)...")
            t0 = time.time()
            direct = _curl(["https://api.ipify.org"])
            t_direct = time.time() - t0
            t0 = time.time()
            proxied = _curl(["--socks5-hostname", f"127.0.0.1:{port}",
                             "https://api.ipify.org"])
            t_proxy = time.time() - t0
            if not direct and not proxied:
                self._blog("[!] Leak test failed: no network answer at all.")
                return
            if not proxied:
                self._blog("[!] Leak test: the SOCKS proxy did not answer - "
                           "is v2rayN running on port " + str(port) + "?")
                return
            if direct == proxied:
                self._blog(f"[!] LEAK: direct and proxied exits are BOTH "
                           f"{proxied} - your real IP leaves outside the TUN!")
            else:
                self._blog(f"[+] NO LEAK: direct exit {direct or '?'}, "
                           f"tunnel exit {proxied}.")
            self._blog(f"[*] Latency: direct {t_direct * 1000:.0f} ms, "
                       f"via tunnel {t_proxy * 1000:.0f} ms.")

        threading.Thread(target=_worker, daemon=True).start()

    # ── Diagnostics export ([D]) ────────────────────────────────────────────

    def _export_diagnostics(self):
        """Write diagnostics_<timestamp>.txt next to the script: config, state,
        last health scan, event log tail, live routes and adapters. Everything
        a bug report needs, minus screenshots."""
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            time.strftime("diagnostics_%Y%m%d_%H%M%S.txt"))

        def _worker():
            secs = []
            secs.append(("CONFIG", json.dumps(self._profile_snapshot(),
                                              indent=2, default=str)))
            st = "RUNNING" if (self.proc and self.proc.poll() is None) else "STOPPED"
            pid = self.proc.pid if self.proc else None
            secs.append(("STATE", f"tunnel={st} helper_pid={pid} "
                                   f"graph_mode={self.graph_mode}"))
            rows = "\n".join(f"  [{'PASS' if ok else 'FAIL'}] {n}: {d}"
                             for _num, n, ok, d in self.results) or "  (no scan yet)"
            secs.append(("LAST HEALTH SCAN", rows))
            logs = "\n".join(self.log_lines[-150:]) or "  (empty)"
            secs.append(("EVENT LOG (last 150)", logs))
            # Structured event log — machine-readable version of the above.
            secs.append(("STRUCTURED EVENT LOG (all)", self.event_log.dump_text()
                          or "  (empty)"))
            # Visual health summary
            secs.append(("HEALTH REPORT", "\n".join(
                _health_format_panel(self.results, use_unicode=True))
                or "  (no scan yet)"))
            ok, out = _ps(
                "Get-NetRoute -ErrorAction SilentlyContinue | "
                "Where-Object { $_.InterfaceAlias -eq 'wintun' -or "
                "$_.DestinationPrefix -like '*/32' -or "
                "$_.DestinationPrefix -like '*/128' } | "
                "Select-Object DestinationPrefix,InterfaceAlias,NextHop,RouteMetric | "
                "Format-Table -AutoSize | Out-String -Width 200")
            secs.append(("ROUTES (wintun + host bypasses)",
                         out if ok else "  (query failed)"))
            ok, out = _ps(
                "Get-NetAdapter | Select-Object Name,Status,LinkSpeed | "
                "Format-Table -AutoSize | Out-String")
            secs.append(("ADAPTERS", out if ok else "  (query failed)"))
            try:
                with open(path, "w", encoding="utf-8") as f:
                    for title, body in secs:
                        f.write(f"{'=' * 70}\n{title}\n{'=' * 70}\n{body}\n\n")
                self._blog(f"[+] Diagnostics written: {os.path.basename(path)} "
                           f"- attach it to your bug report.")
            except Exception as e:
                self._blog(f"[!] Could not write diagnostics: {e}")

        threading.Thread(target=_worker, daemon=True).start()

    def _change_port(self, new_port_str):
        try:
            new_port = int(new_port_str)
            if not (1 <= new_port <= 65535):
                raise ValueError
        except ValueError:
            self.log_lines.append(f"[!] Invalid port: {new_port_str!r}")
            return
        old_port = self.ns.port
        if new_port == old_port:
            self.log_lines.append(f"[i] Already using SOCKS port {old_port}.")
            return
        self.log_lines.append(
            f"[*] Changing SOCKS port {old_port} -> {new_port}; tun2socks has to restart "
            "for this (no live hot-swap), so the tunnel will briefly drop...")
        self.stop()
        self.ns.port = new_port
        self.checks = build_checks(self.ns)
        self.speed_hist = []
        self.rx_hist = []
        self.tx_hist = []
        self.ping_samples = []
        self.baseline_bytes = [None]
        self._last_raw_rx = None
        self._last_raw_tx = None
        self.launch()
        self.log_lines.append(f"[+] Restarted with SOCKS port {new_port}")

    def _write_control_file(self):
        """Write the helper's live-reconfig control file (the exact path the
        helper polls in its monitor loop). Currently carries the DNS choice,
        so a running tunnel re-binds its DNS without a restart."""
        path = os.path.normpath(os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "tunnel", ".tuntop_control.json"))
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"dns4": getattr(self.ns, "dns4", None),
                           "dns6": getattr(self.ns, "dns6", None)}, f)
        except Exception as e:
            self.log_lines.append(f"[!] Could not write control file: {e}")

    def _change_dns(self, new_dns):
        import ipaddress
        ip = new_dns.strip()
        try:
            ipaddress.IPv4Address(ip)
        except Exception:
            self.log_lines.append(f"[!] Invalid IPv4 DNS address: {new_dns!r}")
            return
        old_dns = self.ns.dns4
        if ip == old_dns:
            self.log_lines.append(f"[i] Already using DNS4 {old_dns}.")
            return
        self.ns.dns4 = ip
        try:
            self.checks = build_checks(self.ns)
        except Exception as e:
            self.log_lines.append(f"[!] Health-check rebuild failed: {e}")
        self.log_lines.append(
            f"[*] Changing DNS4 {old_dns} -> {ip} LIVE - no tunnel restart needed.")
        # 1) Tell the RUNNING helper via the control file: it rebinds its
        #    active DNS and re-applies the Wintun config, so a later self-heal
        #    keeps the NEW choice instead of reverting to the launch value.
        self._write_control_file()
        # 2) Apply immediately here too (the helper's monitor loop would get
        #    there within ~1 s; doing it now makes [N] instant).
        def _apply():
            try:
                _ps("Set-DnsClientServerAddress -InterfaceAlias 'wintun' "
                    f"-ServerAddresses '{ip}' -ErrorAction SilentlyContinue; "
                    "Clear-DnsClientCache -ErrorAction SilentlyContinue | Out-Null")
                self._blog(f"[+] Wintun DNS set to {ip} (live).")
            except Exception as e:
                self._blog(f"[!] Live DNS apply failed ({e}) - the helper's "
                           "monitor loop will re-apply it within seconds.")
        threading.Thread(target=_apply, daemon=True).start()
        self.log_lines.append(
            "[i] Applies to NEW lookups right away; apps that cached the old "
            "answer refresh on their next resolver query.")

    def _change_endpoint_port(self, new_port_str):
        try:
            new_port = int(new_port_str)
            if not (1 <= new_port <= 65535):
                raise ValueError
        except ValueError:
            self.log_lines.append(f"[!] Invalid endpoint port: {new_port_str!r}")
            return
        old_port = getattr(self.ns, "endpoint_port", 443)
        if new_port == old_port:
            self.log_lines.append(f"[i] Already using endpoint port {old_port}.")
            return
        # The VLESS server is reached by IP regardless of port, so the endpoint
        # port only affects the connectivity health check and the displayed
        # config - no tunnel restart is required.
        self.ns.endpoint_port = new_port
        self.checks = build_checks(self.ns)
        self.log_lines.append(
            f"[+] Endpoint (VLESS server) port set to {new_port}; "
            "health check now targets this port.")

    def _edit_proxy2(self):
        """[Z] - add / change / remove the SECOND proxy (proxy2) while the app
        is running. Brings the second TUN hop (wintun2) up or down via a
        transparent background tunnel restart - no need to quit and relaunch,
        and no re-answering of the launch menu."""
        if getattr(self.ns, "proxy2_port", None):
            val = self._read_line(
                f"proxy2 is ON at 127.0.0.1:{self.ns.proxy2_port}. "
                "Type OFF to remove it, a port number to switch, "
                "or press Enter to cancel:",
                title="PROXY2  -  SECOND HOP",
                examples=["OFF   -> disable proxy2",
                          "10809 -> switch to that port",
                          "Enter -> cancel"])
            if not val:
                return
            if val.strip().lower() == "off":
                self.ns.proxy2_port = None
                self.ns.proxy2_server = []
                self.log_lines.append("[*] proxy2 disabled - restarting the "
                                      "tunnel in the background to tear wintun2 down...")
                self._apply_launch_change("proxy2 removed")
            else:
                self._proxy2_set_port(val)
        else:
            val = self._read_line(
                "Port of the SECOND local SOCKS5 proxy (e.g. 10809):",
                title="ADD PROXY2  -  SECOND HOP",
                examples=["the 2nd proxy client's inbound SOCKS5 port",
                          "hosts added via [A] -> 2 will route through it",
                          "empty = cancel"])
            self._proxy2_set_port(val)

    def _proxy2_set_port(self, val):
        try:
            port = int(val)
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            self.log_lines.append(f"[!] Invalid port: {val!r}")
            return
        self.ns.proxy2_port = port
        srv = self._read_line(
            "proxy2's own upstream server(s) (comma/space separated, "
            "empty = none):",
            title="PROXY2 SERVERS",
            examples=["IP/hostname(s) of the 2nd proxy's server",
                      "kept direct so the second hop can connect"])
        hosts = []
        if srv:
            for part in re.split(r"[,\s]+", srv.strip()):
                h = _host_from_url(part)
                if h and h not in hosts:
                    hosts.append(h)
        self.ns.proxy2_server = hosts
        try:
            self.checks = build_checks(self.ns)
        except Exception as e:
            self.log_lines.append(f"[!] Health-check rebuild failed: {e}")
        self.log_lines.append(
            f"[*] proxy2 set to 127.0.0.1:{port}"
            + (f" (upstream: {', '.join(hosts)})" if hosts else "")
            + " - restarting the tunnel in the background to bring wintun2 up...")
        self._apply_launch_change("proxy2 added/changed")

    def _geo_target(self):
        """Current geoip egress target: 'direct' | 'proxy2' | 'winvpn'.
        Falls back to the legacy --geoip-via-win-vpn bool when no explicit
        target has been chosen in [F] yet."""
        t = getattr(self.ns, "geoip_target", None)
        if t in ("direct", "proxy2", "winvpn"):
            return t
        return "winvpn" if getattr(self.ns, "geoip_via_win_vpn", False) else "direct"

    def _set_geo_target(self, t):
        """Persist a geoip egress target chosen in [F]. Keeps the legacy
        bool flags in sync so profiles/launch flags stay correct."""
        self.ns.geoip_target = t
        self.ns.geoip_via_win_vpn = (t == "winvpn")
        # An explicit choice wins over the legacy wintun (--geoip-via-vpn) mode.
        self.ns.geoip_via_vpn = False

    def _reapply_geo_bypass(self, target=None):
        """Re-install the configured geoip country bypass LIVE, without a full
        stop/start of the tunnel. Imports the helper module's pure-Python geo
        decoder + batched route installer and runs them in this process, so a
        changed geoip file or country code takes effect immediately. Routes
        installed here are tracked in self._live_geo_added and removed on stop()
        (the helper's own atexit only cleans what IT added at startup).

        target: egress for the country ranges - 'direct' (physical adapter),
        'proxy2' (second TUN hop) or 'winvpn' (connected Windows VPN). None
        keeps the currently configured target.

        This is invoked synchronously from the main thread by the [R] key, so it
        MUST NOT do the slow work inline: parse_geoip() (uncached) and
        add_geoip_bypass() (potentially thousands of routes via ThreadPool) would
        otherwise block draw() and keypress handling for the whole duration,
        freezing the UI. It hands the work to a background thread the same way
        every other mutating action (_add_bypass_ip, telemetry, connection
        polling) is backgrounded."""
        geo = getattr(self.ns, "geoip", None)
        if not geo:
            self.log_lines.append(
                "[!] No geoip file configured - set --geoip (and optional "
                "--geoip-code) and (re)start, or pick it in the launch menu.")
            return
        target = target or self._geo_target()
        code = (getattr(self.ns, "geoip_code", None) or "cn")
        self.log_lines.append(
            f"[*] Re-applying geoip bypass '{code}' live from {geo} "
            f"(via {target}) ...")
        threading.Thread(target=self._reapply_geo_bypass_worker,
                         args=(geo, code, target), daemon=True).start()

    def _reapply_geo_bypass_worker(self, geo, code, target="direct"):
        """Background worker for _reapply_geo_bypass(): does the actual parse +
        route install off the UI thread, logs via the thread-safe _blog(), and
        routes the helper's stdout (GEO markers + geoip diagnostics) through the
        same dispatcher the [S] subprocess reader uses, so the live GEO BYPASS
        LOADING panel actually appears for [R] (it previously never did, because
        the redirect swallowed [GEO-PARSE]/[GEO-LOAD]/[GEO-DONE] markers)."""
        try:
            import importlib
            here = os.path.dirname(os.path.abspath(__file__))
            pkg_dir = os.path.dirname(here)   # tuntop/ package (helper ships in tuntop/tunnel/)
            if pkg_dir not in sys.path:
                sys.path.insert(0, pkg_dir)
            helper = importlib.import_module("tuntop.tunnel.helper")
        except Exception as e:
            self._blog(f"[!] Could not import helper module: {e}")
            return
        try:
            # Route file-load progress to the geo panel too (mirrors the [S]
            # launch path, which passes an on_progress that emits [GEO-PARSE]).
            def _on_progress(pos, total):
                if total:
                    self._update_geo_progress(
                        f"[GEO-PARSE] code={code} loaded={pos} total={total}")
            cidrs = helper.parse_geoip(geo, code, on_progress=_on_progress)
        except Exception as e:
            self._blog(f"[!] geoip parse failed ({code}): {e}")
            return
        # Egress target changed live? Remove the routes that still point at
        # the OLD egress first, so no country CIDR ends up with two routes
        # (one via the old egress, one via the new).
        if (self._live_geo_added and self._geo_applied_target
                and self._geo_applied_target != target):
            self._blog(f"[*] Geo egress changed {self._geo_applied_target} -> "
                       f"{target}; removing the old country routes first...")
            for fam, dest, iface, gw in list(self._live_geo_added):
                if fam == "v4":
                    _del_route_v4(dest, iface, gw)
                else:
                    _del_route_v6(dest, iface, gw)
            self._live_geo_added = []
        if target == "proxy2":
            # Route the country ranges through the SECOND proxy hop (wintun2),
            # exactly how proxy2-tagged bypass entries are routed.
            if not getattr(self.ns, "proxy2_port", None):
                self._blog("[!] geoip via proxy2 requested but proxy2 is not "
                           "configured (press [Z]) - using the direct egress.")
                target = "direct"
            else:
                t2, t2_ip4, t2_ip6 = self._tun2_constants()
                g_iface, g_gw = t2, t2_ip4
                v6iface, v6gw = t2, t2_ip6
                self._blog(f"[*] geoip:{code} routed via the second proxy (wintun2).")
        if target == "direct" and (self._geo_target() == "winvpn"
                                   or getattr(self.ns, "geoip_via_win_vpn", False)):
            # Route the country ranges out through a CONNECTED Windows VPN.
            vpn4 = _get_vpn_ipv4_default(getattr(self.ns, "vpn_interface", None))
            vpn6 = _get_vpn_ipv6_default(getattr(self.ns, "vpn_interface", None))
            if not vpn4:
                self._blog(
                    "[!] geoip via Windows VPN requested but no connected Windows "
                    "VPN default route found - falling back to the physical adapter.")
                iface_gw = _get_ipv4_default()
                if not iface_gw:
                    self._blog(
                        "[!] No physical IPv4 gateway - cannot apply geo bypass live.")
                    return
                v6 = _get_ipv6_default()
                v6iface = v6gw = None
                if v6:
                    v6iface, v6gw = v6[0], v6[1]
                g_iface, g_gw = iface_gw[0], iface_gw[1]
            else:
                g_iface, g_gw = vpn4[0], vpn4[1]
                v6iface = v6gw = None
                if vpn6:
                    v6iface, v6gw = vpn6[0], vpn6[1]
                self._blog(
                    f"[*] geoip:{code} routed via connected Windows VPN ({g_iface}).")
        elif target == "direct" and getattr(self.ns, "geoip_via_vpn", False):
            # Mode 3 ("vpn as geo"): tunnel the country ranges through wintun
            # instead of sending them direct via the physical adapter.
            helper.ensure_wintun_ipv4()
            g_iface, g_gw = helper.TUN, helper.TUN4
            v6iface, v6gw = helper.TUN, helper.TUN6
            self._blog(
                f"[*] geoip:{code} tunneled via Wintun (vpn-as-geo mode).")
        else:
            iface_gw = _get_ipv4_default()
            if not iface_gw:
                self._blog(
                    "[!] No physical IPv4 gateway - cannot apply geo bypass live.")
                return
            v6 = _get_ipv6_default()
            v6iface = v6gw = None
            if v6:
                v6iface, v6gw = v6[0], v6[1]
            g_iface, g_gw = iface_gw[0], iface_gw[1]
        # Capture only the routes this call adds (the helper appends to its own
        # module-global geoip_added); we then hand ownership to the dashboard.
        # Redirect stdout to a sink that dispatches each line exactly like the
        # [S] subprocess reader: [GEO-...] markers feed the live progress panel,
        # repeated geoip diagnostics are deduplicated, and everything else is
        # surfaced to the event log via _blog (the thread-safe queue).
        before = len(helper.geoip_added)
        _old_stdout = sys.stdout
        sys.stdout = _GeoLogSink(self)
        try:
            helper.add_geoip_bypass(code, cidrs, g_iface, g_gw, v6iface, v6gw)
        except Exception as e:
            sys.stdout = _old_stdout
            self._blog(f"[!] geoip live apply failed: {e}")
            return
        sys.stdout = _old_stdout
        # The "[*] Installing geoip:code bypass (...)" and any deduplicated
        # geoip diagnostics were already routed through the sink; here we just
        # account for the routes we installed live. Dedup against what we already
        # track so repeated [R] presses don't accumulate duplicate tuples.
        new = [t for t in helper.geoip_added[before:] if t not in self._live_geo_added]
        self._live_geo_added.extend(new)
        helper.geoip_added = helper.geoip_added[:before]
        self._geo_applied_target = target
        if new:
            self._blog(
                f"[+] Geo bypass '{code}' re-applied live ({len(new)} routes).")
        else:
            self._blog(
                f"[i] Geo bypass '{code}' applied (routes already present).")

    def _poll_connections(self):
        """Throttled: log newly-seen [net] connections (process name + PID +
        remote endpoint) to the event log. Only runs while the tunnel is up.

        Runs on the background telemetry thread, so log lines go through
        self._blog() (the queue the main loop drains) rather than touching
        self.log_lines directly - loop() reassigns self.log_lines every frame,
        and appending from another thread races that and can silently drop
        lines."""
        now = time.time()
        if now - self._conn_poll_ts < 5.0:
            return
        self._conn_poll_ts = now
        if self.state != "RUNNING":
            return
        # Expire connections we haven't seen in a while (closed/finished), so a
        # finished flow can't pin a slot forever and a genuine later reconnect
        # can re-log cleanly.
        aged = [k for k, t in self._seen_conns.items() if now - t > 600]
        for k in aged:
            self._seen_conns.pop(k, None)
        for r in _get_active_connections():
            key = (r.get("Proc"), r.get("Remote"), r.get("Port"))
            if key in self._seen_conns:
                # Still open: move to the end so it counts as "most recently
                # seen" and is never evicted as one of the oldest entries.
                self._seen_conns.pop(key)
                self._seen_conns[key] = now
                continue
            self._seen_conns[key] = now
            # Evict the genuinely oldest entries (dict order = insertion/last-seen
            # order) instead of an arbitrary subset, so a long-lived connection
            # that keeps getting re-seen is never wrongly dropped and re-logged.
            if len(self._seen_conns) > 500:
                excess = len(self._seen_conns) - 300
                for _ in range(excess):
                    self._seen_conns.pop(next(iter(self._seen_conns)))
            self._blog(
                f"[net] {r.get('Proc')} (PID {r.get('Pid')}) -> {r.get('Remote')}:{r.get('Port')}")

    def _handle_key(self, key):
        """Handle one logical key press, from either the keyboard or a mouse
        click mapped to the same action. Returns True if the loop should
        redraw immediately instead of waiting out the rest of the frame.

        Every handler runs inside a guard: a bug in one action (a bad attribute,
        a failed PowerShell call, ...) must log itself and leave the dashboard
        running instead of taking the whole window down."""
        try:
            return self._handle_key_action(key)
        except Exception as e:
            import traceback
            self.log_lines.append(f"[!] Action '{key}' failed: {e.__class__.__name__}: {e}")
            for _ln in traceback.format_exc().splitlines()[-3:]:
                self.log_lines.append("    " + _ln.strip())
            self._full_repaint = True
            return True

    def _handle_key_action(self, key):
        if key == 'q':
            # Clear the routing table with a live progress bar, and do NOT exit
            # until every route is gone. Re-pressing [Q] during the cleanup is
            # ignored - the app commits to finishing the teardown first.
            self._shutdown_with_progress()
            return True
        elif key == 'c':
            self.run_checks()
            self.page = 0
            return True
        elif key == 's':
            if not self.proc or self.proc.poll() is not None:
                self.launch()
            return True
        elif key == 't':
            if self.proc and self.proc.poll() is None:
                self.log_lines.append("[*] Stopping tunnel (press [S] to restart)...")
                self.stop()
            return True
        elif key == 'v':
            self._toggle_vless_over_vpn()
            return True
        elif key == 'y':
            self._toggle_vpn_bypass()
            return True
        elif key == 'u':
            self._edit_servers()
            return True
        elif key == 'f':
            self._edit_geo()
            return True
        elif key == 'z':
            self._edit_proxy2()
            return True
        elif key == 'o':
            self._save_profile()
            return True
        elif key == 'i':
            self._load_profile()
            return True
        elif key == 'l':
            self._leak_test()
            return True
        elif key == 'd':
            self._export_diagnostics()
            return True
        elif key == 'w':
            # [W]: download / update the v2fly geoip database. No-op-free
            # when the file is already current; a background worker keeps
            # the UI responsive and logs progress into the event log.
            self._start_geo_download(force=True)
            return True
        elif key == 'k':
            self.page = max(0, self.page - 1)
            return True
        elif key == 'j':
            page_count = max(1, (max(len(self.results), 1) +
                                 self.page_size - 1) // self.page_size)
            self.page = min(page_count - 1, max(0, self.page + 1))
            return True
        elif key in ('up', 'pgup'):
            # Scroll the event log toward older entries.
            step = 10 if key == 'pgup' else 1
            self._log_scroll = min(len(self.log_lines), self._log_scroll + step)
            return True
        elif key in ('down', 'pgdn'):
            # Scroll the event log toward newer entries.
            step = 10 if key == 'pgdn' else 1
            self._log_scroll = max(0, self._log_scroll - step)
            return True
        elif key == 'home':
            self._log_scroll = len(self.log_lines)
            return True
        elif key == 'end':
            self._log_scroll = 0
            return True
        elif key in ('left', 'right'):
            # Horizontal scroll for long log lines / health details.
            step = 8
            self._hscroll = max(0, self._hscroll + (step if key == 'right' else -step))
            return True
        elif key == 'a':
            # Target choice: direct by default (existing muscle memory - just
            # press Enter and type a host); pick proxy2 only when the second
            # pipe is actually configured.
            target = "direct"
            examples = ["Enter -> direct (bypass the TUN entirely)",
                        "2     -> through the second proxy (if configured)",
                        "3     -> out through a connected Windows VPN"]
            if getattr(self.ns, "proxy2_port", None):
                t = self._read_line(
                    "Route via: [Enter]=direct, 2=proxy2 "
                    f"(127.0.0.1:{self.ns.proxy2_port}), 3=vpn:",
                    title="ADD BYPASS  -  CHOOSE TARGET",
                    examples=examples)
                if t and t.strip() == "2":
                    target = "proxy2"
                elif t and t.strip() == "3":
                    target = "vpn"
            else:
                t = self._read_line(
                    "Route via: [Enter]=direct, 3=vpn (Windows VPN):",
                    title="ADD BYPASS  -  CHOOSE TARGET",
                    examples=examples)
                if t and t.strip() == "3":
                    target = "vpn"
            val = self._read_line(
                "IP, hostname or URL to route via "
                f"{target.upper() if target == 'proxy2' else 'DIRECT (not through the TUN)'}:",
                title="ADD BYPASS  -  INSTANT, NO RESTART",
                examples=["https://whatismyip.com/   (a full URL is fine)",
                          "example.com   or   sub.example.com:443",
                          "1.2.3.4   or   2606:4700::1111"])
            if val:
                self._add_bypass_ip(val, target=target)
            return True
        elif key == 'x':
            self._select_bypass()
            return True
        elif key == 'b':
            # Toggle the dedicated Bypass list panel so the user can always see
            # what is currently routed DIRECT (not through the tunnel).
            if 'bypass' in self._hidden:
                self._hidden.discard('bypass')
                self.log_lines.append("[*] Bypass list panel: shown (toggle with [B]).")
            else:
                self._hidden.add('bypass')
                self.log_lines.append("[*] Bypass list panel: hidden (toggle with [B]).")
            self._shrink_size = None   # panel height changed -> re-budget
            return True
        elif key == 'p':
            val = self._read_line(f"New SOCKS5 port (current {self.ns.port}):")
            if val:
                self._change_port(val)
            return True
        elif key == 'n':
            val = self._read_line(f"New DNS4 server (current {self.ns.dns4}):")
            if val:
                self._change_dns(val)
            return True
        elif key == 'e':
            val = self._read_line(
                f"New VLESS endpoint port (current {getattr(self.ns, 'endpoint_port', 443)}):")
            if val:
                self._change_endpoint_port(val)
            return True
        elif key == 'g':
            self._cycle_graph_mode()
            self.log_lines.append(
                f"[*] Graph mode: {self._resolve_graph_mode()} "
                f"(cycle with [G]: block/half/braille/line; auto picks by host)")
            return True
        elif key == 'm':
            name = self._cycle_theme()
            self.log_lines.append(f"[*] Theme: {name} (cycle with [M])")
            self._full_repaint = True
            return True
        elif key == 'h':
            self._show_help = not self._show_help
            self._shrink_size = None   # footer height changed -> re-budget
            self.log_lines.append(
                f"[*] Help {'hidden' if not self._show_help else 'shown'} "
                f"(toggle with [H])")
            self._full_repaint = True
            return True
        elif key in ('1', '2', '3', '4', '5', '6', '0'):
            # Number keys follow the panels' TOP-TO-BOTTOM order on screen:
            # [1]=Metrics  [2]=Endpoint/TUN  [3]=Bypass list  [4]=Throughput
            # graph  [5]=Health checks  [6]=Event log  [0]=show all.
            if key == '0':
                self._hidden = set()
                self.log_lines.append("[*] All sections shown (toggle with [1]-[6])")
            else:
                sec = {'1': 'metrics', '2': 'endpoint', '3': 'bypass',
                       '4': 'graph', '5': 'checks', '6': 'log'}[key]
                if sec in self._hidden:
                    self._hidden.discard(sec)
                    self.log_lines.append(f"[*] Section shown: {sec} (toggle with [{key}])")
                else:
                    self._hidden.add(sec)
                    self.log_lines.append(f"[*] Section hidden: {sec} (toggle with [{key}])")
            self._shrink_size = None   # a panel's height changed -> re-budget
            self._full_repaint = True
            return True
        elif key == 'r':
            # Re-apply the configured geoip country bypass LIVE (no tunnel
            # restart needed).
            self._reapply_geo_bypass()
            return True
        return False

    # ── Health checks ────────────────────────────────────────────────────

    def run_checks(self):
        if self.checking:
            return
        self.checking = True
        self.results = []

        def _work():
            for i, (name, fn) in enumerate(self.checks, 1):
                try:
                    ok, detail = fn()
                    detail = str(detail).replace("\n", " ")[:80]
                    self.results.append((i, name, bool(ok), detail))
                except Exception as e:
                    self.results.append((i, name, False, str(e)[:80]))
            self.checking = False
            self.last_checked = time.strftime("%H:%M:%S")

        threading.Thread(target=_work, daemon=True).start()

    # ── Drawing ──────────────────────────────────────────────────────────

    def _update_geo_progress(self, line):
        """Parse helper geo markers and stash them for the geo-progress widget.

        Two marker kinds drive the panel:
          * [GEO-PARSE] code=<c> loaded=<L> total=<T>  - the file is being
            decoded (the *load* phase).  Stashed in geo_parse so the panel can
            show file loading progress instead of sitting at 0% until the whole
            file is read and then snapping to 100%.
          * [GEO-LOAD]  code=<c> loaded=<L> total=<T>  - the bypass routes are
            being installed (the *install* phase).
        Also handles [GEO-DONE] code=<c> (emitted once a category's install
        pass finishes, even if some routes failed) which opens the linger window
        so the panel clears instead of sticking forever.

        Called from the helper-reader thread (the [S] subprocess stdout) and
        from the [R] re-apply worker, so all mutations are guarded by
        _geo_lock - draw() snapshots these same dicts under that lock, which is
        what eliminates the "dictionary changed size during iteration" race."""
        with self._geo_lock:
            m = re.match(r'^\[GEO-PARSE\]\s+code=(\S+)\s+loaded=(\d+)\s+total=(\d+)', line)
            if m:
                code = m.group(1)
                loaded = int(m.group(2))
                total = int(m.group(3))
                if getattr(self, "_geo_load_started_ts", None) is None:
                    self._geo_load_started_ts = time.time()
                self.geo_parse[code] = (loaded, total)
                return
            m = re.match(r'^\[GEO-LOAD\]\s+code=(\S+)\s+loaded=(\d+)\s+total=(\d+)', line)
            if m:
                code = m.group(1)
                loaded = int(m.group(2))
                total = int(m.group(3))
                if getattr(self, "_geo_load_started_ts", None) is None:
                    self._geo_load_started_ts = time.time()
                self.geo_progress[code] = (loaded, total)
                # The install phase starting means the FILE DECODE is finished;
                # snap any stale [GEO-PARSE] value (e.g. frozen mid-file because
                # the decoder never emitted a final 100% marker) up to complete,
                # otherwise the File bar sits frozen forever next to a moving
                # Routes bar.
                _snap_parse_done(self.geo_parse, code)
                if total and loaded >= total:
                    self._geo_progress_done_ts = time.time()
                return
            m = re.match(r'^\[GEO-DONE\]\s+code=(\S+)', line)
            if m:
                # Install pass is finished (successfully or not).  Start the linger
                # window so the panel shows the final state briefly, then hides -
                # otherwise a partially-failed load (loaded < total) would keep the
                # "incomplete" panel on screen indefinitely.
                self._geo_progress_done_ts = time.time()
                _snap_parse_done(self.geo_parse, m.group(1))

    def draw(self):
        # While the [Q] progress-bar cleanup is running we own the whole screen;
        # never let the normal dashboard frame paint over it (or error out on a
        # half-torn-down tunnel state).
        if self._shutting_down:
            return
        size = shutil.get_terminal_size((100, 30))
        # Prefer the *visible console window* size. The true visible width is
        # never wider than the backing buffer, so taking the smaller of the
        # reported widths guarantees no line is ever laid out wider than the
        # screen (which would wrap and interleave the panels). srWindow is the
        # authoritative window rectangle; shutil falls back to the buffer.
        win = _get_window_size()
        widths = [size.columns]
        if win:
            widths.append(win[0])
            h = win[1]
        else:
            h = size.lines
        # Leave one column of slack so no line ever reaches the terminal's
        # final column. Writing to the last column triggers the classic Windows
        # console "pending-wrap" quirk: it shifts every subsequent
        # cursor-positioned line down a row, so the screen looks duplicated and
        # garbled after a few frames. Keeping every row strictly inside the
        # viewport (w-1) avoids it entirely.
        w = max(40, min(widths) - 1)

        # ── Adaptive shrink: units shrink FIRST, help footer removed LAST ──
        # On short windows (e.g. 16:9 screens) the fixed panels used to keep
        # their full size while the help footer was dropped first. Instead:
        #   1. health-check rows shrink (page of 8-12 -> down to 5)
        #   2. the throughput graph shrinks (5 -> 2 rows per direction)
        #   3. the help footer halves (4 -> 2 rows)
        #   4. and only THEN the footer is removed entirely.
        #
        # FEEDBACK-LOOP GUARD: the budget is derived from the panels' measured
        # height, and the panels' height depends on the budget - recomputing it
        # every frame oscillates (shrink -> smaller measurement -> un-shrink ->
        # bigger measurement -> shrink ...), which showed up as the graph/log
        # flickering big/small at certain window sizes. So the budget is only
        # recomputed when the window size (or a panel toggle) CHANGES, and the
        # height measurement is only taken from a frame with NO caps applied,
        # so it always reflects the un-shrunk layout.
        self._checks_cap = None
        self._graph_cap = None
        self._help_rows = 4 if self._show_help else 0
        if self._shrink_size != (h, w):
            self._shrink_size = (h, w)
            self._fixed_rows = None        # force a clean un-shrunk measurement
        if self._show_help and self._fixed_rows:
            deficit = (self._fixed_rows + 4 + 8 + 2) - h   # 8 = min log rows
            if deficit > 0:
                # A cap only frees rows if its panel is actually drawn.
                if "checks" not in self._hidden and self.results:
                    page = max(8, min(12, (w - 2) // 40))
                    take = min(max(0, page - 5), deficit)
                    if take:
                        self._checks_cap = page - take
                        deficit -= take
                if deficit > 0 and "graph" not in self._hidden:
                    cap = max(2, 5 - (deficit + 1) // 2)   # 2 rows freed per step
                    deficit -= 2 * (5 - cap)
                    if cap < 5:
                        self._graph_cap = cap
                if deficit > 0 and self._help_rows == 4:
                    self._help_rows = 2
                    deficit -= 2
                if deficit > 0:
                    self._help_rows = 0    # last resort: footer gone
        # Telemetry now runs in a background thread (see _telemetry_worker), so
        # draw() only reads the latest samples - it must never block on the
        # PowerShell/socket calls, or a slow proxy (get_ping can hang for
        # seconds) would freeze the whole UI, including keypress handling.
        # Snapshot the (concurrently-mutated) history lists once under the
        # lock so the rest of draw() reads a consistent, race-free view.
        with self._tel_lock:
            rx_snap = list(self.rx_hist)
            tx_snap = list(self.tx_hist)
            spd_snap = list(self.speed_hist)
            ping_snap = list(self.ping_samples)
        self._click_map = []
        pal = theme()   # active palette for this frame (switchable with [M])

        state = self.state
        passed = sum(1 for _, _, ok, _ in self.results if ok)
        failed = len(self.results) - passed
        done = len(self.results)
        total = len(self.checks)
        pct = (done / total) * 100 if total else 0

        L = []

        # ── Layout constants (symmetric panel widths) ───────────────────
        W    = w                # full terminal width
        IW   = w - 2            # inner width (between side borders)

        # Clamp the horizontal scroll so it can't run off the end of the widest
        # line we might show (event-log entries + health-check rows).
        _hmax = 0
        for e in self.log_lines:
            _w = len(re.sub(r'\x1b\[[^m]*m', '', str(e)))
            if _w > _hmax:
                _hmax = _w
        for num, name, ok, detail in self.results:
            _w = len(f"[{num:02}] {name}") + 1 + len(detail)
            if _w > _hmax:
                _hmax = _w
        self._hscroll = max(0, min(self._hscroll, max(0, _hmax - (IW - 1) + 2)))

        # ── Helper: ANSI-aware centre (escape codes are zero-width) ─
        def _acenter(text, width, fill=BOX_MID):
            vis = len(re.sub(r'\x1b\[[^m]*m', '', text))
            if vis >= width:
                return text
            total = width - vis
            left = total // 2
            right = total - left
            return fill * left + text + fill * right

        # ── Helper: symmetric top border for a titled panel (always w chars) ─
        # `accent` overrides the default border/title colour so each panel can
        # carry its own distinct accent (see THEMES). The title text itself is
        # brightened with BRIGHT for legibility.
        # Titles often embed their own colour codes that end in RESET (e.g. the
        # green ▼ DOWNLOAD label in THROUGHPUT). After such a RESET every later
        # character would fall back to the terminal default (white fill dashes,
        # white closing corner) - so RESET is re-armed with the border colour.
        def _recolor(body, col):
            return body.replace(RESET, RESET + col)

        def _top(title, accent=None):
            col = accent if accent else pal["active"]
            body = _recolor(_acenter(title, IW, BOX_MID), col)
            return f"{col}{BOX_LC}{BRIGHT}{body}{col}{BOX_RC}{RESET}"

        # ── Helper: symmetric side-border row (always w visible chars) ─
        def _row(content, color=None, hscroll=0, accent=None):
            c = accent if accent else (color if color else pal["light"])
            # _hpad() both pads short content AND horizontally scrolls/clips
            # content that runs over IW-1 visible columns, so a long label,
            # log line, or health detail can be scrolled into view with the
            # Left/Right arrow keys instead of silently overrunning the border.
            inner = _hpad(content, IW - 1, hscroll)
            return f"{c}{BOX_V} {inner}{c}{BOX_V}{RESET}"

        # ── Helper: symmetric bottom border (always W visible chars) ───
        def _bot(accent=None):
            col = accent if accent else pal["inact"]
            return f"{col}{BOX_BL}{BOX_BS * IW}{BOX_BR}{RESET}"

        # ── Width-parameterised variants (for the side-by-side wide layout) ──
        # Same as the above but build at an arbitrary panel width so two panels
        # can be placed next to each other instead of stacked full width.
        def _topw(title, width, accent=None):
            col = accent if accent else pal["active"]
            iw = width - 2
            body = _recolor(_acenter(title, iw, BOX_MID), col)
            return f"{col}{BOX_LC}{BRIGHT}{body}{col}{BOX_RC}{RESET}"

        def _roww(content, width, hscroll=0, accent=None):
            c = accent if accent else pal["light"]
            inner = _hpad(content, width - 3, hscroll)
            return f"{c}{BOX_V} {inner}{c}{BOX_V}{RESET}"

        def _botw(width, accent=None):
            col = accent if accent else pal["inact"]
            return f"{col}{BOX_BL}{BOX_BS * (width - 2)}{BOX_BR}{RESET}"

        def _blankw(width, accent=None):
            col = accent if accent else pal["light"]
            return f"{col}{BOX_V}{' ' * (width - 2)}{BOX_V}{RESET}"

        # ── Status bar (top) ───────────────────────────────────────────
        # Styled like the TUN CONFIG panel: coloured [ STATE ] badge (clickable),
        # then dot-separated dim-KEY bright-VALUE pairs. The badge stays the
        # first thing on the row so its click-map columns (2 .. 2+len) hold.
        mode = "VLESS via VPN" if getattr(self.ns, "vless_over_vpn", False) else "DIRECT"
        vpn_bp_on = not getattr(self.ns, "no_vpn_bypass", False)

        badge = f"[ {state} ]"
        # Colour by state category, not just the RUNNING string: green =
        # traffic flowing (RUNNING/DEGRADED keeps green but see below),
        # yellow = a start/stop/self-heal phase in flight, red = stopped or
        # failed. A normal start now reads VERIFYING in yellow instead of
        # flashing an alarming red "not RUNNING".
        if state in (TunnelState.RUNNING.value, TunnelState.DEGRADED.value):
            badge_color = GREEN
        elif state in (TunnelState.STOPPED.value, TunnelState.FAILED.value):
            badge_color = RED
        else:
            badge_color = YELLOW
        pairs = [
            ("MODE", WHITE + mode + RESET),
            ("PROXY", CYAN + f"127.0.0.1:{self.ns.port}" + RESET),
            ("VPN BP", (GREEN if vpn_bp_on else YELLOW)
                       + ("on" if vpn_bp_on else "off") + RESET),
        ]
        if getattr(self.ns, "geoip", None):
            gcode = str(getattr(self.ns, "geoip_code", "cn")).upper()
            pairs.append(("GEO", BRIGHT + gcode + RESET))
        if getattr(self.ns, "proxy2_port", None):
            # Second pipe status - only rendered when --proxy2-port is set, so
            # the bar looks unchanged for anyone not using the feature. The
            # wintun2 pipe lives and dies with the helper subprocess, so its
            # up/down mirrors the tunnel's operational state (never guessed
            # from a route that might be stale).
            p2_up = state in (TunnelState.RUNNING.value,
                              TunnelState.DEGRADED.value)
            pairs.append(("PROXY2", (GREEN if p2_up else YELLOW)
                          + f"127.0.0.1:{self.ns.proxy2_port} "
                          + ("up" if p2_up else "down") + RESET))
        if getattr(self.ns, "vless_over_vpn", False) and self._vpn_status:
            vpn_ok = self._vpn_status != "NOT CONNECTED"
            pairs.append(("VPN", (GREEN if vpn_ok else YELLOW)
                                 + self._vpn_status + RESET))

        L.append(_top("V2RAY TUN - NETWORK MONITOR"))
        status_row = len(L)
        # Clickable [ RUNNING ]/[ STOPPED ] badge - toggles start/stop.
        # Content starts 2 columns in (border + one space); the badge is the
        # first item. Briefly highlight it when the user just clicked it.
        badge_disp = self._flash_wrap(
            status_row, 2, 2 + len(badge), f"{badge_color}{BRIGHT}{badge}{RESET}")
        sep = f"{GRAY} \u00b7 {RESET}"
        status_text = badge_disp + sep + sep.join(
            f"{GRAY}{k}{RESET} {v}" for k, v in pairs)
        L.append(_row(status_text))
        self._click_map.append((status_row, 2, 2 + len(badge), "toggle"))
        L.append(_bot())

        # ── Metric cards (panel) ───────────────────────────────────────
        # Histories hold KiB/s (get_wintun_speed divides the byte delta by
        # 1024); convert to MiB/s for display. Use the snapshots taken at the
        # top of draw() so we never read a list mid-mutation by the worker.
        cur_k  = (spd_snap[-1] if spd_snap else 0.0) / 1024
        avg_k  = (sum(spd_snap) / len(spd_snap) if spd_snap else 0.0) / 1024
        peak_k = (max(spd_snap) if spd_snap else 0.0) / 1024
        total_mb = max(0, self.total_traffic / 1024 / 1024)

        # PING colour/quality ramp: 0 ms -> green, ~75 ms -> amber, >=150 ms -> red.
        # Same green->yellow->red gradient the bars use, instead of a flat cyan.
        ping_avg = round(sum(ping_snap) / len(ping_snap)) if ping_snap else None
        if ping_avg is not None:
            ping_frac = min(1.0, ping_avg / 150.0)
            ping_col = _gradient_color(ping_frac)
            ping_val = f"{ping_avg:>3d} ms"
            # Quality bar: full when the ping is low (good), empty when high.
            ping_bar = 1.0 - ping_frac
        else:
            ping_col = CYAN
            ping_val = "  - ms"
            ping_bar = 0.0

        # Cards for the METRICS panel. The HEALTH row is only shown while the
        # HEALTH CHECKS panel itself is visible ([5] toggles both together) -
        # duplicating it while its panel is hidden just shows stale "0 pass /
        # 0 fail". TOTAL carries no bar (a cumulative total has no meaningful
        # fill level) - just the bright value.
        total_bytes = max(0, int(self.total_traffic))
        cards = [
            (GREEN, "SPEED",  f"{cur_k:6.2f} MiB/s",
             (cur_k / max(peak_k, 0.1)) if peak_k > 0 else 0.0),
            (ping_col, "PING", ping_val, ping_bar, False),
        ]
        if "checks" not in self._hidden:
            cards.append((
                GREEN if failed == 0 and done > 0 else YELLOW,
                "HEALTH", (f"{passed} pass / {failed} fail" if done > 0 else "-"),
                pct / 100, done > 0))
        cards.append((CYAN, "TOTAL", f"{total_mb:6.1f} MiB", 0.0, False))

        # ── Unified CONFIG panel (single entity: ENDPOINT/TUN + BYPASS) ──
        # The endpoint/TUN settings and the "what is NOT tunneled" list are ONE
        # concept: the VLESS server (and anything added live via [A]) are exactly
        # the routes that are bypassed. They used to be two separately-titled
        # panels that both printed the server address - a duplicated view of
        # the same data. They are now ONE panel rendered as two aligned columns:
        #   LEFT  - TUNNEL  : key/value config rows (server, proxy, DNS...)
        #   RIGHT - DIRECT  : what is routed AROUND the tunnel, with status dots
        # Every line is kept well under half-panel width so the wide side-by-side
        # layout never runs into the shared inner border.
        resolved = self.endpoint_v4 + self.endpoint_v6

        def _kv(label, value):
            """Aligned 'LABEL  value' row: dim fixed-width key, coloured value."""
            return f"{GRAY}{label:<10}{RESET}{value}"

        srv_txt = ", ".join(self.ns.server)
        tun = [
            _kv("SERVER", f"{BRIGHT}{srv_txt}{RESET}"),
        ]
        if resolved:
            # Avoid echoing an identical duplicate of SERVER - say so instead.
            if all(r in self.ns.server for r in resolved) and len(resolved) <= len(self.ns.server):
                tun.append(_kv("RESOLVED", f"{GRAY}(same as server){RESET}"))
            else:
                tun.append(_kv("RESOLVED", f"{CYAN}{', '.join(resolved)}{RESET}"))
        else:
            tun.append(_kv("RESOLVED", f"{GRAY}-{RESET}"))
        tun.append(_kv("PROXY", f"{CYAN}127.0.0.1:{self.ns.port}{RESET}"
                                f"{GRAY} socks5{RESET}"))
        tun.append(_kv("DNS", f"{CYAN}{self.ns.dns4}{RESET}"
                              f"{GRAY} · endpoint TCP/{getattr(self.ns, 'endpoint_port', 443)}{RESET}"))
        tun.append(_kv("EDIT", f"{GREEN}[A]{RESET} add "
                               f"{GREEN}[X]{RESET} remove "
                               f"{GRAY}· instant, no restart{RESET}"))
        tun.append(_kv("", f"{GREEN}[P]{RESET} port  "
                           f"{GREEN}[N]{RESET} dns  "
                           f"{GREEN}[E]{RESET} ep-port"))

        # Right column body: everything routed DIRECT (not through the TUN).
        bl = []
        bl.append(f"{BRIGHT}{pal['endpoint']}ROUTED DIRECT{RESET}"
                  f"{GRAY} - these never enter the tunnel{RESET}")
        if getattr(self.ns, "vless_over_vpn", False):
            vpn_val = f"{GREEN}ON{RESET}{GRAY} · VLESS rides Windows VPN{RESET}"
            vpn_dot = DOT_OK
        elif getattr(self.ns, "no_vpn_bypass", False):
            vpn_val = f"{YELLOW}OFF{RESET}{GRAY} · VPN traffic IS tunneled{RESET}"
            vpn_dot = DOT_WARN
        else:
            vpn_val = f"{GREEN}ON{RESET}{GRAY} · VPN endpoints stay direct{RESET}"
            vpn_dot = DOT_OK
        bl.append(" " + vpn_dot + " " + _kv("VPN", vpn_val))
        if getattr(self.ns, "geoip", None):
            _gt = self._geo_target()
            if _gt == "proxy2":
                geo_egress, geo_dot = "via second proxy (proxy2)", DOT_OK
            elif _gt == "winvpn":
                geo_egress, geo_dot = "via connected Windows VPN", DOT_OK
            elif getattr(self.ns, "geoip_via_vpn", False):
                geo_egress, geo_dot = "tunneled via wintun (vpn-as-geo)", DOT_WARN
            else:
                geo_egress, geo_dot = "direct via wifi/physical", DOT_OK
            code = str(getattr(self.ns, "geoip_code", "cn")).upper()
            geo_val = f"{BRIGHT}{code}{RESET}{GRAY} · {geo_egress}{RESET}"
            bl.append(" " + geo_dot + " " + _kv("GEO", geo_val))
        else:
            bl.append(" " + DOT_IDLE + " " +
                      _kv("GEO", f"{GRAY}none configured{RESET}"))

        extras = self._bypass_resolved_list()
        rule = BOX_MID * 3
        bl.append(f" {GRAY}{rule} added live {rule}"
                  f"{RESET} {GRAY}([A]/[X]){RESET}")
        if extras:
            for it in extras:
                if it["status"] == "ok" and it["ips"]:
                    dot = DOT_OK
                elif it["status"] == "pending":
                    dot = DOT_WARN
                else:
                    dot = DOT_FAIL
                bl.append(f"   {dot} {BRIGHT}{it['entry']}{RESET}  {it['detail']}")
        else:
            bl.append(f"   {DOT_IDLE} {GRAY}none yet"
                      f"{RESET} {GRAY}- [A] routes a host/IP around the tunnel{RESET}")

        metrics_hidden = "metrics" in self._hidden
        endpoint_hidden = "endpoint" in self._hidden
        bypass_hidden = "bypass" in self._hidden

        # ── METRICS panel (SPEED / PING / HEALTH) ───────────────────────
        # Always drawn full width. The speed/ping/health bar width is derived
        # from the panel's REAL inner width minus the actual label+value width,
        # so the bar is present at every terminal width - it used to vanish once
        # the window grew past the wide side-by-side threshold (the old fixed
        # "name_w - 30" magic number shrank it to nothing on wide layouts).
        if not metrics_hidden:
            metrics_body = []
            for c in cards:
                show_bar = c[4] if len(c) > 4 else True
                _label = f"{c[1]} {c[2]}"
                _labw = len(re.sub(r'\x1b\[[^m]*m', '', _label))
                bw = max(6, IW - _labw - 4)
                bar_str = _bar(c[3], bw) if show_bar else ""
                # Dim key + bright coloured value (same kv style as TUN CONFIG).
                metrics_body.append(
                    f"{GRAY}{c[1]}{RESET} {c[0]}{BRIGHT}{c[2]}{RESET}"
                    + (f" {bar_str}" if bar_str else ""))
            # Clicking a panel's TITLE bar toggles that panel (same as [1]..[6]).
            self._click_map.append((len(L), 0, w, "1"))
            L.append(_topw("METRICS", w, pal["metrics"]))
            for b in metrics_body:
                L.append(_roww(b, w, accent=pal["metrics"]))
            L.append(_botw(w, pal["metrics"]))

        # ── Single CONFIG entity: ENDPOINT/TUN  +  BYPASS ───────────────
        # One titled box. On wide terminals both halves render as two columns
        # inside that single box (split by one shared inner border), so the
        # config and the bypass set are presented as ONE entity, never two panels.
        if not (endpoint_hidden and bypass_hidden):
            show_cfg = not endpoint_hidden
            show_bp = not bypass_hidden
            cfg_body = ["  " + line for line in tun]
            bypass_body = ["  " + line for line in bl]
            n_live = len(extras)
            title = (f"TUN CONFIG {BOX_MID}{BOX_MID} BYPASS LIST {BOX_MID}{BOX_MID} "
                     f"{n_live} added live")
            if show_cfg and show_bp and w > 140:
                # Column maths: each row is BOX_V + A + BOX_V + B + BOX_V, where
                # A = " " + left(La) and B = " " + right(Lb). For the row to be
                # EXACTLY w visible columns (matching _topw/_botw):
                #   3 borders + (1+La) + (1+Lb) = w  ->  La + Lb = w - 5.
                # The old "(w-3)//2 for both" formula made every body row ONE
                # column short on even widths, so the closing border hung a
                # space behind the panel edge.
                La = (w - 5) // 2
                Lb = (w - 5) - La
                body_h = max(len(cfg_body), len(bypass_body))
                self._click_map.append((len(L), 0, w, "3"))
                L.append(_topw(title, w, pal["endpoint"]))
                for i in range(body_h):
                    lc = cfg_body[i] if i < len(cfg_body) else ""
                    rc = bypass_body[i] if i < len(bypass_body) else ""
                    A = " " + _hpad(lc, La)
                    B = " " + _hpad(rc, Lb)
                    acc = pal["endpoint"]
                    # Re-arm the accent before each wall - the column content
                    # ends in RESET and would otherwise leave white walls.
                    L.append(f"{acc}{BOX_V}{A}{acc}{BOX_V}{B}{acc}{BOX_V}{RESET}")
                L.append(_botw(w, pal["endpoint"]))
            else:
                self._click_map.append((len(L), 0, w, "3"))
                L.append(_topw(title, w, pal["endpoint"]))
                if show_cfg:
                    for b in cfg_body:
                        L.append(_roww(b, w, accent=pal["endpoint"]))
                if show_bp:
                    for b in bypass_body:
                        L.append(_roww(b, w, accent=pal["endpoint"]))
                L.append(_botw(w, pal["endpoint"]))

        # ── Geo bypass load progress (live while loading, lingers 6s) ─────
        # Snapshot the (concurrently-mutated by the helper-reader thread) geo
        # progress state once under the lock, so the rest of this block reads a
        # consistent view and never iterates a dict mid-mutation by _update_geo_progress().
        with self._geo_lock:
            geo_progress = dict(self.geo_progress)
            geo_parse = dict(self.geo_parse)
            geo_done_ts = self._geo_progress_done_ts
            geo_disp = self._geo_disp_loaded
        if geo_progress or geo_parse:
            # Two phases, both keyed by code:
            #   geo_parse     = the geoip file is being decoded (the *load* itself)
            #   geo_progress  = the bypass routes are being installed
            gp_codes = list(geo_progress.keys()) or list(geo_parse.keys())
            # File-load phase fraction (0..1) from [GEO-PARSE] markers. This is
            # what shows the file actually being read instead of sitting at 0%.
            if geo_parse:
                fp_loaded = sum(v[0] for v in geo_parse.values())
                fp_total = max(1, sum(v[1] for v in geo_parse.values()))
                file_frac = min(1.0, fp_loaded / fp_total)
            else:
                file_frac = 0.0
            # Route-install phase (eased toward the real target) from [GEO-LOAD].
            gp_loaded_target = sum(v[0] for v in geo_progress.values())
            gp_total = max(1, sum(v[1] for v in geo_progress.values()))
            # Ease the *shown* loaded value so the bar animates smoothly instead
            # of snapping 0 -> 100% (install chunks finish in a short burst).
            if gp_loaded_target > geo_disp:
                geo_disp = min(
                    gp_loaded_target,
                    geo_disp + max(1.0, (gp_loaded_target - geo_disp) * 0.2))
            else:
                geo_disp = gp_loaded_target
            # Write the eased value back under the lock (draw() is its only
            # writer, but keep it consistent with the snapshot above).
            with self._geo_lock:
                self._geo_disp_loaded = geo_disp
            gp_loaded = int(round(geo_disp))
            inst_frac = min(1.0, gp_loaded / gp_total)
            any_incomplete = any(v[0] < v[1] for v in geo_progress.values())
            finished = geo_done_ts is not None
            # Show while the file is still being parsed, or the install is
            # incomplete, or within the 6s linger after the [GEO-DONE] marker.
            lingering = finished and (time.time() - geo_done_ts) < 6
            gp_show = lingering or (not finished and (any_incomplete or bool(geo_parse)))
            if gp_show:
                def _gkv(label, text):
                    # Same aligned kv style as the TUN CONFIG panel.
                    return f"{GRAY}{label:<8}{RESET}{text}"
                bw = max(6, IW - 24)
                # ── Live-activity extras (so the panel never looks stuck) ──
                # Spinner driven by wall-clock (animates every frame even when
                # no new marker arrived) + a phase label that names what is
                # actually happening right now + elapsed seconds.
                _spin = "|/-\\"[int(time.time() * 6) % 4]
                if not finished and geo_parse and not any_incomplete \
                        and gp_loaded == 0:
                    phase = f"Decoding geoip file {_spin}"
                elif not finished:
                    phase = (f"Installing routes {_spin} "
                             f"(netsh batches in parallel)")
                else:
                    phase = "Finished - panel hides shortly"
                start_ts = getattr(self, "_geo_load_started_ts", None)
                if finished and start_ts and geo_done_ts:
                    _elapsed = max(0, int(geo_done_ts - start_ts))
                elif start_ts:
                    _elapsed = max(0, int(time.time() - start_ts))
                else:
                    _elapsed = 0
                phase += f"{GRAY}   elapsed {_elapsed:3d}s{RESET}" \
                    if start_ts else ""
                _geolines = [
                    _gkv("Phase", f"{BRIGHT}{phase}{RESET}"),
                    _gkv("Codes", f"{BRIGHT}{', '.join(gp_codes)}{RESET}"),
                    _gkv("File", f"{CYAN}{file_frac * 100:5.1f}%{RESET}  "
                                 f"{_bar(file_frac, bw)}"),
                    _gkv("Routes", f"{GREEN}{inst_frac * 100:5.1f}%{RESET}  "
                                   f"{_bar(inst_frac, bw)}"),
                    _gkv("Loaded", f"{BRIGHT}{gp_loaded}{RESET}"
                                   f"{GRAY} / {gp_total} routes{RESET}"),
                ]
                L.append(_topw("GEO BYPASS LOADING", w, pal["health"]))
                for _b in _geolines:
                    L.append(_roww(_b, w, accent=pal["health"]))
                L.append(_botw(w, pal["health"]))

        # ── Throughput graph: edge-to-edge gradient area chart ───────────
        # The graph fills the entire inner width and touches both side borders
        # (no leading indent) so it reads as one continuous, modern panel.
        # Each direction is a vertical-gradient filled area with a bright
        # "live" edge on the newest sample; both share one scale so download
        # and upload are directly comparable.
        graph_w = IW                 # edge-to-edge: span the full inner width
        series_h = max(2, min(5, self._graph_cap or 5))  # area rows per direction (taller = smoother)
        gmode = self._resolve_graph_mode()   # block | half | braille | line

        # ── Mood engine ─────────────────────────────────────────────────
        # The chart should FEEL like traffic, not just plot it: a smooth wave,
        # colours that heat up with intensity, and a named state (idle /
        # trickle / flowing / surge) rendered in the title. Everything here is
        # pure presentation - it never touches the sampled values themselves.
        def _smooth(vals):
            """3-tap moving average over the stretched series - kills the
            1-sample jitter without shifting peaks (half-weight on edges)."""
            if len(vals) < 3:
                return list(vals)
            out = [vals[0]]
            for i in range(1, len(vals) - 1):
                out.append(0.25 * vals[i - 1] + 0.5 * vals[i] + 0.25 * vals[i + 1])
            out.append(vals[-1])
            return out

        _SPARK_BLOCKS = "\u2581\u2582\u2583\u2584\u2585\u2586\u2587\u2588"

        def _spark(seq, width=18):
            """Tiny inline sparkline for the title strip (Unicode terminals
            only; empty string otherwise so ASCII mode is unaffected).
            Renders left-to-right with newest sample on the left."""
            if not USE_UNICODE or not seq:
                return ""
            seq = list(reversed(list(seq)[-width:]))
            m = max(max(seq), 1e-9)
            n = len(_SPARK_BLOCKS) - 1
            return "".join(
                _SPARK_BLOCKS[min(n, int(v / m * n))] for v in seq)

        # Shared vertical scale so the two directions are directly comparable.
        peak_ref = max((max(rx_snap) if rx_snap else 0.0),
                       (max(tx_snap) if tx_snap else 0.0), 0.01)

        # Mood state per direction from the CURRENT sample vs window peak.
        def _mood_of(cur):
            if cur <= 2048:                       # < 2 KiB/s == idle
                return "idle", DIM
            frac = cur / max(peak_ref, 1.0)
            if frac >= 0.66:
                return "surge", YELLOW
            if frac >= 0.15:
                return "flowing", BRIGHT + WHITE
            return "trickle", CYAN

        cur_rx = rx_snap[-1] if rx_snap else 0.0
        cur_tx = tx_snap[-1] if tx_snap else 0.0
        mood_r, col_r = _mood_of(cur_rx)
        mood_t, col_t = _mood_of(cur_tx)
        # Overall chip follows whichever direction is livelier.
        overall_mood, overall_col = \
            ((mood_r, col_r) if cur_rx >= cur_tx else (mood_t, col_t))
        # Colour temperature of the fills: idle/trickle keep the cool brand
        # palette, surge heats the tip stops toward warm white so sustained
        # heavy traffic visibly "glows hot".
        hot = overall_mood == "surge"
        down_stops = ((16, 74, 44), (58, 208, 112),
                      (235, 255, 200) if hot else (150, 255, 180))
        up_stops = ((12, 60, 88), (48, 168, 220),
                    (230, 244, 255) if hot else (140, 235, 255))

        def _area(vals, hi, lo, peak, height, mode="block", idle_mark=None,
                  stops=None, pulse=False):
            """Vertical-gradient filled area chart for one series.

            All modes use the SAME bottom-up orientation as the block view:
            0 at the bottom of the section, max at the top (the callers reverse()
            the returned rows, which drops the baseline to the section's bottom).
            They differ only in glyph style / vertical resolution:
              block   = 1x  (PROGRESS_FULL / PROGRESS_MED)
              half    = 2x  (adds the upper-half block U+2580 for a smooth edge)
              braille = 4x  (braille dots, left column)
              line    = 2x  (NO fill - just a bright edge line riding on the
                             series top; falls back to block without Unicode)
            - `stops` is an ordered RGB list the gradient interpolates through
              piecewise-linearly (bottom -> top); pass 3 stops for the
              deep-base -> mid -> hot-tip "glow" look. Falls back to the classic
              two-colour lo->hi ramp when omitted.
            - idle_mark: when given, empty cells on the BASELINE row render as
              this dim glyph, so a flat/idle graph still reads as a live chart
              with a visible zero-line instead of blank rows.
            - pulse: gently blink the newest live sample (~2 Hz) so an active
              edge reads as alive; pass False when traffic is idle.
            - The newest (leftmost) sample gets a bright edge so the live data
              point is always visible at the left edge.
            - Per-column ANSI is preserved and every column is exactly one
              visible cell wide, so the row is safe to drop straight between
              the box borders."""
            # Pre-compute the per-row band colour by piecewise-linear
            # interpolation across the gradient stops.
            grad = [tuple(c) for c in stops] if stops else [tuple(lo), tuple(hi)]
            if len(grad) == 1:
                grad = grad * 2
            segs = len(grad) - 1
            bands = []
            for row_i in range(height):
                t = row_i / max(1, height - 1)
                seg = min(segs - 1, int(t * segs))
                f = t * segs - seg
                a, b = grad[seg], grad[seg + 1]
                r = round(a[0] + (b[0] - a[0]) * f)
                g = round(a[1] + (b[1] - a[1]) * f)
                bb = round(a[2] + (b[2] - a[2]) * f)
                bands.append(_rgb(r, g, bb))

            # All three modes share the block view's bottom-up orientation: 0 at
            # the bottom of the section, max at the top. _area() draws the fill
            # anchored at the TOP of its own rows (row_i=0 is the baseline, just
            # like block), and the callers reverse() that so the baseline lands at
            # the section's bottom. The earlier half/braille bug was that they
            # anchored the fill at the BOTTOM of _area (inverted vs block); now
            # they anchor at the top, so upload and download both read 0=low,
            # max=high. Only the glyph style / resolution differ between modes.
            mult = {"block": 1, "half": 2, "braille": 4, "line": 2}.get(mode, 1)
            # Left-column braille dots, ordered BOTTOM -> TOP so a partially filled
            # cell fills from its bottom upward (continuous with the full cell
            # below). 0x40=dot7 (bottom), 0x04=dot3, 0x02=dot2, 0x01=dot1 (top).
            # NB: 0x08 is dot4 = top-RIGHT, NOT a bottom dot - using it scattered a
            # dot to the upper-right, which is what made the braille view look broken.
            braille_dots = (0x40, 0x04, 0x02, 0x01)
            rows = []
            for row_i in range(height):
                band = bands[row_i]
                chars = []
                for i, v in enumerate(vals):
                    ratio = (v / peak) if peak else 0.0
                    live = (i == 0 and ratio > 0)
                    # Gentle ~2 Hz heartbeat on the newest sample - only when
                    # the mood engine says traffic is flowing/surge, never
                    # while idle (a blinking dot at rest reads as noise).
                    if live and pulse and int(time.time() * 2) % 2 == 0:
                        col = BRIGHT + WHITE
                    else:
                        col = WHITE if live else band
                    # Sub-levels filled from the baseline (top of _area). One cell
                    # spans `mult` sub-levels, so `passed` is how many of THIS
                    # cell's sub-levels are filled (the rest stay empty).
                    passed = ratio * height * mult - mult * row_i
                    if mode == "line":
                        # Unfilled edge line: ink only in the cell where the
                        # series top sits, riding on the TOP of the fill level
                        # so it reads as a line above the (omitted) area.
                        # Sub-cell resolution: low fraction -> lower-half block,
                        # high fraction -> upper-half block.
                        if passed > 0:
                            frac = min(1.0, passed / mult)
                            glyph = "\u2580" if frac >= 0.5 else "\u2584"
                            chars.append(f"{col}{glyph}")
                        elif idle_mark and row_i == 0:
                            chars.append(f"{P_INACT}{idle_mark}{RESET}")
                        else:
                            chars.append(" ")
                        continue
                    if passed >= mult:                 # cell fully filled
                        if mode == "braille":
                            bits = 0
                            for k in range(mult):
                                bits |= braille_dots[k]
                            chars.append(f"{col}{chr(0x2800 | bits)}")
                        else:
                            chars.append(f"{col}{PROGRESS_FULL}")
                    elif passed > 0:                   # partial cell
                        if mode == "half":
                            # Fill from the bottom of the cell (U+2584) so the
                            # partial row connects to the full cell below.
                            chars.append(f"{col}\u2584")
                        elif mode == "braille":
                            bits = 0
                            for k in range(int(passed)):
                                bits |= braille_dots[k]
                            chars.append(f"{col}{chr(0x2800 | bits)}")
                        else:
                            chars.append(f"{col}{PROGRESS_MED}")
                    else:
                        if idle_mark and row_i == 0:
                            # Baseline zero-line: keeps an idle chart visibly
                            # "alive" instead of four blank rows.
                            chars.append(f"{P_INACT}{idle_mark}{RESET}")
                        else:
                            chars.append(" ")
                rows.append("".join(chars) + RESET)
            return rows

        def _grow(content):
            # Edge-to-edge graph row. Use the same BOX_V side-wall glyph as
            # every other panel (coloured to this panel's accent) so the graph
            # doesn't look like a heavier-weight widget bolted onto the layout.
            # The density blocks inside the content still do the "this is a
            # graph" visual work; the walls don't need to. `content` ends in
            # RESET (the per-column colouring does that), so re-arm the accent
            # before the closing wall or it renders default-white.
            acc = pal["throughput"]
            return f"{acc}{BOX_V}{content}{acc}{BOX_V}{RESET}"

        # Stretch/truncate each series to exactly `graph_w` columns so the
        # chart always spans the full inner width edge-to-edge. The time axis
        # runs RIGHT-TO-LEFT: the newest sample is at the left edge (column 0)
        # and older samples trail off to the right. Before history fills up,
        # the available samples are linearly stretched across the whole width
        # instead of being padded with blanks, so the graph never looks empty.
        def _fit(vals):
            n = len(vals)
            if n == 0:
                return [0.0] * graph_w
            if n >= graph_w:
                # Newest first: reverse the most-recent graph_w samples.
                return list(reversed(vals[-graph_w:]))
            out = []
            for i in range(graph_w):
                # Column 0 = newest sample, right edge = oldest.
                pos = (graph_w - 1 - i) * (n - 1) / (graph_w - 1)
                lo = int(pos)
                hi = min(n - 1, lo + 1)
                frac = pos - lo
                out.append(vals[lo] * (1 - frac) + vals[hi] * frac)
            return out

        if "graph" not in self._hidden:
            down = _smooth(_fit(rx_snap))
            up   = _smooth(_fit(tx_snap))

            peak_mib = peak_ref / 1024
            self._click_map.append((len(L), 0, w, "4"))
            _spark_rx = _spark(rx_snap)
            _title_bits = [f"{GREEN}\u25bc DOWNLOAD{RESET}  /  "
                           f"{CYAN}\u25b2 UPLOAD{RESET}"]
            if _spark_rx:
                _title_bits.append(f"{GREEN}{_spark_rx}{RESET}")
            L.append(_top("   ".join(_title_bits), pal["throughput"]))
            # Upload (cyan glow, ▲) on top - baseline at the middle divider, fills up.
            for gl in reversed(_area(up, up_stops[-1], up_stops[0],
                                     peak_ref, series_h, gmode,
                                     stops=up_stops,
                                     pulse=overall_mood in ("flowing", "surge"))):
                L.append(_grow(gl))
            # Faint divider between the two directions (keeps them readable).
            L.append(f"{P_INACT}{BOX_V}{BOX_MID * graph_w}{BOX_V}{RESET}")
            # Download (green glow, ▼) on the bottom - 0 at the BOTTOM of this
            # section, filling UPWARD, exactly like upload. Each direction is its own
            # area chart with its baseline at its own base (0 at the bottom),
            # brightening toward the top. _area()'s baseline is its top row, so the
            # reverse places that baseline at the bottom of the section.
            for gl in reversed(_area(down, down_stops[-1], down_stops[0],
                                     peak_ref, series_h, gmode,
                                     stops=down_stops,
                                     pulse=overall_mood in ("flowing", "surge"))):
                L.append(_grow(gl))

            # Stats line: current (+ share of scale) + window average + peak per
            # direction, plus session total. avg gives the eye a reference the
            # raw peak hides; %-of-scale explains how tall the bars SHOULD look.
            _avg_r = (sum(rx_snap) / len(rx_snap) / 1024) if rx_snap else 0.0
            _avg_t = (sum(tx_snap) / len(tx_snap) / 1024) if tx_snap else 0.0
            down_k = cur_rx / 1024
            up_k   = cur_tx / 1024
            pdown_k = (max(rx_snap) if rx_snap else 0.0) / 1024
            pup_k   = (max(tx_snap) if tx_snap else 0.0) / 1024
            _pct_r = min(100.0, cur_rx / max(peak_ref, 1e-9) * 100)
            _pct_t = min(100.0, cur_tx / max(peak_ref, 1e-9) * 100)
            L.append(_row(
                f"{GREEN}\u25bc {down_k:6.2f}{DIM}%{_pct_r:3.0f}{RESET}"
                f"{DIM} avg {_avg_r:5.1f} peak {pdown_k:6.2f}{RESET}   "
                f"{CYAN}\u25b2 {up_k:6.2f}{DIM}%{_pct_t:3.0f}{RESET}"
                f"{DIM} avg {_avg_t:5.1f} peak {pup_k:6.2f}{RESET}   "
                f"{DIM}total {total_mb:7.1f} MiB   "
                f"scale {peak_mib:.2f} MiB/s  [G] {gmode}{RESET}"))
            L.append(_bot(pal["throughput"]))


        # ── Health checks table (paged) ────────────────────────────────
        if "checks" not in self._hidden:
            page_size = max(8, min(12, IW // 40))
            if self._checks_cap:
                page_size = max(5, min(page_size, self._checks_cap))
            self.page_size = page_size
            page_count = max(1, (max(done, 1) + page_size - 1) // page_size)
            self.page = min(self.page, max(0, page_count - 1))
            start = self.page * page_size

            # Title shows a plain (ANSI-free) pass/fail summary so _top() can still
            # centre it by visible width; the per-row colour/shape lives below.
            self._click_map.append((len(L), 0, w, "5"))
            L.append(_top(f"HEALTH CHECKS   \u2714 {passed} ok   \u2717 {failed} fail",
                          pal["health"]))

            if not self.results:
                # No checks run yet - don't pad to a fixed height, just show a short
                # hint so the panel collapses instead of eating a full page of blanks.
                L.append(_row(DIM + "  Press [C] Scan to run the health-check suite" + RESET))
            else:
                sep_line = f"{pal['light']}{BOX_V} {BOX_MID * (IW - 1)}{BOX_V}{RESET}"
                L.append(sep_line)

                check_rows = self.results[start:start + page_size]
                # Proportional column widths: {border} {name(n_w)} {detail(d_w)} {border}
                # Content fills panel minus left/right spacing: n_w + d_w = IW - 4.
                # Clamp both columns to a minimum of 1 so a very narrow window (or
                # mid-resize) can never produce a negative width - f"{x:<{n_w}}"
                # raises ValueError for negative n_w, which used to feed the
                # unthrottled "[!] Draw error" spam loop in loop().
                iw_inner = max(2, IW - 4)
                n_w = min(36, max(1, iw_inner // 2))      # name column
                d_w = iw_inner - n_w                      # detail column
                if d_w < 1:
                    d_w = 1
                    n_w = iw_inner - d_w
                n_w = max(1, n_w)
                d_w = max(1, d_w)

                for num, name, ok, detail in check_rows:
                    if ok:
                        mark = GREEN + "\u2714" + RESET        # ✔ green check
                        name_col = GREEN + BRIGHT
                        det_col = DIM
                        border = P_LIGHT
                    else:
                        mark = RED + "\u2717" + RESET          # ✗ red cross
                        name_col = RED + BRIGHT
                        det_col = RED
                        border = RED                          # failed rows get a red frame
                    name_plain = f"{num:02} {name}"
                    name_part = f"{name_plain:<{n_w}}"         # pad the plain text only
                    det_part = detail
                    L.append(_row(
                        f"{mark} {name_col}{name_part}{RESET} {det_col}{det_part}{RESET}",
                        hscroll=self._hscroll, color=border,
                    ))

                if len(check_rows) < page_size:
                    for _ in range(page_size - len(check_rows)):
                        L.append(_row(""))

                footer_sep = f"{pal['health']}{BOX_V} {BOX_MID * (IW - 1)}{BOX_V}{RESET}"
                L.append(footer_sep)
                if page_count > 1:
                    pg_label = f"Page {self.page + 1}/{page_count}"
                    pg_row = len(L)
                    L.append(_row(pg_label.center(IW - 4, BOX_MID)))
                    # Left half of the page-label row = prev page, right half = next.
                    mid_x = 2 + (IW - 1) // 2
                    self._click_map.append((pg_row, 2, mid_x, "k"))
                    self._click_map.append((pg_row, mid_x, 2 + (IW - 1), "j"))
            L.append(_bot(pal["health"]))

        # ── Event log (bottom panel, scrollable with Up/Down / PgUp/PgDn) ──
        # Its height adapts to the (freely-resizable) window: every fixed
        # section above is drawn first and stays fully visible, and any extra
        # rows the user adds by making the window taller are given to THIS
        # panel. The top of the dashboard never moves or gets pushed off-screen.
        # The guide (three help rows) is rendered AFTER the log. When the window
        # gets short, the guide yields its space to the log FIRST - it is hidden
        # before the log loses rows, never the other way around. _show_help is
        # toggled with [H] (key or the footer button).
        GUIDE_MIN_LOG = 8  # keep the guide only while the log can stay this tall
        footer_h = self._help_rows   # 4 / 2 / 0 - decided by the shrink budget
        log_visible = h - len(L) - footer_h - 2   # -2 = this panel's own borders
        if self._show_help and footer_h and log_visible < GUIDE_MIN_LOG:
            # Absolute fallback (first frame after a resize, before the shrink
            # budget has a measurement): drop the guide so the log keeps its
            # rows. Normally the panels ABOVE have already shrunk instead.
            footer_h = 0
            log_visible = h - len(L) - footer_h - 2
        if log_visible < 3:
            log_visible = 3
        self._log_visible = log_visible
        # Measure everything above the log + footer - but ONLY from a frame
        # with no shrink caps applied, so the next budget is computed from the
        # UNSHRUNK height (measuring a shrunk frame feeds the feedback loop).
        if not self._checks_cap and not self._graph_cap:
            self._fixed_rows = len(L)

        if "log" not in self._hidden:
            total = len(self.log_lines)
            # Clamp the scroll position so it stays within the history.
            self._log_scroll = max(0, min(self._log_scroll, max(0, total - 1)))
            v = self._log_visible
            end = total - self._log_scroll
            start = max(0, end - v)
            visible = self.log_lines[start:end] if total else ["Waiting for events..."]
            title = "EVENT LOG"
            if total > v:
                # 1-based range of the slice currently shown.
                title += f"  ({start + 1}-{end} of {total})"
            if self._hscroll > 0:
                title += f"  [\u25c4 scrolled {self._hscroll}c]"
            self._click_map.append((len(L), 0, w, "6"))
            L.append(_top(title, pal["log"]))
            for entry in visible:
                formatted = _format_log_line(entry)
                if formatted == entry:
                    formatted = f"{DIM}{entry}{RESET}"
                L.append(_row(formatted, hscroll=self._hscroll))
            # Keep the panel a fixed height so the border doesn't jump while scrolling.
            for _ in range(max(0, v - len(visible))):
                L.append(_row(""))
            L.append(_bot(pal["log"]))

        # ── Keyboard/mouse help (footer, two rows: run controls + live edit) ─
        def _help_row(items):
            # Each item is (action, "[X] description"). Render the key as a
            # filled chip and the description in dim text, so the bindings read
            # like a modern TUI footer. Build the row from already-coloured
            # segments and feed it through _row() so it is clipped to the safe
            # width. The old code did plain_line.center(w) (which does NOT clip
            # when the text is wider than the window) then sliced the ANSI-laden
            # string by *visible* indices, cutting escape sequences in half and
            # letting the row overflow/wrap - that wrapped, corrupted line is
            # exactly what produced the duplicated, literal-"2m" footer.
            gap = "    "
            segs = []
            offset = 0
            row = len(L)
            for key, label in items:
                keychar = label[1] if len(label) > 1 else "?"
                br = label.find("]")
                desc = label[br + 1:].strip() if br != -1 else ""
                chip = (f"\033[48;2;55;68;92m\033[38;2;225;232;255m"
                        f" {keychar} \033[0m")
                seg = chip + f"{DIM}{desc}{RESET}"
                seg_vis = len(re.sub(r'\x1b\[[^m]*m', '', seg))
                # Click-map offsets use the rendered (visible) width so they line
                # up with the chips the user actually sees.  The row is drawn via
                # _row(), which prepends a border char plus a literal space, so
                # real content starts at screen column 2 - add that +2 offset to
                # match the convention used by the status badge and pagination row.
                self._click_map.append((row, offset + 2, offset + seg_vis + 2, key))
                offset += seg_vis + len(gap)
                segs.append(seg)
            L.append(_row(gap.join(segs)))

        if footer_h:
            _help_rows = [
                [
                    ('h', "[H] Hide help"), ('c', "[C] Scan"), ('s', "[S] Start"),
                    ('t', "[T] Stop"), ('q', "[Q] Quit"), ('l', "[L] Leak Test"),
                    ('d', "[D] Diagnostics"), ('m', "[M] Color"), ('g', "[G] Graph"),
                ],
                [
                    ('a', "[A] +Bypass (instant)"), ('x', "[X] -Bypass (instant)"),
                    ('b', "[B] Bypass List"),
                    ('r', "[R] Re-apply Geo"), ('z', "[Z] Proxy2"), ('p', "[P] Port"), ('n', "[N] DNS"),
                    ('e', "[E] Endpoint"),
                ],
                [
                    ('u', "[U] Servers"), ('v', "[V] Proxy(VLESS) thru VPN"),
                    ('y', "[Y] VPN Bypass"), ('f', "[F] Geo Config"),
                    ('w', "[W] Get/Update GeoIP"),
                    ('o', "[O] Save Profile"), ('i', "[I] Load Profile"),
                    ('k', "[K/J] Page"), ('up', "[Arrows] Scroll"),
                ],
                [
                    ('1', "[1] Metrics"), ('2', "[2] Endpoint"),
                    ('3', "[3] Bypass"), ('4', "[4] Graph"),
                    ('5', "[5] Checks"), ('6', "[6] Log"),
                    ('0', "[0] Show All"),
                ],
            ]
            # Shrink-aware: 2 footer rows keep the essentials (controls +
            # live-edit); only a full window shows all four.
            for items in _help_rows[:footer_h]:
                _help_row(items)

        # ── Render to terminal ─────────────────────────────────────────
        # Flicker reduction strategy:
        #   1. Wrap the whole paint in the DEC synchronized-output pair so the
        #      terminal only flips the new frame to the screen once, atomically.
        #   2. Skip entirely when nothing changed (no-op frames).
        #   3. Otherwise, only rewrite the *lines that actually changed* since
        #      the previous frame (per-line diff) instead of clearing and
        #      repainting the whole screen every tick.
        #   4. Cap the redraw rate (~25 fps) via _frame_interval in the loop.
        #
        # Clip the row list to the visible window height FIRST. If the frame is
        # taller than the window, the console would otherwise scroll as it
        # writes and leave the VIEWPORT parked at the bottom (showing the event
        # log, not the header). By never emitting more than `h` rows we keep the
        # viewport pinned to the top.
        if h and len(L) > h:
            L = L[:h]
        frame = "\n".join(L)
        if frame == self._last_frame:
            return
        self._last_frame = frame

        # Decide between a full repaint and a surgical diff update.
        needs_full = self._full_repaint or len(L) != len(self._prev_lines) \
            or w != self._prev_w
        self._full_repaint = False
        self._prev_w = w

        out = []
        if needs_full:
            # Hide the cursor, clear, home, then paint every line.
            out.append("\033[?25l\033[2J\033[H")
            out.append("\033[?2026h")  # begin synchronized output
            out.append("\n".join(L))
            out.append("\033[?2026l")  # end synchronized output
            out.append("\033[H")
        else:
            out.append("\033[?25l")
            out.append("\033[?2026h")  # begin synchronized update
            out.append("\033[H")
            for i, line in enumerate(L):
                if i >= len(self._prev_lines) or line != self._prev_lines[i]:
                    # Move to row i+1, clear it, write the new content. The
                    # trailing \r returns the cursor to column 1 of this row so a
                    # stray auto-wrap can never bleed into the next positioned
                    # write and shift the frame.
                    out.append(f"\033[{i + 1};1H\033[2K{line}\r")
            out.append("\033[?2026l")  # end synchronized update
            out.append("\033[H")
        sys.stdout.write("".join(out))
        sys.stdout.flush()
        self._prev_lines = L

    # ── Main loop ────────────────────────────────────────────────────────

    def loop(self):
        import msvcrt
        self._init_mouse()
        self.log_lines.append(
            f"[*] Terminal: {_detect_terminal_host()}  "
            f"Glyphs: {'unicode' if USE_UNICODE else 'ascii'}  "
            f"Mouse: {'on' if self._mouse_ok else 'off (keyboard only)'}")
        # One delayed mouse retry: right after an elevated relaunch the input
        # handle can briefly report unusable; a second attempt ~2s in recovers
        # those cases without touching working setups.
        _mouse_retry_at = time.time() + 2.0

        # All speed/ping/connection sampling now runs in a background thread, so
        # this loop stays purely: drain logs -> draw -> handle input. A slow
        # proxy or PowerShell call can no longer stall keypress handling.
        self._telemetry_running = True
        threading.Thread(target=self._telemetry_worker, daemon=True).start()
        # Bypass-entry resolver: normalises entries, resolves them (with the
        # UDP/DoH fallbacks), retries with backoff while they fail, and installs
        # the /32 - /128 bypass routes as soon as they resolve. Off the UI thread
        # so a slow or dead resolver can never freeze a frame or a keypress.
        self._ensure_bypass_resolver()

        try:
            while self.running:
                # Delayed mouse re-init (see _mouse_retry_at above).
                if not self._mouse_ok and not self._mouse_retry_done and \
                        time.time() >= _mouse_retry_at:
                    self._mouse_retry_done = True
                    before = self._stdin_handle
                    self._init_mouse()
                    if self._mouse_ok and self._stdin_handle is not before:
                        self.log_lines.append("[+] Mouse: on (late init worked).")

                # Tunnel state watcher: announce the tunnel going DOWN the
                # moment the machine reaches a terminal state (with the
                # reason). Every other transition is already mirrored into
                # the event log by _on_tunnel_state_change; the very first
                # check only primes the tracker so a fresh dashboard doesn't
                # log a bogus "DOWN" line.
                st = self.state
                if st != self._last_seen_state:
                    if self._last_seen_state is not None and \
                            st in (TunnelState.STOPPED.value,
                                   TunnelState.FAILED.value):
                        self.logs.put("[!] TUN went DOWN - traffic leaves "
                                      "via the physical NIC until restarted.")
                    self._last_seen_state = st

                # Drain log queue
                while not self.logs.empty():
                    try:
                        self.log_lines.append(self.logs.get_nowait())
                    except queue.Empty:
                        break
                self.log_lines = self.log_lines[-200:]

                try:
                    self.draw()
                except Exception as e:
                    # A single bad frame (odd terminal-resize timing, a
                    # console-API hiccup, etc.) must not take the whole
                    # dashboard down - log it and keep going. BUT never let the
                    # same draw failure append every frame (~25/s): the
                    # geo-progress race (or a too-narrow terminal) used to spam
                    # the identical "[!] Draw error: ..." string until it evicted
                    # all other log history. Log it once, and only repeat if the
                    # message actually changes or 5s have passed (so a genuinely
                    # new error still surfaces).
                    msg = f"[!] Draw error: {e}"
                    now = time.time()
                    if msg != self._last_draw_err or now - self._last_draw_err_ts > 5.0:
                        self.log_lines.append(msg)
                        self._last_draw_err = msg
                        self._last_draw_err_ts = now

                # Poll input until the next scheduled redraw. A short sleep
                # keeps key detection near-instant without busy-spinning the
                # CPU; a keypress is handled and the screen refreshes at once.
                deadline = time.time() + self._frame_interval
                redraw_now = False
                while time.time() < deadline and not redraw_now:
                    key = self._next_key()
                    if key is None:
                        time.sleep(0.005)
                        continue
                    redraw_now = self._handle_key(key)
        finally:
            # Always tear down the tunnel and routes, even on an unhandled
            # exception above - leaving them behind is what makes the *next*
            # launch fail or hang.
            self._telemetry_running = False
            sys.stdout.write("\033[?25h")  # restore the caret
            sys.stdout.flush()
            # Stop the recovery worker before teardown: no attempt may fire
            # while the route table is being cleared, and its thread must
            # never keep the process alive past exit.
            self.recovery.pause("app exiting")
            self.recovery.shutdown()
            self.stop()
            self._restore_console_mode()

    def launch(self):
        if not getattr(self.ns, "server", None):
            return
        # A fresh user start always re-arms recovery (clears give-up state)
        # and closes any stale incident from the previous run.
        self.recovery.resume()
        self.logs.put("[*] Start requested - launching tunnel helper...")
        import sys as _sys
        # helper.py ships in the tuntop/tunnel package, one level up from this
        # ui module, not alongside dashboard.py.
        cmd = [_sys.executable, os.path.join(os.path.dirname(os.path.dirname(__file__)), "tunnel", "helper.py"),
               "--server", *self.ns.server, "--port", str(self.ns.port),
               "--tun2socks", self.ns.tun2socks, "--dns4", self.ns.dns4]
        if getattr(self.ns, "no_vpn_bypass", False):
            cmd.append("--no-vpn-bypass")
        if getattr(self.ns, "vless_over_vpn", False):
            cmd.append("--proxy-over-vpn")
        if getattr(self.ns, "vpn_interface", None):
            cmd += ["--vpn-interface", self.ns.vpn_interface]
        for ip in getattr(self.ns, "bypass_ip", []) or []:
            cmd += ["--bypass-ip", ip]
        if getattr(self.ns, "proxy2_port", None):
            # Second proxy pipe: the port flag turns the whole feature on.
            cmd += ["--proxy2-port", str(self.ns.proxy2_port)]
            for s in getattr(self.ns, "proxy2_server", []) or []:
                cmd += ["--proxy2-server", s]
            for ip in getattr(self.ns, "proxy2_bypass_ip", []) or []:
                cmd += ["--proxy2-bypass-ip", ip]
        geo_ready = bool(getattr(self.ns, "geoip", None))
        if geo_ready and not os.path.isfile(self.ns.geoip):
            # Configured geoip file is not on disk: start the tunnel WITHOUT
            # country bypass right away, and fetch the v2fly database in the
            # BACKGROUND instead of freezing the UI on a multi-megabyte
            # download. A [T]+[S] cycle applies it once saved.
            self.logs.put(f"[!] Geoip file not found: {self.ns.geoip}")
            if self._start_geo_download():
                self.logs.put("[*] Starting WITHOUT geo bypass for now - "
                              "[T]hen [S] after the download to apply it.")
            else:
                self.logs.put("[!] Download could not start - starting "
                              "without geo bypass.")
            geo_ready = False
        if geo_ready:
            cmd += ["--geoip", self.ns.geoip]
            if getattr(self.ns, "geoip_code", "cn") != "cn":
                cmd += ["--geoip-code", self.ns.geoip_code]
        if getattr(self.ns, "geoip_via_vpn", False) and self._geo_target() == "direct":
            cmd.append("--geoip-via-vpn")
        if self._geo_target() == "winvpn":
            cmd.append("--geoip-via-win-vpn")

        try:
            # Force the child (helper) into UTF-8 so its log lines are readable
            # and never turn into '?'.
            child_env = os.environ.copy()
            child_env["PYTHONUTF8"] = "1"
            child_env["PYTHONIOENCODING"] = "utf-8"
            child_env["PYTHONUNBUFFERED"] = "1"  # critical: helper stdout is
            # piped (not a TTY), so Python block-buffers it by default.
            # Without this the "[+] TUNNEL ACTIVE" marker can sit in a 4KB
            # buffer forever, leaving the dashboard stuck at STARTING.
            self.proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                encoding="utf-8", errors="replace", env=child_env,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
            # The helper is alive: the machine leaves STOPPED and walks the
            # start sequence from here (VERIFYING on "[+] TUNNEL ACTIVE",
            # RUNNING on the START SEQUENCE COMPLETE marker - see _read).
            self.tunnel.try_transition(TunnelState.STARTING,
                                       f"helper launched (PID {self.proc.pid})")
            self.logs.put(f"[+] Helper launched (PID {self.proc.pid}) - "
                          f"bringing up the Wintun adapter, routes follow...")
            self.logs.put(f"[dns] configured resolver: {self.ns.dns4}")
            # Fresh tunnel: fresh dedup for [net] lines (ordered dict; see
            # _poll_connections for why a set is no longer used).
            self._seen_conns = {}
            # Fresh tunnel: drop stale prior-run geo categories / progress.
            # Guarded by _geo_lock for consistency with _update_geo_progress()
            # and draw(), even though no reader thread is live at this point.
            with self._geo_lock:
                self.geo_progress = {}           # drop stale prior-run categories
                self.geo_parse = {}              # drop stale prior-run file-load phase
                self._geo_progress_done_ts = None
                self._geo_disp_loaded = 0.0
                self._geo_load_started_ts = None  # re-time this run's geo load
            self._geo_done_announced = False     # re-announce geo load per start
            # Startup watchdog: if the helper doesn't emit "[+] TUNNEL ACTIVE"
            # within STARTUP_TIMEOUT seconds it's almost certainly hung on a
            # PowerShell/netsh call.  Kill it and report FAILED instead of
            # leaving the dashboard stuck at STARTING forever.
            self._start_ts = time.time()
            self._start_timeout = 90  # seconds
            def _read():
                for line in self.proc.stdout:
                    try:
                        s = _console_safe(line.rstrip())
                    except Exception:
                        break
                    # [GEO-PARSE] / [GEO-LOAD] / [GEO-DONE] markers carry live
                    # load progress; route them to the progress widget instead of
                    # the event log. GEO-DONE also gets a one-shot event-log
                    # announcement so the user sees the geo phase finish.
                    if s.startswith("[GEO-PARSE]") or s.startswith("[GEO-LOAD]") or s.startswith("[GEO-DONE]"):
                        self._update_geo_progress(s)
                        if s.startswith("[GEO-DONE]") and not getattr(self, "_geo_done_announced", False):
                            self._geo_done_announced = True
                            self.logs.put("[+] Geo bypass loaded - country routes installed.")
                        continue
                    # The helper's geoip diagnostics (the "skipped N non-routable"
                    # note and its siblings) are otherwise emitted on every tunnel
                    # restart; deduplicate them to ONE event-log line per session.
                    if self._geo_diag_suppress(s):
                        continue
                    # Start-sequence milestones: surface each phase to the
                    # user AND advance the tunnel state machine to match.
                    if s.strip() == "[+] TUNNEL ACTIVE":
                        self.tunnel.try_transition(
                            TunnelState.VERIFYING,
                            "routes installed - probing real traffic")
                        self.logs.put("[*] Routes installed - verifying traffic "
                                      "through the TUN...")
                        self.logs.put(s)
                        continue
                    if "Press Ctrl+C to stop" in s:
                        # Emitted by the helper only AFTER wait_for_tunnel_stable()
                        # succeeded - this is the true "ready" moment.
                        self.tunnel.try_transition(
                            TunnelState.RUNNING,
                            "start sequence complete - tunnel stable")
                        self.logs.put("[+] START SEQUENCE COMPLETE - the TUN is "
                                      "READY TO USE.")
                        continue
                    if s.strip() == "[*] Press Ctrl+C to stop.":
                        continue   # replaced by the READY announcement above
                    if s.startswith("[*] Loading geoip file bypass"):
                        self.logs.put("[*] Loading geo bypass ranges (this can "
                                      "take a moment)...")
                        continue
                    # Monitor failures/self-heal: reflect them on the state
                    # machine immediately, so DEGRADED/RECOVERING show up in
                    # the UI instead of the dashboard claiming RUNNING while
                    # the tunnel silently struggles.
                    if s.startswith("[MONITOR] tunnel check failed"):
                        self.tunnel.try_transition(
                            TunnelState.DEGRADED,
                            s.split(":", 1)[-1].strip() or "monitor probe failed")
                        # Also tell the recovery engine. It waits 90s (the
                        # helper's own self-heal window) before escalating;
                        # a self-heal success (-> RUNNING) closes the
                        # incident instead.
                        self.recovery.report_failure(
                            FailureKind.DNS,
                            s.split(":", 1)[-1].strip() or "monitor probe failed")
                    if s.startswith("[*] Self-healing:"):
                        self.tunnel.try_transition(
                            TunnelState.RECOVERING,
                            "self-heal: re-applying wintun config and routes")
                        self.logs.put(s)
                        continue
                    if s.startswith("[+] Self-heal applied."):
                        self.tunnel.try_transition(
                            TunnelState.RUNNING, "self-heal applied")
                        self.logs.put(s)
                        continue
                    # The helper's monitor prints "[MONITOR] tunnel OK: ..."
                    # every 30s forever - pure noise in the log (it says nothing
                    # new). Drop the success heartbeats; a DEGRADED tunnel that
                    # probes OK again is silently restored to RUNNING above the
                    # drop. FAILURES still pass through below, since those
                    # actually need attention.
                    if s.startswith("[MONITOR] tunnel OK"):
                        self.tunnel.try_transition(
                            TunnelState.RUNNING, "monitor probe OK")
                        continue
                    self.logs.put(s)
                # Helper stdout closed: the process has exited (clean stop,
                # crash or external kill). Drive the machine down so neither
                # the UI nor live-bypass logic can keep treating a dead
                # tunnel as RUNNING. try_transition (not transition): the
                # user's [Q] teardown may already have claimed STOPPING.
                self.tunnel.try_transition(TunnelState.STOPPING,
                                           "helper process exited")
                self.tunnel.try_transition(TunnelState.STOPPED,
                                           "helper process exited")
            threading.Thread(target=_read, daemon=True).start()
            # Watchdog: fires even when the helper produces zero output (hung
            # on a netsh/PowerShell call).  Checks every 5 s; if the helper
            # is still alive and still in STARTING after _start_timeout
            # seconds, kill it so the user gets FAILED instead of a frozen
            # dashboard.
            def _startup_watchdog():
                while self.proc and self.proc.poll() is None:
                    time.sleep(5)
                    if self.tunnel.current is not TunnelState.STARTING:
                        return  # moved past STARTING - all good
                    elapsed = time.time() - self._start_ts
                    if elapsed > self._start_timeout:
                        self.logs.put(
                            f"[!] Helper hung for {elapsed:.0f}s without "
                            f"completing startup (no '[+] TUNNEL ACTIVE' "
                            f"marker). Killing it - check v2rayN and your "
                            f"VLESS server, then try [S] again.")
                        self.tunnel.try_transition(
                            TunnelState.FAILED,
                            f"helper hung for {elapsed:.0f}s during startup")
                        try:
                            self.proc.kill()
                        except Exception:
                            pass
                        self.recovery.report_failure(
                            FailureKind.PROCESS,
                            f"helper hung for {elapsed:.0f}s")
                        return
            threading.Thread(target=_startup_watchdog, daemon=True).start()
        except Exception as e:
            # Still in STOPPED (the STARTING transition only happens after a
            # successful Popen): record the failure on the machine so the UI
            # and diagnostics see it, not just the log line.
            self.tunnel.try_transition(TunnelState.FAILED,
                                       f"helper launch failed: {e}")
            self.log_lines.append(f"[!] Failed to launch: {e}")

    def _final_host_route_sweep(self):
        """Last-resort exit sweep: remove any leftover per-host bypass route
        (/32 + /128) for the VLESS servers and every configured bypass entry,
        regardless of which interface/gateway they were installed through.

        This catches the one case the layered cleanup above cannot: the helper
        child had to be FORCE-killed (hung >13s), so its own Python atexit
        cleanup never ran and its startup bypass routes are still in the table.
        One batched PowerShell call, idempotent (removing an absent prefix is
        silently ignored)."""
        hosts = []
        hosts += list(self.endpoint_v4) + list(self.endpoint_v6)
        for h in (list(getattr(self.ns, "bypass_ip", []) or [])
                  + list(getattr(self.ns, "server", []) or [])):
            if h not in hosts:
                hosts.append(h)
        ips = []
        for h in hosts:
            v4, v6 = _resolve_cached(h)
            for ip in list(v4) + list(v6):
                if ip not in ips:
                    ips.append(ip)
        if not ips:
            return
        stmts = []
        for ip in ips:
            if ":" in ip:
                stmts.append(f"Remove-NetRoute -DestinationPrefix '{ip}/128' "
                             f"-AddressFamily IPv6 -Confirm:$false "
                             f"-ErrorAction SilentlyContinue | Out-Null")
            else:
                stmts.append(f"Remove-NetRoute -DestinationPrefix '{ip}/32' "
                             f"-AddressFamily IPv4 -Confirm:$false "
                             f"-ErrorAction SilentlyContinue | Out-Null")
        try:
            _ps("\n".join(stmts))
        except Exception:
            pass

    def _cleanup_live_routes(self):
        """Remove every route THIS dashboard process installed live: the geoip
        bypass ranges (self._live_geo_added) and the [A]-added bypass-IP routes
        (self._live_bypass_added). The helper child cleans up its own startup
        routes on exit; this clears what the dashboard added on top, so nothing
        lingers after the tunnel is turned off. Safe to call repeatedly."""
        for fam, dest, iface, gw in self._live_geo_added:
            if fam == "v4":
                _del_route_v4(dest, iface, gw)
            else:
                _del_route_v6(dest, iface, gw)
        self._live_geo_added = []
        for fam, dest, iface, gw in self._live_bypass_added:
            if fam == "v4":
                _del_route_v4(dest, iface, gw)
            else:
                _del_route_v6(dest, iface, gw)
        self._live_bypass_added = []

    def _dump_route_table(self):
        """One-shot dump of the live routing table as dicts
        (DestinationPrefix / InterfaceAlias / NextHop). Empty list on failure."""
        ps = ("$ProgressPreference='SilentlyContinue'; "
              "$out = Get-NetRoute -ErrorAction SilentlyContinue | "
              "Select-Object DestinationPrefix, InterfaceAlias, NextHop | "
              "ConvertTo-Json -Compress; Write-Output $out")
        try:
            ok, out = _ps(ps, timeout=90)
        except Exception:
            return []
        if not ok or not out:
            return []
        try:
            doc = json.loads(out.strip())
        except Exception:
            return []
        if not isinstance(doc, list):
            return []
        return [r for r in doc if isinstance(r, dict) and r.get("DestinationPrefix")]

    def _geo_sweep_cidrs(self):
        """The full CIDR prefix set for --geoip-code (cached per process;
        tuntop.geoip's cross-run disk cache makes even the first decode
        instant for a cached file). Empty set when no geoip config is active.
        """
        if getattr(self, "_geo_sweep_cidrs_val", None) is not None:
            return self._geo_sweep_cidrs_val
        cidrs = set()
        geo = getattr(self.ns, "geoip", None)
        code = getattr(self.ns, "geoip_code", None)
        if geo and code and os.path.isfile(geo):
            try:
                import importlib
                here = os.path.dirname(os.path.abspath(__file__))
                if here not in sys.path:
                    sys.path.insert(0, here)
                cidrs = set(importlib.import_module(
                    "TunTop.geoip").parse_geoip(geo, code))
            except Exception:
                cidrs = set()
        self._geo_sweep_cidrs_val = cidrs
        return cidrs

    def _leftover_geo_routes(self):
        """Live routes whose DestinationPrefix exactly matches one of the
        --geoip-code country CIDRs (i.e. bypass routes that should have been
        removed but are still installed - on ANY interface/gateway)."""
        cidrs = self._geo_sweep_cidrs()
        if not cidrs:
            return []
        return [r for r in self._dump_route_table()
                if str(r.get("DestinationPrefix")) in cidrs]

    def _sweep_geo_leftovers(self, progress=None):
        """Last-resort exit sweep for HELPER-installed geoip country-bypass
        routes. The helper removes its own routes in cleanup() when it exits
        cleanly, but if it had to be force-killed (hung > timeout) its Python
        cleanup never ran and potentially thousands of active-store netsh
        routes stay behind - the "routing still on my system after quitting"
        bug.

        The dashboard knows exactly which prefixes belong to --geoip-code
        (tuntop.geoip keeps a cross-run disk cache, so decoding is instant
        even for a multi-megabyte .dat). We dump the live routing table ONCE,
        match DestinationPrefixes exactly against those CIDRs client-side, and
        batch-delete every match by interface + next-hop, so only leftover
        bypass routes are touched - never a VPN's own routes.
        Returns how many leftover routes were found/removed."""
        leftovers = []
        for r in self._leftover_geo_routes():
            dp = str(r.get("DestinationPrefix")).replace("'", "")
            alias = str(r.get("InterfaceAlias", "") or "").replace("'", "")
            nh = str(r.get("NextHop", "") or "").replace("'", "")
            leftovers.append((dp, alias, nh))
        if not leftovers:
            return 0
        removed = 0
        # Concurrent netsh -f batches - the SAME fast path the installer uses.
        # The old Remove-NetRoute-per-prefix scripts cost ~50-100ms per route
        # (minutes for a few thousand leftovers even in parallel); plain
        # `netsh interface ipv4|ipv6 delete route` lines batch hundreds per
        # process, matching load speed. Disjoint prefixes cannot collide, and
        # each script runs from a temp file (no command-line length limit).
        chunks = [leftovers[i:i + self._SWEEP_CHUNK]
                  for i in range(0, len(leftovers), self._SWEEP_CHUNK)]
        done = [0]
        lock = threading.Lock()

        def _report():
            if progress:
                try:
                    progress(done[0], len(leftovers))
                except Exception:
                    pass

        _report()   # announce the total before anything completes
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(len(chunks), self._SWEEP_WORKERS)) as ex:
            futs = []
            for chunk in chunks:
                lines = []
                for dp, alias, nh in chunk:
                    verb = "ipv6" if ":" in dp else "ipv4"
                    iface_dq = '"' + alias.replace('"', '') + '"'
                    nh_tok = ""
                    if nh and nh not in ("0.0.0.0", "::"):
                        nh_tok = f" {nh}"
                    lines.append(f"interface {verb} delete route {dp} "
                                 f"{iface_dq}{nh_tok}")

                def _run(_lines=lines, _n=len(chunk)):
                    try:
                        fd, path = tempfile.mkstemp(suffix=".txt",
                                                    prefix="geo_sweep_")
                        try:
                            with os.fdopen(fd, "w", encoding="utf-8") as f:
                                f.write("\n".join(_lines))
                            subprocess.run(["netsh", "-f", path],
                                           capture_output=True, timeout=180)
                        finally:
                            try:
                                os.unlink(path)
                            except Exception:
                                pass
                    except Exception:
                        pass
                    with lock:
                        done[0] += _n
                    _report()
                futs.append(ex.submit(_run))
            for _f in concurrent.futures.as_completed(futs):
                pass
        return len(leftovers)

    def _exit_route_sweep(self):
        """Run all last-resort sweeps idempotently; never raises."""
        for sweep in (self._cleanup_live_routes,
                      self._sweep_geo_leftovers,
                      self._final_host_route_sweep):
            try:
                sweep()
            except Exception:
                pass

    # ── [Q] shutdown with progress bar ───────────────────────────────────────
    # Pressing [Q] must clear every route and only THEN let the app quit. We run
    # the whole teardown synchronously on the main thread (so a key press can't
    # abort it) and redraw a dedicated full-screen panel with a live progress
    # bar. The loop's draw() is suppressed while this runs.

    def _shutdown_stop_helper(self):
        """Signal the helper child to exit; its own atexit removes the bulk of
        the routes it installed, so this is step one of 'clearing routing'."""
        if self.proc and self.proc.poll() is None:
            try:
                # Give the helper a generous window: on CTRL_BREAK its handler
                # runs cleanup() SYNCHRONOUSLY, bulk-removing potentially
                # thousands of geoip bypass routes before exiting. Killing it
                # too early skips that cleanup entirely and leaves every route
                # behind in the system routing table.
                self.proc.send_signal(signal.CTRL_BREAK_EVENT)
                try:
                    self.proc.wait(timeout=45)
                except subprocess.TimeoutExpired:
                    pass
            except Exception:
                pass
            if self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=10)
                except Exception:
                    self.proc.kill()

    def _start_geo_download(self, force=False):
        """Fetch the official v2fly geoip database in a BACKGROUND thread
        (a multi-megabyte HTTPS download must never freeze the UI thread).

        Destination: the configured --geoip path, or tuntop/geoip.dat when
        none is set (and then ns.geoip is pointed at it). force=True refreshes
        an existing file ([W] update); without force a missing-file trigger is
        expected (launch-time auto-download). Returns True if started."""
        if getattr(self, "_geo_dl_active", False):
            self._blog("[i] A geoip download is already in progress.")
            return False
        dest = getattr(self.ns, "geoip", None) or _DEFAULT_GEOIP_PATH
        updating = os.path.isfile(dest)
        if updating and not force:
            self._blog(f"[i] Geoip file already present: {dest} - nothing to do "
                       "(press [W] to force an update).")
            return False
        t0 = time.time()
        last_pct = [0]
        last_bytes = [0]

        def _prog(done, total):
            if total:
                pct = int(done * 100 / total)
                if pct >= last_pct[0] + 10 or pct >= 100:
                    last_pct[0] = pct
                    self._blog(f"[geo-dl] {pct:3d}%  ({done / 1048576:.1f} MB)")
            elif done - last_bytes[0] >= (4 << 20):
                last_bytes[0] = done
                self._blog(f"[geo-dl] {done / 1048576:.1f} MB downloaded...")

        def _work():
            try:
                verb = "Updating" if updating else "Downloading"
                self._blog(f"[*] {verb} geoip database from v2fly -> {dest}")
                from tuntop.geoip import download_geoip
                size = download_geoip(dest, progress=_prog)
                dt = max(0.001, time.time() - t0)
                self._blog(f"[+] Geoip saved: {size / 1048576:.1f} MB in "
                           f"{dt:.0f}s ({size / dt / 1048576:.1f} MB/s), "
                           f"SHA-256 verified.")
                # The sweep's CIDR cache and any active tunnel reference the
                # OLD file; drop the cache so the next start uses the new data.
                with self._geo_lock:
                    self._geo_sweep_cidrs_val = None
                if getattr(self.ns, "geoip", None) != dest:
                    self.ns.geoip = dest
                    self._blog(f"[*] Geoip file now configured: {dest}.")
                running = bool(self.proc and self.proc.poll() is None)
                if running:
                    self._blog("[i] Tunnel is RUNNING on the old data - "
                               "press [T] then [S] to apply the update.")
                else:
                    self._blog("[i] Press [S] to start and install the "
                               "country bypass routes.")
            except Exception as e:
                self._blog(f"[!] Geoip download failed: {e}")
            finally:
                self._geo_dl_active = False

        self._geo_dl_active = True
        threading.Thread(target=_work, daemon=True,
                         name="geo-download").start()
        return True

    def _shutdown_del_route(self, fam, dest, iface, gw):
        if fam == "v4":
            _del_route_v4(dest, iface, gw)
        else:
            _del_route_v6(dest, iface, gw)

    def _sweep_progress_cb(self, done, total):
        """Live counter for the [Q] checklist while the geo-leftover sweep
        deletes its batches, so the shutdown screen never looks frozen."""
        if not total:
            return
        self._shutdown_stage = (
            f"Sweeping leftover geoip routes... {done}/{total}")
        if getattr(self, "_shutting_down", False):
            try:
                # Same thread as the shutdown loop -> safe to redraw directly.
                frac0 = max(0.0, min(1.0, self._shutdown_progress))
                # Nudge the bar between its checkpoint ticks with the inner
                # sweep progress (weight it lightly so the outer step bar
                # still dominates).
                self._shutdown_progress = frac0 + 0.8 * ((done / total) / 10)
                self._draw_shutdown()
            except Exception:
                pass

    def _shutdown_teardown_wintun(self):
        _teardown_wintun()

    @staticmethod
    def _count_wintun_routes():
        """Routes on BOTH tunnel adapters (wintun + optional wintun2) - the
        shutdown progress verifies the second pipe's routes are gone too."""
        total = 0
        for _adapter in ("wintun", "wintun2"):
            ok, out = _ps(
                f"Get-NetRoute -InterfaceAlias '{_adapter}' -ErrorAction SilentlyContinue | "
                "Measure-Object | Select-Object -ExpandProperty Count")
            if ok:
                try:
                    total += int(out.strip())
                except Exception:
                    pass
        return total

    @staticmethod
    def _tun2socks_running():
        ok, out = _ps(
            "Get-Process -ErrorAction SilentlyContinue | "
            "Where-Object {$_.ProcessName -like 'tun2socks*'} | "
            "Measure-Object | Select-Object -ExpandProperty Count")
        if ok:
            try:
                return int(out.strip()) > 0
            except Exception:
                return False
        return False

    def _shutdown_with_progress(self):
        """Run the full route-clearing teardown with a live progress bar and do
        NOT return (and thus do NOT let the app quit) until the routing table is
        genuinely clear. Subsequent [Q] presses are ignored while this runs."""
        if self._shutting_down:
            return
        self._shutting_down = True
        # The [Q] path does NOT go through stop() - pause recovery (this is
        # a user-initiated quit, never a crash to repair) and drive the
        # machine into STOPPING so the UI/telemetry see the teardown phase.
        self.recovery.pause("shutdown requested [Q]")
        self.tunnel.try_transition(TunnelState.STOPPING,
                                   "shutdown requested [Q]")

        # Ordered, weighted cleanup tasks. Each becomes a CHECKLIST row in the
        # redesigned shutdown panel: ✔ done / ▸ running / ◦ pending, plus a
        # cyan->mint gradient bar and a step counter.
        tasks = []
        if self.proc is not None and self.proc.poll() is None:
            tasks.append(("Stopping tunnel helper (clears its own routes)",
                          self._shutdown_stop_helper))
        for fam, dest, iface, gw in list(self._live_geo_added):
            tasks.append((f"Removing geo route {dest}",
                          lambda f=fam, d=dest, i=iface, g=gw:
                              self._shutdown_del_route(f, d, i, g)))
        for fam, dest, iface, gw in list(self._live_bypass_added):
            tasks.append((f"Removing bypass route {dest}",
                          lambda f=fam, d=dest, i=iface, g=gw:
                              self._shutdown_del_route(f, d, i, g)))
        tasks.append(("Tearing down wintun routes + tun2socks",
                      self._shutdown_teardown_wintun))
        tasks.append(("Sweeping leftover geoip country routes",
                      lambda: self._sweep_geo_leftovers(
                          progress=self._sweep_progress_cb)))
        tasks.append(("Sweeping endpoint host bypass routes",
                      self._final_host_route_sweep))
        tasks.append(("Verifying routes are clear",
                      lambda: None))

        # Checklist state: [label, state] with state pending|run|ok|fail.
        self._shutdown_items = [[label, "pending"] for label, _fn in tasks]
        total = max(1, len(tasks))
        for idx, (label, fn) in enumerate(tasks):
            self._shutdown_items[idx][1] = "run"
            self._shutdown_stage = label
            self._shutdown_progress = idx / total
            self._draw_shutdown()
            try:
                fn()
            except Exception as e:
                self._shutdown_stage = f"{label} (error: {e})"
                self._shutdown_items[idx][1] = "fail"
            else:
                if self._shutdown_items[idx][1] == "run":
                    self._shutdown_items[idx][1] = "ok"
            self._shutdown_progress = (idx + 1) / total
            self._draw_shutdown()

        # Final verification: keep tearing down until the route table is truly
        # empty and tun2socks is dead. This is what guarantees the app never
        # quits while routes are still lingering (the "clear and clean" part).
        verify_idx = len(tasks) - 1
        geo_left = 0
        for attempt in range(6):
            leftover = self._count_wintun_routes()
            if attempt > 0:
                # After the first pass, ALSO count leftover geoip country
                # routes on any interface (the wintun counter alone said
                # "clear" while thousands of Wi-Fi bypass routes remained).
                geo_left = self._sweep_geo_leftovers()
            else:
                geo_left = len(self._leftover_geo_routes())
            if leftover == 0 and geo_left == 0 and not self._tun2socks_running():
                break
            self._shutdown_stage = (
                f"Verifying routes are clear... ({leftover} wintun"
                + (f", {geo_left} geoip" if geo_left else "")
                + f" left, retry {attempt + 1})")
            try:
                _teardown_wintun()
            except Exception:
                pass
            time.sleep(0.4)
        if leftover == 0 and geo_left == 0 and not self._tun2socks_running():
            self._shutdown_items[verify_idx][1] = "ok"
            self._shutdown_stage = "Routes cleared - safe to quit."
        else:
            warn = f"{geo_left} geoip route(s)" if geo_left \
                else f"{leftover} wintun route(s)"
            self._shutdown_items[verify_idx][1] = "fail"
            self._shutdown_stage = (
                f"Warning: {warn} still present - exiting anyway; "
                f"rerun to clean up.")
        self._shutdown_progress = 1.0
        self._draw_shutdown()
        time.sleep(0.6)

        self._cleanup_done = True
        self.running = False
        # Every route is verified gone: the machine may now rest.
        self.tunnel.try_transition(TunnelState.STOPPED,
                                   "shutdown complete - routes verified clear")

    def _draw_shutdown(self):
        """Render the full-screen teardown screen: a CHECKLIST of cleanup steps
        (✔ done / ▸ running / ◦ pending), an icy cyan->mint gradient bar with
        percentage + step counter, and a status footer. Self-contained (does
        not use the dashboard's normal draw pipeline)."""
        cols = 60
        try:
            sz = _get_window_size()
            if sz:
                cols = min(max(44, sz[0] - 2), 92)
        except Exception:
            pass
        pal = theme()
        acc = pal["active"]
        frac = max(0.0, min(1.0, self._shutdown_progress))
        pct = int(round(frac * 100))
        items = getattr(self, "_shutdown_items", [])
        n_done = sum(1 for _l, st in items if st == "ok")
        step_txt = f"step {min(n_done + 1, len(items))}/{len(items)}" if items else ""
        # New bar colours: icy cyan -> aqua -> mint green (was green->amber->red,
        # which read as an ERROR meter while shutting down).
        _SHUTDOWN_STOPS = ((80, 200, 255), (110, 235, 200), (140, 255, 170))
        bar_w = max(10, cols - 24)
        bar = _bar_stops(frac, bar_w, _SHUTDOWN_STOPS)
        stage = self._shutdown_stage or "Cleaning up..."

        def _acenter(text, width, fill=BOX_MID):
            vis = len(re.sub(r"\x1b\[[^m]*m", "", text))
            if vis >= width:
                return text
            total = width - vis
            left = total // 2
            right = total - left
            return fill * left + text + fill * right

        def _row(content, accent=None):
            c = accent if accent else pal["light"]
            return f"{c}{BOX_V} {_hpad(content, cols - 3)}{c}{BOX_V}{RESET}"

        lines = [
            f"{acc}{BOX_LC}{BRIGHT}{_acenter(' SHUTTING DOWN ', cols - 2, BOX_MID)}{BOX_RC}{RESET}",
            _row(""),
        ]
        if items:
            marks = {"ok":   (GREEN + "\u2714" + RESET),
                     "run":  (pal["throughput"] + "\u25b8" + RESET),
                     "fail": (RED + "\u2717" + RESET),
                     "pending": (GRAY + "\u25cb" + RESET)}
            cols_style = {"ok": GRAY, "run": BRIGHT + WHITE,
                          "fail": RED, "pending": GRAY}
            for label, st in items:
                mark = marks.get(st, GRAY + "\u25cb" + RESET)
                body = cols_style.get(st, GRAY) + label + RESET
                lines.append(_row(f"  {mark} {body}"))
            lines.append(_row(""))
        else:
            lines.append(_row(stage))
            lines.append(_row(""))
        lines.append(_row(f"  {bar}  {BRIGHT}{pct:3d}%{RESET}"
                          + (f"{GRAY}   {step_txt}{RESET}" if step_txt else "")))
        lines.append(_row(""))
        warn = any(st == "fail" for _l, st in items)
        if warn:
            lines.append(_row(f"{YELLOW}Some steps failed - rerun the app once to "
                              f"re-clean.{RESET}"))
        else:
            lines.append(_row(f"{GRAY}Keep this window open until it reaches "
                              f"100%.{RESET}"))
        lines.append(f"{pal['inact']}{BOX_BL}{BOX_BS * (cols - 2)}{BOX_BR}{RESET}")
        sys.stdout.write("\033[2J\033[H" + "\n".join(lines) + "\n")
        sys.stdout.flush()

    def stop(self):
        # The [Q] path runs the full route-clearing sequence itself (with a
        # progress bar) and sets `_cleanup_done`; don't repeat that work here.
        if self._cleanup_done:
            return
        # User-initiated stop: pause recovery FIRST so the machine's walk
        # down (STOPPING/STOPPED) is never mistaken for a crash to repair.
        self.recovery.pause("stop requested")
        # Announce teardown on the machine (no-op if the helper-exit path in
        # _read already claimed STOPPING/STOPPED - try_transition ignores it).
        self.tunnel.try_transition(TunnelState.STOPPING, "stop requested")
        if self.proc and self.proc.poll() is None:
            try:
                self.logs.put("[*] Stopping helper...")
                self.proc.send_signal(signal.CTRL_BREAK_EVENT)
                self.proc.wait(timeout=8)
            except Exception:
                pass
            if self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=5)
                except Exception:
                    self.proc.kill()
        # Remove every route this dashboard process added live (geo bypass +
        # [A] bypass-IP). The helper cleans its own startup routes on exit.
        self._cleanup_live_routes()
        _teardown_wintun()
        # Belt-and-braces: also clear anything the helper may have left behind
        # if it had to be force-killed (its own cleanup never ran then).
        self._exit_route_sweep()
        self.tunnel.try_transition(TunnelState.STOPPED, "teardown complete")

    def _schedule_bypass_restart(self, reason):
        """Apply a changed --bypass-ip list by fully restarting the tunnel
        (stop + start) in a background thread, so the helper re-installs every
        bypass route cleanly at startup - the reliable way to make an added or
        removed entry take effect without leaving stale/duplicate routes.

        Only restarts when the tunnel is currently running; if it is stopped the
        change is simply noted (it applies on the next [S]). A restart already in
        flight is skipped (not queued), because it reads ns.bypass_ip at launch
        time and therefore already captures the latest edit."""
        if not getattr(self.ns, "server", None):
            return
        if not (self.proc and self.proc.poll() is None):
            self._blog(f"[i] {reason}; tunnel is stopped - bypass change applies "
                       "on next [S] start.")
            return
        with self._restart_lock:
            if self._bypass_restart_active:
                self._blog(f"[*] {reason}; restart already in progress (queued).")
                return
            self._bypass_restart_active = True

        def _worker():
            try:
                self._blog(f"[*] {reason} - stopping tunnel to re-apply bypass list...")
                try:
                    self.stop()
                except Exception as e:
                    self._blog(f"[!] stop during bypass restart failed: {e}")
                try:
                    self.launch()
                except Exception as e:
                    self._blog(f"[!] launch during bypass restart failed: {e}")
                if self.proc and self.proc.poll() is None:
                    self._blog("[+] Tunnel restarted with the updated bypass list.")
                else:
                    self._blog("[!] Tunnel did not come back up after the bypass restart.")
            finally:
                with self._restart_lock:
                    self._bypass_restart_active = False
        threading.Thread(target=_worker, daemon=True).start()


# ─── Main ───────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="btop-style dashboard for v2ray TUN monitoring.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    ap.add_argument("--server", nargs="+", default=["198.51.100.1"],
                    help="VLESS server IP or hostname (repeatable: --server a b)")
    ap.add_argument("--port", type=int, default=10808, help="SOCKS5 inbound port")
    ap.add_argument("--tun2socks", default=os.path.join(app_dir(), "tun2socks-windows-amd64-v3.exe"))
    ap.add_argument("--no-vpn-bypass", action="store_true")
    ap.add_argument("--no-auto-recover", action="store_true",
                    help="Disable automatic crash/degradation recovery "
                         "(auto-restart of a dead helper is off; the state "
                         "machine still reports phases)")
    ap.add_argument("--trust-binaries", action="store_true",
                    help="Skip the SHA-256 verification of tun2socks.exe / "
                         "wintun.dll (only for binaries you rebuilt "
                         "yourself - NOT recommended)")
    ap.add_argument("--proxy-over-vpn", "--vless-over-vpn", action="store_true",
                    dest="vless_over_vpn")
    ap.add_argument("--proxy2-port", type=int, default=None, metavar="PORT",
                    help="SOCKS5 port of a SECOND local proxy; hosts marked "
                         "'proxy2' are routed through it")
    ap.add_argument("--proxy2-server", nargs="+", default=[], metavar="HOST_OR_IP",
                    help="The second proxy's own upstream server(s) (bypassed direct)")
    ap.add_argument("--proxy2-bypass-ip", action="append", default=[], metavar="HOST_OR_IP",
                    help="IP/hostname to route through the SECOND proxy (repeatable)")
    ap.add_argument("--vpn-interface", default=None)
    ap.add_argument("--endpoint-port", type=int, default=443)
    ap.add_argument("--dns4", default="8.8.8.8")
    ap.add_argument("--unicode", action="store_true",
                    help="Force Unicode box/block glyphs even if auto-detection is unsure")
    ap.add_argument("--ascii", action="store_true",
                    help="Force plain ASCII glyphs (+/-/#) even if Unicode looks supported")
    ap.add_argument("--bypass-ip", action="append", default=[], metavar="HOST_OR_IP",
                    help="IP address or hostname/domain to bypass the TUN (repeatable)")
    ap.add_argument("--geoip", default=None, metavar="PATH",
                    help="Path to v2rayN geoip.dat; bypass every CIDR of --geoip-code "
                         "(e.g. cn = bypass mainland traffic through the TUN)")
    ap.add_argument("--geoip-code", default="cn", metavar="CC",
                    help="Country code inside geoip.dat to bypass (default cn)")
    ap.add_argument("--geoip-via-vpn", action="store_true",
                    help="Tunnel the geoip country ranges via wintun (mode 3 / "
                         "vpn-as-geo) instead of bypassing them through the "
                         "physical adapter")
    ap.add_argument("--geoip-via-win-vpn", action="store_true",
                    help="Route the geoip country ranges out through a connected "
                         "Windows VPN instead of the physical adapter or wintun. "
                         "Overrides --geoip-via-vpn. Falls back to wifi when no "
                         "connected Windows VPN default route is found")

    args = ap.parse_args()

    # Accept URLs / host:port anywhere a host is expected - a route needs a
    # bare host or IP, so normalise once, up front (the [A] key does the same).
    args.bypass_ip = [h for h in (_host_from_url(x) for x in (args.bypass_ip or [])) if h]
    args.proxy2_bypass_ip = [h for h in (_host_from_url(x)
                                         for x in (args.proxy2_bypass_ip or [])) if h]
    args.proxy2_server = [_host_from_url(s) or s for s in (args.proxy2_server or [])]
    args.server = [_host_from_url(s) or s for s in (args.server or [])]

    if not _admin():
        sys.exit("[!] Run this as Administrator (use Run_Helper.bat).")

    # ── Binary integrity (tuntop/integrity.py) ─────────────────────────
    # tun2socks.exe / wintun.dll run inside this ADMIN process: a swapped
    # or corrupted binary is elevated code execution, so verify both
    # against the pinned SHA-256 hashes BEFORE anything is launched.
    # Refuses to start on MISSING/MISMATCH unless --trust-binaries.
    _bin_ok, _bin_reports, _bin_msgs = integrity.verify_for_launch(
        args.tun2socks, trust=args.trust_binaries)
    for _m in _bin_msgs:
        print(_m)
    if not _bin_ok:
        sys.exit(1)

    # Fix the console codepage/font up *before* deciding whether Unicode
    # glyphs are safe - this is what actually makes a plain cmd.exe or
    # PowerShell console render them, so the probe below has to run after it,
    # not before (the previous version decided glyphs first and enabled ANSI
    # second, which meant the decision never saw the fix-up's result).
    _enable_ansi()
    # Resize the console so the full dashboard fits on one screen.
    _resize_console()

    # ── Startup crash recovery (tuntop/startup_recovery.py) ────────────
    # A hard-killed previous run leaves orphaned tun2socks, the Wintun
    # adapter + its routes, and per-host bypass routes behind. Detect and
    # clean ALL of it BEFORE the new tunnel starts, so this launch never
    # builds on top of stale state.
    _startup_hosts = list(dict.fromkeys(
        [s for s in (args.server or []) if s]
        + [h for h in (args.bypass_ip or []) if h]))
    try:
        _recovery_actions = startup_recovery.startup_recover(
            hosts=_startup_hosts, log=lambda m: print(m))
        if _recovery_actions:
            print("[+] Startup recovery complete - clean slate for this run.")
    except Exception as e:
        # Recovery must never block the launch; the helper's own
        # preflight_cleanup is still there as the second line of defence.
        print(f"[!] Startup recovery could not run: {e}")

    def _atexit_all():
        try:
            if app is not None:
                # Full sweep (live routes + geo leftovers + host routes): even
                # if [Q]'s own teardown was skipped somehow, nothing lingers.
                app._exit_route_sweep()
        except Exception as e:
            print(f"[!] Route cleanup on exit failed: {e}")
        _teardown_wintun()
        # Verified clean exit: the crash marker goes away, so the NEXT
        # launch knows it starts from a clean slate.
        startup_recovery.clear_marker()
    atexit.register(_atexit_all)

    if args.ascii:
        _apply_glyphs(False)
    elif args.unicode:
        _apply_glyphs(True)
    else:
        _apply_glyphs(_probe_unicode_support())

    try:
        def _ctrl(ct):
            try:
                if app is not None:
                    app._cleanup_live_routes()
            except Exception as e:
                # Best-effort only - the OS is killing us; still surface why.
                print(f"[!] Ctrl-cleanup failed: {e}")
            _teardown_wintun()
            return False
        wf = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_uint32)
        # Keep the function pointer alive in module state so Python's GC can't
        # reclaim it out from under the OS before the handler is ever invoked.
        global _CTRL_HANDLER_REF
        _CTRL_HANDLER_REF = wf(_ctrl)
        ctypes.windll.kernel32.SetConsoleCtrlHandler(_CTRL_HANDLER_REF, True)
    except Exception:
        pass

    app = None
    try:
        app = BTopTui(args)
        app.launch()
        app.loop()
    except SystemExit:
        raise
    except BaseException:
        # Anything that gets this far (including the KeyboardInterrupt from
        # a raw Ctrl+C, which the loop's own try/finally doesn't swallow)
        # used to either print-and-vanish or leave routes/tun2socks behind.
        # Now: tear down cleanly, and if it wasn't just Ctrl+C, show and log
        # the real cause instead of letting the window disappear silently.
        import traceback
        is_interrupt = isinstance(sys.exc_info()[1], KeyboardInterrupt)
        tb = traceback.format_exc()
        try:
            if app is not None:
                app.stop()
                app._restore_console_mode()
        except Exception:
            pass
        _teardown_wintun()
        if is_interrupt:
            print("\n[*] Interrupted - tunnel and routes cleaned up.")
            return
        sys.stdout.write("\033[0m\033[?25h\033[2J\033[3J\033[H\n")
        print("=" * 70)
        print("[!] TunTop crashed. Details below, and saved to:")
        print(f"    {CRASH_LOG}")
        print("=" * 70)
        print(tb)
        try:
            with open(CRASH_LOG, "a", encoding="utf-8") as f:
                f.write(f"\n--- {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n{tb}\n")
        except Exception:
            pass
        print("Press any key to close this window...")
        try:
            import msvcrt
            msvcrt.getwch()
        except Exception:
            pass
        sys.exit(1)

    # Normal exit (e.g. [Q]): blank the screen so the launcher's
    # "Press any key to close this window..." prompt doesn't paint over the
    # last dashboard frame.
    sys.stdout.write("\033[0m\033[?25h\033[2J\033[3J\033[H")
    sys.stdout.flush()


if __name__ == "__main__":
    main()

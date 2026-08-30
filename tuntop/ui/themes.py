"""Pure terminal text/layout primitives - no globals, no state, no I/O.

This is the dashboard's formatting layer, extracted (Phase 1) so the UI
module shrinks and the primitives become independently testable. Every
function takes everything it needs as arguments; NOTHING here reads or
writes module state, so the dashboard's own globals (glyph sets, unicode
mode, themes) stay in tuntop/ui/dashboard.py and are passed in at call time.

Pure stdlib, zero pip dependencies (tests: tests/unit/test_dashboard_text.py).
"""
from __future__ import annotations

import re

ANSI_RE = re.compile(r"\x1b\[[^m]*m")

# Green -> yellow -> red, the same ramp btop uses for its CPU/mem/net meters.
GRAD_STOPS = ((76, 175, 80), (255, 193, 7), (244, 67, 54))

RESET = "\033[0m"


def console_safe(text, use_unicode: bool) -> str:
    """Keep child-process messages printable in classic cmd.exe (where some
    font/combination choices render Unicode as '?'). Unicode mode passes
    text through; ASCII mode replaces anything outside printable ASCII
    (tab allowed) with '.'."""
    text = str(text)
    if use_unicode:
        return text
    return "".join(ch if 32 <= ord(ch) < 127 or ch in "\t" else "."
                   for ch in text)


def pad(text, width: int) -> str:
    """Right-pad to a VISIBLE width (ANSI codes don't count as columns);
    over-long input is truncated to its visible width."""
    t = str(text)
    vis_w = len(ANSI_RE.sub("", t))
    if vis_w > width:
        return ANSI_RE.sub("", t)[:width]
    return t + " " * max(0, width - vis_w)


def hslice(text: str, start: int, width: int) -> str:
    """Horizontal window of `text` (may contain ANSI colour codes) spanning
    visible columns [start, start+width). Escape sequences are always
    preserved so the colour state continues after a cut; only visible
    characters are windowed."""
    out = []
    vis = 0
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\x1b":
            j = i
            while j < n and text[j] != "m":
                j += 1
            out.append(text[i:j + 1])
            i = j + 1
            continue
        if start <= vis < start + width:
            out.append(ch)
        vis += 1
        if vis > start + width:
            break
        i += 1
    return "".join(out)


def hpad(text: str, width: int, start: int = 0) -> str:
    """Horizontally scroll `text` to column `start` (preserving ANSI) then
    right-pad to `width` with spaces."""
    s = hslice(text, start, width) if start else text
    vis_w = len(ANSI_RE.sub("", s))
    if vis_w < width:
        s = s + " " * (width - vis_w)
    elif vis_w > width:
        # start==0 fast path already handled by hslice; this guards the
        # (shouldn't happen) case of an over-long unescaped remainder.
        s = ANSI_RE.sub("", s)[:width]
    return s


def split_hostport(s: str) -> tuple:
    """Split 'host:port' / '[ipv6]:port' / 'host' into (host, port)."""
    s = s.strip()
    if s.startswith("["):
        rb = s.find("]")
        if rb != -1:
            host = s[1:rb]
            port = s[rb + 2:] if s[rb + 1:rb + 2] == ":" else ""
            return host, port
    if ":" in s:
        host, _, port = s.rpartition(":")
        return host, port
    return s, ""


def rgb(r: int, g: int, b: int) -> str:
    """24-bit ANSI foreground escape for an absolute (r,g,b) colour."""
    return f"\033[38;2;{r};{g};{b}m"


def gradient_color(frac: float, stops=GRAD_STOPS) -> str:
    """24-bit ANSI foreground for frac in [0, 1], interpolated along the
    given (r,g,b) stop list."""
    frac = max(0.0, min(1.0, frac))
    seg = frac * (len(stops) - 1)
    i = min(len(stops) - 2, int(seg))
    t = seg - i
    r0, g0, b0 = stops[i]
    r1, g1, b1 = stops[i + 1]
    return rgb(round(r0 + (r1 - r0) * t),
               round(g0 + (g1 - g0) * t),
               round(b0 + (b1 - b0) * t))


def bar_stops(frac: float, width: int, stops, full: str, empty: str,
              inactive: str, reset: str = RESET) -> str:
    """Horizontal meter coloured along a CUSTOM stop list, e.g. the icy
    cyan->mint ramp used by the shutdown panel. Glyphs (`full`/`empty`)
    and the inactive colour are caller-supplied so glyph-set/theme changes
    are always reflected."""
    frac = max(0.0, min(1.0, frac))
    if width <= 0:
        return ""
    filled = int(round(frac * width))
    cells = []
    for i in range(filled):
        t = i / max(1, width - 1)
        seg = t * (len(stops) - 1)
        j = min(len(stops) - 2, int(seg))
        u = seg - j
        r0, g0, b0 = stops[j]
        r1, g1, b1 = stops[j + 1]
        cells.append(rgb(round(r0 + (r1 - r0) * u),
                         round(g0 + (g1 - g0) * u),
                         round(b0 + (b1 - b0) * u)) + full)
    cells.append(f"{inactive}{empty * (width - filled)}")
    cells.append(reset)
    return "".join(cells)


def bar(frac: float, width: int, full: str, empty: str, inactive: str,
        reset: str = RESET, gradient: bool = True,
        stops=GRAD_STOPS) -> str:
    """Render a horizontal meter. Glyphs/colours are caller-supplied (read
    at call time, not captured once at import, so a later glyph-set change
    - --unicode/--ascii or the terminal probe - is always reflected).

    gradient=True colours each filled cell along the stop ramp by its
    position in the bar, the way btop's own meters shift colour across
    their length, instead of one flat colour for the whole bar."""
    frac = max(0.0, min(1.0, frac))
    if width <= 0:
        return ""
    filled = int(round(frac * width))
    if not gradient:
        return full * filled + empty * (width - filled)
    cells = []
    for i in range(filled):
        cells.append(f"{gradient_color(i / max(1, width - 1), stops)}{full}")
    cells.append(f"{inactive}{empty * (width - filled)}")
    cells.append(reset)
    return "".join(cells)


def spark(values, width: int, mode: str = None,
          use_unicode: bool = True) -> str:
    """Gradient sparkline.

    mode=None/"block" - classic ramp ( .:-=+*#@ ), ASCII-safe.
    mode="half"       - half-block doubling (U+2580/2584/2588): 2x vertical
                        resolution, using glyphs the program already draws.
    mode="braille"    - U+2800 block: 4x vertical resolution.

    Falls back to "block" automatically when Unicode glyphs are unavailable."""
    if not values:
        return " " * width
    use_mode = mode or "block"
    if use_mode in ("half", "braille") and not use_unicode:
        use_mode = "block"
    vals = values[-width:]
    lo, hi = min(vals), max(vals)
    span = hi - lo if hi - lo > 1e-9 else 1.0
    if use_mode == "block":
        RAMP = " .:-=+*#@"
        chars = []
        for v in vals:
            idx = min(len(RAMP) - 1,
                      max(1, int(round((v - lo) / span * (len(RAMP) - 1)))))
            chars.append(RAMP[idx])
        return "".join(chars) + " " * max(0, width - len(vals))
    if use_mode == "half":
        chars = []
        for v in vals:
            frac = (v - lo) / span
            lvl = round(frac * 8)        # 0..8 half-block sub-levels
            if lvl >= 8:
                chars.append("\u2588")
            elif lvl % 2 == 1:           # 7, 5, 3, 1
                chars.append("\u2580")
            elif lvl >= 2:               # 6, 4, 2
                chars.append("\u2584")
            else:
                chars.append(" ")
        return "".join(chars) + " " * max(0, width - len(vals))
    # braille: 4 vertical levels per column
    chars = []
    for v in vals:
        frac = (v - lo) / span
        lvl = min(4, int(round(frac * 4)))   # 0..4 dots from bottom
        bits = 0
        for d, bit in ((0, 0x40), (1, 0x04), (2, 0x02), (3, 0x01)):
            if lvl >= d + 1:
                bits |= bit
        chars.append(chr(0x2800 | bits))
    return "".join(chars) + " " * max(0, width - len(vals))


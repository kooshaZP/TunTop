"""Visual health report for TunTop.

Takes the raw health-check results from the dashboard and renders a
one-glance summary with pass/fail indicators, reasons, and fix
suggestions.  The dashboard calls ``format_panel()`` when it needs to
draw the health panel, and ``overall_status()`` for the status badge.

Pure stdlib, no Windows calls, no state.
"""
from __future__ import annotations


# ── Fix suggestions per probe name (case-insensitive prefix match) ────────
# Maps a probe name (or prefix) to a short, actionable suggestion.
_FIX_SUGGESTIONS: dict[str, str] = {
    "vless server": (
        "Check that your proxy client is running and the proxy server "
        "address is reachable. Try pressing [U] to change the server."
    ),
    "socks": (
        "Ensure your proxy client's SOCKS5 inbound is enabled on the "
        "expected port. Press [P] to change the port."
    ),
    "dns": (
        "DNS resolution failed. Press [N] to switch DNS servers, or check "
        "your network connection."
    ),
    "ipv4": (
        "IPv4 connectivity lost. Check your network adapter and cable/"
        "Wi-Fi connection."
    ),
    "ipv6": (
        "IPv6 route missing or unreachable. If your network doesn't support "
        "IPv6, this probe can be ignored."
    ),
    "default route": (
        "No default route through the TUN adapter. The tunnel may have "
        "dropped. Press [T] then [S] to restart."
    ),
    "wintun": (
        "Wintun adapter not found or not functioning. Restart the tunnel "
        "with [T] then [S]."
    ),
    "tun2socks": (
        "tun2socks process not running. The tunnel may have crashed. "
        "Press [T] then [S] to restart."
    ),
    "leak": (
        "Traffic is leaking outside the tunnel. Verify your proxy's SOCKS "
        "inbound and press [R] to re-apply routes."
    ),
    "vpn": (
        "VPN connection issue. Press [V] to toggle VPN mode, or [Y] to "
        "configure VPN bypass."
    ),
    "latency": (
        "High latency detected. The proxy server may be overloaded or "
        "your connection is slow."
    ),
}


def _suggest(name: str) -> str:
    """Return a fix suggestion for a failing probe, or empty string.

    Uses longest-prefix matching (case-insensitive) rather than naive
    substring search: ``"tun2socks"`` must resolve to the tun2socks tip,
    not the ``"socks"`` (SOCKS5) one, even though it contains that string.
    """
    lower = name.lower()
    for prefix in sorted(_FIX_SUGGESTIONS, key=len, reverse=True):
        if lower.startswith(prefix):
            return _FIX_SUGGESTIONS[prefix]
    return ""


def overall_status(results: list[tuple]) -> str:
    """Return 'HEALTHY', 'DEGRADED', or 'UNHEALTHY' from the results list.

    results: list of (index, name, ok: bool, detail: str)
    """
    if not results:
        return "UNKNOWN"
    fails = sum(1 for _, _, ok, _ in results if not ok)
    if fails == 0:
        return "HEALTHY"
    if fails < len(results):
        return "DEGRADED"
    return "UNHEALTHY"


def format_panel(results: list[tuple], width: int = 60,
                 use_unicode: bool = True) -> list[str]:
    """Render the health results as a list of formatted lines.

    Returns lines ready to be drawn into the dashboard's panel area.
    Each line is pre-stripped of ANSI for width calculation but may
    contain colour codes for rendering.
    """
    lines: list[str] = []
    if not results:
        lines.append("  (no health scan yet - press [C] to run)")
        return lines

    # Overall status header
    status = overall_status(results)
    if use_unicode:
        sym = "\u2713" if status == "HEALTHY" else (
            "\u2717" if status == "UNHEALTHY" else "\u25cb")
    else:
        sym = "OK" if status == "HEALTHY" else (
            "!!" if status == "UNHEALTHY" else "~")
    lines.append(f"  {sym} {status}")
    lines.append(f"  {'-' * (width - 4)}")

    for _num, name, ok, detail in results:
        if use_unicode:
            mark = "\u2713" if ok else "\u2717"
        else:
            mark = "OK" if ok else "!!"
        # Truncate to fit.  Guard the budget: a name longer than the panel
        # makes max_detail negative, and detail[:negative] would slice from
        # the END of the string (silently dropping the whole detail and
        # emitting a bare "..."), so truncate the name itself first and
        # never let the detail budget go below zero.  The per-row overhead
        # is the indent + mark + separator ("    X name: detail"), and the
        # mark is 2 chars in ASCII mode ("OK"/"!!") vs 1 in unicode mode.
        overhead = 7 + len(mark)
        name_budget = max(width - overhead, 1)
        if len(name) > name_budget:
            name = name[:name_budget - 3] + "..."
        max_detail = max(width - overhead - len(name), 0)
        if len(detail) > max_detail:
            # The ellipsis itself must fit the budget: with no room for it,
            # drop the detail entirely instead of overflowing by 3 chars.
            detail = detail[:max(max_detail - 3, 0)] + \
                ("..." if max_detail >= 3 else "")
        lines.append(f"    {mark} {name}: {detail}")

    # Add suggestions for failures
    failures = [(name, detail) for _, name, ok, detail in results if not ok]
    if failures:
        lines.append("")
        lines.append("  Issues found:")
        for name, detail in failures:
            suggestion = _suggest(name)
            lines.append(f"    \u2022 {name}: {detail}")
            if suggestion:
                # Wrap suggestion at ~56 chars
                words = suggestion.split()
                wrapped = []
                current = "      "
                for w in words:
                    if len(current) + len(w) + 1 > width - 2:
                        lines.append(current)
                        current = "      " + w
                    else:
                        current += (" " if current.strip() else "") + w
                if current.strip():
                    lines.append(current)

    return lines


def format_compact(results: list[tuple], use_unicode: bool = True) -> str:
    """One-line summary: '12/12 HEALTHY' or '9/12 DEGRADED'."""
    if not results:
        return "no scan"
    total = len(results)
    passed = sum(1 for _, _, ok, _ in results if ok)
    status = overall_status(results)
    if use_unicode:
        sym = "\u2713" if status == "HEALTHY" else (
            "\u2717" if status == "UNHEALTHY" else "\u25cb")
    else:
        sym = "OK" if status == "HEALTHY" else (
            "!!" if status == "UNHEALTHY" else "~")
    return f"{passed}/{total} {sym} {status}"

"""Low-level PowerShell script-building helpers shared by the Network
routing layer (tuntop/network/routing.py) and the Tunnel-layer helper
(tuntop/tunnel/helper.py).

Pure stdlib leaf with zero tuntop imports - same pattern as
tuntop/network/leak_probe.py: the helper still runs standalone (it just
needs the small sys.path bootstrap it already carries), and both import
paths resolve to the SAME implementation so a quoting fix can never land
in one copy and silently miss the other.
"""


def ps_quote(s):
    """Escape a string for safe interpolation inside a single-quoted
    PowerShell literal.  PowerShell escapes an embedded single quote by
    doubling it, so e.g. "Bob's VPN" -> "Bob''s VPN" and can no longer
    break out of the surrounding quotes in a generated script."""
    return str(s).replace("'", "''")
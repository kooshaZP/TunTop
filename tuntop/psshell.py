"""Low-level PowerShell script-building helpers shared by the Network
routing layer (tuntop/network/routing.py) and the Tunnel-layer helper
(tuntop/tunnel/helper.py).

Pure stdlib leaf with zero tuntop imports - same pattern as
tuntop/network/leak_probe.py: the helper still runs standalone (it just
needs the small sys.path bootstrap it already carries), and both import
paths resolve to the SAME implementation so a quoting fix can never land
in one copy and silently miss the other.
"""

#: Characters PowerShell's tokenizer accepts as a single-quote delimiter.
#: Only the ASCII one is obviously a quote, but the Unicode lookalikes are
#: real delimiters too - a value carrying U+2018/U+2019/U+201A/U+201B closes
#: the literal it sits in just as effectively as an ASCII apostrophe, and a
#: naive "double the ASCII quote" escape leaves all four untouched. Any host
#: name, interface alias or exemption namespace that reached a generated
#: script could therefore break out of its string literal. They are escaped
#: the same way (doubled), which is exactly how PowerShell represents an
#: escaped instance of that delimiter.
_PS_QUOTES = "'\u2018\u2019\u201a\u201b"


def ps_quote(s):
    """Escape a string for safe interpolation inside a single-quoted
    PowerShell literal.  PowerShell escapes an embedded quote character by
    doubling it, so e.g. "Bob's VPN" -> "Bob''s VPN" and "Bob\u2019s VPN" ->
    "Bob\u2019\u2019s VPN", neither of which can break out of the surrounding
    quotes in a generated script.

    Note this ESCAPES; it does not add the surrounding quotes. Callers
    interpolate as f"'{ps_quote(x)}'".
    """
    out = str(s)
    for q in _PS_QUOTES:
        out = out.replace(q, q + q)
    return out

"""Name resolution: URL normalisation, system resolver, cached lookups,
and UDP/53 + DoH wire-format fallbacks (moved verbatim from the old
single-file dashboard)."""
import base64
import socket
import threading
import time


# ─── Name resolution ────────────────────────────────────────────────────────
# Everything that turns a user-supplied "endpoint" (VLESS server, bypass entry)
# into routable IPs goes through here. Two things this has to survive:
#
#   * URL-shaped input. People paste what they know - "https://www.whatismyip.com/"
#     - and socket.getaddrinfo() cannot resolve a scheme/path/port, so such an
#     entry used to sit at "(unresolved)" forever. _host_from_url() reduces any
#     of those forms to the bare host/IP first (mirrors the same helper in
#     tuntop/helper.py so both sides agree on what gets routed).
#   * A broken system resolver. While the TUN is up, Windows DNS may point at
#     the tunnel; if that path is dead, getaddrinfo() fails even though the
#     network is fine. We then fall back to our own DNS queries (UDP/53 to
#     public resolvers, then DNS-over-HTTPS over TCP/443, which relays through
#     the proxy when plain UDP does not).

_DNS_CACHE = {}                  # host -> (v4, v6, expiry_ts, err)
_DNS_CACHE_LOCK = threading.Lock()
_DNS_TTL_OK = 120.0             # cache successful lookups this long
_DNS_TTL_FAIL = 5.0             # ... and failures only briefly, so retries work
_DNS_FALLBACK_SERVERS = ("1.1.1.1", "8.8.8.8", "9.9.9.9")
_DNS_DOH_ENDPOINTS = ("https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query")


def _host_from_url(value):
    """Reduce any user-supplied endpoint to something that can actually be
    resolved and routed: strip scheme, path, query, fragment, userinfo and
    port, and unwrap a bracketed IPv6 literal.

        https://www.whatismyip.com/   -> www.whatismyip.com
        user:pw@example.com:8443/x    -> example.com
        [2606:4700::1111]:443         -> 2606:4700::1111
        1.2.3.4                       -> 1.2.3.4

    A bare IPv6 literal (more than one colon, no brackets) is left alone."""
    if value is None:
        return ""
    h = str(value).strip().strip('"').strip("'").strip()
    if not h:
        return ""
    if "://" in h:
        h = h.split("://", 1)[1]
    elif h.startswith("//"):
        h = h[2:]
    for sep in ("/", "\\", "?", "#"):
        h = h.split(sep, 1)[0]
    if "@" in h:                      # user:pass@host
        h = h.rsplit("@", 1)[1]
    h = h.strip()
    if not h:
        return ""
    if h.startswith("["):             # [v6]:port
        return h[1:].split("]", 1)[0].strip().lower()
    if h.count(":") == 1:             # host:port (never a bare IPv6)
        head, _, tail = h.partition(":")
        if tail == "" or tail.isdigit():
            h = head
    return h.strip().rstrip(".").lower()


def _dns_build_query(host, qtype):
    """Build a minimal DNS query packet. Returns (transaction_id, bytes)."""
    import random
    tid = random.randrange(1, 0xFFFF)
    q = bytearray()
    q += tid.to_bytes(2, "big")
    q += b"\x01\x00"                  # standard query, recursion desired
    q += (1).to_bytes(2, "big")       # QDCOUNT
    q += b"\x00" * 6                  # AN/NS/AR counts
    for label in host.rstrip(".").split("."):
        if not label:
            continue
        try:
            lb = label.encode("ascii") if label.isascii() else label.encode("idna")
        except Exception:
            lb = label.encode("utf-8", "ignore")
        q.append(min(len(lb), 63))
        q += lb[:63]
    q.append(0)
    q += qtype.to_bytes(2, "big") + (1).to_bytes(2, "big")   # QTYPE, IN
    return tid, bytes(q)


def _dns_parse_answers(data, want):
    """Pull the A (want=1) / AAAA (want=28) addresses out of a DNS response.
    Tolerates truncation and name compression; never raises."""
    out = []
    try:
        if len(data) < 12:
            return []
        qd = int.from_bytes(data[4:6], "big")
        an = int.from_bytes(data[6:8], "big")

        def skip_name(p):
            while p < len(data):
                ln = data[p]
                if ln == 0:
                    return p + 1
                if ln & 0xC0 == 0xC0:
                    return p + 2
                p += 1 + ln
            return p

        pos = 12
        for _ in range(qd):
            pos = skip_name(pos) + 4
        for _ in range(an):
            pos = skip_name(pos)
            if pos + 10 > len(data):
                break
            rtype = int.from_bytes(data[pos:pos + 2], "big")
            rdlen = int.from_bytes(data[pos + 8:pos + 10], "big")
            rd = data[pos + 10:pos + 10 + rdlen]
            pos += 10 + rdlen
            if rtype == 1 and len(rd) == 4 and want in (1, 255):
                ip = ".".join(str(b) for b in rd)
                if ip not in out:
                    out.append(ip)
            elif rtype == 28 and len(rd) == 16 and want in (28, 255):
                ip = socket.inet_ntop(socket.AF_INET6, rd)
                if ip not in out:
                    out.append(ip)
    except Exception:
        return out
    return out


def _dns_query_udp(host, server, qtype, timeout=1.5):
    """Ask `server` directly over UDP/53. Used when the system resolver fails."""
    try:
        tid, pkt = _dns_build_query(host, qtype)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(pkt, (server, 53))
            for _ in range(3):
                data, _addr = s.recvfrom(4096)
                if len(data) >= 2 and int.from_bytes(data[:2], "big") == tid:
                    return _dns_parse_answers(data, qtype)
    except Exception:
        return []
    return []


def _dns_query_doh(host, qtype, endpoint, timeout=4.0):
    """DNS-over-HTTPS (RFC 8484 GET, wire format). Rides TCP/443, so it works
    in the situations where UDP/53 through the tunnel does not."""
    try:
        import urllib.request
        _tid, pkt = _dns_build_query(host, qtype)
        q = base64.urlsafe_b64encode(pkt).rstrip(b"=").decode("ascii")
        req = urllib.request.Request(
            f"{endpoint}?dns={q}",
            headers={"Accept": "application/dns-message",
                     "User-Agent": "v2ray-tun-btop/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return _dns_parse_answers(resp.read(), qtype)
    except Exception:
        return []


def _dns_cache_clear():
    with _DNS_CACHE_LOCK:
        _DNS_CACHE.clear()


def _resolve_detail(server, use_cache=True, fallback=False):
    """Resolve `server` (host, IP, or URL) to (v4_list, v6_list, err, source).

    err is None on success, otherwise a short reason suitable for the UI.
    source is one of literal | cache | system | udp:<ip> | doh:<url> | none.
    Never raises and never calls sys.exit - a failed lookup is data, not an
    error the dashboard should die on.

    fallback=False (default) means "system resolver only", which is what any
    UI-thread caller wants: the fallback stack can take seconds. The background
    bypass resolver calls it with fallback=True."""
    import ipaddress
    host = _host_from_url(server)
    if not host:
        return [], [], "empty entry", "none"
    try:
        ip = ipaddress.ip_address(host)
        return ([str(ip)] if ip.version == 4 else [],
                [str(ip)] if ip.version == 6 else [], None, "literal")
    except ValueError:
        pass

    now = time.time()
    if use_cache:
        with _DNS_CACHE_LOCK:
            hit = _DNS_CACHE.get(host)
        if hit and hit[2] > now:
            return list(hit[0]), list(hit[1]), hit[3], "cache"

    v4, v6, err, src = [], [], None, "system"
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for fam, _t, _p, _c, sa in infos:
            if fam == socket.AF_INET and sa[0] not in v4:
                v4.append(sa[0])
            elif fam == socket.AF_INET6 and sa[0] not in v6:
                v6.append(sa[0])
        if not v4 and not v6:
            err = "no usable addresses"
    except Exception as e:
        err = getattr(e, "strerror", None) or str(e) or e.__class__.__name__

    if not v4 and not v6 and fallback:
        for srv in _DNS_FALLBACK_SERVERS:
            a = _dns_query_udp(host, srv, 1)
            aaaa = _dns_query_udp(host, srv, 28)
            if a or aaaa:
                v4, v6, err, src = a, aaaa, None, f"udp:{srv}"
                break
    if not v4 and not v6 and fallback:
        for ep in _DNS_DOH_ENDPOINTS:
            a = _dns_query_doh(host, 1, ep)
            aaaa = _dns_query_doh(host, 28, ep)
            if a or aaaa:
                v4, v6, err, src = a, aaaa, None, f"doh:{ep.split('//')[-1]}"
                break

    ttl = _DNS_TTL_OK if (v4 or v6) else _DNS_TTL_FAIL
    with _DNS_CACHE_LOCK:
        _DNS_CACHE[host] = (list(v4), list(v6), now + ttl, err)
        if len(_DNS_CACHE) > 512:
            for k in [k for k, v in list(_DNS_CACHE.items()) if v[2] <= now]:
                _DNS_CACHE.pop(k, None)
    if not v4 and not v6:
        return [], [], err or "could not resolve", "none"
    return v4, v6, None, src


def _resolve(server, use_cache=True, fallback=False):
    """(v4_list, v6_list) for a host / IP / URL. Empty lists mean "not resolved
    right now" - callers must treat that as retryable, not fatal."""
    v4, v6, _err, _src = _resolve_detail(server, use_cache=use_cache, fallback=fallback)
    return v4, v6


def _resolve_cached(server):
    """Cache-only lookup: (v4, v6) if we already know them (or the entry is an
    IP literal), otherwise ([], []). Does ZERO network I/O, so UI-thread code
    (build_checks, panels) can call it on every rebuild without ever stalling a
    frame. The background bypass resolver is what fills the cache."""
    import ipaddress
    host = _host_from_url(server)
    if not host:
        return [], []
    try:
        ip = ipaddress.ip_address(host)
        return ([str(ip)] if ip.version == 4 else [],
                [str(ip)] if ip.version == 6 else [])
    except ValueError:
        pass
    with _DNS_CACHE_LOCK:
        hit = _DNS_CACHE.get(host)
    if hit and (hit[0] or hit[1]):
        return list(hit[0]), list(hit[1])
    return [], []

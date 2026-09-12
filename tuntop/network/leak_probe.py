"""Leak-probe mechanics (shared stdlib leaf - no tuntop imports).

Answers one question: "does traffic actually exit through the tunnel, or
does some of it escape to the Internet via the physical NIC?"

This module is imported by BOTH the dashboard's monitor layer
(tuntop/monitor/leak.py) and the standalone tunnel helper
(tuntop/tunnel/helper.py), so their leak semantics can never drift apart.
It is a pure stdlib leaf: it imports nothing from the tuntop package, no
UI, no Windows calls - the helper (launched as its own process) only needs
the package root on sys.path to use it.

Method (the same proof the manual [L] test always used, now automated):
  * DIRECT leg - fetch an IP-echo URL with plain sockets. When the
    full-tunnel routes are healthy this request traverses the TUN adapter
    anyway, so its source IP IS the tunnel exit (the startup verification
    probe has always relied on exactly this behaviour).
  * TUNNEL leg - fetch the same echo through the local SOCKS5 inbound
    (127.0.0.1:<port>), which by construction exits at the proxy server.

Verdict (this fixes the old inverted interpretation - the previous code
claimed "direct == proxied -> LEAK", which is backwards: when both legs
show the SAME IP that IP is the tunnel exit, i.e. even "direct" traffic
rides the TUN and nothing escapes):

  ok            direct == tunnel exit -> NO leak, all egress via the tunnel
  same-exit     direct != tunnel exit BUT both addresses belong to the
                SAME network (same /32) -> both legs still exited through
                the tunnel; the addresses differ only because the exit
                rotates its outbound address between connections (dual-
                stack pools, CDNs). NOT a leak: the real ISP IP would be
                from a completely different network. (The old code called
                this a LEAK - a false positive on every provider that
                rotates IPv6 addresses per connection.)
  leak          direct != tunnel exit AND the addresses belong to
                DIFFERENT networks -> direct traffic escapes the TUN and
                reveals the real (ISP) public IP
  no-proxy      the SOCKS inbound did not answer - tunnel leg impossible,
                                       not a leak verdict
  inconclusive  the tunnel leg is proven fine but the direct probe got no
                                       answer - leak state unknown
  no-network    neither leg answered

Robustness: each leg races SEVERAL echo endpoints concurrently and the
first answer that validates as a real IP address wins, so one blocked or
lying endpoint (captive portal, proxy interception page) can never
produce a false verdict.  Both legs run at the same time, so a healthy
setup is verified in about one round-trip.

Pure stdlib, zero pip dependencies.
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import socket
import ssl
import time

__all__ = ["run_leak_probe", "run_dns_leak_probe", "LEAK_TIMEOUT"]

# How long one echo attempt may take, and therefore the practical upper
# bound of the whole probe (both legs run concurrently).
_LEAK_V4_TIMEOUT = 3.0
LEAK_TIMEOUT = 5.0

# Prefix length under which two different addresses count as "the same
# network". /32 covers both real-world rotation cases: IPv6 providers hand
# out addresses from one /32 (or larger) block per exit, and IPv4 hosts sit
# on a single /32 by definition - so a genuine ISP IP (a different network
# altogether) can never land inside it, while exit-side rotation (pools,
# CDNs, per-connection IPv6) reliably does.
_PREFIX_LEN = 32


def _same_network(a, b):
    """True when two address strings belong to the same /{_PREFIX_LEN}.

    Two connections through the same tunnel exit frequently echo DIFFERENT
    addresses (the exit rotates its outbound IP: v6 pools, CDN frontends).
    A real leak shows a different NETWORK (your ISP), not a different
    address from the exit's own block - so comparing ownership, not string
    equality, is what stops the probe from crying wolf."""
    try:
        na = ipaddress.ip_network(f"{a}/{_PREFIX_LEN}", strict=False)
        nb = ipaddress.ip_network(f"{b}/{_PREFIX_LEN}", strict=False)
        return na == nb
    except ValueError:
        return False


#: Prefix lengths for the DNS probe's network comparison. DNS answers must
#: NOT be judged with the IP probe's /32: the ISP's recursive resolver is a
#: DIFFERENT host than the ISP egress (same /24 on a typical home IPv4
#: link, same /64 on IPv6) - at /32 a genuine leak would report "unknown".
_DNS_PREFIX = {4: 24, 6: 64}


def _dns_same_network(a, b):
    """True when two addresses share the DNS-probe network prefix (/24 for
    IPv4, /64 for IPv6); different families are never the same network."""
    try:
        fa = ipaddress.ip_address(a)
        fb = ipaddress.ip_address(b)
    except ValueError:
        return False
    if fa.version != fb.version:
        return False
    plen = _DNS_PREFIX[fa.version]
    return (ipaddress.ip_network(f"{a}/{plen}", strict=False)
            == ipaddress.ip_network(f"{b}/{plen}", strict=False))


# IP-echo endpoints raced per leg: (scheme, host, path).  HTTPS first
# (captive portals cannot forge a valid TLS certificate for these hosts),
# plain HTTP as fallback for hosts/networks where :443 egress is filtered.
_ECHO_ENDPOINTS = [
    ("https", "api.ipify.org", "/"),
    ("https", "ifconfig.me", "/ip"),
    ("https", "icanhazip.com", "/"),
    ("https", "api.ip.sb", "/ip"),
    ("http", "api.ipify.org", "/"),
    ("http", "icanhazip.com", "/"),
]

_UA = "tuntop-leak/1.0"

#: Shared TLS context for the IP-echo fetches: system-trusted CAs, hostname
#: verification ON, TLS 1.2+ only. One explicit context (not bare
#: ssl.wrap_socket) is both the secure construction and what static
#: analysers (CodeQL "use of insecure SSL/TLS version") require to see the
#: protocol floor is pinned.
_SSL_CONTEXT = ssl.create_default_context()
if hasattr(ssl, "TLSVersion"):
    try:
        _SSL_CONTEXT.minimum_version = ssl.TLSVersion.TLSv1_2
    except Exception:
        pass


def _tls_wrap(sock, host):
    """Server-authenticated TLS over an already-connected socket."""
    return _SSL_CONTEXT.wrap_socket(sock, server_hostname=host)


def _valid_ip(text):
    """Return the parsed IP string, or None if *text* is not a bare IP.

    Echo endpoints answer with a bare address; a captive portal or a proxy
    interception page answers with HTML - rejecting everything that does
    not strictly parse is what keeps the verdict honest."""
    if not text:
        return None
    candidate = text.strip().splitlines()[0].strip() if text.strip() else ""
    if not candidate:
        return None
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def _recv_exact(sock, size):
    """Read exactly *size* bytes unless the peer closes the socket."""
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _http_get(sock, scheme, host, path, timeout):
    """One raw HTTP GET over an already-connected socket.

    Returns the response BODY string.  Raises on any socket/TLS/HTTP
    error; non-200 replies raise too (a 301 to HTTPS or a portal's 302
    carries no usable IP)."""
    if scheme == "https":
        sock = _tls_wrap(sock, host)
    sock.settimeout(timeout)
    req = (f"GET {path} HTTP/1.1\r\n"
           f"Host: {host}\r\n"
           f"User-Agent: {_UA}\r\n"
           "Accept: */*\r\n"
           "Accept-Encoding: identity\r\n"
           "Connection: close\r\n\r\n").encode("ascii")
    sock.sendall(req)
    buf = b""
    while len(buf) < 16384:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
    head, _, body = buf.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0] if head else b""
    parts = status_line.split(b" ")
    if len(parts) < 2 or not parts[1].startswith(b"2"):
        code = parts[1].decode("ascii", "replace") if len(parts) > 1 else "?"
        raise OSError(f"HTTP {code}")
    return body.decode("utf-8", "replace")


def _fetch_direct(scheme, host, path, timeout):
    """Fetch the echo URL with a DIRECT socket.  With the full-tunnel
    routes installed this connection is routed through the TUN, so the
    echoed source IP is the tunnel exit."""
    port = 443 if scheme == "https" else 80
    with socket.create_connection((host, port), timeout=timeout) as sock:
        return _http_get(sock, scheme, host, path, timeout)


def _fetch_direct_v4(scheme, host, path, timeout):
    """_fetch_direct constrained to IPv4: resolve the host's A record and
    connect to it by literal IP (SNI/Host still the hostname).  Used when
    the plain direct leg answers over a DIFFERENT family than the tunnel
    leg - the TUN routes IPv4, so the honest comparison is v4 vs v4."""
    port = 443 if scheme == "https" else 80
    infos = [(ai[0], ai[4]) for ai in socket.getaddrinfo(host, port)
             if ai[0] == socket.AF_INET]
    if not infos:
        raise OSError(f"{host}: no IPv4 address")
    last = None
    for _fam, sa in infos[:3]:
        try:
            with socket.create_connection((sa[0], port), timeout=timeout) as sock:
                if scheme == "https":
                    return _http_get(_tls_wrap(sock, host),
                                     scheme, host, path, timeout)
                return _http_get(sock, scheme, host, path, timeout)
        except OSError as e:
            last = e
    raise last or OSError(f"{host}: IPv4 connect failed")


def _socks5_connect(socks_port, host, dst_port, timeout):
    """SOCKS5 CONNECT (no-auth, remote DNS) to host:dst_port via
    127.0.0.1:<socks_port>; returns the connected tunnelled socket."""
    sock = socket.create_connection(("127.0.0.1", socks_port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        if _recv_exact(sock, 2) != b"\x05\x00":
            raise OSError("SOCKS5 handshake rejected")
        dom = host.encode("ascii")
        if len(dom) > 255:
            raise OSError(f"host too long: {host}")
        sock.sendall(b"\x05\x01\x00\x03" + bytes((len(dom),)) + dom
                     + dst_port.to_bytes(2, "big"))
        head = _recv_exact(sock, 4)
        if len(head) < 4:
            raise OSError(f"SOCKS5 short reply: {head!r}")
        if head[1] != 0:
            raise OSError(f"SOCKS5 CONNECT rejected (code {head[1]})")
        atyp = head[3]
        tail_len = {1: 4 + 2, 4: 16 + 2}.get(atyp)
        if tail_len is None:
            length = _recv_exact(sock, 1)
            if len(length) != 1:
                raise OSError("SOCKS5 malformed reply")
            tail_len = length[0] + 2
        tail = _recv_exact(sock, tail_len)
        if len(tail) != tail_len:
            raise OSError("SOCKS5 truncated reply")
        return sock
    except Exception:
        try:
            sock.close()
        except OSError:
            pass
        raise


def _fetch_via_socks(socks_port, scheme, host, path, timeout):
    """Fetch the echo URL THROUGH the local SOCKS5 inbound.  The echoed
    source IP is by construction the proxy's exit IP."""
    port = 443 if scheme == "https" else 80
    sock = _socks5_connect(socks_port, host, port, timeout)
    try:
        return _http_get(sock, scheme, host, path, timeout)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _race_leg(fetcher, timeout):
    """Race every echo endpoint concurrently; the first VALIDATED IP wins.

    Returns {"ip": str|None, "err": str|None, "ms": int}.  An endpoint that
    answers with junk (HTML/redirect/empty) is simply discarded - the race
    continues until a clean answer arrives or the budget runs out.

    TIMEOUT BOUNDING (do not "simplify" this back into a `with` block):
    socket.create_connection() resolves DNS via getaddrinfo() BEFORE any
    socket exists, and that resolution is an unbounded blocking OS call the
    socket timeout does NOT cover; Future.cancel() likewise cannot stop a
    thread that already started running.  On DPI-heavy networks individual
    hostnames get blackholed exactly like this, so the executor's implicit
    context-manager join would stall the caller with no real ceiling - and
    on the helper side the caller is the single-threaded monitor loop that
    also drives self-heal.  So: wait with our own ceiling, then shut the
    executor down WITHOUT joining.  Abandoned stragglers are harmless:
    _run only ever fills out["ip"] from None and shares no other state."""
    t0 = time.time()
    out = {"ip": None, "err": None, "ms": 0}

    def _run(scheme, host, path):
        if out["ip"]:
            return
        try:
            body = fetcher(scheme, host, path, timeout)
        except Exception as e:
            if out["err"] is None:
                out["err"] = f"{host}: {e}"
            return
        ip = _valid_ip(body)
        if ip and out["ip"] is None:
            out["ip"] = ip

    ex = concurrent.futures.ThreadPoolExecutor(
        max_workers=len(_ECHO_ENDPOINTS))
    try:
        futs = [ex.submit(_run, *ep) for ep in _ECHO_ENDPOINTS]
        concurrent.futures.wait(futs, timeout=timeout + 2)
    finally:
        # Never join the workers (see the timeout-bounding note above).
        ex.shutdown(wait=False, cancel_futures=True)
    out["ms"] = int((time.time() - t0) * 1000)
    return out


def _sequential_leg(fetcher, timeout):
    """Thread-free fallback for _race_leg(): try the echo endpoints ONE BY
    ONE (first validated IP wins, same discard rules).

    Exists for environments where the thread pool itself is unavailable -
    notably the frozen exe, whose FIRST `concurrent.futures.thread` import
    happens inside the probe (module-level __getattr__ lazy import) and
    decompresses a PYZ entry with zlib; a damaged/tampered archive raises
    zlib.error ("Error -3 ... incorrect header check") exactly there, which
    used to escape every per-endpoint handler and crash the [L] test."""
    out = {"ip": None, "err": None, "ms": 0}
    t0 = time.time()
    for scheme, host, path in _ECHO_ENDPOINTS:
        try:
            body = fetcher(scheme, host, path, timeout)
        except Exception as e:
            if out["err"] is None:
                out["err"] = f"{host}: {e}"
            continue
        ip = _valid_ip(body)
        if ip:
            out["ip"] = ip
            break
    out["ms"] = int((time.time() - t0) * 1000)
    return out


def _race_leg_or_sequential(fetcher, timeout):
    """_race_leg(), but immune to a thread-pool failure outside the
    per-endpoint handlers: if the executor cannot be created/used (frozen
    exe lazy import failing, thread exhaustion, ...), retry the endpoints
    sequentially. The leak probe must produce a VERDICT, never crash."""
    try:
        return _race_leg(fetcher, timeout)
    except Exception:
        return _sequential_leg(fetcher, timeout)


def _verdict(direct, tunnel, socks_port):
    """Map (direct_leg, tunnel_leg) onto (status, message)."""
    dip, tip = direct["ip"], tunnel["ip"]
    if dip is None and tip is None:
        return "no-network", ("neither the direct nor the tunneled probe got "
                              f"an answer (direct: {direct['err'] or 'no answer'}; "
                              f"tunnel: {tunnel['err'] or 'no answer'})")
    if tip is None:
        return "no-proxy", (f"SOCKS inbound 127.0.0.1:{socks_port} did not "
                            f"answer ({tunnel['err'] or 'no answer'}) - is "
                            "your proxy client running on that port?")
    if dip is None:
        return "inconclusive", (f"tunnel exit {tip} OK, but the direct probe "
                                f"got no answer ({direct['err'] or 'no answer'}) "
                                "- leak state unknown (the tunnel itself works)")
    if dip == tip:
        return "ok", (f"no leak - direct egress matches the tunnel exit {tip}; "
                      "all traffic rides the TUN")
    if _same_network(dip, tip):
        return "same-exit", (
            f"no leak - direct egress {dip} and tunnel exit {tip} differ but "
            f"belong to the SAME network (/{_PREFIX_LEN}): both legs exited "
            "through the tunnel; the exit server rotated its outbound address "
            "between the two connections. Your real IP was NOT exposed.")
    # Mixed families (direct answered v6, tunnel exited v4 - or reverse):
    # a cross-family /32 compare is ALWAYS False, which used to produce a
    # bogus "LEAK" whenever the machine had native/VPN-provided IPv6. The
    # TUN routes IPv4, so re-probe the direct leg forced to IPv4 and make
    # the honest v4-vs-v4 comparison; the v6 divergence is reported as its
    # own informational verdict.
    try:
        fam_d = ipaddress.ip_address(dip).version
        fam_t = ipaddress.ip_address(tip).version
    except ValueError:
        fam_d = fam_t = 0
    if fam_d != fam_t:
        v4 = _race_leg_or_sequential(_fetch_direct_v4, _LEAK_V4_TIMEOUT)
        if v4["ip"]:
            if v4["ip"] == tip or _same_network(v4["ip"], tip):
                return "v6-side", (
                    f"no IPv4 leak - direct IPv4 egress {v4['ip']} rides the "
                    f"tunnel exit {tip}. The plain direct leg answered over "
                    f"IPv6 ({dip}), i.e. IPv6 leaves via a DIFFERENT path "
                    "(native or VPN-provided v6 that the TUN does not route). "
                    "IPv4-only clients leak nothing; to cover v6 too, block "
                    "or route IPv6 as well.")
            return "leak", (f"LEAK: direct IPv4 egress {v4['ip']} != tunnel "
                            f"exit {tip} (re-probed v4-vs-v4 after the first "
                            f"direct leg answered over v6 {dip}) - IPv4 "
                            "traffic escapes the TUN.")
        return "inconclusive", (
            f"tunnel exit {tip}, direct leg answered over IPv6 ({dip}) and "
            "the forced-IPv4 re-probe got no answer - leak state unknown "
            "(the tunnel itself works)")
    return "leak", (f"LEAK: direct egress {dip} != tunnel exit {tip} - the two "
                    "addresses belong to DIFFERENT networks, so direct traffic "
                    "escapes outside the TUN and shows your real IP "
                    "(expected only if you deliberately bypass this destination)")


# ─── DNS leak probe ──────────────────────────────────────────────────────────
# Answers the second half of the leak question: "does DNS itself stay inside
# the tunnel, or do name queries escape to the ISP?" A full-tunnel IP check
# can pass while every DNS packet still rides the physical NIC (wintun's DNS
# is set on the ADAPTER - anything that bypasses it, a hardcoded resolver,
# an app with its own DoH fallback disabled/overridden, ... leaks silently).
#
# Two independent sub-tests, both pure stdlib (no third-party resolver API,
# same philosophy as the IP-echo racing above):
#
# 1) SYSTEM RESOLVER identity - socket.getaddrinfo("whoami.akamai.net").
#    That hostname's A record IS the public IP of the recursive resolver
#    that asked Akamai. With the tunnel up, wintun's configured DNS
#    (e.g. 8.8.8.8) answers, so the seen resolver belongs to the tunnel's
#    DNS provider - never to the ISP. If the seen resolver sits on the same
#    network as the direct (ISP) egress IP, system DNS is leaking.
#
# 2) FORCED UDP/53 path test - a hand-built DNS query sent straight to a
#    public resolver (8.8.8.8 / 1.1.1.1) over the system routing table.
#    "o-o.myaddr.l.google.com" TXT (and "whoami.akamai.net" A against the
#    same server as fallback) echoes back the egress IP that carried the
#    query. That egress matching the TUNNEL EXIT -> DNS rides the TUN.
#    Matching the DIRECT (ISP) egress -> UDP/53 escapes the TUN: leak.
#
# Verdicts: "ok" (DNS rides the tunnel), "dns-leak" (name queries escape),
# "unknown" (answers arrived but the comparison was inconclusive - e.g. no
# egress IPs from the IP probe to compare against), "no-dns" (nothing
# answered). A sub-test failure never crashes the caller: every step is
# guarded, the probe must always return a verdict like the IP probe does.

_DNS_IDENTITY_HOSTS = ("whoami.akamai.net",)
_DNS_PATH_SERVERS = ("8.8.8.8", "1.1.1.1")
_DNS_PATH_QNAME = "o-o.myaddr.l.google.com"

#: DNS record types used below (RFC 1035): A = 1, TXT = 16.
_DNS_TYPE_A = 1
_DNS_TYPE_TXT = 16


def _dns_build_query(qname, qtype, qid=0x1F2E):
    """One standard UDP DNS query packet for `qname`/`qtype` (recursion
    desired, single question - everything the echo endpoints need)."""
    labels = b"".join(
        bytes((len(part),)) + part.encode("idna" if not part.isascii()
                                          else "ascii")
        for part in qname.split(".") if part) + b"\x00"
    header = (qid.to_bytes(2, "big")
              + (0x0100).to_bytes(2, "big")   # RD=1
              + (1).to_bytes(2, "big")        # QDCOUNT
              + b"\x00\x00\x00\x00\x00\x00")  # AN/NS/ARCOUNT = 0
    return header + labels + qtype.to_bytes(2, "big") + (1).to_bytes(2, "big")


def _dns_skip_name(msg, off):
    """Skip a (possibly compressed) DNS name starting at `off`.
    Returns the offset just past it, or None on a malformed name."""
    n = len(msg)
    jumped = False
    end = None
    for _ in range(64):              # pointer-cycle guard: real names never
        if off >= n:                 # need anywhere near this many jumps
            return None
        length = msg[off]
        if length == 0:
            off += 1
            return end if jumped else off
        if length >= 0xC0:               # compression pointer
            if off + 1 >= n:
                return None
            if end is None:
                end = off + 2
            off = ((length & 0x3F) << 8) | msg[off + 1]
            jumped = True
            continue
        if length > 63:                  # reserved label type - malformed
            return None
        off += 1 + length
    return None                          # pointer cycle - treat as malformed


def _dns_parse_reply(msg, want_types=(_DNS_TYPE_A, _DNS_TYPE_TXT)):
    """Extract the first usable value from a DNS reply's answer section:
    an IPv4 address (A) or the concatenation of a TXT record's strings.
    Returns the payload string or None."""
    try:
        if len(msg) < 12:
            return None
        qd = int.from_bytes(msg[4:6], "big")
        an = int.from_bytes(msg[6:8], "big")
        off = 12
        for _ in range(qd):              # skip the question section
            off = _dns_skip_name(msg, off)
            if off is None:
                return None
            off += 4
        for _ in range(an):
            off = _dns_skip_name(msg, off)
            if off is None or off + 10 > len(msg):
                return None
            rtype = int.from_bytes(msg[off:off + 2], "big")
            rdlen = int.from_bytes(msg[off + 8:off + 10], "big")
            rdata = msg[off + 10:off + 10 + rdlen]
            off += 10 + rdlen
            if rtype not in want_types or len(rdata) == 0:
                continue
            if rtype == _DNS_TYPE_A and rdlen == 4:
                return str(ipaddress.IPv4Address(rdata))
            if rtype == _DNS_TYPE_TXT:
                # TXT rdata = sequence of <len><bytes> strings; the echo
                # services put the IP in the first (or only) string.
                texts, i = [], 0
                while i < len(rdata):
                    ln = rdata[i]
                    texts.append(rdata[i + 1:i + 1 + ln].decode(
                        "ascii", "ignore"))
                    i += 1 + ln
                return "".join(texts)
    except Exception:
        return None
    return None


def run_leak_probe(socks_port, timeout=LEAK_TIMEOUT):
    """Run both legs CONCURRENTLY and compare the egress IPs.

    Returns (status, message, legs) with status in
    {"ok", "leak", "no-proxy", "inconclusive", "no-network"} and
    legs = {"direct": {...}, "tunnel": {...}} (ip/err/ms per leg).

    The two legs are joined here with result(), but that is bounded:
    _race_leg() always returns within ~timeout + 2 regardless of whether
    its worker threads are still stuck (see its timeout-bounding note).

    Resilience: a failure of the THREADING machinery itself (outside the
    per-endpoint handlers _race_leg already has) - e.g. the frozen exe's
    lazy `concurrent.futures.thread` import decompressing a damaged PYZ
    entry (zlib.error "incorrect header check") - is caught here and both
    legs are re-run SEQUENTIALLY, so [L] always returns a verdict."""
    socks_port = int(socks_port)

    def _tunnel(scheme, host, path, t):
        return _fetch_via_socks(socks_port, scheme, host, path, t)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            f_direct = ex.submit(_race_leg, _fetch_direct, timeout)
            f_tunnel = ex.submit(_race_leg, _tunnel, timeout)
            direct = f_direct.result()
            tunnel = f_tunnel.result()
    except Exception:
        direct = _sequential_leg(_fetch_direct, timeout)
        tunnel = _sequential_leg(_tunnel, timeout)
    status, message = _verdict(direct, tunnel, socks_port)
    return status, message, {"direct": direct, "tunnel": tunnel}


def _dns_udp_query(server, qname, qtype, timeout):
    """Send one UDP DNS query to `server`:53, return the parsed answer
    payload (IP string) or None. Never raises."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(_dns_build_query(qname, qtype), (server, 53))
        data, _addr = sock.recvfrom(2048)
        return _dns_parse_reply(data)
    except Exception:
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _system_resolver_ip():
    """The public IP of the recursive resolver the SYSTEM currently uses
    (A record of whoami.akamai.net), or None. getaddrinfo has no timeout
    knob - callers run this on a raced worker thread like every other leg."""
    for host in _DNS_IDENTITY_HOSTS:
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET,
                                       socket.SOCK_DGRAM)
        except Exception:
            continue
        for _fam, _typ, _proto, _canon, sockaddr in infos:
            ip = _valid_ip(sockaddr[0])
            if ip:
                return ip
    return None


def _forced_path_echo_ip(timeout):
    """Egress IP as seen by a public resolver when WE send the DNS query:
    race TXT(o-o.myaddr.l.google.com) against 8.8.8.8/1.1.1.1 (plus the
    whoami.akamai.net A fallback against the same servers). The first valid
    IP wins - one hijacking/hiding resolver can never own the verdict."""
    attempts = [(srv, _DNS_PATH_QNAME, _DNS_TYPE_TXT)
                for srv in _DNS_PATH_SERVERS]
    attempts += [(srv, _DNS_IDENTITY_HOSTS[0], _DNS_TYPE_A)
                 for srv in _DNS_PATH_SERVERS]
    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(attempts)) as ex:
        futs = {ex.submit(_dns_udp_query, srv, qn, qt,
                          max(1.0, timeout - (time.time() - t0))): (srv, qn)
                for srv, qn, qt in attempts}
        done, _not = concurrent.futures.wait(futs, timeout=timeout + 2)
        for f in done:
            ip = _valid_ip(f.result() or "")
            if ip:
                return ip
    return None


def run_dns_leak_probe(direct_ip=None, tunnel_ip=None, expected_dns=(),
                       timeout=LEAK_TIMEOUT):
    """DNS half of the leak test. Returns (status, message, detail) with
    status in {"ok", "dns-leak", "unknown", "no-dns"} and detail =
    {"resolver": ..., "echo": ...}.

    `direct_ip` / `tunnel_ip` are the egress IPs the IP leak probe already
    measured (pass them so the two tests share one picture); `expected_dns`
    lists the tunnel's configured DNS servers (a resolver identity matching
    one of these is proof-positive that system DNS rides the tunnel).
    """
    expected = [str(x).strip() for x in (expected_dns or ()) if x]

    def _expected_match(ip):
        return any(ip == e or _dns_same_network(ip, e) for e in expected)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            f_res = ex.submit(_system_resolver_ip)
            f_echo = ex.submit(_forced_path_echo_ip, timeout)
            resolver = f_res.result(timeout + 5)
            echo = f_echo.result(timeout + 5)
    except Exception:
        # Frozen-exe lazy-import/thread-pool failure: retry sequentially
        # (same resilience rule as _race_leg_or_sequential above).
        resolver = _system_resolver_ip()
        echo = _forced_path_echo_ip(timeout)

    detail = {"resolver": resolver, "echo": echo}
    parts = []
    if resolver:
        parts.append(f"system resolver = {resolver}")
    if echo:
        parts.append(f"UDP/53 path egress = {echo}")
    suffix = f" ({'; '.join(parts)})" if parts else ""
    resolver_is_expected = bool(
        resolver and expected and _expected_match(resolver))

    # ── Leak evidence first: any hit decides the verdict. ──
    if echo and direct_ip and _dns_same_network(echo, direct_ip):
        # The forced query went straight to a PUBLIC resolver: if its UDP/53
        # packet exits on the ISP network, the TUN is being escaped - a leak
        # no matter which DNS the user configured.
        return "dns-leak", (
            f"DNS LEAK: a direct UDP/53 query to a public resolver exited "
            f"via {echo}, the same network as your direct (ISP) egress "
            f"{direct_ip} - DNS packets escape the TUN instead of riding "
            f"the tunnel.{suffix}"), detail
    if (resolver and direct_ip and _dns_same_network(resolver, direct_ip)
            and not resolver_is_expected):
        return "dns-leak", (
            f"DNS LEAK: your system resolver ({resolver}) sits on the same "
            f"network as your direct (ISP) egress {direct_ip} - name queries "
            "are answered by the ISP's resolver, OUTSIDE the tunnel. Set the "
            "tunnel's DNS ([N]) or make sure the wintun adapter's DNS is "
            f"actually being used.{suffix}"), detail

    # ── Positive evidence next. ──
    if resolver_is_expected:
        extra = ""
        if echo and tunnel_ip and _dns_same_network(echo, tunnel_ip):
            extra = (" The forced UDP/53 path test confirms it: the query "
                     f"egress {echo} is the tunnel exit.")
        elif echo and tunnel_ip:
            extra = (f" Note: the forced UDP/53 egress {echo} differs from "
                     f"the tunnel exit {tunnel_ip} - resolver identity "
                     "still rides the configured DNS.")
        return "ok", (
            f"no DNS leak - the system resolver ({resolver}) matches the "
            f"tunnel's configured DNS; name resolution rides the tunnel."
            f"{extra}{suffix}"), detail
    if echo and tunnel_ip and _dns_same_network(echo, tunnel_ip):
        return "ok", (
            f"no DNS leak - a forced UDP/53 query to a public resolver "
            f"exited via {echo}, the tunnel exit; DNS traffic rides the "
            f"TUN.{suffix}"), detail

    # ── Nothing usable. ──
    if not resolver and not echo:
        return "no-dns", (
            "DNS leak test inconclusive: neither the system-resolver probe "
            "nor the forced UDP/53 path probe got an answer (network or "
            f"resolver filtering){suffix}"), detail
    return "unknown", (
        "DNS leak test inconclusive - answers arrived but could not be "
        "compared against the egress IPs the IP leak probe measured "
        f"(run the IP test alongside this one for a full picture){suffix}"), detail

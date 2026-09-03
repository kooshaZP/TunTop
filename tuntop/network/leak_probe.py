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
  leak          direct != tunnel exit -> direct traffic escapes the TUN and
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

__all__ = ["run_leak_probe", "LEAK_TIMEOUT"]

# How long one echo attempt may take, and therefore the practical upper
# bound of the whole probe (both legs run concurrently).
LEAK_TIMEOUT = 5.0

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
        sock = ssl.create_default_context().wrap_socket(
            sock, server_hostname=host)
    sock.settimeout(timeout)
    req = (f"GET {path} HTTP/1.1\r\n"
           f"Host: {host}\r\n"
           f"User-Agent: {_UA}\r\n"
           "Accept: */*\r\n"
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
    return "leak", (f"LEAK: direct egress {dip} != tunnel exit {tip} - direct "
                    "traffic escapes outside the TUN and shows your real IP "
                    "(expected only if you deliberately bypass this destination)")


def run_leak_probe(socks_port, timeout=LEAK_TIMEOUT):
    """Run both legs CONCURRENTLY and compare the egress IPs.

    Returns (status, message, legs) with status in
    {"ok", "leak", "no-proxy", "inconclusive", "no-network"} and
    legs = {"direct": {...}, "tunnel": {...}} (ip/err/ms per leg).

    The two legs are joined here with result(), but that is bounded:
    _race_leg() always returns within ~timeout + 2 regardless of whether
    its worker threads are still stuck (see its timeout-bounding note)."""
    socks_port = int(socks_port)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        f_direct = ex.submit(_race_leg, _fetch_direct, timeout)
        f_tunnel = ex.submit(
            _race_leg,
            lambda s, h, p, t: _fetch_via_socks(socks_port, s, h, p, t),
            timeout)
        direct = f_direct.result()
        tunnel = f_tunnel.result()
    status, message = _verdict(direct, tunnel, socks_port)
    return status, message, {"direct": direct, "tunnel": tunnel}


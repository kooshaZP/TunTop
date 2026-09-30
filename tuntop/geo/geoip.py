"""GeoIP database parsing: v2ray .dat (protobuf wire format), raw protobuf
and JSON variants, plus an on-disk cache. Moved verbatim out of the old
single-file helper."""
import hashlib
import ipaddress
import json
import os
import ssl
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request


def _read_varint(buf, pos):
    result = 0
    shift = 0
    while pos < len(buf):
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def _read_bytes(buf, pos):
    length, pos = _read_varint(buf, pos)
    return buf[pos:pos + length], pos + length


#: Minimum prefix length for an installable country range, per family. No real
#: country block is this broad; a range this wide is a default route or a slice
#: of the entire address space. Installed at metric=1 as an active route it is
#: more specific than the tunnel's 0/0 + /1 (and ::/0 + ::/1 + 8000::/1)
#: split-defaults, so it would capture ALL traffic that is supposed to stay in
#: the tunnel - a silent, total exfiltration rather than a misroute.
#:
#: Deliberately duplicated from
#: tuntop.tunnel.helper._is_routable_bypass_cidr, which enforces the same
#: floors at the INSTALL boundary. Two layers, on purpose: the helper and this
#: parser are separately importable, and the check must not be optional on
#: either path. tests/unit/test_geoip_trust.py pins them to the same values.
_MIN_PREFIXLEN = {4: 8, 6: 16}


def _normalise_cidr(text):
    """Canonicalise one CIDR string; return None if it is unusable.

    The single gate every geo range passes through, whichever decoder
    produced it. Rejects non-strings, unparseable input, and any range at or
    above the per-family prefix floor. Returns the CANONICAL compressed form
    (`ipaddress.ip_network(..., strict=False)`), which is also what
    `Get-NetRoute` reports - so the route table, the conflict sweep's HashSet
    and the live-table comparisons all agree by construction. (They did not:
    a non-canonical `2001:0DB8::/32` installed fine and then failed every
    string comparison against the live table forever - see CHANGELOG 1.0.41.)
    """
    try:
        net = ipaddress.ip_network(str(text).strip(), strict=False)
    except (ValueError, TypeError):
        return None
    if net.prefixlen < _MIN_PREFIXLEN[net.version]:
        return None
    return str(net)


def _geoip_skip(buf, pos, wire):
    if wire == 0:
        _, pos = _read_varint(buf, pos)
    elif wire == 1:
        pos += 8
    elif wire == 2:
        _, pos = _read_bytes(buf, pos)
    elif wire == 5:
        pos += 4
    else:
        raise ValueError("bad wire type %d" % wire)
    return pos


def _clean_err(err):
    """Pull a human-readable line out of a PowerShell stderr blob, skipping
    the '#< CLIXML' progress/telemetry records PowerShell wraps around errors
    so the geo-install failure reason is actually readable."""
    for line in (err or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#<"):
            continue
        return line
    return ""


def _geoip_parse_cidr(msg):
    """Return (ip_bytes, prefix) for one CIDR message.

    `prefix` starts as None, NOT 0: a truncated/hand-edited .dat whose CIDR
    message carries no prefix field used to decode as "1.2.3.4/0", which
    normalises to 0.0.0.0/0 and routed the ENTIRE internet to the direct
    egress. A missing prefix is now reported as such and dropped.
    """
    ip = None
    prefix = None
    pos = 0
    n = len(msg)
    while pos < n:
        tag, pos = _read_varint(msg, pos)
        field = tag >> 3
        wire = tag & 0x07
        if field == 1 and wire == 2:
            ip, pos = _read_bytes(msg, pos)
        elif field == 2 and wire == 0:
            prefix, pos = _read_varint(msg, pos)
        else:
            pos = _geoip_skip(msg, pos, wire)
    return ip, prefix


def _geoip_cidr_to_str(ip, prefix):
    """Render one CIDR, NORMALISED through ipaddress.

    Three bugs this removes:
      * a missing prefix became 0 -> "1.2.3.4/0" -> 0.0.0.0/0, i.e. the whole
        IPv4 (or IPv6) space routed to the direct egress. A default route is
        never a geoip country range, so it is rejected outright.
      * IPv6 came out as eight uncompressed groups ("2001:db8:0:0:0:0:0:0/32")
        while Get-NetRoute and the exit sweeps use the canonical compressed
        form ("2001:db8::/32") - so every IPv6 geo route failed every string
        comparison against the live route table and survived every sweep.
      * no per-family prefix floor, so an explicit 0.0.0.0/0 or 0.0.0.0/1 in a
        .dat came out verbatim. The install boundary refuses those, but the
        SWEEP boundary (dashboard / cleanup_watchdog) deletes on exact-prefix
        match with no allow-list, and 0.0.0.0/1 + 128.0.0.0/1 are TunTop's own
        split-defaults - so [R] or exiting removed half of them and the
        tunnel's traffic fell back to the physical NIC. _MIN_PREFIXLEN now
        applies here too, which is what makes _normalise_cidr's "single gate,
        whichever decoder produced it" true.
    """
    if ip is None or prefix is None:
        return None
    maxlen = 32 if len(ip) == 4 else 128 if len(ip) == 16 else None
    if maxlen is None:
        return None
    try:
        if len(ip) == 4:
            addr = ".".join(str(b) for b in ip)
        else:
            addr = ":".join("%x" % int.from_bytes(ip[i:i + 2], "big")
                            for i in range(0, 16, 2))
        plen = int(prefix)
    except Exception:
        return None
    if not 0 <= plen < maxlen:
        # 0 (and anything out of range) would be a default route: never a
        # country range, and the worst possible thing to install.
        return None
    # The per-family floor (_MIN_PREFIXLEN) is enforced HERE as well as in
    # _normalise_cidr. Without it this decoder accepted e.g. 0.0.0.0/1, which
    # is one of the split-defaults TunTop installs ITSELF - so the geo sweep
    # could delete half the tunnel's own default set on [R] or on exit. The
    # install boundary (_is_routable_bypass_cidr) already refuses these; the
    # sweep boundary has to refuse them too, and it only sees what this
    # function emits.
    if plen < _MIN_PREFIXLEN[4 if len(ip) == 4 else 6]:
        return None
    try:
        return str(ipaddress.ip_network("%s/%d" % (addr, plen), strict=False))
    except ValueError:
        return None


def _geoip_parse_entry(msg):
    """Return (country_code, [(ip_bytes, prefix), ...]) for one GeoIP entry."""
    country = None
    cidrs = []
    pos = 0
    n = len(msg)
    while pos < n:
        tag, pos = _read_varint(msg, pos)
        field = tag >> 3
        wire = tag & 0x07
        if field == 1 and wire == 2:
            s, pos = _read_bytes(msg, pos)
            country = s.decode("utf-8", "replace")
        elif field == 2 and wire == 2:
            cmsg, pos = _read_bytes(msg, pos)
            ip, prefix = _geoip_parse_cidr(cmsg)
            if ip is not None:
                cidrs.append((ip, prefix))
        else:
            pos = _geoip_skip(msg, pos, wire)
    return country, cidrs


# ─── geoip file loading (.dat OR .json) ──────────────────────────────────────
# v2rayN ships geoip data in two formats:
#   * .dat  → protobuf (GeoIPList). Parsed in pure Python, with an OPTIONAL
#             fast-path through the official `google.protobuf` library when it
#             happens to be importable (NO hard dependency is added).
#   * .json → the v2fly "geoformat" (plain JSON). Simpler and more robust than
#             binary protobuf, and now produced by v2rayN / sing-box tooling.
#
# The format is decoded ONCE per file into a cached dict (every country at
# once), so repeated --geoip-code lookups never re-read and re-parse the whole
# multi-megabyte file. Format is auto-detected from the file contents.

_GEOIP_CACHE = {}
_GEO_PROTO = None  # geoip message class (built lazily), or None
_GEO_PROTO_LOGGED = False  # emit the "protobuf vs pure-Python" log line only once

# ── v2fly release download ────────────────────────────────────────────────────
# Official community-built database. The .sha256sum sibling verifies the
# payload so a truncated / tampered file never reaches the routing layer.
GEOIP_DAT_URL = ("https://github.com/v2fly/geoip/releases/"
                 "latest/download/geoip.dat")
GEOIP_DAT_SHA_URL = GEOIP_DAT_URL + ".sha256sum"


#: Hosts the geo database (and its checksum) may legitimately come from.
#: A 30x that leaves this set is refused rather than followed - see
#: config.updates._SameHostRedirectHandler, which this downloader now shares
#: the transport with.
GEO_ALLOWED_HOSTS = frozenset({"github.com", "objects.githubusercontent.com",
                               "release-assets.githubusercontent.com",
                               "raw.githubusercontent.com"})

#: Hard cap on the download. The real file is a few MB; anything vastly larger
#: is either a mistake or an attempt to exhaust memory/disk in an admin process.
GEO_MAX_BYTES = 64 * 1024 * 1024

_SSL_CONTEXT = ssl.create_default_context()
if hasattr(ssl, "TLSVersion"):
    _SSL_CONTEXT.minimum_version = ssl.TLSVersion.TLSv1_2


class _GeoSameHostRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse a 30x that leaves GEO_ALLOWED_HOSTS.

    urlopen() installs the DEFAULT redirect handler, which follows a 302 to
    any host and any scheme. The updater already learned this lesson and built
    its own opener; the geo downloader kept using bare urlopen, so it had
    neither a TLS floor, nor a redirect allow-list, nor a size cap.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            host = urllib.parse.urlsplit(newurl).hostname or ""
        except ValueError:
            raise urllib.error.HTTPError(
                newurl, code, f"malformed redirect target: {msg}",
                headers, fp)
        if host.lower() not in GEO_ALLOWED_HOSTS:
            raise urllib.error.HTTPError(
                newurl, code,
                f"refusing redirect to an unexpected host ({host})",
                headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_GEO_OPENER = urllib.request.build_opener(
    _GeoSameHostRedirectHandler(),
    urllib.request.HTTPSHandler(context=_SSL_CONTEXT),
)


def _assert_allowed_geo_url(url):
    try:
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
    except ValueError:
        raise ValueError(f"malformed geoip URL: {url!r}")
    if host not in GEO_ALLOWED_HOSTS:
        raise ValueError(
            f"refusing to download the geo database from an unexpected host "
            f"({host or 'none'}) - allowed: "
            f"{', '.join(sorted(GEO_ALLOWED_HOSTS))}")


def download_geoip(dest_path, url=GEOIP_DAT_URL, sha_url=GEOIP_DAT_SHA_URL,
                   progress=None, timeout=60, strict_checksum=True):
    """Stream the v2fly geoip database to `dest_path` and return its size.

    * Downloads via streaming chunks into a temp `.part` file IN THE SAME
      directory as dest_path, then atomically os.replace()s it - an aborted
      download can never leave a half-written geoip.dat behind.
    * Goes through `_GEO_OPENER`, not urlopen: an explicit TLS 1.2+ floor, a
      redirect allow-list (every hop must stay on a GitHub host), and a size
      cap. Bare urlopen had NONE of the three, even though the updater in
      config/updates.py has had all three since it was written.
    * SHA-256 is computed WHILE downloading (no re-read), then compared with
      the release's .sha256sum: a MISMATCH raises ValueError and the bad file
      is never installed.
    * `strict_checksum=True` (the default) also FAILS CLOSED when the checksum
      itself cannot be fetched. It used to fail OPEN - `except: ref = None`
      and the install proceeded - which for a geo database is not a cosmetic
      weakness: these CIDRs decide what leaves the machine unencrypted. The
      README describes the weaker behaviour honestly, but "trust on first
      use" is a reasonable thing to opt into deliberately and a bad default to
      ship silently. Pass strict_checksum=False to get the old behaviour.
    * progress(done_bytes, total_bytes_or_0) is called per chunk - total comes
      from Content-Length and may be 0 when the server does not send it.
    * Honors HTTP(S)_PROXY environment variables automatically (urllib)."""
    dest_path = os.path.abspath(dest_path)
    dest_dir = os.path.dirname(dest_path)
    os.makedirs(dest_dir, exist_ok=True)
    fd, tmp = tempfile.mkstemp(suffix=".part", prefix="geoip_dl_", dir=dest_dir)
    sha = hashlib.sha256()
    done = 0

    def _abort():
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass
        try:
            os.unlink(tmp)
        except Exception:
            pass

    try:
        _assert_allowed_geo_url(url)
        req = urllib.request.Request(url, headers={"User-Agent": "TunTop/1.0"})
        with _GEO_OPENER.open(req, timeout=timeout) as resp:
            # Re-check where we ACTUALLY ended up, after redirects.
            _assert_allowed_geo_url(getattr(resp, "url", None) or url)
            total = int(resp.headers.get("Content-Length") or 0)
            if total > GEO_MAX_BYTES:
                raise ValueError(
                    f"geoip download is {total} bytes, over the "
                    f"{GEO_MAX_BYTES}-byte cap - refusing")
            with os.fdopen(fd, "wb") as f:
                fd = None   # ownership moved to f (closed by the with-block)
                while True:
                    chunk = resp.read(262144)
                    if not chunk:
                        break
                    done += len(chunk)
                    if done > GEO_MAX_BYTES:
                        raise ValueError(
                            f"geoip download exceeded the "
                            f"{GEO_MAX_BYTES}-byte cap - refusing")
                    f.write(chunk)
                    sha.update(chunk)
                    if progress is not None:
                        try:
                            progress(done, total)
                        except Exception:
                            pass
    except Exception:
        # Never leave a partial file (or leaked fd) behind on failure.
        _abort()
        raise
    local_hex = sha.hexdigest()
    if sha_url:
        ref = None
        why = ""
        try:
            _assert_allowed_geo_url(sha_url)
            sreq = urllib.request.Request(
                sha_url, headers={"User-Agent": "TunTop/1.0"})
            with _GEO_OPENER.open(sreq, timeout=30) as r:
                txt = (r.read(512) or b"").decode("ascii", "replace")
            tok = txt.split()[0].strip().lower() if txt.split() else ""
            if len(tok) == 64 and all(c in "0123456789abcdef" for c in tok):
                ref = tok
            else:
                why = "checksum response was not a sha256 hex digest"
        except Exception as e:
            why = f"{e.__class__.__name__}: {e}"
        if ref and ref != local_hex:
            _abort()
            raise ValueError(
                "geoip download failed checksum verification "
                "(computed %s..., expected %s...)" % (local_hex[:12], ref[:12]))
        if not ref and strict_checksum:
            _abort()
            raise ValueError(
                "geoip download could not be verified - the release's "
                ".sha256sum was unusable (%s). Refusing to install an "
                "unverified database: these CIDRs decide what traffic "
                "leaves the machine unencrypted. Retry, or pass "
                "strict_checksum=False to accept it anyway."
                % (why or "no digest returned"))
    os.replace(tmp, dest_path)
    return done

# ── Cross-run (on-disk) geo decode cache ──────────────────────────────────────
# tuntop/helper.py is a brand-new Python process on every [S]/[T]→[S] cycle,
# so the in-memory _GEOIP_CACHE below is wiped each time and the
# whole .dat would be re-parsed from scratch every single run.  We mirror the
# decoded result to a small JSON file next to the script, keyed on the source
# file's path + mtime + size (+ requested code), so a repeat run reuses the
# previous decode instead of paying the multi-megabyte parse cost again.
# JSON, not pickle: see _geo_disk_load's note on why deserialising a
# user-writable file was a privilege-escalation hazard.

_GEO_DISK_CACHE_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), ".geo_cache")


def _geo_cache_key(file_path, code):
    st = os.stat(file_path)
    return "%s|%d|%d|%s" % (os.path.abspath(file_path), st.st_mtime_ns, st.st_size, code or "")


def _geo_disk_load(file_path, code):
    """Read the mirror cache.

    JSON, never pickle. This file lives in a user-writable directory (and in
    a source tree it is the repo itself) and its name is a deterministic
    SHA-256 of the source file's path/mtime/size plus the code - trivially
    predictable. pickle.load() on it gave any unprivileged process that could
    write next to the install arbitrary code execution in the ELEVATED
    helper on the next [S]. JSON keeps the cache useful (a list of CIDR
    strings) with no deserialization risk.
    """
    try:
        if not os.path.isdir(_GEO_DISK_CACHE_DIR):
            return None
        key = _geo_cache_key(file_path, code)
        path = os.path.join(_GEO_DISK_CACHE_DIR,
                            hashlib.sha256(key.encode("utf-8")).hexdigest() + ".json")
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Validate the shape: a wrong-typed value used to reach
        # all_codes.get(code) and raise AttributeError on every lookup.
        #
        # Shape is NOT enough. This cache file is exactly the unprivileged-
        # writable -> elevated-read channel the pickle removal was about, and
        # the old validation stopped at "dict[str, list[str]]" - so
        # {"cn": ["2000::/3"]} written here by ANY unprivileged process was
        # returned straight into _GEOIP_CACHE and installed by the ELEVATED
        # helper on the next [S]: the whole IPv6 address space routed
        # outside the tunnel, no error, dashboard still green. Re-validate
        # every value through the same normaliser the decoders use.
        if not (isinstance(data, dict) and all(
                isinstance(k, str) and isinstance(v, list)
                and all(isinstance(x, str) for x in v)
                for k, v in data.items())):
            return None
        clean = {}
        for code_key, v in data.items():
            seen, cidrs = set(), []
            for raw in v:
                norm = _normalise_cidr(raw)
                if norm and norm not in seen:
                    seen.add(norm)
                    cidrs.append(norm)
            clean[code_key] = cidrs
        return clean
    except Exception:
        return None


def _geo_disk_save(file_path, code, value):
    """Persist the decoded result in a BACKGROUND thread (atomic temp+replace).

    Serialising a full-country mapping can take noticeable time on slow
    disks; doing it inline stalled the tunnel-start sequence right after
    route install. The in-memory result is already handed back to the caller
    - this write is purely for the NEXT process's cross-run cache, so it can
    finish later.
    """
    def _write():
        try:
            os.makedirs(_GEO_DISK_CACHE_DIR, exist_ok=True)
            path = os.path.join(
                _GEO_DISK_CACHE_DIR,
                hashlib.sha256(_geo_cache_key(file_path, code).encode("utf-8")).hexdigest() + ".json")
            fd, tmp = tempfile.mkstemp(suffix=".json.tmp",
                                       dir=_GEO_DISK_CACHE_DIR)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(value, f)
                os.replace(tmp, path)
            finally:
                try:
                    if os.path.exists(tmp):
                        os.unlink(tmp)
                except Exception:
                    pass
        except Exception:
            pass
    threading.Thread(target=_write, daemon=True,
                     name="geo-disk-save").start()


def _ensure_geo_proto():
    """Build the v2fly protobuf descriptor once (lazy) and log which decode
    path will actually be used. The optional fast path relies on
    google.protobuf being importable; if it isn't, every .dat load silently
    falls back to the slow pure-Python byte-by-byte parser - this log line is
    the only visibility into which path a given run took."""
    global _GEO_PROTO, _GEO_PROTO_LOGGED
    if _GEO_PROTO is None:
        _GEO_PROTO = _build_v2fly_descriptors()
    if not _GEO_PROTO_LOGGED:
        _GEO_PROTO_LOGGED = True
        if _GEO_PROTO is not None:
            print("[*] geo decode: using protobuf fast path (google.protobuf available).")
        else:
            print("[*] geo decode: using pure-Python fallback (google.protobuf not installed).")


def _geo_format_of(file_path):
    """Return 'json' or 'dat' for a geo file, sniffing its contents (so a file
    with the wrong extension still loads correctly)."""
    with open(file_path, "rb") as f:
        head = f.read(64)
    if head[:1] == b"{":
        return "json"
    # A protobuf wire stream begins with a varint tag; both geo files start with
    # field 1 (repeated entry/site), wire type 2 (length-delimited) => 0x0A.
    if head[:1] == b"\x0a":
        return "dat"
    if str(file_path).lower().endswith(".json"):
        return "json"
    return "dat"


def _build_v2fly_descriptors():
    """Build the v2fly GeoIPList message class at runtime via the
    official `google.protobuf` library (no .proto file or protoc required).

    This is a pure OPTIONAL fast-path: if the library is missing or descriptor
    construction fails for any reason, callers fall back to the pure-Python
    parser. Returns the geoip message class, or None."""
    try:
        from google.protobuf import (
            descriptor_pb2, descriptor_pool, message_factory,
        )
    except Exception:
        return None
    try:
        TYPE_BYTES = 12
        TYPE_UINT32 = 13
        TYPE_STRING = 9
        TYPE_MESSAGE = 11
        LABEL_OPTIONAL = 1
        LABEL_REPEATED = 3

        def _field(msg, name, number, ftype, label, type_name=None):
            f = msg.field.add()
            f.name = name
            f.number = number
            f.label = label
            f.type = ftype
            if type_name:
                f.type_name = type_name
            return f

        # ---- geoip.proto ----
        geoip_fd = descriptor_pb2.FileDescriptorProto()
        geoip_fd.name = "v2fly_geoip.proto"
        geoip_fd.package = "geoip"
        m_cidr = geoip_fd.message_type.add()
        m_cidr.name = "CIDR"
        _field(m_cidr, "ip", 1, TYPE_BYTES, LABEL_OPTIONAL)
        _field(m_cidr, "prefix", 2, TYPE_UINT32, LABEL_OPTIONAL)
        m_geoip = geoip_fd.message_type.add()
        m_geoip.name = "GeoIP"
        _field(m_geoip, "country_code", 1, TYPE_STRING, LABEL_OPTIONAL)
        _field(m_geoip, "cidr", 2, TYPE_MESSAGE, LABEL_REPEATED, ".geoip.CIDR")
        m_glist = geoip_fd.message_type.add()
        m_glist.name = "GeoIPList"
        _field(m_glist, "entry", 1, TYPE_MESSAGE, LABEL_REPEATED, ".geoip.GeoIP")

        pool = descriptor_pool.DescriptorPool()
        pool.Add(geoip_fd)
        # protobuf 6.x renamed GetPrototype -> GetMessageClass; support both so
        # the fast path actually engages on modern installs (the old name makes
        # the whole build fail and silently fall back to the slow pure-Python
        # parser, which is exactly the slowdown this fast path exists to avoid).
        builder = getattr(message_factory, "GetMessageClass", None) or getattr(
            message_factory, "GetPrototype", None)
        geoip_cls = builder(pool.FindMessageTypeByName("geoip.GeoIPList"))
        return geoip_cls
    except Exception:
        return None


def _geoip_decode_pure(data, code=None, on_progress=None):
    """Pure-Python protobuf decode of a geoip.dat → {code: [cidr, ...]}.
    When `code` is given, entries for every other country are skipped entirely
    (their CIDRs are never even stringified), so decoding one country out of the
    ~250 the file holds is dramatically cheaper. `on_progress(pos, total)` is
    called periodically with the byte offset scanned, so the dashboard can show
    the *file load* phase (not just the later route install) instead of sitting
    at 0% and snapping to 100% when the parse finishes.
    """
    out = {}
    code_l = code.lower() if code else None
    pos = 0
    n = len(data)
    _next_report = 0
    while pos < n:
        tag, pos = _read_varint(data, pos)
        field = tag >> 3
        wire = tag & 0x07
        if field == 1 and wire == 2:
            msg, pos = _read_bytes(data, pos)
            country, cidrs = _geoip_parse_entry(msg)
            if not country or (code_l is not None and country.lower() != code_l):
                # Report progress BEFORE skipping: the ~250 entries that are
                # not the requested country are most of the file, so a
                # `continue` here left the dashboard's [GEO-PARSE] bar frozen
                # at its initial value for the whole multi-MB decode and then
                # snapping to 100% - exactly what the progress callback
                # exists to prevent.
                if on_progress is not None and pos >= _next_report:
                    on_progress(pos, n)
                    _next_report = pos + max(1, n // 100)
                continue
            lst = out.setdefault(country.lower(), [])
            for ip, prefix in cidrs:
                c = _geoip_cidr_to_str(ip, prefix)
                if c:
                    lst.append(c)
        else:
            pos = _geoip_skip(data, pos, wire)
        if on_progress is not None and pos >= _next_report:
            on_progress(pos, n)
            _next_report = pos + max(1, n // 100)
    if on_progress is not None:
        on_progress(n, n)
    return out


def _geoip_decode_proto(raw, geoip_cls, code=None, on_progress=None):
    msg = geoip_cls()
    msg.ParseFromString(raw)
    out = {}
    code_l = code.lower() if code else None
    entries = list(msg.entry)
    total = len(entries)
    for idx, entry in enumerate(entries):
        # Report progress for EVERY entry - matching or not. The old code only
        # emitted a marker for the requested country's own entry (usually ONE
        # line, mid-file - e.g. 43% of ~250 entries), so the dashboard's
        # file-load bar froze there while decoding was still running on to the
        # end of the file with no further updates.
        c = (entry.country_code or "").lower()
        if c and (code_l is None or c == code_l):
            lst = out.setdefault(c, [])
            for cd in entry.cidr:
                try:
                    if len(cd.ip) == 4:
                        addr = ".".join(str(b) for b in cd.ip)
                    elif len(cd.ip) == 16:
                        addr = ":".join("%x" % int.from_bytes(cd.ip[i:i + 2], "big")
                                        for i in range(0, 16, 2))
                    else:
                        continue
                except Exception:
                    continue
                # Through _normalise_cidr, like every other decoder here. This
                # used to be a raw "%s/%d" append, and `prefix` is
                # LABEL_OPTIONAL, so a .dat entry with the field OMITTED (which
                # hand-edited / merged v2rayN databases routinely have) decoded
                # to 0 and produced "5.6.7.8/0" -> 0.0.0.0/0. The install side
                # drops that in helper._is_routable_bypass_cidr, but the SWEEP
                # side is not protected: dashboard._remove_geo_routes_for /
                # _sweep_geo_leftovers and cleanup_watchdog.sweep_geo_routes
                # canonicalise with ip_network(strict=False) and hand the
                # result to _batch_delete_routes, so [R] or quitting deleted the
                # machine's default route on every interface. The same skip also
                # let a /1 or /7 entry through the prefix floor, which can match
                # TunTop's OWN split-default routes (0.0.0.0/1, 128.0.0.1,
                # ::/1) and delete half the tunnel.
                c = _normalise_cidr("%s/%d" % (addr, cd.prefix))
                if c:
                    lst.append(c)
        if on_progress is not None:
            on_progress(idx + 1, total)
    if on_progress is not None and not total:
        on_progress(1, 1)   # degenerate file: still mark the load as complete
    return out


def _geoip_decode_json(text, code=None):
    doc = json.loads(text)
    out = {}
    code_l = code.lower() if code else None
    for entry in doc.get("country", []):
        c = str(entry.get("code", "")).lower()
        if not c or (code_l is not None and c != code_l):
            continue
        # Through _normalise_cidr, NOT a raw str() pass-through. This decoder
        # used to hand every string in entry["ip"] straight to the route
        # installer with no ip_network parse and no /0 rejection, so a v2fly
        # "geoformat" .json could carry 2000::/3 - the entire IPv6 global
        # unicast space - as a "country range". The binary decoder beside it
        # has rejected /0 since 1.0.41; this path never did.
        seen, cidrs = set(), []
        for raw in entry.get("ip", []):
            norm = _normalise_cidr(raw)
            if norm and norm not in seen:
                seen.add(norm)
                cidrs.append(norm)
        out[c] = cidrs
    return out


def _load_geoip_all(file_path, code=None, on_progress=None):
    """Decode a geoip file (in-memory + on-disk cached) → {code: [cidr, ...]};
    auto-detects .dat (protobuf, optional `protobuf`-lib fast path) vs .json.

    When `code` is given, only that country is materialized (the decoder skips
    every other entry), so a multi-megabyte .dat is not fully parsed just to
    pick out one country.  The result is cached to disk keyed on the source
    file's path + mtime + size (+ code), so a brand-new helper process - the
    dashboard starts one on every [S]/[T]→[S] cycle - reuses the previous decode
    instead of re-parsing the whole file from scratch."""
    mem_key = (file_path, code)
    cached = _GEOIP_CACHE.get(mem_key)
    if cached is not None:
        if on_progress is not None:
            on_progress(1, 1)   # cached decode: file is already loaded
        return cached
    disk = _geo_disk_load(file_path, code)
    if disk is not None:
        _GEOIP_CACHE[mem_key] = disk
        if on_progress is not None:
            on_progress(1, 1)   # cached decode: file is already loaded
        return disk
    _ensure_geo_proto()
    if _geo_format_of(file_path) == "json":
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            data = _geoip_decode_json(f.read(), code)
    else:
        with open(file_path, "rb") as f:
            raw = f.read()
        geoip_cls = _GEO_PROTO
        if geoip_cls is not None:
            try:
                data = _geoip_decode_proto(raw, geoip_cls, code, on_progress)
            except Exception:
                data = _geoip_decode_pure(raw, code, on_progress)
        else:
            data = _geoip_decode_pure(raw, code, on_progress)
    _GEOIP_CACHE[mem_key] = data
    _geo_disk_save(file_path, code, data)
    return data


def parse_geoip(file_path, code, on_progress=None):
    """Load geoip data (auto-detecting .dat/.json) and return the CIDR list for
    `code` (e.g. 'cn') as a list of 'ip/prefix' strings. Raises ValueError if
    the code is absent, so the caller can warn-and-continue."""
    code = (code or "").lower()
    all_codes = _load_geoip_all(file_path, code, on_progress)
    if not all_codes.get(code):
        raise ValueError("no CIDR entries found for geoip code '%s'" % code)
    return list(all_codes[code])

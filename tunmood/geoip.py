"""GeoIP database parsing: v2ray .dat (protobuf wire format), raw protobuf
and JSON variants, plus an on-disk cache. Moved verbatim out of the old
single-file helper."""
import hashlib
import ipaddress
import json
import os
import pickle
import struct
import tempfile
import threading
import time
import urllib.request


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
    """Return (ip_bytes, prefix) for one CIDR message."""
    ip = None
    prefix = 0
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
    if ip is None:
        return None
    try:
        if len(ip) == 4:
            addr = ".".join(str(b) for b in ip)
        elif len(ip) == 16:
            addr = ":".join("%x" % int.from_bytes(ip[i:i + 2], "big")
                            for i in range(0, 16, 2))
        else:
            return None
    except Exception:
        return None
    return "%s/%d" % (addr, prefix)


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


def download_geoip(dest_path, url=GEOIP_DAT_URL, sha_url=GEOIP_DAT_SHA_URL,
                   progress=None, timeout=60):
    """Stream the v2fly geoip database to `dest_path` and return its size.

    * Downloads via streaming chunks into a temp `.part` file IN THE SAME
      directory as dest_path, then atomically os.replace()s it - an aborted
      download can never leave a half-written geoip.dat behind.
    * SHA-256 is computed WHILE downloading (no re-read), then compared with
      the release's .sha256sum when that is reachable: a MISMATCH raises
      ValueError (bad file never installed); if the checksum URL itself is
      unreachable the install proceeds with only a silent skip.
    * progress(done_bytes, total_bytes_or_0) is called per chunk - total comes
      from Content-Length and may be 0 when the server does not send it.
    * Honors HTTP(S)_PROXY environment variables automatically (urllib)."""
    dest_path = os.path.abspath(dest_path)
    dest_dir = os.path.dirname(dest_path)
    os.makedirs(dest_dir, exist_ok=True)
    fd, tmp = tempfile.mkstemp(suffix=".part", prefix="geoip_dl_", dir=dest_dir)
    sha = hashlib.sha256()
    done = 0
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "TunMood/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            total = int(resp.headers.get("Content-Length") or 0)
            with os.fdopen(fd, "wb") as f:
                fd = None   # ownership moved to f (closed by the with-block)
                while True:
                    chunk = resp.read(262144)
                    if not chunk:
                        break
                    f.write(chunk)
                    sha.update(chunk)
                    done += len(chunk)
                    if progress is not None:
                        try:
                            progress(done, total)
                        except Exception:
                            pass
    except Exception:
        # Never leave a partial file (or leaked fd) behind on failure.
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass
        try:
            os.unlink(tmp)
        except Exception:
            pass
        raise
    local_hex = sha.hexdigest()
    if sha_url:
        ref = None
        try:
            sreq = urllib.request.Request(
                sha_url, headers={"User-Agent": "TunMood/1.0"})
            with urllib.request.urlopen(sreq, timeout=30) as r:
                txt = (r.read(512) or b"").decode("ascii", "replace")
            tok = txt.split()[0].strip().lower() if txt.split() else ""
            if len(tok) == 64 and all(c in "0123456789abcdef" for c in tok):
                ref = tok
        except Exception:
            ref = None   # checksum endpoint unreachable -> best-effort skip
        if ref and ref != local_hex:
            try:
                os.unlink(tmp)
            except Exception:
                pass
            raise ValueError(
                "geoip download failed checksum verification "
                "(computed %s..., expected %s...)" % (local_hex[:12], ref[:12]))
    os.replace(tmp, dest_path)
    return done

# ── Cross-run (on-disk) geo decode cache ──────────────────────────────────────
# tunmood/helper.py is a brand-new Python process on every [S]/[T]→[S] cycle,
# so the in-memory _GEOIP_CACHE below is wiped each time and the
# whole .dat would be re-parsed from scratch every single run.  We mirror the
# decoded result to a small pickle next to the script, keyed on the source
# file's path + mtime + size (+ requested code), so a repeat run reuses the
# previous decode instead of paying the multi-megabyte parse cost again.

_GEO_DISK_CACHE_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), ".geo_cache")


def _geo_cache_key(file_path, code):
    st = os.stat(file_path)
    return "%s|%d|%d|%s" % (os.path.abspath(file_path), st.st_mtime_ns, st.st_size, code or "")


def _geo_disk_load(file_path, code):
    try:
        if not os.path.isdir(_GEO_DISK_CACHE_DIR):
            return None
        key = _geo_cache_key(file_path, code)
        path = os.path.join(_GEO_DISK_CACHE_DIR,
                            hashlib.sha256(key.encode("utf-8")).hexdigest() + ".pkl")
        if not os.path.exists(path):
            return None
        with open(path, "rb") as f:
            return pickle.load(f)
    except Exception:
        return None


def _geo_disk_save(file_path, code, value):
    """Persist the decoded result in a BACKGROUND thread (atomic temp+replace).

    Pickling a full-country dict can take noticeable time on slow disks; doing
    it inline stalled the tunnel-start sequence right after route install.
    The in-memory result is already handed back to the caller - this write is
    purely for the NEXT process's cross-run cache, so it can finish later."""
    def _write():
        try:
            os.makedirs(_GEO_DISK_CACHE_DIR, exist_ok=True)
            path = os.path.join(
                _GEO_DISK_CACHE_DIR,
                hashlib.sha256(_geo_cache_key(file_path, code).encode("utf-8")).hexdigest() + ".pkl")
            fd, tmp = tempfile.mkstemp(suffix=".pkl.tmp",
                                       dir=_GEO_DISK_CACHE_DIR)
            try:
                with os.fdopen(fd, "wb") as f:
                    pickle.dump(value, f, protocol=pickle.HIGHEST_PROTOCOL)
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
                lst.append("%s/%d" % (addr, cd.prefix))
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
        out[c] = [str(ip) for ip in entry.get("ip", []) if ip]
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

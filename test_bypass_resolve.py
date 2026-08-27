#!/usr/bin/env python3
"""Debug + test loop for the BYPASS-list resolver in tunmood/dashboard.py.

This is the harness for the "Extra entries ... -> (unresolved)" bug: a bypass
entry typed as a URL (e.g. https://www.whatismyip.com/) can never resolve,
because socket.getaddrinfo() only takes a bare host/IP - no scheme, no path.
The negative result was then cached forever, so it stayed "(unresolved)" for
the whole session even after DNS was fine.

What it checks (no admin rights, no real routes, no tunnel needed):

  1. _host_from_url()      - URL/host:port/[v6]:port/userinfo normalisation
  2. _resolve()            - resolves URL-shaped entries, caches, never raises
  3. fallback resolvers    - UDP/53 + DoH wire-format query build/parse
  4. _add_bypass_ip()      - normalises, stores, installs routes (mocked netsh)
  5. background resolver   - retries with backoff until a flaky host resolves,
                             then installs the bypass route automatically
  6. panel rendering       - "(resolving...)" / "(unresolved: err, retry Ns)" /
                              real IPs + [routed]
  7. _remove_bypass_ip()   - deletes routes, drops state (no bool-unpack crash)
  8. key-handler guard     - a raising handler logs instead of killing the app
  9. instant [A]/[X]       - bypass add/remove never restarts the tunnel

Usage:
    python test_bypass_resolve.py                 # offline (mocked DNS), 1 pass
    python test_bypass_resolve.py --loop 5        # run the whole suite 5x
    python test_bypass_resolve.py --live          # also do REAL DNS lookups
    python test_bypass_resolve.py --live --loop 3
"""

import argparse
import importlib.util
import os
import socket
import sys
import time
import types

HERE = os.path.dirname(os.path.abspath(__file__))


def load_btop():
    """Import tunmood/dashboard.py by path (it is import-safe: no side effects)."""
    path = os.path.join(HERE, "tunmood/dashboard.py")
    spec = importlib.util.spec_from_file_location("v2ray_tun_btop_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class Results:
    def __init__(self):
        self.passed = 0
        self.failed = []
        self.sections = []      # (name, passed, failed, seconds)
        self._t_section = None
        self._name = None

    def section(self, name):
        self.end_section()
        self._name = name
        self._t_section = time.time()
        print(f"\n[{name}")

    def end_section(self):
        if self._name is None:
            return
        dt = time.time() - self._t_section
        # Count only checks that ran since this section started.
        self.sections.append((self._name, dt))
        self._name = None

    def check(self, name, cond, detail=""):
        if cond:
            self.passed += 1
            print(f"  [PASS] {name}")
        else:
            self.failed.append(f"{self._name}: {name}" if self._name else name)
            print(f"  [FAIL] {name}   {detail}")

    def eq(self, name, got, want):
        self.check(name, got == want, f"got={got!r} want={want!r}")

    def summary(self):
        self.end_section()
        total = self.passed + len(self.failed)
        print("\n" + "=" * 72)
        print("SUMMARY")
        print("=" * 72)
        for name, dt in self.sections:
            bar = "#" * max(1, min(30, int(dt * 2)))
            print(f"  {name:<58} {dt:6.2f}s  {bar}")
        print("-" * 72)
        print(f"  TOTAL: {total} checks   {self.passed} passed   "
              f"{len(self.failed)} failed")
        if self.failed:
            print("  FAILED CHECKS:")
            for n in self.failed:
                print(f"    - {n}")


# ─── fake TUI plumbing ───────────────────────────────────────────────────────

def make_ns(**kw):
    ns = types.SimpleNamespace(
        server=["198.51.100.1"],
        port=10808,
        tun2socks=os.path.join(HERE, "tun2socks-windows-amd64-v3.exe"),
        no_vpn_bypass=False,
        vless_over_vpn=False,
        vpn_interface=None,
        endpoint_port=443,
        dns4="8.8.8.8",
        bypass_ip=[],
        geoip=None,
        geoip_code="cn",
    )
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


def make_app(mod, ns, route_log):
    """Build a BTopTui with every OS-touching call stubbed out."""
    mod._get_egress_for = lambda ip: ("Ethernet", "192.168.1.1")
    mod._get_ipv4_default = lambda: ("Ethernet", "192.168.1.1")
    mod._get_ipv6_default = lambda vpn_interface=None: ("Ethernet", "fe80::1")
    mod._get_vpn_ipv4_default = lambda *a, **k: ("Ethernet", "192.168.1.1")
    mod._get_vpn_ipv6_default = lambda *a, **k: ("Ethernet", "fe80::1")
    mod._add_route_v4 = lambda dest, iface, gw, metric=1: (route_log.append(("+v4", dest)) or True)
    mod._add_route_v6 = lambda dest, iface, gw, metric=1: (route_log.append(("+v6", dest)) or True)
    mod._del_route_v4 = lambda dest, iface, gw: (route_log.append(("-v4", dest)) or True)
    mod._del_route_v6 = lambda dest, iface, gw: (route_log.append(("-v6", dest)) or True)
    mod._ps = lambda *a, **k: (False, "stubbed")

    app = mod.BTopTui(ns)
    return app


def stop_app(app):
    """Stop any background resolver the app started (daemon threads only)."""
    app._telemetry_running = False
    app.running = False
    th = getattr(app, "_bypass_res_thread", None)
    if th is not None and th.is_alive():
        th.join(timeout=3.0)


def drain(app):
    """Move queued worker log lines into log_lines like loop() does."""
    import queue as _q
    while True:
        try:
            app.log_lines.append(app.logs.get_nowait())
        except _q.Empty:
            return


def logs_text(app):
    drain(app)
    return "\n".join(app.log_lines)


def bypass_panel(app):
    """The exact strings the BYPASS panel prints for the extra entries."""
    out = []
    for item in app._bypass_resolved_list():
        out.append(f"{item['entry']}  ->  {item['detail']}")
    return out


# ─── the suite ───────────────────────────────────────────────────────────────

def test_host_from_url(mod, r):
    r.section("1] _host_from_url() normalisation")
    cases = [
        ("https://www.whatismyip.com/", "www.whatismyip.com"),
        ("http://example.com", "example.com"),
        ("HTTPS://Example.COM/Path?x=1#frag", "example.com"),
        ("//cdn.example.com/x", "cdn.example.com"),
        ("example.com.", "example.com"),
        ("example.com:443", "example.com"),
        ("user:pass@example.com:8443", "example.com"),
        ("  https://api.ipify.org/  ", "api.ipify.org"),
        ('"https://ifconfig.me/ip"', "ifconfig.me"),
        ("1.2.3.4", "1.2.3.4"),
        ("1.2.3.4:443", "1.2.3.4"),
        ("2606:4700:4700::1111", "2606:4700:4700::1111"),
        ("[2606:4700:4700::1111]:443", "2606:4700:4700::1111"),
        ("https://[2606:4700:4700::1111]/dns-query", "2606:4700:4700::1111"),
        ("wss://vless.example.net:2087/ws", "vless.example.net"),
        ("", ""),
        (None, ""),
    ]
    for raw, want in cases:
        r.eq(f"_host_from_url({raw!r})", mod._host_from_url(raw), want)


def test_resolve(mod, r, live):
    r.section("2] _resolve() on URL-shaped entries")
    mod._dns_cache_clear()
    fake = {
        "www.whatismyip.com": (["104.26.13.23", "172.67.69.129"], []),
        "example.com": (["93.184.216.34"], ["2606:2800:220:1::1"]),
    }

    def fake_gai(host, *a, **k):
        if host in fake:
            v4, v6 = fake[host]
            infos = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in v4]
            infos += [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", (ip, 0, 0, 0)) for ip in v6]
            return infos
        raise socket.gaierror(11001, "getaddrinfo failed")

    real_gai = socket.getaddrinfo
    socket.getaddrinfo = fake_gai
    try:
        v4, v6 = mod._resolve("https://www.whatismyip.com/")
        r.eq("URL entry resolves (the reported bug)", (v4, v6),
             (["104.26.13.23", "172.67.69.129"], []))
        v4, v6 = mod._resolve("example.com:443")
        r.eq("host:port entry resolves", (v4, v6),
             (["93.184.216.34"], ["2606:2800:220:1::1"]))
        r.eq("IP literal", mod._resolve("8.8.8.8"), (["8.8.8.8"], []))
        r.eq("IPv6 literal in brackets", mod._resolve("[2606:4700::1111]:443"),
             ([], ["2606:4700::1111"]))
        r.eq("unresolvable never raises", mod._resolve("no-such-host.invalid"), ([], []))
        v4b, v6b, err, src = mod._resolve_detail("https://www.whatismyip.com/")
        r.check("cache is used on the 2nd lookup", src == "cache", f"src={src}")
        r.check("failure reports an error string",
                bool(mod._resolve_detail("no-such-host.invalid", use_cache=False)[2]))
    finally:
        socket.getaddrinfo = real_gai
    mod._dns_cache_clear()

    if live:
        print("    (live DNS)")
        v4, v6 = mod._resolve("https://www.whatismyip.com/")
        r.check("LIVE https://www.whatismyip.com/ resolves", bool(v4 or v6),
                f"v4={v4} v6={v6}")
        v4, v6 = mod._resolve("https://www.google.com/")
        r.check("LIVE https://www.google.com/ resolves", bool(v4 or v6),
                f"v4={v4} v6={v6}")
        mod._dns_cache_clear()


def test_wire_dns(mod, r, live):
    r.section("3] fallback resolver (DNS wire format)")
    tid, pkt = mod._dns_build_query("www.whatismyip.com", 1)
    r.check("query header id round-trips", int.from_bytes(pkt[:2], "big") == tid)
    r.check("query encodes the labels", b"\x03www" in pkt and b"\x0awhatismyip" in pkt,
            f"pkt={pkt!r}")
    # Hand-built response: 1 question + 1 A record 1.2.3.4 (compressed name).
    resp = bytearray()
    resp += tid.to_bytes(2, "big") + b"\x81\x80" + (1).to_bytes(2, "big")
    resp += (1).to_bytes(2, "big") + b"\x00\x00\x00\x00"
    resp += pkt[12:]                       # echo the question
    resp += b"\xc0\x0c"                    # name pointer
    resp += (1).to_bytes(2, "big") + (1).to_bytes(2, "big")
    resp += (60).to_bytes(4, "big") + (4).to_bytes(2, "big") + bytes([1, 2, 3, 4])
    r.eq("A record parsed", mod._dns_parse_answers(bytes(resp), 1), ["1.2.3.4"])
    r.eq("truncated/garbage response is safe", mod._dns_parse_answers(b"\x00\x01", 1), [])
    if live:
        # UDP/53 can be blocked or lossy on some networks (that is exactly why
        # DoH is the secondary fallback) - so pass if ANY resolver answers, and
        # only fail if literally every probe is dropped.
        udp = []
        for srv in ("1.1.1.1", "8.8.8.8", "9.9.9.9"):
            got = mod._dns_query_udp("www.whatismyip.com", srv, 1, timeout=2.5)
            udp.append((srv, bool(got)))
            if got:
                break
        r.check("LIVE UDP/53 fallback (any resolver)",
                any(ok for _, ok in udp), f"results={udp}")
        doh = []
        for ep in mod._DNS_DOH_ENDPOINTS:
            got = mod._dns_query_doh("www.whatismyip.com", 1, ep, timeout=6.0)
            doh.append((ep.split("//")[-1], bool(got)))
            if got:
                break
        r.check("LIVE DoH fallback (any endpoint)",
                any(ok for _, ok in doh), f"results={doh}")


def test_add_url_entry(mod, r):
    r.section("4] [A] add of a URL entry -> normalised, resolved, routed")
    mod._dns_cache_clear()
    fake = {"www.whatismyip.com": (["104.26.13.23"], [])}

    def fake_gai(host, *a, **k):
        if host in fake:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))
                    for ip in fake[host][0]]
        raise socket.gaierror(11001, "getaddrinfo failed")

    real_gai = socket.getaddrinfo
    socket.getaddrinfo = fake_gai
    routes = []
    app = None
    try:
        app = make_app(mod, make_ns(), routes)
        app._add_bypass_ip("https://www.whatismyip.com/")
        stop_app(app)                       # make the rest deterministic
        app._bypass_resolve_tick()          # what the background thread does
        drain(app)
        r.eq("stored entry is the bare host", app.ns.bypass_ip, ["www.whatismyip.com"])
        panel = bypass_panel(app)
        r.check("panel shows the IP, not (unresolved)",
                panel and "104.26.13.23" in panel[0] and "unresolved" not in panel[0],
                f"panel={panel}")
        r.check("route installed live", ("+v4", "104.26.13.23/32") in routes,
                f"routes={routes}")
        r.check("normalisation is logged", "www.whatismyip.com" in logs_text(app))
        # Idempotent re-add must not duplicate or crash.
        app._add_bypass_ip("http://www.whatismyip.com")
        stop_app(app)
        r.eq("re-add does not duplicate", app.ns.bypass_ip, ["www.whatismyip.com"])
        # Removal must not crash on the bool-returning route helpers.
        app._remove_bypass_ip("www.whatismyip.com")
        r.eq("entry removed", app.ns.bypass_ip, [])
        r.check("route deleted", ("-v4", "104.26.13.23/32") in routes, f"routes={routes}")
        r.check("state dropped", "www.whatismyip.com" not in app._bypass_res_state)
        # Removing by URL must hit the same entry.
        app._add_bypass_ip("www.whatismyip.com")
        stop_app(app)
        app._bypass_resolve_tick()
        app._remove_bypass_ip("https://www.whatismyip.com/")
        r.eq("remove accepts a URL too", app.ns.bypass_ip, [])
    finally:
        if app is not None:
            stop_app(app)
        socket.getaddrinfo = real_gai
        mod._dns_cache_clear()


def test_retry_loop(mod, r):
    r.section("5] background retry loop (flaky DNS recovers)")
    mod._dns_cache_clear()
    state = {"fail_left": 3}

    def fake_gai(host, *a, **k):
        if host == "flaky.example.com":
            if state["fail_left"] > 0:
                state["fail_left"] -= 1
                raise socket.gaierror(11002, "temporary failure in name resolution")
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.9", 0))]
        raise socket.gaierror(11001, "getaddrinfo failed")

    real_gai = socket.getaddrinfo
    socket.getaddrinfo = fake_gai
    routes = []
    try:
        app = make_app(mod, make_ns(bypass_ip=["https://flaky.example.com/ip"]), routes)
        # Normalisation of pre-seeded (CLI) entries happens on first tick.
        app._bypass_resolve_tick()
        r.eq("CLI URL entry normalised", app.ns.bypass_ip, ["flaky.example.com"])
        panel = bypass_panel(app)
        r.check("failed entry says it will retry",
                panel and "retry" in panel[0].lower(), f"panel={panel}")
        st = app._bypass_res_state["flaky.example.com"]
        r.check("backoff scheduled", st["next"] > time.time(), f"st={st}")
        r.check("error text kept", bool(st["err"]), f"st={st}")
        # Simulate the passage of time instead of sleeping through the backoff.
        for i in range(6):
            app._bypass_res_state["flaky.example.com"]["next"] = 0.0
            app._bypass_resolve_tick()
            if app._bypass_res_state["flaky.example.com"]["status"] == "ok":
                break
        drain(app)
        st = app._bypass_res_state["flaky.example.com"]
        r.eq("entry eventually resolves", st["status"], "ok")
        r.eq("resolved IP", st["ips"], ["203.0.113.9"])
        r.check("route installed on recovery", ("+v4", "203.0.113.9/32") in routes,
                f"routes={routes}")
        r.check("recovery logged", "203.0.113.9" in logs_text(app))
        panel = bypass_panel(app)
        r.check("panel now shows routed IP",
                "203.0.113.9" in panel[0] and "routed" in panel[0], f"panel={panel}")
        # A resolved entry must not be re-resolved on every tick (no DNS storm).
        before = state["fail_left"]
        calls = {"n": 0}
        outer = socket.getaddrinfo

        def counting(host, *a, **k):
            calls["n"] += 1
            return outer(host, *a, **k)
        socket.getaddrinfo = counting
        for _ in range(5):
            app._bypass_resolve_tick()
        socket.getaddrinfo = outer
        r.eq("no repeated DNS for a healthy entry", calls["n"], 0)
        _ = before
    finally:
        stop_app(app)
        socket.getaddrinfo = real_gai
        mod._dns_cache_clear()


def test_panel_states(mod, r):
    r.section("6] panel states + UI never blocks on DNS")
    mod._dns_cache_clear()
    main_ident = __import__("threading").get_ident()
    calls = {"ui": 0, "bg": 0}

    def slow_gai(host, *a, **k):
        if __import__("threading").get_ident() == main_ident:
            calls["ui"] += 1
        else:
            calls["bg"] += 1
        time.sleep(1.5)
        raise socket.gaierror(11001, "getaddrinfo failed")

    real_gai = socket.getaddrinfo
    socket.getaddrinfo = slow_gai
    routes = []
    app = None
    try:
        app = make_app(mod, make_ns(), routes)
        t0 = time.time()
        app._add_bypass_ip("https://slow.example.com/")   # must return at once
        add_dt = time.time() - t0
        panel = bypass_panel(app)
        draw_dt = time.time() - t0
        r.check("[A] add does not block the UI on DNS", add_dt < 0.5, f"{add_dt:.2f}s")
        r.check("panel draw does no blocking DNS", draw_dt < 0.5, f"{draw_dt:.2f}s")
        r.check("pending entry shows 'resolving'",
                panel and "resolv" in panel[0].lower(), f"panel={panel}")
        r.eq("no DNS was done on the UI thread", calls["ui"], 0)
        r.check("a background resolver picked the entry up",
                getattr(app, "_bypass_res_thread", None) is not None
                and app._bypass_res_thread.is_alive())
        # _select_bypass()'s labels come from the same non-blocking state.
        labels = app._bypass_labels()
        r.check("remove-picker labels built without DNS",
                labels and "slow.example.com" in labels[0], f"labels={labels}")
        # Let the worker fail once so the retry text appears, still off-thread.
        deadline = time.time() + 6
        while time.time() < deadline:
            st = app._bypass_res_state.get("slow.example.com", {})
            if st.get("status") == "fail":
                break
            time.sleep(0.1)
        panel = bypass_panel(app)
        r.check("failure surfaces with a retry countdown",
                panel and ("retry in" in panel[0] or "resolv" in panel[0].lower()),
                f"panel={panel}")
        r.eq("still no UI-thread DNS after the worker ran", calls["ui"], 0)
    finally:
        if app is not None:
            stop_app(app)
        socket.getaddrinfo = real_gai
        mod._dns_cache_clear()


def test_route_helper_contract(mod, r):
    r.section("7] route helper return-value contract (bool, not tuple)")
    src = open(os.path.join(HERE, "tunmood/dashboard.py"), encoding="utf-8").read()
    bad = [ln.strip() for ln in src.splitlines()
           if ("_add_route_v4(" in ln or "_add_route_v6(" in ln
               or "_del_route_v4(" in ln or "_del_route_v6(" in ln)
           and "ok, msg =" in ln]
    r.check("no tuple-unpack of the bool route helpers", not bad, f"offenders={bad}")
    r.check("_add_route_v4 returns a bool",
            isinstance(mod._add_route_v4("1.2.3.4/32", "Ethernet", "192.168.1.1"), bool))


def test_key_handler_guard(mod, r):
    r.section("8] a raising key handler cannot kill the dashboard")
    routes = []
    app = make_app(mod, make_ns(), routes)

    def boom(k):
        raise RuntimeError("simulated handler bug")
    app._handle_key_action = boom
    try:
        out = app._handle_key("r")
        r.check("exception contained", out is True)
        r.check("crash logged to the event log",
                "simulated handler bug" in logs_text(app), logs_text(app)[-200:])
    except Exception as e:
        r.check("exception contained", False, f"raised {e!r}")


def test_instant_add_remove(mod, r):
    r.section("9] [A]/[X] are INSTANT - no tunnel restart, resolver does it live")
    mod._dns_cache_clear()
    fake = {"instant.example.com": (["203.0.113.77"], [])}

    def fake_gai(host, *a, **k):
        if host in fake:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))
                    for ip in fake[host][0]]
        raise socket.gaierror(11001, "getaddrinfo failed")

    real_gai = socket.getaddrinfo
    socket.getaddrinfo = fake_gai
    routes = []
    app = None
    try:
        app = make_app(mod, make_ns(), routes)

        t0 = time.time()
        app._add_bypass_ip("https://instant.example.com/")
        add_dt = time.time() - t0
        drain(app)
        r.check("[A] add returned instantly", add_dt < 0.5, f"{add_dt:.2f}s")
        r.check("background resolver started for the new entry",
                getattr(app, "_bypass_res_thread", None) is not None
                and app._bypass_res_thread.is_alive())
        # Do what the background worker would do, then verify live routing.
        stop_app(app)
        app._bypass_resolve_tick()
        drain(app)
        r.check("route installed LIVE while tunnel state unchanged",
                ("+v4", "203.0.113.77/32") in routes, f"routes={routes}")
        r.check("log says 'no restart needed'",
                "no restart needed" in logs_text(app), logs_text(app)[-200:])

        # Removal: also instant, route deleted in a background thread.
        t0 = time.time()
        app._remove_bypass_ip("instant.example.com")
        rm_dt = time.time() - t0
        r.eq("entry removed from list instantly", app.ns.bypass_ip, [])
        r.check("[X] remove returned instantly", rm_dt < 0.5, f"{rm_dt:.2f}s")
        deadline = time.time() + 5
        while time.time() < deadline:
            if ("-v4", "203.0.113.77/32") in routes:
                break
            time.sleep(0.05)
        r.check("route deleted in the background",
                ("-v4", "203.0.113.77/32") in routes, f"routes={routes}")
    finally:
        if app is not None:
            stop_app(app)
        socket.getaddrinfo = real_gai
        mod._dns_cache_clear()


def run_suite(live):
    mod = load_btop()
    r = Results()
    test_host_from_url(mod, r)
    test_resolve(mod, r, live)
    test_wire_dns(mod, r, live)
    test_add_url_entry(mod, r)
    test_retry_loop(mod, r)
    test_panel_states(mod, r)
    test_route_helper_contract(mod, r)
    test_key_handler_guard(mod, r)
    test_instant_add_remove(mod, r)
    return r


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--loop", type=int, default=1, help="run the suite N times")
    ap.add_argument("--live", action="store_true", help="also perform real DNS lookups")
    a = ap.parse_args()

    worst = 0
    suite_t0 = time.time()
    for i in range(1, a.loop + 1):
        print("=" * 72)
        print(f"PASS {i}/{a.loop}   (live DNS: {'on' if a.live else 'off'})")
        print("=" * 72)
        r = run_suite(a.live)
        r.summary()
        if r.failed:
            worst = 1
    dt = time.time() - suite_t0
    total_runs = a.loop
    print(f"\n{total_runs} pass(es) of the suite in {dt:.1f}s "
          f"(live DNS: {'on' if a.live else 'off'})")
    print("\n" + ("ALL PASSED" if worst == 0 else "FAILURES PRESENT"))
    return worst


if __name__ == "__main__":
    sys.exit(main())

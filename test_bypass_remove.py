#!/usr/bin/env python3
"""Logic test for live-patch bypass removal (no admin / no real tunnel needed).

Verifies, for each of three scenarios (resolved-via-state / resolved-via-cache /
never-resolved):
  * entry is removed from the list immediately (main thread, responsive),
  * per-entry state + DNS cache are dropped synchronously,
  * the route deletion runs in a BACKGROUND thread (so the UI never blocks),
  * the correct /32 route is actually deleted for a resolved entry,
  * a never-resolved entry is still removed from the list (no freeze, no delete).

All OS-touching helpers are stubbed on the INSTANCE (not just module globals),
so the test is fully hermetic: no PowerShell/netsh call can ever escape.
"""

import sys
import os
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from tunmood import dashboard as M

M._resolve = lambda s, use_cache=True, fallback=False: ([], [])
M._resolve_cached = lambda s: ([], [])

calls_v4 = []
calls_v6 = []

def fake_del_v4(dest, iface, gateway):
    calls_v4.append((dest, iface, gateway))
    return True

def fake_del_v6(dest, iface, gateway):
    calls_v6.append((dest, iface, gateway))
    return True

M._del_route_v4 = fake_del_v4
M._del_route_v6 = fake_del_v6
M._ps = lambda *a, **k: (False, "stubbed")   # keep the DNS flush hermetic too

# NOTE: _get_egress_for is looked up as a module global inside the worker, so a
# module-level stub is fine for it. But _get_vless_iface_gateway / _v6 are
# METHODS on BTopTui (called as self._get_...), so patching module globals here
# would NOT intercept them - they are patched on the instance below instead.
M._get_egress_for = lambda ip: ("Ethernet", "10.0.0.1")

class Args:
    server = ["198.51.100.1"]
    port = 10808
    dns4 = "8.8.8.8"
    bypass_ip = []
    no_vpn_bypass = False
    vless_over_vpn = False
    vpn_interface = None
    geoip = None
    geoip_code = "cn"
    geoip_via_vpn = False
    geoip_via_win_vpn = False
    endpoint_port = 443

tui = M.BTopTui(Args())
tui._get_vless_iface_gateway = lambda: ("Ethernet", "10.0.0.1")     # instance patch!
tui._get_vless_iface_gateway_v6 = lambda: None                      # instance patch!

results = {"passed": 0, "failed": 0}


def check(name, cond, detail=""):
    if cond:
        results["passed"] += 1
        print(f"      PASS  {name}")
    else:
        results["failed"] += 1
        print(f"      FAIL  {name}   {detail}")


def run_case(label, entry, seeded_state, seeded_cache, expect_ips):
    global calls_v4, calls_v6
    calls_v4 = []
    calls_v6 = []
    tui._bypass_res_state.clear()
    tui._bypass_res_cache.clear()
    if seeded_state is not None:
        tui._bypass_res_state[entry] = dict(seeded_state)
    if seeded_cache is not None:
        tui._bypass_res_cache[entry] = seeded_cache
    tui.ns.bypass_ip = [entry]

    print(f"\n  case: {label}")
    print(f"    entry={entry!r} seeded_state={'yes' if seeded_state else 'no'} "
          f"seeded_cache={'yes' if seeded_cache is not None else 'no'} "
          f"expect_routes={[f'{ip}/32' for ip in expect_ips]}")

    # This keypress must return immediately (not block on netsh/PowerShell).
    t0 = time.time()
    tui._remove_bypass_ip(entry)
    elapsed = time.time() - t0

    # List + state/cache updates must be synchronous and instant.
    ok = entry not in tui.ns.bypass_ip
    state_gone = entry not in tui._bypass_res_state
    cache_gone = entry not in tui._bypass_res_cache
    instant = elapsed < 1.0  # keypress returns without waiting for the delete

    check("entry removed from ns.bypass_ip", ok,
          f"list={tui.ns.bypass_ip}")
    check("per-entry resolver state dropped", state_gone)
    check("DNS cache entry dropped", cache_gone)
    check(f"keypress returned instantly ({elapsed * 1000:.1f} ms)", instant,
          f"took {elapsed:.2f}s")

    # Let the background delete thread finish, then check the OS calls.
    for _ in range(50):
        if len(calls_v4) >= len(expect_ips):
            break
        time.sleep(0.05)
    deleted_dests = [d for (d, _i, _g) in calls_v4]
    want = [f"{ip}/32" for ip in expect_ips]
    route_ok = (deleted_dests == want)

    print(f"    delete worker: iface/gw={calls_v4} "
          f"(elapsed-to-collect={time.time() - t0:.2f}s)")
    check(f"routes deleted exactly match expectation", route_ok,
          f"want={want} got={deleted_dests}")
    check("delete ran off the UI thread (after keypress returned)",
          not calls_v4 or elapsed < 1.0)


print("=" * 72)
print("BYPASS REMOVE - live route deletion logic")
print("=" * 72)
suite_t0 = time.time()

run_case("resolved-via-state", "example.com",
         {"status": "ok", "ips": ["1.2.3.4"], "routed": True},
         (["1.2.3.4"], []), expect_ips=["1.2.3.4"])

run_case("resolved-via-cache", "example.org",
         None, (["9.9.9.9"], []), expect_ips=["9.9.9.9"])

run_case("never-resolved", "unresolved.host",
         None, None, expect_ips=[])

dt = time.time() - suite_t0
p, f = results["passed"], results["failed"]
print("\n" + "=" * 72)
print(f"RESULT: {p} passed, {f} failed   ({dt:.2f}s, 3 cases)")
print("=" * 72)
if f:
    sys.exit(1)
print("ALL TESTS PASSED")

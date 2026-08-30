# TunTop test matrix (Phase 0)

Legend: **AUTO** = covered by the automated suite (`py -m pytest tests`);
**MANUAL** = needs a real Windows box + real network — walk it before every
release (see the release checklist in `docs/MILESTONE-v1.0.md`);
**pending** = not yet walked on the current build.

## Environments

| # | Environment | Coverage | Status |
|---|-------------|----------|--------|
| 1 | Windows 10 (PowerShell 5.1 console) | MANUAL | pending |
| 2 | Windows 11 (Windows Terminal) | MANUAL | pending |
| 3 | Wi-Fi (default: lease renew mid-session) | MANUAL | pending |
| 4 | Ethernet | MANUAL | pending |
| 5 | Another VPN active (connect & disconnect *during* a session) | MANUAL | pending |
| 6 | IPv4-only network (no IPv6 route) | MANUAL | pending |
| 7 | IPv6-enabled network | MANUAL | pending |
| 8 | DNS failures (block UDP/53; DoH fallback path) | AUTO (dns unit tests) + MANUAL | pending |
| 9 | VLESS endpoint unreachable | AUTO (proxy failure-kind tests) + MANUAL | pending |
| 10 | Laptop sleep/wake mid-tunnel | MANUAL | pending |

## Failure / stress scenarios

| # | Scenario | Expected behaviour | Coverage | Status |
|---|----------|--------------------|----------|--------|
| 11 | `tun2socks` killed (Task Manager) mid-session | State → STOPPING via reader thread; recovery relaunches with backoff; UI never shows RUNNING | AUTO (test_tunnel_lifecycle, test_recovery_engine) | passing |
| 12 | Helper process killed (`kill -9` equivalent) | Crash marker written; next launch scans + cleans stale adapter/routes/process | AUTO (test_startup_recovery, test_crash_scenario) | passing |
| 13 | Route install fails halfway | Transaction rolls back applied routes in reverse order; FAILED state with readable reason | AUTO (test_routes_txn rollback cases) | passing |
| 14 | Repeated crash loop | Recovery engine gives up after N incidents, demands human, never loops hot | AUTO (test_recovery_engine crash-loop) | passing |
| 15 | Adapter disappears (device manager disable) | ADAPTER failure-kind ladder; recover with backoff or give up clearly | AUTO (recovery ladders) + MANUAL | pending |
| 16 | Wi-Fi network change (adapter index shifts) | Bypass routes re-pinned to new interface on next repair | MANUAL | pending |
| 17 | VPN connects/disconnects while tunnel runs | Conflicting re-injected default routes removed; tunnel stays verified | AUTO (bypass install flow) + MANUAL | pending |
| 18 | Bypass add/remove while tunnel is UP | Live edit works without restart; routes land on the right interface | AUTO (test_bypass_install_flow) + MANUAL | passing (auto) |
| 19 | Binary tampered / truncated (`tun2socks.exe`, `wintun.dll`) | SHA-256 mismatch → refuse to launch, clear message | AUTO (test_integrity) | passing |
| 20 | geoip.dat corrupted / truncated | Parse falls back to pure-Python decoder or fails loudly; no half-installed routes | AUTO (geoip parse tests) | passing |

## How to walk a MANUAL row

1. Fresh shell: `powershell -ExecutionPolicy Bypass -File Run_Helper.ps1`
2. Record `Get-NetRoute` + `Get-NetAdapter` before starting ([S]).
3. Apply the scenario.
4. After stop ([Q]) or crash+relaunch: diff the recorded state — it must match
   exactly (kill-safe teardown), or the diff must be captured and filed in
   `docs/KNOWN-ISSUES.md`.

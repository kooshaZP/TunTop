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
| 21 | DNS leak: multi-homed machine (Wi-Fi has a DHCP resolver) while the tunnel is up | Catch-all NRPT rule pins every name to the tunnel resolvers; `Get-DnsClientNrptPolicy -Effective` shows the root namespace; dnsleaktest.com shows only the tunnel resolver; `[C]` DNS-leak-protection row PASS | AUTO (test_dns_guard) + MANUAL | passing (auto) |
| 22 | DNS leak guard left behind by a hard kill | Next launch removes it BEFORE any route work and logs it; DNS works again with no tunnel | AUTO (test_startup_recovery, test_cleanup_watchdog) + MANUAL | passing (auto) |
| 23 | Guard removed mid-session (Group Policy refresh / another VPN client) | Monitor re-asserts it on the next healthy cycle, no restart needed | AUTO (test_dns_guard helper integration) + MANUAL | passing (auto) |
| 24 | LAN-only name (printer/NAS) while the guard is up | `.local` (and any `--dns-guard-exempt` domain) still resolves; everything else pinned | MANUAL | pending |
| 25 | PowerShell unavailable / times out during guard removal | Removal reported as a FAILURE (never a false "removed"), and the install record is kept so the next launch retries; a stale pin is never silently orphaned | AUTO (test_dns_guard failed-runner cases) + MANUAL | passing (auto) |
| 26 | Registry key removal denied (ACL / in use) | The removal script re-enumerates after the sweep and reports the survivors instead of assuming success | AUTO (test_dns_guard verification) + MANUAL | passing (auto) |
| 27 | Disconnected adapter with a stale static resolver | Not reported as a leak source (SMHNR only fans out over adapters that are Up), so no false "dns-leak" | AUTO (test_dns_guard script text) + MANUAL | passing (auto) |
| 28 | `[L]` DNS test while the guard state cannot be read (probe raises) | Verdict is `unknown` naming the adapters and the reason — never a confirmed `dns-leak` against a healthy tunnel | AUTO (test_dns_leak_probe tri-state) | passing (auto) |
| 29 | Only the `.local` exemption rule survives (catch-all wiped) | Guard reports NOT in force (the exemption claims no namespace); a foreign managed catch-all does not make ours look installed | AUTO (test_dns_guard match-count) | passing (auto) |
| 30 | `--no-dns-guard` chosen deliberately | `[C]` row reads "DISABLED by choice" (pass), not a red failure indistinguishable from a broken install | AUTO (test_dns_guard opt-out row) + MANUAL | passing (auto) |
| 31 | DoH registration succeeds for one family and fails for the other | The failed resolver is named explicitly; it is never silently downgraded to raw UDP/53 behind the sibling's success line | AUTO (test_dns_choice partial DoH) | passing (auto) |

## How to walk a MANUAL row

1. Fresh shell: `powershell -ExecutionPolicy Bypass -File Run_Helper.ps1`
2. Record `Get-NetRoute` + `Get-NetAdapter` before starting ([S]).
3. Apply the scenario.
4. After stop ([Q]) or crash+relaunch: diff the recorded state — it must match
   exactly (kill-safe teardown), or the diff must be captured and filed in
   `docs/KNOWN-ISSUES.md`.

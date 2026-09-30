# Known bugs and edge cases — v1.0 register (Phase 0)

Statuses: **OPEN** (affects users) / **COSMETIC** (no functional impact) /
**FIXED** (kept for history — do not delete rows).

| # | Severity | Status | Area | Description | Workaround |
|---|----------|--------|------|-------------|------------|
| 1 | blocker | FIXED | geo | `geo/geoip.py` lost `_read_varint`/`_read_bytes` in the package restructure — any `.dat` parse raised `NameError`. | — |
| 2 | blocker | FIXED | helper | `tunnel/helper.py:1487` called `_clean_err()` which was never defined in the helper process — geo route-batch failures crashed instead of reporting. | — |
| 3 | blocker | FIXED | profiles | `config/profiles.py:apply_to_args()` referenced undefined `_host_from_url` — loading a saved profile with bypass entries crashed. | — |
| 4 | blocker | FIXED | helper | GeoIP parse helpers `_read_varint`/`_read_bytes` were missing from the extracted `geo/geoip.py`. | — |
| 5 | cosmetic | FIXED | dashboard | Several unused imports/locals remained from the verbatim refactor. Cleaned in 1.0.41; the re-exported surfaces the dashboard and helper deliberately re-bind (`tuntop.routing`'s shared helpers, `VPN_IFACE_RE`, `NRPT_PS_ROOT`) are now `noqa: F401`-marked with the reason, so a sweep cannot silently delete them again. | none needed |
| 6 | cosmetic | FIXED | compat | Tier facade modules (`monitor/diagnostics.py`, `network/interfaces.py`, `network/resolver.py`, `network/vpn.py`, `tunnel/socks.py`, `tunnel/tun2socks.py`, `tunnel/wintun.py`, `ui/widgets.py`) re-exported via `import *` from the engine modules, which also made pyflakes unable to analyze them. There was no compat to preserve: a repo-wide search over `.py`/`.md`/`.ps1`/`.toml`/`.yml`/`.spec`/`.bat` found **zero** importers — not the UI, not the helper, not a single test — and no dynamic `getattr`/`importlib` access either. The eight were deleted and their now-dead `ruff.toml` per-file-ignores dropped with them. The five `sys.modules[...]` alias shims that ARE still imported (`state.py`, `routing.py`, `recovery.py`, `routes_txn.py`, `startup_recovery.py`, `profiles.py`, `netdns.py`, `health_report.py`, `structured_log.py`, `ui_text.py`, `integrity.py`, `geoip.py`) were kept. | none needed |
| 7 | minor | FIXED | helper | `global vpn_override_routes` / `global vpn_saved_routes` declared but never assigned in that scope (dead declarations at helper.py:1133-area). Removed in 1.0.41. | none needed |
| 8 | blocker | FIXED | geo/security | `geo/geoip.py` cached the decoded CIDR set as a **pickle** in a user-writable directory, read by the **elevated** helper under a predictable name — arbitrary code execution. Now JSON, shape-validated. A CIDR decoding to `/0` is also rejected (it was a default route). 1.0.41. | — |
| 9 | blocker | FIXED | security | `network/procguard.py` matched the bare vendored `tun2socks-windows-amd64-v3.exe` name, which is the **upstream xjasonlyu release asset name** — every teardown/recovery/watchdog sweep could `taskkill /F /T` another application's proxy. The name is now only honoured from a TunTop-controlled directory. 1.0.41. | — |
| 10 | blocker | FIXED | watchdog | `cleanup_watchdog.wait_for_exit` read `ctypes.GetLastError()` from a `ctypes.windll` handle that does not set `use_last_error` (and truncated a 64-bit `HANDLE` to `int`), so it could declare a **live** dashboard dead and tear down its tunnel. Fixed, and the dashboard wait is now bounded. 1.0.41. | — |
| 11 | blocker | FIXED | core | Launching TunTop twice: the second instance read the first's crash marker, concluded "crash", and killed its tun2socks / removed its adapter / swept its routes. `marker_is_live()` now gates on the recorded PID; the watchdog re-checks before its first destructive step. 1.0.41. | — |
| 12 | blocker | FIXED | helper | DoH was re-registered against the Wintun adapter's **own** address on a re-add, pointing the whole resolver list at itself (nothing resolved). 1.0.41. | — |
| 13 | blocker | FIXED | routing | Geo CIDRs were compared as **strings**, and `parse_geoip` renders IPv6 uncompressed while `Get-NetRoute` returns the compressed form — every IPv6 geo route survived every sweep, keeping the bypass armed against a dead tunnel. Now compared as `ip_network`. 1.0.41. | — |
| 14 | blocker | FIXED | routing | The LAN sweep accepted "a real next-hop that is not the current gateway" as its own, so it deleted corporate static routes / VPN split tunnels it never created. Now gateway-exact. 1.0.41. | — |
| 15 | major | FIXED | routing | The crashed-helper host-route sweep emitted an **unscoped** `Remove-NetRoute -DestinationPrefix`, which deletes the prefix on every interface (including a VPN client's pinned `/32`). Now scoped to the tunnel adapters. 1.0.41. | — |
| 16 | major | FIXED | recovery | A `BaseException` from a recovery rung left `_in_attempt = True` forever, silently killing auto-recovery; and a 1-second "verified success" reset the crash-loop counter, so a helper that kept dying produced an infinite restart loop with no backoff. 1.0.41. | — |
| 17 | major | FIXED | dashboard | Two DNS health rows were permanently red (one CRITICAL, so the badge read UNHEALTHY) because they probed the *display default* resolver for a family the user never configured. Every DNS row is now gated on the configured resolvers. 1.0.41. | — |
| 18 | major | FIXED | dashboard | Crash logs and the `[D]` diagnostics export were written into the onefile `_MEIPASS` extraction dir, which is deleted on exit — from the standalone exe, every crash report and diagnostics file was silently lost. Both now write next to `TunTop.exe`. 1.0.41. | — |

## Edge cases to watch (from the Phase 0 environment matrix)

These are scenarios the recovery/startup-recovery engines are designed for;
each maps to a row in `docs/TEST-MATRIX.md`. If a user report matches one,
update the matrix row instead of opening a duplicate issue.

- **Another VPN active**: a self-healing VPN can re-inject default routes on a
  different interface mid-run. Geo bypass install removes conflicting routes
  first (batched `Remove-NetRoute`), but live VPN connect/disconnect *during*
  a session should re-verify routes (DEGRADED → RECOVERING path).
- **IPv6-only / IPv4-only networks**: helper never invents an IPv6 gateway;
  expect a clean DEGRADED state with a readable reason, not a hang.
- **DNS failures**: DoH fallback exists; total DNS loss should show
  RESOLVING → FAILED with a retry, never a silent stuck STARTING.
- **DNS leak guard (1.0.40)**: the catch-all NRPT rule makes system name
  resolution depend on the tunnel, which is fail-closed by design. Three
  consequences to expect: (a) an internal/LAN-only name that only the
  router resolver answers will NXDOMAIN while the tunnel is up - add
  `--dns-guard-exempt <domain>` (`.local` is always exempt) or
  `--no-dns-guard`; (b) a hard kill (Task Manager, power loss) can leave the
  rule behind, so DNS would stay pinned to a dead tunnel - startup recovery
  and the cleanup watchdog both remove it, and the next launch says so in
  its log. If a removal cannot actually complete (PowerShell unavailable, key
  removal denied), it is now reported as a **failure** and the install record
  is **kept**, so the next launch retries; it is never reported as a clean
  "removed" with the rule still in place. If DNS breaks after quitting TunTop,
  run TunTop once more and report it; (c) deliberately running
  `--no-dns-guard` shows `[C]` as "DISABLED by choice" (a pass), not as a
  failed guard - a real failure and a deliberate opt-out are distinguishable.
- **Sleep/wake**: adapters can vanish and routes can be flushed by Windows.
  The next health poll must classify this as ADAPTER/ROUTES failure and
  recover with backoff.
- **Laptop with metered Wi-Fi**: geo `.dat` download (~10 MB) honors HTTP(S)
  proxies but has no "ask before downloading" prompt yet.
- **Non-ASCII interface names (1.0.41)**: PowerShell 5.1 writes host output in
  the console code page, which under `CREATE_NO_WINDOW` is the system OEM page
  (cp936, cp1251, …) and is **not** fixed by the launchers' `chcp 65001` when
  started from Task Scheduler or a double-click. Every probe used to decode that
  as UTF-8, so an adapter named `WLAN 无线` came back as `WLAN ` and the egress
  lookup returned a name `netsh` could not match — the bypass silently never
  installed. All probes now set `[Console]::OutputEncoding = UTF8` themselves.
  If you still see a mojibake alias in the `[2]` panel, it is a console
  rendering issue, not a routing one.
- **Hard kill (Task Manager / power loss)**: the detached watchdog repairs the
  routing table, the geo routes and the DNS guard on the next launch. Since
  1.0.41 it also refuses to run while a dashboard is still alive, and it
  re-reads the session marker immediately before its first destructive step so
  a relaunch inside the grace period is not torn down.
- **Run from source AND from the exe**: the two use different persistent
  directories (the package dir vs. the exe dir) for the control file, profile
  store, geoip default, crash log and diagnostics. A `[N]` DNS change made
  while running from source is not seen by an exe-launched helper (and vice
  versa) — they are separate installs, deliberately.

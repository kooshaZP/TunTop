# Changelog

All notable changes to TunTop are documented here.

## [Unreleased]

### Fixed
- **Leak-test verdict was INVERTED** (the "fix any bug" find of this change):
  the old `[L]` test claimed `direct == proxied -> LEAK`, which is backwards.
  With the full-tunnel routes healthy, a *direct* (non-proxied) fetch
  traverses the TUN and exits at the SAME IP as the SOCKS-proxied fetch -
  that equality is the proof the tunnel carries everything (the startup
  verification probe has always relied on exactly this behaviour). The real
  leak signature is the opposite: the direct probe showing a DIFFERENT IP
  (the real ISP IP) than the tunnel exit. Dashboard `[L]`, the FAQ, and the
  new monitor check all use the corrected semantics now.
- **Health-scan results no longer race the UI thread** (`run_checks` used to
  append to `self.results` from its worker while `draw()` iterated the same
  list): the race aborted draw() mid-frame with "list changed size during
  iteration", freezing the whole dashboard - event log included - which
  looked exactly like "the log has a delay". Results are now published by
  atomic rebinding, and the main loop wakes instantly when a background
  thread queues a new log line instead of waiting out the rest of the frame.

### Added
- **Leak test is now part of the regular check while the tunnel runs**:
  the helper's monitor loop (every `--monitor-interval` cycle, default 30 s)
  runs a direct-vs-tunnel-egress probe after the tunnel verifies and logs
  `[MONITOR] leak check OK` / `[MONITOR] LEAK DETECTED` / inconclusive lines
  when the verdict CHANGES. A `LEAK DETECTED` marks the tunnel DEGRADED in
  the dashboard's state machine; a later `leak check OK` restores RUNNING.
- **"Tunnel leak test (direct vs tunnel egress)" health-check row** - the
  `[C]` scan now includes the same probe, so the leak state is visible in
  the health panel and exported with `[D]` diagnostics.
- **Monitor-layer leak probe** (`tuntop/monitor/leak.py`, pure stdlib - the
  module now owns the real logic instead of re-exporting the dashboard):
  both legs (direct + SOCKS5-proxied) race SEVERAL IP-echo endpoints
  concurrently and the first strictly-validated IP wins, so a single
  blocked/lying endpoint (captive portal, interception page) can never
  produce a false verdict; the manual `[L]` test no longer depends on
  `curl.exe` and reports per-leg latency plus a clear verdict for every
  outcome (ok / leak / no-proxy / inconclusive / no-network).

## Previous

### Fixed
- **geoip no longer hijacks the tunnel's own endpoints or user bypass routes**
  (the "[U] server change broke it" + "bypass must outrank geoip" bugs):
  a geoip country list routinely contains the VLESS/VPN server's own IP - and
  can even ship an exact /32 IDENTICAL to the server's host route - so the geo
  install's conflict sweep deleted that /32 and re-added it pointing at the
  GEO egress (wintun2 / Windows VPN / wintun), looping the proxy transport
  into its own tunnel: endless failing connects to the server IP in the log
  after changing the server live with `[U]`. Now `add_geoip_bypass()` takes a
  `protected` prefix list (VLESS/proxy2/VPN endpoints, bypass entries) and
  skips any geo CIDR equal to or INSIDE a protected prefix from both the
  removal sweep and the install, and re-asserts endpoint host routes after
  the geo pass (`reassert=`). Same protection on the live `[R]` geo re-apply
  (dashboard builds the list from every live-installed route + resolved
  endpoints) and at helper startup (all resolved endpoint IPs are protected).
  User bypass entries keep the egress their entry names even when a geo
  subnet falls inside the bypassed range. The live bypass install also
  pre-cleans any same-prefix route on another egress first, so `[A]`/`[U]`
  can no longer silently "succeed" while the old geo route keeps winning.
- **`[U]` server change now re-detects the egress** (the stale cached
  interface/gateway made a fresh host route land on the wrong interface) and
  logs explicit diagnostics: which geo ranges cover the new server IP, and a
  hard warning if the bypass route could not be installed (the loop
  condition).

### Added
- **Parallel tunnel verification**: `wait_for_tunnel_stable()` now probes ALL
  verification endpoints (gstatic, cloudflare, ipify) CONCURRENTLY instead of
  one by one - the first success wins, so a blocked endpoint no longer adds
  its full 5×(timeout+2 s) retry budget before the working one is even tried.
  The DoH escalation round uses the same parallel scheme.
- **`Start_TunTop.bat` launcher** - double-click entry point that fixes the
  classic "downloaded from GitHub, PowerShell won't run it" errors (strips
  Mark-of-the-Web via `Unblock-File`, relaunches under
  `-ExecutionPolicy Bypass`) and styles the console (title, UTF-8, 120x36,
  Consolas preselected so box glyphs render). `Run_Helper.ps1` also unblocks
  itself and self-relaunches under Bypass when the machine policy is
  Restricted.
- **"vpn" bypass target** - `[A]` now asks "direct or proxy2 or vpn"; entries
  tagged `vpn` are routed out through a CONNECTED Windows VPN (separate
  resolver store, [X] picker tags, profile key `vpn_bypass_ip`).
- **GeoIP egress target** - `[F]` now asks the same "direct / proxy2 / vpn"
  question for the geoip country ranges, and the choice applies LIVE while the
  tunnel runs: changing it removes the old country routes and re-points them
  at the new egress (physical adapter / wintun2 / Windows VPN) without a
  restart. Persisted as `geoip_target` in profiles.
- **proxy2 at runtime (`[Z]`)** - the second proxy can now be added, switched
  or removed while the app is running (transparent background tunnel restart),
  not only at launch.
- **Live config channel (helper control file)** - the dashboard writes
  `tuntop/tunnel/.tuntop_control.json`; the helper's monitor loop picks up
  changes (currently DNS) within ~1 s and re-applies the Wintun config, so
  self-heal keeps the new choice instead of reverting to launch values.
- **Adaptive layout: units shrink FIRST, help removed LAST** - on short
  windows (16:9 screens) health-check rows shrink first (12 -> 5), then the
  throughput graph (5 -> 2 rows per direction), then the help footer halves
  (4 -> 2 rows); removing the footer entirely is now the last resort.

### Changed
- **DNS selection is now exact** - pass `--dns4` (and/or `--dns6`) and the
  tunnel uses EXACTLY the resolver(s) you gave: a v4-only choice no longer
  gets the default IPv6 resolver injected (and vice versa). With no DNS input
  at all, both defaults (8.8.8.8 + 2606:4700:4700::1111) still apply, and the
  legacy "pass 8.8.8.8 alone" case keeps the old dual-stack behavior. The
  `[N]` live editor and the helper control-file channel follow the same rule
  (a v4-only pick also clears the v6 resolver off the adapter), profiles can
  now store `dns6`, and `Run_Helper.ps1` gained a `$DnsServerV6` knob.
- **DNS changes no longer restart the tunnel (`[N]`)** - applied live on the
  Wintun adapter + helper rebind; applies to new lookups immediately.
- **Server changes no longer restart the tunnel (`[U]`)** - old VLESS
  endpoints' host routes are removed and the new servers' routes installed
  live; the health check and display update in place.
- Endpoint-port changes (`[E]`) were already live; behaviour unchanged.

### Fixed
- **Stale helper control file no longer overrides a fresh run's DNS** - a
  `.tuntop_control.json` left over from a previous session (e.g. an old `[N]`
  DNS change) was applied by the new run's first monitor tick, silently
  replacing the launch-time `--dns4/--dns6` choice. The helper now baselines
  the control file's mtime at startup (only writes made while the run is up
  count as live changes) and removes the file on exit.
- **Graph/log flicker at certain window sizes** - the adaptive shrink budget
  was recomputed from the previous frame's measured panel height every frame,
  and the panels' height depends on the budget: shrink -> smaller measurement
  -> un-shrink -> bigger measurement -> shrink ... oscillated at boundary
  sizes. The budget is now only recomputed when the window size (or a panel
  toggle) actually changes, and the height measurement is only taken from a
  frame with no shrink caps applied. Verified stable across 360 size/visibility
  combinations.
- Test discovery for `tests/routing`, `tests/recovery`, `tests/network`
  (missing `__init__.py`) - `python -m unittest discover -s tests` now runs
  the whole suite cleanly.
- **Generic SOCKS5 backend naming** (Task 1): TunTop now documents that ANY
  local SOCKS5 proxy works (v2rayN, Xray, sing-box, Clash Meta, ...) - no
  protocol code ever depended on v2rayN. Docs/help-text only; zero behavior
  change. `--proxy-over-vpn` added as the documented alias for the legacy
  `--vless-over-vpn` flag (both work; the profile schema key is unchanged).
- **Second proxy hop (proxy2, Task 2)**: route specific hosts through a
  SECOND local SOCKS5 proxy while the primary tunnel keeps the default route.
  - `start_tun2socks_pipe()` extracted from `helper.main()` so one TUN +
    tun2socks bring-up sequence serves both pipes (pure refactor first).
  - `--proxy2-port` turns the feature on; `--proxy2-server` gives the second
    proxy's own upstream direct bypass routes (no TUN loop); `--proxy2-bypass-ip`
    routes hosts through the second hop from the CLI.
  - `Profile.proxy2_port` / `proxy2_server` / `proxy2_bypass_ip` in the
    profile schema - old profiles without these keys load unchanged.
  - Dashboard `[A]` add-bypass now asks "direct or proxy2?" (default direct:
    pressing Enter keeps existing muscle memory); `[X]` picker tags each
    entry with its target; status bar shows `PROXY2 up/down` only when the
    second pipe is configured.
  - Crash recovery covers the second adapter: startup recovery and the
    shutdown sweep clean `wintun2` routes/adapter and orphaned tun2socks
    from a hard-killed proxy2 session.
  - The second pipe NEVER receives a default route (0/0) - only specific
    /32+/128 destinations - so two adapters can never fight over the
    default route. 17 new tests cover schema round-trips, route targeting,
    rollback, bookkeeping and wintun2 crash recovery.

## [1.0.1] - 2026-08-30

### Added
- Layered package architecture (Phase 1): `core` / `network` / `tunnel` /
  `monitor` / `config` / `geo` / `ui` subpackages with a strict downward
  dependency rule (UI -> Core -> Network/Tunnel -> Windows).
- `core.tunnel_manager` + `core.lifecycle`: the Core facade the UI must
  drive instead of calling Windows internals or the tun2socks process
  directly. Backward-compatible top-level module aliases preserved.
- `config.profiles.secret_store`: Windows Credential Manager backed secret
  storage (ctypes, zero pip deps) so profiles never embed plaintext secrets.
- `config.models.Profile` and `config.defaults` for typed, shared config.
- GitHub issue templates for IPv6 and DNS problems (in addition to bug /
  routing / feature).
- Packaged-build pipeline: `TunTop-x64.zip` with per-file SHA-256
  checksums and an optional PyInstaller `TunTop.exe` step.

### Changed
- Profile store renamed to `MyTunTopProfile.json`.
- Release zip renamed to `TunTop-x64.zip` and made self-contained
  (vendored binaries included).
- Test suite expanded to ~230 tests: added VPN-detection, sleep/wake,
  Wi-Fi-change and VLESS-endpoint-down failure scenarios, plus a
  `TunnelManager` lifecycle test and a secret-store test.

### Fixed
- `health_report`: `_suggest()` now uses longest-prefix matching so a
  `tun2socks` failure surfaces the tun2socks fix (not the SOCKS5 one).

## [1.0.0] - 2026-08-29

### Added
- Tunnel state machine with 12 explicit states and formal transition graph
- Recovery engine with exponential backoff (1s-30s), escalation ladders, crash-loop protection
- Transactional route management (plan/apply/verify/rollback)
- Startup crash recovery — detects and cleans stale state from previous runs
- Binary integrity verification — SHA-256 pins for vendored tun2socks.exe and wintun.dll
- Test suite: 164 tests across 5 tiers (unit/routing/recovery/integration/network)
- `--no-auto-recover` flag to disable auto-recovery
- `--trust-binaries` flag to bypass integrity checks for custom builds

### Changed
- Rebranded from TunMood to TunTop
- README rewritten for users (not developers)
- Test system restructured into unit/routing/recovery/integration/network tiers

### Fixed
- Recovery engine: `resume()` always re-arms after crash-loop give-up on fresh launch
- Dashboard: state badge now shows yellow for in-progress phases, not alarming red during normal startup

## [0.9.0] - 2026-08-25

### Added
- Full-tunnel IPv4/IPv6 routing via Wintun + tun2socks
- btop-style dashboard with gradient throughput graphs, 7 color themes
- Health monitoring with ~30 probes
- Live bypass add/remove without restarting the tunnel
- Geo-IP country routing from geoip.dat
- Self-healing helper that monitors the tunnel
- Leak test, diagnostics export, profiles
- VPN mode with VPN bypass
- Mouse support, graph modes, panel visibility toggles

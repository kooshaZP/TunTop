# Changelog

All notable changes to TunTop are documented here.

## [Unreleased]

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
- **DNS changes no longer restart the tunnel (`[N]`)** - applied live on the
  Wintun adapter + helper rebind; applies to new lookups immediately.
- **Server changes no longer restart the tunnel (`[U]`)** - old VLESS
  endpoints' host routes are removed and the new servers' routes installed
  live; the health check and display update in place.
- Endpoint-port changes (`[E]`) were already live; behaviour unchanged.

### Fixed
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

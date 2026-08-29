# Changelog

All notable changes to TunTop are documented here.

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

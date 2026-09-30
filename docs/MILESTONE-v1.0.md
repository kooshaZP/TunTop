# TunTop v1.0 Milestone

This document is the **contract** for TunTop 1.0. It defines what is frozen,
what "stable" means, and the exact criteria that must be boringly reliable
before the 1.0.0 tag ships.

## Feature freeze (Phase 0)

The feature set for 1.0 is **frozen**. New features land only after 1.0.

* Bug fixes, performance fixes, test coverage, and docs **are allowed**.
* New user-facing features, new CLI flags, new dashboard panels are **not**.
* Exceptions require a written justification in the PR description and a
  maintainer's explicit approval (treat the freeze as a budget: every
  unplanned feature must buy its way in with an equal amount of testing).

## What "stable" means

A build is **stable** when ALL of the following hold:

1. The full automated suite passes:
   `python -m unittest discover -s tests -t . -v` (the `network/` tier is
   skipped unless `TUNTOP_NET_TESTS=1` is set, so CI never touches the live
   network; run that variant on a real box before a release).
2. Zero undefined names / syntax errors: `ruff check tuntop tests` and
   `bandit -q -r tuntop --skip B104` are both clean. Those are the exact
   invocations CI runs (`ruff`/`bandit` are CI-only tooling, not project
   dependencies); `ruff.toml` documents the deliberately narrow rule set,
   and `B104` is skipped because "0.0.0.0" route prefixes are the point.
3. Every start → stop → start cycle in the TEST-MATRIX scenarios leaves the
   Windows routing table exactly as it was before the first start
   (kill-safe teardown is *verified*, not assumed).
4. No scenario in the test matrix leaves a half-configured tunnel, a stale
   Wintun adapter, or persistent routes behind — including crashes
   (Task Manager kill) and sleep/wake.
5. When the tunnel breaks, the state machine shows it (never
   "tun2socks died but the dashboard still says connected"), and the
   recovery engine either fixes it with backoff or clearly reports it
   gave up — it never repairs in a tight loop.

## v1.0 criteria — the three pillars

### 1. Reliable (route engine)
- [x] Explicit tunnel state machine (`core/state.py`) — single source of truth
- [x] Formal recovery engine with 1s→30s exponential backoff, capped attempts,
      and crash-loop protection (`core/recovery.py`)
- [x] Transactional route management: plan → apply → verify → rollback
      (`core/routes_txn.py`)
- [x] Startup crash recovery: stale adapter/routes/process cleanup at launch
      (`core/startup_recovery.py`)
- [x] IPv4 + IPv6 full tunnel, kill-safe teardown on every exit path
- [x] DNS leak protection (UDP/53 + DoH fallback)

### 2. Easy (one-click use)
- [x] `Run_Helper.ps1` bootstrap with execution-policy guidance (README)
- [x] Auto-download of `tun2socks.exe` / `wintun.dll` with SHA-256 pinning
      (`core/integrity.py`) — bad binaries are rejected
- [x] Profiles with import/export; secrets via Windows Credential Manager
      (`config/profiles.py`)
- [x] `build_release.py` + `TunTop.spec` produce `TunTop.exe` (PyInstaller)
- [x] In-app release **check** + verified staging (`config/updates.py`) — runs
      at startup on the packaged `TunTop.exe` only: a GitHub release check
      over a TLS 1.2 floor with a per-hop GitHub host allow-list, then
      SHA-256 against the published `checksums.txt`. The verified
      `TunTop-<version>.exe` is staged next to the running one and picked up
      on the next manual start — the running exe is never touched or
      launched. Opt out with `--no-update-check` or `BTOP_NO_UPDATE`.
- [ ] Silent **installer** — **post-1.0** (still out of scope for 1.0)

### 3. Visible (live health)
- [x] btop-style dashboard: throughput graphs, latency, health counter
- [x] 46 health probes rendered with fix suggestions (built by
      `build_checks()` in `ui/dashboard.py`; the suggestions themselves live
      in `monitor/health.py`) — plus one row per bypass IP, three per extra
      configured server, and one in `--vless-over-vpn` mode
- [x] Structured event log (timestamp/severity/component/state) in the UI
      and in diagnostics export (`core/events.py`)
- [x] Leak test ([L]) — direct vs proxied egress proof
- [x] Diagnostics export bundled into GitHub bug-report templates

## Release checklist (per release, incl. 1.0.0)

1. `CHANGELOG.md` updated (version, date, highlights).
2. Full suite green (see "What stable means" #1–2).
3. Test matrix re-walked; KNOWN-ISSUES.md reviewed (no new blockers).
4. Tag `vX.Y.Z` → GitHub Actions `release.yml` builds `TunTop-x64.zip`,
   `TunTop.exe`, and `checksums.txt`, and attaches them to the release.
5. `dist/checksums.txt` matches the uploaded artifacts.

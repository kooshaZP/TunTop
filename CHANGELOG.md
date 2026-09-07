# Changelog

All notable changes to TunTop are documented here.

## [1.0.13] - 2026-09-07

### Fixed
- **Typed keys echo / app stops responding (intermittent)**: every
  child process sharing the console (each `powershell.exe` the route
  sweeps and telemetry spawn, the helper, AV scanners) can reset the
  shared stdin handle's console mode to its own default (line + echo).
  That stomp persists after the child exits: typed characters are then
  echoed by the host's line discipline while the dashboard stops seeing
  them normally. A per-frame console-mode watchdog now detects the stomp,
  re-applies the dashboard's input mode, and logs it once.
- **False "Tunnel leak test" failure with IPv6**: the direct probe leg
  answered over IPv6 (native/VPN-provided v6, e.g. a WARP-class address)
  while the tunnel leg exited over IPv4; the cross-family comparison
  always failed and was reported as a LEAK. Mixed-family results now
  trigger a forced-IPv4 re-probe: v4-vs-v4 matching passes with an
  explicit "IPv6 leaves via a different path" note (new `v6-side`
  verdict), a real v4 mismatch still fails, and a mute re-probe reports
  inconclusive.

## [1.0.12] - 2026-09-07

### Fixed
- **[T] stop freeze, round 2**: the 1.0.11 VPN telemetry sampled
  `get_vpn_status()` (2 PowerShell spawns) every 4s with no gate while a
  stop was running - the route sweep competed with constant PowerShell
  spawns and a VPN-arrival event could re-install routes mid-sweep.
  Sampling, arrival re-apply, and the bypass resolver are now all skipped
  while a teardown is in flight.
- **[S] during a stop now QUEUES the start**: the tunnel launches
  automatically the moment the sweep finishes (previously the UI said
  "press [S] again in a few seconds", which read as frozen when the sweep
  took longer than expected).
- Exit path waits at most 30s on an in-flight teardown and never fires a
  queued start during [Q]/exit.

### Changed
- `get_vpn_status()` uses ONE PowerShell spawn instead of two per sample
  (halves process churn on machines with slow AV-scanned PowerShell
  starts).

## [1.0.11] - 2026-09-06

### Fixed
- **VPN egress lookups silently always failed (root cause)** - every
  PowerShell route lookup that needed "most-specific route first" used
  `Sort-Object { ... } -Descending,` with a trailing comma - a PARSE ERROR
  in Windows PowerShell 5.1 (a trailing comma cannot follow a switch
  parameter). The lookup returned nothing, so [V] VLESS-over-VPN reported
  "no active Windows VPN" with the VPN up, [F] geo-via-VPN fell back to the
  physical adapter, and [A] vpn-target bypass entries stayed "[route
  pending]" forever. All sites (helper x4, dashboard routing copy x4)
  rewritten to the parse-safe hashtable-property form
  (`@{Expression=...;Descending=$true}, RouteMetric, InterfaceMetric`),
  verified against the live routing table.

### Added
- **Live VPN chip in the top bar** - shows the connected VPN's
  connection/adapter name (GREEN); turns RED "NOT CONNECTED"/"DOWN" when
  the VPN drops. Visible whenever a VPN-dependent mode is on.
- **Live VPN name on the BYPASS row** - "VPN ON · VPN endpoints stay
  direct · Shirazu-VPN" with a red dot while disconnected.
- **VPN-arrival auto-apply** - when a Windows VPN connects while TunTop is
  running, pending [vpn] bypass entries and an unapplied geo-via-VPN
  request are re-applied automatically (~5s detection cadence).
- **Third-party VPN status** - get_vpn_status() now falls back to
  VPN-pattern adapters (Get-VpnConnection misses clients like "VPN Client
  Adapter - VPN"), matching what the route lookup finds.

## [1.0.10] - 2026-09-06

### Fixed
- **A user-requested stop no longer masquerades as a crash** - the helper's
  stdout EOF could reach the reader thread a moment BEFORE the stop path
  paused the recovery engine, so a normal [T] stop produced
  "Problem detected (process: helper process exited)" and an automatic
  restart right after the tunnel was intentionally stopped. Teardown-in-
  flight exits are now absorbed.
- **Recovery no longer declares victory on a helper that dies during
  startup** - "Recovery verified" fired on PID-alive alone; the helper can
  still exit seconds later on a startup gate (e.g. --vless-over-vpn with no
  VPN connected). The verify step now watches the process through its
  startup window (~3s) before claiming a fix.
- **--vless-over-vpn survives a VPN that is still reconnecting** - a start
  landing while the Windows VPN adapter is mid-reconnect (no routes for a
  few seconds) used to exit immediately with "no active Windows VPN default
  route found". The lookup now retries for ~9s before giving up (helper and
  the [F] geo-via-VPN worker).

## [1.0.9] - 2026-09-06

### Fixed
- **The app no longer freezes after stop / blocks restart or exit** - [T]
  (stop on a worker), [Q] (inline teardown screen) and the exit atexit path
  could all run their route sweeps CONCURRENTLY: two PowerShell sweeps
  fighting over the route table while both waited on the same helper, which
  froze the UI for the whole overlap ("after stopping the program becomes
  unresponsive and I can't start it again or exit"). A teardown lock now
  serialises every stop path; [Q] and exit wait out an in-flight stop
  worker; [S] during a stop reports "still in progress" instead of
  launching a helper into the middle of a teardown.
- **[P] SOCKS-port change no longer freezes the dashboard** - the stop +
  relaunch now runs on a background thread like every other restart.
- **Third-party VPN clients are found for [V] / geo-via-VPN** - clients that
  neither appear in Get-VpnConnection nor install a 0.0.0.0/0 default route
  (e.g. "VPN Client Adapter - VPN") were invisible to the VPN lookup, so
  geo-via-VPN fell back to the physical adapter. The lookup now scans
  VPN-pattern adapters (pptp/l2tp/sstp/ikev2/vpn/wan miniport) for their
  most-specific Alive route as a final fallback (helper + dashboard copies).

## [1.0.8] - 2026-09-06

### Fixed
- **[F] Geo Manager: "3 = vpn" egress now actually applies** - the live
  re-apply worker only recognised the "proxy2" and "direct" targets, so a
  Windows-VPN egress silently fell through to the physical-adapter branch:
  the user saw normal physical traffic and geo-via-VPN did nothing. A real
  `winvpn` branch now looks up the connected VPN's default route and installs
  the country routes there; without a connected VPN it reports clearly
  instead of pretending.
- **Split-tunnel VPNs work with [V] / geo-via-VPN** - the VPN lookup
  REQUIRED a 0.0.0.0/0 route on the VPN adapter; VPN clients that install
  only on-link/split routes (no default route) were rejected, so
  vless-over-vpn exited at startup and geo-via-VPN found nothing. The lookup
  (helper + dashboard routing copies) now falls back to the most-specific
  Alive route on the connected VPN's adapter.

### Changed
- **[V]** logs what the mode needs (a connected Windows VPN; split-tunnel
  VPNs supported) instead of a bare on/off line.

### Build
- **build_release.py survives AV quarantine of dist/TunTop.exe**: a versioned
  backup copy (TunTop-<ver>.exe) is written the moment the build lands, and
  a vanished exe now prints exact Defender restore/exclusion steps instead
  of a bare None.

## [1.0.7] - 2026-09-06

### Changed
- **No country is bypassed by default** - the geo-bypass code defaulted to
  `cn` (a leftover from the original China-use case), so every fresh start
  hinted at - and any geoip run silently assumed - mainland-China bypass.
  The default is now EMPTY: nothing is bypassed by country until the user
  picks a code ([F] Geo Manager -> 2=Change code, `--geoip-code`, or a
  profile). The helper refuses an empty code explicitly instead of guessing.

### Fixed
- **Saved profiles survive the window closing (exe)** - the profiles store
  lived next to `dashboard.py`, which inside the onefile exe is the throwaway
  `_MEIPASS` extraction dir that is DELETED on exit: profiles only lived as
  long as the window. The store (`MyTunTopProfile.json`) now sits next to
  `TunTop.exe` itself (source runs keep the historical location), the same
  stable-per-install spot geoip.dat and the control file already use.

## [1.0.6] - 2026-09-06

### Changed
- **The exe moves itself into Windows Terminal when available** - a classic
  conhost window (what you get double-clicking the exe) is the weakest
  renderer TunTop can end up in: several glyph slots keep showing '?' even
  after the font/codepage fix-up, because the console HOST - not cmd vs
  PowerShell - does the drawing. When the frozen exe starts inside a plain
  conhost and Windows Terminal is installed, it now relaunches itself there
  (every original argument carried over) instead: WT renders every
  box/block/●/✔ glyph natively with its own profile font. Running from
  Windows Terminal, VS Code, ConEmu or any other modern host is detected
  and left untouched; child helper/watchdog processes never relaunch;
  `BTOP_NO_WT=1` opts out.

## [1.0.5] - 2026-09-06

### Fixed
- **The frozen exe can actually launch its tunnel helper now** - the
  dashboard spawned the helper as `python.exe tuntop/tunnel/helper.py`,
  but in the exe `sys.executable` IS TunTop.exe, so TunTop re-launched
  itself with the helper's script path as an argument and its own argparse
  refused: `error: unrecognized arguments: ...\Temp\tunnel\helper.py`.
  The exe now re-enters ITSELF with an internal `--helper-child` flag and
  runs the bundled `tuntop.tunnel.helper` module in that child process.
  The cleanup watchdog had the identical defect (spawned as
  `python.exe .../cleanup_watchdog.py`) - same fix via `--watchdog-child`.
  Both modules are now explicit `hiddenimports` in `TunTop.spec`, so they
  are guaranteed to be inside the exe.
- **Unicode glyphs are genuinely the default in the exe** - the default
  path still ran the legacy terminal probe after the font/codepage fix-up
  and silently downgraded to ASCII whenever the probe guessed wrong
  (isatty/terminal-host heuristics). Unicode is now on unless the user
  opts out with `--ascii` or `BTOP_ASCII=1` - exactly what the 1.0.4
  notes already claimed.
- **The live-DNS handoff and the crash marker survive the exe's onefile
  sandbox** - both were `__file__`-relative, but onefile gives every
  process its own throwaway `_MEIPASS` dir: the helper child would have
  polled a control file the dashboard never wrote ([N] live DNS would
  silently do nothing), and the watchdog a crash marker that vanishes
  every run. The control file is now handed to the helper explicitly
  (`--control-file`) and the marker resolves NEXT TO TunTop.exe when
  frozen, so both processes agree on the same file.

## [1.0.4] - 2026-09-06

### Added
- **Antivirus false-positive hardening for the exe**: UPX packing disabled
  (the single biggest heuristic trigger for PyInstaller onefile builds),
  a full Windows version-info resource (name/company/description/1.0.4),
  and a real multi-resolution icon (Bootstrap Icons `shield-lock`, MIT).
  Unsigned exes can still be flagged - README Troubleshooting now has the
  Defender restore/exclusion steps and the `certutil -hashfile` check
  against `checksums.txt`.
- **Cascadia Mono SemiLight is the default console font** (Windows 11's
  terminal face): the frozen exe requests it at startup and falls back
  through Cascadia Mono -> Consolas -> Lucida Console; `--font` still
  overrides. SemiLight gets its proper GDI weight (350).
- **The exe downloads its own missing files**: at startup a frozen exe
  missing tun2socks/wintun (bare-exe handoff) fetches the official
  tun2socks v2.7.0 / wintun 0.14.1 builds into its own folder - the
  SHA-256 integrity gate still judges the result, so a bad download
  refuses to start exactly as before. The geoip database auto-downloads
  in the background when missing (previously launcher-only), and its
  default location in a frozen exe is now NEXT TO TunTop.exe instead of
  the throwaway _MEIPASS temp dir, so the download persists across runs.

### Changed
- **Unicode glyphs are the default** in the standalone exe (and everywhere
  else): box-drawing/block glyphs render without passing `--unicode`. The
  conhost font/codepage fix-up runs before the decision, so the classic
  console can draw them. `--ascii` (or `BTOP_ASCII=1`) still opts out; the
  launcher's glyph menu text now matches.

## [1.0.3] - 2026-09-05

### Added
- **Truecolor backgrounds for every theme** - the TUI paints its own
  background instead of the terminal default showing through every padded
  space. All 7 palettes ([M] cycles) carry a matching dark bg; armed before
  each frame/overlay/shutdown screen, re-armed by every colour-span end,
  flooded on full repaints and diff rows; quitting restores the terminal
  default. Shipped in the standalone exe.
- **`--font FACE` / `--font-size N`** - explicit console font (classic
  conhost; Windows Terminal keeps its profile font by design).

## [1.0.2] - 2026-09-05

### Fixed
- **Sudden-exit cleanup actually works now** - the detached cleanup watchdog
  had three defects that left it inert in real runs (unit tests import the
  module and never execute it as a script, so all passed): wrong package-root
  path (`ModuleNotFoundError` before any logic), doubled log plumbing through
  a lambda sink, and a `TunTop.geoip` typo in the dashboard's own geo sweep
  that made it match zero CIDRs. Live-fire rehearsed: dead PID + stale crash
  marker -> helper tree-kill, Wintun adapter/routes teardown, geo bypass
  routes on the PHYSICAL adapter swept by CIDR (new `--geoip/--geoip-code`
  handoff from the dashboard), marker cleared; diary in
  `tuntop/core/.cleanup_watchdog.log`.


- **The released standalone exe starts now** - the v1.0.2 exe CI published
  first had NO tun2socks/wintun inside (both are gitignored, so the Actions
  checkout had none and `TunTop.spec` silently dropped them), and the
  integrity check refused with `NOT FOUND at ..._MEI...`. Fixed three ways:
  CI fetches both binaries before building (same sources `Run_Helper.ps1`
  uses), the frozen app now also looks next to `TunTop.exe` itself (where
  the PS1 downloader drops them), and the refusal message names the exact
  fix for the frozen case. Verified end-to-end: rebuilt exe (14.4 MB) has
  both binaries embedded, `--help` exits 0, non-admin boot reaches the
  elevation hint.

### Added
- **Truecolor backgrounds for every theme** - the TUI now paints its own
  background instead of showing the terminal default through every padded
  space. Each of the 7 palettes ([M] to cycle) carries a matching dark bg
  (cool near-black blue, amber deep brown, matrix green-black, ...); the
  background is armed before each frame/overlay, re-armed by every colour
  span end (bg-aware `_R` reset), and painted over the whole screen on
  full repaints, diff rows, list/input overlays and the shutdown screen.
  Quitting still restores the terminal's own default.
- **`--font FACE` / `--font-size N`** - pick the console font explicitly
  (classic conhost only; Windows Terminal keeps its profile font). With no
  flags the old auto behaviour stays: keep the current font if TrueType,
  else the Consolas/Lucida fallback chain.

### Changed
- **The event log and the health-check panel each get their own scroll, and
  the mouse decides which one is ACTIVE**: moving the cursor over a visible
  panel makes it the active scroll target (its title grows a "⇕ scroll"
  marker). j/k, the arrow keys, PgUp/PgDn, Home/End, the mouse wheel and
  the Left/Right horizontal scroll all apply to that one panel only —
  Left/Right now use a separate column
  offset per panel (`_log_hscroll` / `_checks_hscroll`) instead of one
  shared offset that moved both panels' columns at once. Before the mouse
  has hovered anything, j/k keeps its historical role (health checks) and
  the wheel behaves exactly as before, so keyboard-only hosts are
  unaffected. If the active panel is hidden with [5]/[6]/[0], scrolling
  falls back to the other panel so the keys never die on a missing panel.

### Fixed
- **The [L] leak test no longer false-alarms on exit-side address
  rotation**: the verdict compared the direct and tunnel egress IPs as
  plain strings, so when the tunnel exit rotates its outbound IPv6
  between the two connections (both addresses inside one provider /32 -
  e.g. 2a09:bac5:465:c00::... vs 2a09:bac5:5275:2864:... on a Wi-Fi with
  no native IPv6, where "direct" traffic provably has no path but the
  TUN) it screamed "LEAK: ... shows your real IP" for traffic that never
  left the tunnel. Verdicts are now ownership-aware: identical address ->
  ok; different address but SAME /32 -> the new "same-exit" verdict (both
  legs rode the tunnel; the exit rotated its outbound address - NOT a
  leak); different NETWORK -> leak (the real-ISP case is still caught).
  The monitor layer, the helper's [MONITOR] loop and the dashboard all
  treat "same-exit" as a pass. Regression tests pin the exact reported
  address pair as same-exit and a cross-network pair as leak.
- **Health-panel rows can no longer overflow the panel or silently lose
  their detail**: `format_panel()` computed the detail budget as
  `width - len(name) - 8` with NO guard - a check label longer than the
  panel (e.g. a long bypass hostname) made the budget negative, and
  `detail[:negative]` sliced from the END of the string, silently dropping
  the whole detail behind a bare "..." while the row overflowed the panel.
  The name is now truncated first, the detail budget can never go below
  zero, the ellipsis itself must fit the budget, and the per-row overhead
  is computed from the actual mark width (the old constant 8 was already
  off by one for the ASCII marks "OK"/"!!"). Regression tests pin the
  row-fits-width invariant in both unicode and ASCII modes.
- **Health-check scripts no longer break on user input containing apostrophes**
  (same "Bob's VPN" quoting class as the routing fix): `build_checks()`
  interpolated raw user-typed values - `--server` entries, `[A]` bypass
  entries, `--dns4` - directly into PowerShell single-quoted literals
  (`Find-NetRoute -RemoteIPAddress '{_s}'`, the bypass "not resolved yet"
  message, the UDP probe's `Connect('{dns}',53)` and the ping targets). A
  value containing `'` closed the literal, the script failed to parse and
  the check row reported a nonsense parse error instead of its verdict.
  All free-text interpolations now go through the shared `ps_quote()`
  (regression tests capture every generated script and assert no raw
  apostrophe survives).
- **The dashboard's routing helpers are no longer shadowed by dead local
  redefinitions** (the "theater import" bug): `tuntop/ui/dashboard.py`
  imported 14 routing helpers from `tuntop.network.routing` and then
  re-defined 13 of them at module scope, so the imports never ran and every
  fix in `network/routing.py` silently missed the dashboard. The copies had
  already drifted: `ps_quote()` (added to the helper so a VPN connection
  named e.g. "Bob's VPN" cannot close the PowerShell string literal) never
  reached the dashboard's live `_get_vpn_ipv4_default` /
  `_get_vpn_ipv6_default` / `_get_ipv6_default` / `_get_egress_for`, so any
  bypass entry routed through a VPN whose name contains an apostrophe failed
  to install with no error pointing at the real cause. The 13 local
  redefinitions are deleted - the dashboard now runs the shared versions -
  and `ps_quote()` moved to a new stdlib leaf `tuntop/psshell.py` imported
  by BOTH `network/routing.py` and `tunnel/helper.py`, so a quoting fix can
  only ever land in one place. Regression tests pin both the escaping and
  that the dashboard binds the shared objects.
- **Leak-probe timeout is now actually bounded.** `_race_leg()` used to
  wait on its futures and then let the executor's context-manager join
  collect the workers - but `socket.create_connection()` resolves DNS via
  `getaddrinfo()` BEFORE any socket exists, and that call is an unbounded
  blocking OS operation the socket timeout does not cover (and
  `Future.cancel()` cannot stop an already-running thread). On networks
  that blackhole individual hostnames - exactly where this probe fires -
  a hung lookup stalled the caller with no ceiling: on the helper side the
  single-threaded monitor loop (which also drives self-heal), on the
  dashboard side the `[C]` scan's `checking` gate. The executor is now
  shut down WITHOUT joining once the wait budget expires; abandoned
  stragglers are harmless. Covered by a regression test that hangs an
  endpoint past the budget and asserts the race returns on time.
- **One shared leak-probe implementation** instead of two diverging copies:
  the stdlib-only mechanics (SOCKS5 client, endpoint racing, IP
  validation, verdict matrix) moved to `tuntop/network/leak_probe.py`, a
  neutral leaf with zero tuntop imports, and `tuntop/tunnel/helper.py`
  now imports it (with a small sys.path bootstrap so the helper still runs
  standalone) instead of carrying its own ~150-line duplicate. Previously
  only the dashboard copy had tests - the exact shape that let the
  inverted-verdict bug survive. Both entry points are covered now, and a
  unit test pins the re-export/delegation chain so the semantics cannot
  silently drift again.
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
- **Release zips can no longer ship your private runtime files**: the
  build's exclusion matcher only understood `endswith`/exact names, so the
  mid-name wildcards `diagnostics_*.txt` / `crash_*.txt` matched nothing -
  and since a diagnostics export ([D]) writes into `tuntop/ui/` (inside the
  zipped tree), building a release after exporting diagnostics would have
  packed the config snapshot (contains server address) and event log into
  the public zip. Matching is now `fnmatch`-based (regression-checked).
- **A failed geoip.dat download no longer poisons future runs**:
  `Run_Helper.ps1` wrote curl/Invoke-WebRequest output straight to the
  final path, so a mid-transfer failure left a truncated `geoip.dat` that
  `Test-Path` then trusted forever - geo bypass silently "enabled" with
  garbage/empty ranges. The download now lands in TEMP, is verified
  against the release's `.sha256sum` (same policy as the Python-side
  downloader; unreachable checksum endpoint = best-effort accept) plus a
  minimum size, and only then moves into `geofil/`.
- **`Start_TunTop.bat` survives install paths containing apostrophes**
  (the "Bob's VPN" quoting class again): `%~dp0` was interpolated directly
  into single-quoted PowerShell literals, so a path like
  `C:\Users\O'Brien\...` closed the literal and the Unblock-File +
  launcher chain never ran. The folder now travels through the
  `TUNTOP_DIR` environment variable instead of string interpolation.

### Changed
- **Dashboard UX polish (keyboard + mouse parity)**: the mouse wheel now
  scrolls list overlays (Remove Bypass / Load Profile) and every overlay
  row is CLICKABLE - first click selects, clicking the selected row
  confirms (double-click-style confirm), so long lists no longer force
  keyboard-only navigation; the overlay footer shows its real verb
  ("load" for profiles, was "remove" for everything) and a Click hint;
  the status-bar title reads "TUNTOP" instead of the internal codename
  "V2RAY TUN"; hiding the help footer with the mouse no longer strands
  mouse users (the status bar grows a dim "click here to show help"
  hotspot while hidden); and [S] while the tunnel is already up logs why
  it's a no-op instead of silence.
- **Health checks scroll exactly like the event log** (j/k keys and mouse
  wheel, 5 rows per step): the old fixed 9-12-row PAGES are gone - no more
  "Page 6/6" hopping where each page jump re-renders the whole list and
  new scan results could never be seen past the last page boundary. The
  panel now uses the same scroll-back model as the log: it auto-follows
  the newest results while at the bottom, j/k (or the wheel) move a
  scroll-back offset up/down the list, Home/End jump to the oldest/newest
  row, and the footer shows the visible range ("26-35 of 45") instead of
  a page counter.

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
- **Monitor-layer leak probe** (mechanics in `tuntop/network/leak_probe.py`,
  exposed through `tuntop/monitor/leak.py` - pure stdlib, shared with the
  helper):
  both legs (direct + SOCKS5-proxied) race SEVERAL IP-echo endpoints
  concurrently and the first strictly-validated IP wins, so a single
  blocked/lying endpoint (captive portal, interception page) can never
  produce a false verdict; the manual `[L]` test no longer depends on
  `curl.exe` and reports per-leg latency plus a clear verdict for every
  outcome (ok / same-exit / leak / no-proxy / inconclusive / no-network).
- **DNS enforcement checks in the health panel** (leak PROTECTION, not
  resolver availability - the distinction the egress probe alone cannot
  make): "DNS v4/v6 enforcement (no path without TUN)" rows ask Windows
  (`Find-NetRoute -RemoteIPAddress <resolver>`) which interface it would
  actually SELECT for the configured resolver. Selected interface is the
  Wintun TUN -> enforced (UDP/53 to that resolver physically cannot leave
  except through the tunnel). Windows selects the physical NIC / a VPN ->
  flagged as bypassable with the interface named (expected only with a
  deliberate resolver bypass; otherwise a leak). The old DNS rows proved
  only that the resolver ANSWERS - a half-broken tunnel that let UDP/53
  escape via the physical NIC still showed a green board. The DoH
  fallback's docstring now states outright that it is availability, never
  privacy enforcement (it rides TCP/443 wherever 443 is routed - which in
  a half-broken state is the physical NIC).

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

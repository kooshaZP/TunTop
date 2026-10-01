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
| 19 | blocker | FIXED | dns | The machine-wide DoH templates written by `Add-DnsClientDohServer` were **never removed by any path** — they live in the DNS client's registry store, not on the wintun adapter, so neither the adapter teardown nor any route sweep reached them. Every DoH address TunTop ever enabled survived a clean exit and a crash alike. A successful registration is now recorded in `.tuntop_residue.json` and removed (and re-verified against the store) by the helper's `cleanup()`, all five dashboard exit paths and the cleanup watchdog. Only addresses in the record are named, so a user's own mapping is untouched. 1.0.51. | — |
| 20 | major | FIXED | routing | The Wintun adapter was removed only by `preflight_cleanup` at the start of the **next** launch, so it survived every exit — including a clean `[Q]`, leaving a connected-looking `wintun` adapter with our static IP, resolvers, lowered metric and a disabled NetBIOS binding. The close handler's comment claimed "the adapter dies with the process tree"; it is a PnP device, not a process. `routing.remove_tunnel_adapters()` now removes the adapter **and then** its `SWD\WINTUN\{GUID}` node (the other order leaves the node, and Wintun then re-enumerates it so tun2socks finds no interface), and the closing read uses `-ErrorAction Stop` so an unreadable table is a leftover, not a false all-clear. 1.0.51. | — |
| 21 | major | FIXED | routing | A hard kill left the **physical** adapter's `InterfaceMetric` lowered permanently (Wi-Fi 4270 → 9): the original lived only in the helper's module global, which a Task Manager kill, power loss or BSOD discards, and no watchdog, startup-recovery or boot-task path restored it. The value is now recorded in `.tuntop_residue.json` when it is lowered and restored by `restore_recorded_physical_metric()` from startup recovery and the watchdog — refused when the record names a live session, so a second instance cannot reconfigure a running tunnel's adapter. 1.0.51. | — |
| 22 | minor | FIXED | routing | A `[F]` country switch left the previous country's routes unsweepable after a crash: `geo_victims` matches a `DestinationPrefix` against a CIDR set, and only the current code's set was recorded, while switching does not remove the old routes. The watchdog sidecar now carries `geoip_codes` — every code the session applied — and sweeps the union. 1.0.51. | — |
| 23 | minor | FIXED | routing | The `netsh` delete token for a LAN leftover was encoded twice and differently: the dashboard used the next-hop-less form (the only one netsh accepts for on-link rows) and the watchdog kept the next hop for the current-gateway class, so the two owners disagreed about the same leftover. One shared rule now, `routeops.sweeps.lan_victim_deletes`. Investigating it also found an unreachable third dashboard branch: its input was already `lan_victims` output, which never contains a real next hop that is not the current gateway, so the "stale gateway pin" case it described could not arrive. 1.0.51. | — |
| 25 | blocker | FIXED | routing | The **geo installer** handed netsh a literal `0.0.0.0` next-hop token — `gw_part = (" " + str(gw)) if gw else ""`, and `"0.0.0.0"` is truthy — which netsh rejects. The value arrived unnormalised from `get_vpn_ipv4_default` (contrast its IPv6 twin, which has normalised `::` since 1.0.30). On any VPN with an on-link default (IKEv2/L2TP/PPTP/SSTP — the case the helper's own docstring calls normal) **geo-via-VPN installed nothing at all**. The geo installer was the only netsh writer that did not normalise. 1.0.51. | — |
| 26 | blocker | FIXED | routing | Same unnormalised value reached `routing._get_ipv4_default` / `_get_vpn_ipv4_default` (so the dashboard's `[A]`/`vpn`-tagged re-point and its whole route re-add failed) and `dashboard._batch_add_routes`, whose twin `_batch_delete_routes` three functions below **did** normalise — a row read from the table with `NextHop 0.0.0.0` could be deleted by the snapshot restore but never re-added by it. One shared `egress_scripts.netsh_gw_token` now normalises at the source and at every netsh boundary. 1.0.51. | — |
| 27 | high | FIXED | routing | `override_vpn_routes` skips prefixes that are geo ranges by reading `geoip_added` — but the geo install runs on a **background thread** that must first decode a multi-megabyte `.dat`, and the shadow pass runs on the main thread while that thread is still parsing. So `geoip_added` was empty at shadow time, every VPN-injected prefix was shadowed, and the shadow won on effective metric (wintun is driven to `InterfaceMetric 2`, the shadow carries `metric=1`). The country was tunneled — the exact opposite of the intent stated three lines above the code — with every health row green. `unshadow_geo_prefixes()` reconciles where the CIDR set is actually known. 1.0.51. | — |
| 28 | high | FIXED | routing | Geo routes were registered into `geoip_added` **upfront**, and that same list was `add_geoip_bypass`'s return value — so a wholly refused `netsh` batch returned the full planned list, the dashboard recorded it in `_live_geo_added` and announced "re-applied live (3000 routes)", and the ledger then held thousands of prefixes that were never in the table. A sub-batch that installed nothing is now withdrawn; a *partial* one is kept. The `done == 0 and rc == 0` shortcut was also removed: `netsh -f` reports per-line failures in its output while still exiting 0, so a total failure scored as a total success. 1.0.51. | — |
| 29 | high | FIXED | routing | `[X]` (remove a bypass entry) left its row in `_live_bypass_added`, which `_reroute_own_bypass_live` rebuilds from with no membership check — so the next `[GATEWAY]` event or `[V]`/`[Y]` toggle re-added a bypass the user had deleted, and rewrote its tracking to the new gateway so nothing repaired it. `_protected_geo_prefixes` also shielded the prefix from geoip forever, and the `[Q]` sweep was handed routes that no longer exist (netsh's "element not found" is a failure, so a **clean** table reported "some routes may still be installed" and retained the crash marker). The lists are now the authority, enforced at removal and at consumption. 1.0.51. | — |
| 30 | high | FIXED | routing | `geoip via proxy2` was **live-only**: the helper had exactly three egress branches (`--geoip-via-win-vpn`, `--geoip-via-vpn`, else-physical) and no proxy2 one, and the launch builder passed only the first two. A `[Z]` port change, a `[U]` server switch or a recovery restart made the new helper install every country CIDR via Wi-Fi — the opposite of the configured intent, silently, while the status bar kept reading proxy2 because it renders config, not the table. `--geoip-via-proxy2` closes it. 1.0.51. | — |
| 31 | high | FIXED | routing | `[R]` ran `_remove_geo_routes_for` **before** resolving the egress, and the proxy2 branch tested `ns.proxy2_port` (configured) instead of `_proxy2_active` (up). With the second SOCKS5 closed the working bypass was deleted, the install targeted an absent adapter, every add failed, and the success line had already printed. The neighbouring `winvpn` branch already returned without touching the table; every branch now does. 1.0.51. | — |
| 32 | high | FIXED | dns | The CONFIG panel and the `[N]` prompt rendered a v6-only configuration as `8.8.8.8 (default) / <v6>`, claiming the default v4 resolver was in force. `resolve_dns_choice` returns `(None, v6)` for a v6-only choice and the helper honours a present-but-null key as "clear this family", so one `[N]` with a v6 address left the tunnel adapter with **no IPv4 resolver** while the UI advertised one — one panel above a health row that said otherwise. Both now resolve the effective pair. 1.0.51. | — |
| 33 | high | FIXED | dns | The same `[N]` path applied DNS to a hardcoded `'wintun'` literal instead of the shared `TUN` constant (every other DNS path names the constant precisely so a renamed tunnel cannot diverge) and ran with `-ErrorAction SilentlyContinue` while discarding the result — so `[N]` with the tunnel **stopped** logged "set to ... (live)" although nothing had been applied. 1.0.51. | — |
| 34 | major | FIXED | proxy2 | `proxy2_port == port` made the helper `sys.exit()`, and neither entry point checked: `_proxy2_set_port` and `_change_port` validate only 1..65535 and then restart. Typing the primary's own port into `[Z]→3` produced "restarting the tunnel in the background", a **FAILED tunnel**, and an explanation buried in helper stdout. Both entry points now refuse it where the value is typed, and the helper degrades to no-second-hop instead of exiting — consistent with every other proxy2 misconfiguration being non-fatal so a second-hop mistake cannot cost the primary tunnel. 1.0.51. | — |
| 35 | major | FIXED | recovery | The geo sweep deleted TunTop's own `100.64.0.0/10` LAN bypass route: that prefix is in `LAN_BYPASS_PREFIXES` (so `_add_lan_bypass` installs it every run) and in `.dat` country lists, and CGNAT is **not** `is_private` on Python 3.10–3.12 — only 3.13+ learned it. The install accepted it, the LAN bypass installed the same prefix, and every `[R]`/`[F]`→5, every `[Q]` and every watchdog pass deleted it, while CGNAT (Tailscale, mobile broadband) rode the physical NIC in between. Routability is now one predicate over an explicit IANA registry, shared by the install and sweep boundaries. 1.0.51. | — |
| 36 | minor | FIXED | routing | The GEO status row rendered a green `via second proxy (proxy2)` whenever the config said so, including a profile carrying `geoip_target: "proxy2"` with `proxy2_port: null` (the two are saved independently) and a configured-but-down pipe. The row is now `DOT_WARN` for both, and the worker degrades to direct with a log line. 1.0.51. | — |
| 37 | minor | FIXED | routing | `[A]` on an entry already `status == "ok"` left `next` at `now + _BYPASS_REFRESH` (300 s), which is what keeps a healthy entry from being re-resolved constantly — but the two log lines below announced "re-applying now" and "resolving + installing the route live", and nothing ran for five minutes. Pressing `[A]` on a working entry is how a user forces a repair after a foreign TUN stripped the route, so it now forces the cycle the same way `_on_vpn_arrived` does. 1.0.51. | — |
| 38 | trivial | FIXED | routing | The comment on `_WINTUN4_NET`/`_WINTUN6_NET` claimed the pair protects the Wintun subnets, but `TUN2_IP6` (`fd00:dead:beef:1::1`) is outside `WINTUN6_NET` and `TUN2_IP4` does not overlap `WINTUN4_NET` — the pair covers the **primary** adapter only. Unreachable either way (both second-hop subnets are private and `is_private` rejects first), so this is a corrected comment, not a behaviour change. 1.0.51. | — |
| 24 | minor | FIXED | recovery | The watchdog's geo sweep swallowed a per-country `parse_geoip` failure, so an unreadable `geoip.dat` produced an empty CIDR set — indistinguishable from "geo bypass was never active" — and returned `0`, the value that retires the crash marker. It now returns `None` (a failure) when no code could be parsed, matching the `None`-vs-`0` contract the rest of the file already uses. 1.0.51. | — |

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
- **Force-killed helper, server /32 left on a DIFFERENT adapter (1.0.51,
  known residual gap)**: `_final_host_route_sweep` deletes the leftover
  per-host bypass `/32`s and `/128`s, and it is deliberately *scoped* — an
  unscoped `Remove-NetRoute -DestinationPrefix '<ip>/32'` removes that prefix
  on **every** interface, which is how 1.0.41 came to delete a corporate VPN
  client's pinned `/32` for the same server. The scope is the union of the
  tunnel adapters, every interface in the dashboard's own live-route ledgers,
  and the **current** physical v4/v6 egress. What that cannot reach is a `/32`
  left on an adapter alias we no longer resolve: switch from Wi-Fi to Ethernet
  and Windows keeps the old adapter alive, and a force-killed helper's server
  `/32` on "Wi-Fi" is outside the scope while "Wi-Fi" is not the current
  egress. The same switch that leaves the route behind usually removes the
  route too, so this is narrow — but it is real, and it is **not** fixed
  rather than fixed unsafely. A genuine fix needs the route ledger to survive
  the process (today `RouteLedger` is in-memory only), so the crash path can
  name the exact `(dest, iface)` the helper installed. **Workaround:** if a
  server's `/32` survives a hard kill and an adapter change, delete it by hand
  in an elevated console —
  `Get-NetRoute -DestinationPrefix '<server-ip>/32'` then
  `Remove-NetRoute -DestinationPrefix '<server-ip>/32' -Confirm:$false` —
  after checking the InterfaceAlias is not a VPN you still need.
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
  routing table, the geo routes, the DNS guard and the non-route residue (the
  lowered physical-adapter `InterfaceMetric` and the DoH templates this
  session registered, both read from `.tuntop_residue.json`) on the next
  launch. Since
  1.0.41 it also refuses to run while a dashboard is still alive, and it
  re-reads the session marker immediately before its first destructive step so
  a relaunch inside the grace period is not torn down. **1.0.51:** the
  watchdog's own table read was inheriting an 8-second timeout while the
  `netsh` deletes beside it were allowed 120 and 180, so on a machine left
  with thousands of geo routes — the case the watchdog exists for — the read
  timed out, the sweep removed nothing, and the marker was kept. It now uses
  the same fast text dump (90 s) the dashboard uses. If a crash cleanup is
  ever reported incomplete again, the reason is written to
  `.cleanup_watchdog.log` and the crash marker is deliberately **kept**; the
  next launch re-runs the whole recovery rather than assuming the system is
  clean. The one thing a hard kill still leaves is the **wintun adapter
  itself** — deliberately, because the next launch's `preflight_cleanup` owns
  it and doing it inside the watchdog's grace budget competes with the route
  sweeps that actually matter. Until that next launch,
  `Get-NetAdapter -Name wintun` will show it.
- **A stale-gateway LAN pin is left in place (1.0.51, known residual gap)**: a
  leftover RFC1918 route whose next hop is not the current gateway — typically
  a Wi-Fi → Ethernet switch Windows kept the old adapter alive for — is **not**
  a sweep victim. A corporate static route (`10.0.0.0/8 → 10.20.30.1` on
  Ethernet), a VPN split tunnel and a NAS subnet are indistinguishable from one
  of our own stale pins, and deleting on that evidence is a coin flip against
  the user's own routes. Every other class (on-link and current-gateway) is
  removed. **Workaround:** remove it by hand in an elevated console —
  `Get-NetRoute -DestinationPrefix 10.0.0.0/8` then
  `Remove-NetRoute -DestinationPrefix 10.0.0.0/8 -NextHop <gateway> -Confirm:$false`
  — after checking the `InterfaceAlias` is not a VPN you still need. The same
  switch usually drops the route itself, so this is narrow.
- **Run from source AND from the exe**: the two use different persistent
  directories (the package dir vs. the exe dir) for the control file, profile
  store, geoip default, crash log and diagnostics. A `[N]` DNS change made
  while running from source is not seen by an exe-launched helper (and vice
  versa) — they are separate installs, deliberately.

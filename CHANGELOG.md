# Changelog

All notable changes to TunTop are documented here.

## [1.0.47] - 2026-09-29

**The DNS leak was self-inflicted.** The catch-all NRPT pin was installed correctly at startup, and then **removed by the user's own next action** - changing the server, adding a bypass, or toggling `[V]`/`[Y]`.

### Fixed (a server edit wiped the resolver AND the leak pin)
- **The dashboard wrote `dns4: null, dns6: null` into the live-reconfig control file on every write, and the helper read that as "clear this family's DNS".** `ns.dns4` is `None` whenever the user relies on the defaults - which is the normal case - and the control file's default payload copied those raw attributes verbatim. The helper's reading is *correct and must stay*: a present-but-null key is how an explicit `[N]` clear is expressed, and a missing key means "no change". So every server change, bypass add/remove and `[V]`/`[Y]` toggle silently cleared the running resolver, and because a guard with no resolvers would black-hole name resolution, `_install_dns_guard()` then **removed the catch-all NRPT pin** along with it. One bypass addition put the machine straight back onto the ISP's resolvers. Live evidence: `wintun` Up and holding 8.8.8.8 + 2606:4700:4700::1111, no `TunTop-*` key under `DnsPolicyConfig`, an effective NRPT policy carrying only a foreign rule (`fe3cr.delivery.mp.microsoft.com` -> 162.159.36.2), and a leak test answering with the ISP's own servers (2.188.21.46, 2.189.44.x).
- **The selection rule is now defined ONCE** (`tuntop.config.defaults.resolve_dns_choice`) and called by the helper at startup *and* by the dashboard when it reports the configuration, writes the control file and builds the health rows. The two hand-synced copies drifting apart is precisely what let this happen silently. The control file now carries the **effective** pair, so an unchanged configuration arrives at the helper as genuinely unchanged - and every real case still means what it says: a v4-only choice is still `(X, null)`, a v6-only choice `(null, Y)`, and an explicit clear still clears.
- **The health rows stopped lying.** "DNS configuration", "DNS leak protection" and the v4/v6 enforcement rows are now built from the effective pair, so they no longer report "no DNS resolver is configured" while the tunnel is up and the adapter really is holding 8.8.8.8 - and no longer declare the leak guard "skipped by design" for a tunnel that has a resolver.
- The matching live `[N]` apply resolves the same way, so it can never build an **empty** server list and strip every resolver off the adapter.

### Fixed (the session log was missing the lines that matter)
- The on-disk session log captured only `[DASHBOARD]` lines. The queue carries the **helper's** stdout - the startup, DNS-guard and self-heal verdicts, i.e. exactly the lines that explain a failure - and those went straight into the in-memory panel. With the panel dying with the process, a session whose helper output explained the problem still left no trace of the explanation. The drain loop now mirrors them, tagged `HELPER`.

### Fixed (`--dns-mode plain` crashed the helper)
- Reviewing the in-flight `configure_tun` change that makes the function report whether the resolver actually moved to DoH (so the start sequence can skip a doomed re-probe): the new `applied` flag was initialised **inside** the mode branches, and `"plain"` matches neither `mode == "doh"` nor `mode == "auto"` - so the final `return applied` raised **`UnboundLocalError`**. The DoH escalation wraps its call in `try/except`, which is why it did not surface there, but the tunnel bring-up, `poll_control_file` and `self_heal_tunnel` all call it **unguarded**: a user who chose `--dns-mode plain` (a documented option) had the helper die at startup. `applied` is now initialised once, before the branches, and the `elif mode == "auto"` arm - which only re-assigned the same `False` - is gone. All three modes are covered by tests, including that a failed registration or a failed adapter-list set is never reported as "DoH applied".

### Tests
- 1045 passed, 7 skipped (was 1025/6). New `TestEffectiveDnsSingleSource` pins the regression at four levels: the shared rule, the control-file payload, an end-to-end `poll_control_file` no-op for an unchanged configuration, and a v4-only choice still clearing v6. `TestConfigureTunDohModes` pins all three `--dns-mode` values. `test_replace_drops_old_and_installs_new` was corrected to the `_live_apply_servers` intent already in the tree (the new server's `/32` is deliberately NOT pre-cleaned: the dashboard installs it first, so the pre-clean did the work twice and briefly tore down a live, correct route), and a `RouteLedger` snapshot/restore in `test_route_family_guard` was corrected to the ledger's real shape (it iterates the same 4-tuples `append()` takes, not receipts).
- Not in this release: the `v1.0.46` commit and tag are local only - `git push` needs your GitHub credentials (`git push origin main` then `git push origin v1.0.46`), and the in-app updater additionally needs a GitHub **Release** carrying `TunTop-x64.zip` + `checksums.txt`.

## [1.0.46] - 2026-09-28

The start sequence no longer waits on a resolver that cannot answer, a clean exit no longer leaves scratch files in the user's folder, and the log says *which* problem it found instead of repeating itself a dozen times.

### Fixed (startup gated on an un-timed-out `getaddrinfo`)
- **The verification asked the resolver a question the resolver could not answer, and the resolver has no timeout.** `wait_for_tunnel_stable()` probed four URLs, every one of which begins with `socket.getaddrinfo`. When plain UDP/53 cannot traverse the tunnel - the normal state for a SOCKS5 client whose UDP relay does not work - Windows walks **every** configured resolver (here 8.8.8.8 *and* an IPv6 one) with its own multi-second timeouts, so each URL cost 5-10 s of pure resolver waiting to report the same thing, and the DoH escalation round then paid it all again. That was both the "Verifying the tunnel is stable..." spinner and the wall of identical `DNS resolve ... [Errno 11001] getaddrinfo failed` lines. The verification now runs in two stages: **stage 1 asks whether the TUN forwards packets at all**, with a TCP connect to a *literal* address (1.1.1.1/8.8.8.8/9.9.9.9 : 443, raced concurrently, 3 s ceiling) - no resolver is consulted, so the answer takes about a tenth of a second and nothing unbounded can be waited on. A stage-1 failure is a genuine routing/`tun2socks` problem and returns immediately with exactly that wording, because resolving hostnames for a tunnel that cannot forward packets was the whole cost. A stage-1 success means the tunnel is fine, so any subsequent failure is a *resolver* failure - which is what stage 2 and the DoH escalation exist to fix.
- **The same resolver failure was reported once per URL per attempt.** The workers now record that every failure was a DNS failure and let the round speak for itself, so a broken resolver produces **one** actionable line - "Name resolution through the TUN is not working ... plain UDP/53 cannot cross it, so DNS is being escalated to DoH over TCP/443" - instead of a dozen identical ones. A resolved-but-failed fetch is a different problem and keeps its full retry budget and its per-URL line.

### Fixed (files left behind after a normal exit)
- **A clean exit did not clean up.** Closing the app left `.tuntop_control.json` (rewritten on every `[N]`/`[V]`/`[Y]` change) and the session log next to the exe. A verified clean exit now retires this session's scratch files: the live-reconfig control file and `tuntop_session_<date>.log` with its `.1` rotation generation. The control file is not merely untidy - a stale one is exactly what the next launch's baseline logic has to reason around - and a session log that accumulates forever is worse than none, given its entire purpose is to explain a session that went *wrong*. **Deliberately NOT removed on an unclean exit**: the crash marker, the watchdog state and both of these files survive a crash precisely because that is when they are evidence. Best-effort throughout: a file an AV scanner is holding open is retried next time, and never blocks the others.

### Tests
- 1016 passed, 6 skipped (was 1005/7).

## [1.0.45] - 2026-09-28

The tunnel was silently failing to come up, so the "DNS is protected" verdict was describing a tunnel that was not carrying anything. Diagnosis on the reported machine: `Get-NetAdapter` listed **no wintun adapter at all**, no `0.0.0.0/1` routes, no `tun2socks` process, no NRPT guard rule - while the dashboard still read as an active tunnel. The cause was a Wintun **device node** that outlived its network adapter.

### Fixed (a hard kill left a Wintun device node that no later start could clear)
- **`preflight_cleanup` removed the network ADAPTER and never the device NODE.** After a window closed forcibly or the process was killed, `Get-PnpDevice -Class Net` still showed `tun2socks Tunnel` / `SWD\WINTUN\{B2DC404F-...}` / status **Unknown** while `Get-NetAdapter` listed no wintun at all - the two are different objects, and `Remove-NetAdapter` on an adapter that no longer exists is a silent no-op. The Wintun driver then enumerates that stale node instead of creating a fresh adapter, so the new `tun2socks` finds no interface and exits, the dashboard restarts it, and the loop never converges: the `.last_run.json` marker showed a helper restart, a 3-deep `TunTop` process chain, and no tunnel. `remove_stale_wintun_devices()` now clears orphaned `SWD\WINTUN\*` nodes, and `preflight_cleanup` calls it **after** `Remove-NetAdapter` - with the adapter still present, every node looks legitimately `OK` and the stale one would be skipped. Only nodes whose status is not `OK` are touched, so a foreign Wintun adapter that is actually running (v2rayN/xray TUN mode) keeps its device.
- **The session log is now persisted, because this whole class of report was undiagnosable.** The log panel is the UI's and dies with the process: a session that ends in a restart loop, a crash or a force kill left *no evidence at all* - neither the user nor anyone debugging it could say what happened. Every line now also appends to `tuntop_session_<date>.log` next to the exe (frozen) or the module (source), with a named severity and the component tag, rotated at 1 MB with one previous generation kept. It never raises and never blocks a line: a read-only folder silently disables it, and `TUNTOP_NO_SESSION_LOG=1` opts out entirely.

### Clarified ("Your DNS requests are exposed" is not the test TunTop's verdict is)
- A browser leak test answers **"which resolver queried my domain?"** - not "did my ISP see it?" - so it reports a leak whenever the answer is a public resolver, *even when that resolver was reached through the tunnel*. With `8.8.8.8` configured (the default) Google answers every lookup, so such a test shows Google and calls it exposed; your ISP still never sees the query, but Google can log it. Only a resolver running **inside** the tunnel can satisfy that test, and TunTop is a transport, not a resolver: it forwards DNS to whichever resolver you chose. The `[C]`/`[L]` checks answer the question that actually matters here - whether anything **outside** the tunnel answered, and which adapter it came from - and the new `check_dns_leak.ps1` says so explicitly in its verdict.

### Tests
- 1005 passed, 7 skipped (was 994/6).

## [1.0.44] - 2026-09-27

A performance release: starting and stopping the tunnel were both dominated by process-launch and unbounded-wait overhead rather than by anything the work actually needed. It also closes the loop on the DNS leak guard, which was installed but repeatedly torn down again.

### Fixed (the DNS leak guard kept being removed again)
- **Six TunTop instances could run at once, and the catch-all NRPT rule is machine-global.** The guard is installed by whichever helper brings the tunnel up and removed by whichever instance tears down - so with several instances running, closing ANY one of them deleted the pin the others were relying on, and the machine went straight back to querying every adapter's resolver in parallel (Smart Multi-Homed Name Resolution) with every health row still green. The exact symptom the guard was built for, reappearing seconds after it was fixed. TunTop now takes a `Global\TunTop-SingleInstance` named mutex before it touches anything - before the binary download, the geoip download, startup recovery and the integrity check - and a second launch refuses with an actionable message instead of racing the first one over the adapter, the route table and the DNS policy. The mutex is released by the OS when the holder dies, so a hard-killed instance never blocks the next start, and a lock that cannot be taken (no ctypes, a locked-down kernel) never blocks the launch either.
- **The install record now names its owner, so a teardown cannot delete a live instance's pin.** `save_state` records `owner_pid`; `ensure_removed` leaves a rule alone when the record names a different process that is still running, and reports why. The RECOVERY owners (startup recovery, the cleanup watchdog) pass `force=True` - they run when nothing should still rely on the rule, and clearing a crash leftover is their entire purpose. A record written before ownership was tracked never blocks a removal, so the pin can never be stranded.
- `check_dns_leak.ps1` (new, repo root): an elevated one-shot diagnostic that separates the three states an operator must be able to tell apart - no rule installed (the leak), a rule in the registry that Windows' effective NRPT policy does not carry (a malformed rule, or a Group Policy NRPT overriding it), and a rule in force (so a leak test showing an ISP resolver is coming from something other than the OS resolver). It also lists the adapters Windows can still query in parallel and how many TunTop instances are running.

### Fixed (startup stalled on "Verifying the tunnel is stable...")
- **Nothing bounded the verification round, and `getaddrinfo` cannot be bounded.** `socket.getaddrinfo` takes no timeout, and when the configured resolver is unreachable - which is exactly the state plain UDP/53 is in while it has to traverse a SOCKS5 tunnel - Windows walks every configured server (here `8.8.8.8` *and* an IPv6 resolver) with its own multi-second timeouts. The `timeout` argument only bounds the HTTP fetch. So a single probe could burn 5-10 s, and `_run_round` then waited on `as_completed()` with no deadline of its own, paying that cost twice: once for the plain-DNS round and again for the DoH escalation round. Verified startup could spend 20-30 s here.
- **The round deadline alone was not enough.** The executor was a `with` block, and `__exit__` calls `shutdown(wait=True)` - which blocks until every worker thread returns. A probe wedged in an un-timed-out resolve held the start open regardless of any deadline set inside the loop. The executor is now shut down with `wait=False, cancel_futures=True`, so a stuck resolve is genuinely abandoned (it finishes on its own and is reaped), and the round returns on the first success or its deadline, whichever comes first.
- **A DNS failure was retried before the fix that repairs it.** The worker gave up after 2 resolve attempts with a 1 s gap, costing a second full resolve sweep immediately before the DoH escalation. DNS failures now give up after the first try; the point of the failure is to trigger that escalation, so reach it in one step. Non-DNS failures (resolved, fetch failed) keep the full retry budget, since those can be transient.
- The whole verification is now bounded by `_VERIFY_BUDGET` (18 s) with `_VERIFY_ROUND_BUDGET` (8 s) per round, and the DoH escalation is skipped when the budget is spent - no point reconfiguring the resolver and flushing the DNS cache with no time left to verify the result. A healthy tunnel is unaffected (it verifies in well under a second). A failed verification is still not a dead tunnel: `main()` announces `DEGRADED` and the monitor loop re-probes ~5 s later and promotes to `RUNNING` on the first pass, so the budget trades a "Verifying..." spinner for a tunnel the user can actually use.
- `--geoip` without `--geoip-code` printed its advisory twice (pre-flight check plus the worker thread); the duplicate is gone.

### Fixed (teardown spawned one `netsh` process per route)
- **`cleanup()` removed every route this helper owns with a separate `netsh` process, serially.** A typical session owns 25-35 such rows - 6 TUN default/split routes, ~10 LAN bypasses, the Wintun host routes, the VLESS `/32`s, the VPN endpoint `/32`s - and a process spawn costs hundreds of ms, so "Stopping tunnel helper (clears its own routes)" was tens of seconds of pure launch overhead before teardown even reached the geo sweep. The batched `netsh -f` mechanism already existed and was used only for the geoip sweep; it now handles the installed routes and the VPN-override routes too (typically ONE process instead of thirty). The critical-before-bulk ordering guarantee is unchanged and still tested.
- **On-link routes were never actually removed.** `remove_route` appended the gateway to the v4 delete unconditionally, so an entry recorded with the on-link spelling (`''` - what `_norm_v4_gw` produces, and what a PPP VPN's routes get) was deleted with an *empty argument*; netsh rejected the command and the route survived every teardown. The v6 branch already omitted the token. Both now do, and this is why 1.0.43's on-link normalization is now safe end-to-end.

## [1.0.43] - 2026-09-27

Four bugs found by testing 1.0.42 on a dual-stack Wi-Fi with a connected Windows VPN. All four are the same species of failure: one wrong value in the routing layer, propagated without a check until the tunnel stopped carrying traffic - and three of the four are the "TUN starts, then the connection and the proxy die" report itself.

### Fixed (a network change could destroy every route and never repair it)
- **The physical-gateway lookup could answer with an IPv6 gateway on a dual-stack NIC.** `Win32_NetworkAdapterConfiguration.DefaultIPGateway` is a string array holding the adapter's IPv4 *and* IPv6 gateways together, and the fallback that recovers the physical gateway (used when a full-tunnel VPN has deleted the NIC's own default) rejected only `0.0.0.0` and `::` - so on dual-stack it could return `NextHop = fe80::...` from a script whose entire job is to answer for IPv4. The gateway monitor read that as a genuine egress change and re-pointed **every route we own** at it (LAN bypasses, the proxy `/32`, the geo set), failing each one with `Invalid nexthop parameter ... should be a valid IPv4 address`; worse, it then **committed** the broken value to `_live_mode['phys']`, so nothing could be re-installed for the rest of the session and the endpoint bypass was stuck failing (`[HEAL] ... re-install FAILED - retrying next cycle`). The filter is now an exact family test (`-notmatch ':'` - every IPv6 literal, including IPv4-mapped forms, contains a colon), and the monitor **refuses** a next hop that is not IPv4 instead of acting on it.
- **A PPP/PPTP VPN's on-link next hop was passed to netsh verbatim.** Such a VPN reports `NextHop = 0.0.0.0` (resolve by neighbour discovery - the same form as `::` for IPv6), and netsh rejects a literal `0.0.0.0` with `The filename, directory name, or volume label syntax is incorrect`. Both the `--vless-over-vpn` transport pin and the VPN endpoint `/32` failed for this reason - leaving the proxy server with no bypass at all, so its traffic fell into the TUN and looped. Because the comparison also treated `'0.0.0.0'` and `''` as different, a *correctly* installed on-link route was never recognised and was torn down and re-added (and re-failed) on every single call. `add_v6` has normalised `::` and omitted the token since 1.0.30; `add_v4` now does the same via `_norm_v4_gw`, and both installers refuse a next hop of the wrong family outright instead of letting netsh produce an opaque error.
- **A VPN endpoint's bypass route could be installed on the VPN itself** - `add 185.64.178.62/32 on Shirazu-VPN via 0.0.0.0`, i.e. the VPN's own server routed through the VPN. `get_ipv4_default()`'s last-resort clause deliberately returns "any non-wintun default route, may be the VPN", which is fine when all you need is *some* egress but poison for a value labelled *physical*. `_direct_bypass_egress()` is now the single choke point for every route that must not ride a tunnel or VPN (proxy server, user bypass, VPN endpoint): it resolves per-IP with VPN excluded, falls back to a **validated** physical egress, and returns `None` rather than a self-referential answer. `physical_egress()` re-validates on every read, so a poisoned cache cannot reach a route install.
- **`_live_mode['phys']` is now validated before it is cached**, and the gateway monitor refuses a VPN or tunnel adapter as a "physical egress change" (which is what a full-tunnel VPN reconnect looks like mid-flight). Belt and braces, but a cache that outlives the call and feeds every later bypass is worth validating twice.

### Fixed (self-heal was dead)
- **A missing `global` silently disabled all self-healing.** `_install_dns_guard` *assigned* `_dns_guard_state` without declaring it `global`, so Python compiled it as a function-local and the *read* in the no-resolver branch raised `UnboundLocalError: cannot access local variable '_dns_guard_state'`. That is reachable by simply clearing both DNS servers (the log line `[i] DNS leak guard: skipped - no DNS resolver is configured` sits directly above the failure), and the exception unwound out of `self_heal_tunnel` - skipping every Wintun address, the default and split-default routes, the entire IPv6 stack and the LAN bypass re-apply. The self-heal did *nothing*, the tunnel stayed broken, and the only symptom was one line naming a variable instead of the routes that were never re-applied. The declaration is restored, and the DNS-guard step is now individually guarded (`except (Exception, SystemExit)`) - the function's own docstring already promised "one failing add cannot abort the rest", which was not true.

## [1.0.42] - 2026-09-27

Fixes the "everything is fine, then the TUN comes up and the connection and the proxy both die" report, and tightens the state machine so it cannot claim a result it did not verify. Three defects compounded into that blackout, plus two more that made the state machine lie about the tunnel.

### Fixed (starting the tunnel could take down the proxy and the connection)
- **The proxy's own transport was never re-checked after the default route went live.** The `/32` bypasses for the VLESS/VPN endpoints were installed *before* the `0.0.0.0/0` and the split-defaults - the right order, but not a proof. If that route ended up on a tunnel adapter (a competing TUN, a metric race, a country-bypass sweep), the moment the default route became live the proxy's connection to its own server was captured by the tunnel: the proxy client could not reach its server, tun2socks was left with no upstream, and every connection the TUN carried died with it - while the dashboard showed a fully installed, healthy tunnel. `verify_endpoints_off_tun()` now re-reads the routing table after the default routes are installed, repairs what it can through the same healer the 15 s self-heal uses, re-reads to confirm, and reports loudly what is still looping (naming the address and the adapter holding it). The "is this route safe" decision was extracted into `_bad_endpoint_rows()` and is now shared by the startup guard and the periodic heal, so the guard can no longer green-light a route the heal would tear down (or vice versa, forever).
- **The tunnel announced itself ready without ever verifying.** `wait_for_tunnel_stable()`'s verdict was discarded and `[*] Press Ctrl+C to stop` was printed unconditionally, so a tunnel that never carried a packet was reported as `RUNNING` - the state the dashboard treats as "verified healthy, traffic flows". The ready marker is now gated on the verification result *and* the loop guard; a tunnel that fails either starts as `DEGRADED` with the actual reason (endpoint loop vs unverified probe) and is re-probed after ~5 s instead of a full monitor interval. It promotes itself to `RUNNING` on the first passing probe, with no restart and no user action.
- **A proxy outage escalated into a restart crash loop that never recovered.** Any failing monitor probe was hard-coded to `FailureKind.DNS`, whose ladder escalates to a full helper restart. But a restart *cannot* fix a closed local SOCKS5 port - `start_tun2socks_pipe()` exits when the connect is refused - so each restart tore down a perfectly good tunnel (adapter, routes and DNS all fine), the replacement helper died on the same refused connect, the `PROCESS` ladder opened its own incident, and the user's connection never came back. The helper's monitor now checks the local SOCKS5 inbound on its own fast 5 s cadence and reports it as an *upstream* outage, distinctly; the `PROXY` ladder waits for the port instead of restarting anything; and when the port answers again the monitor re-probes immediately rather than waiting out the 30 s interval. Recovery also no longer counts such an exhaustion toward crash-loop protection (`register(..., crash_loop=False)`) - three ordinary proxy outages used to disable auto-recovery for the rest of the session.
- **A `tun2socks` crash ended the monitor loop in silence.** The loop's `while tun_proc.poll() is None` fell out on a crash exactly as it does on a requested stop, so the dashboard saw a bare "helper process exited" with no idea the userspace forwarder - the thing that actually moves packets - was gone. The exit code is now reported, and the dashboard carries that reason into the state history and the recovery log.

### Fixed (state machine precision)
- **`RUNNING -> FAILED` was missing from the transition graph.** The helper's self-heal reports "Wintun adapter is gone" and the dashboard answers with `try_transition(FAILED)` - which was a **silent no-op** from `RUNNING`, so the UI kept reporting `RUNNING` for a tunnel with no adapter left. `DEGRADED` and `RECOVERING` already had the edge; `RUNNING` was the odd one out. All three health states can now fail outright, and no health state is a safe harbour.
- **A refused transition was indistinguishable from losing a race.** `try_transition` swallows `TransitionError` by design (racing threads must not raise), which is exactly why the missing edge above went unnoticed. Refusals are now counted and the latest one retained, exposed in the diagnostics export as `rejected` / `last_rejection`; a bad *argument* (`TypeError`) is still not counted, because that is a programming error rather than a refused transition. Added `TunnelState.is_start_sequence` and `is_health` to match the classification the graph already encoded.
- **`ROUTES` and `ADAPTER` were declared but never registered.** Reporting either was answered "no recovery action registered - ignored" and the failure was dropped on the floor - including the self-heal "Wintun adapter is gone" line, which is precisely the case that needs a rebuild. Both now have ladders.
- **A recovery restart could report success against someone else's process.** `_recover_restart_tunnel` returned `True` when a restart was already in flight, so the ladder's `verify` confirmed against *that* restart's helper: the incident closed while the tunnel was still being rebuilt, and a genuinely failed restart was logged as "Recovery verified". It now joins the in-flight restart instead (waiting outside `_restart_lock`, which the running restart needs to clear the flag).

### Changed
- **The helper's stdout vocabulary is now one table.** The dashboard's reader thread carried a ~200-line `startswith` chain that silently decided, per line, the tunnel state, the recovery failure kind and whether to log - which is how `[MONITOR] tunnel check failed` ended up meaning `FailureKind.DNS` for every possible cause. All of it now lives in `tuntop.core.markers` as a pure, table-driven mapping (a line in, a verdict out, no I/O), so the helper's line format is an explicit contract rather than an accident of ordering inside a thread. Tests assert every marker `helper.py` can print is classified, that no cosmetic marker acquired a state meaning, and that the ready marker is still printed behind the verification result.
- The health panel gained fix suggestions and `CRITICAL` severity for a closed upstream SOCKS5 port and for a proxy endpoint that would loop through the TUN: in both cases the tunnel is installed and *looks* perfect, which is exactly when a user believes it is working.

## [1.0.41] - 2026-09-27

A correctness-and-hardening release. No new features and no intentional behaviour changes beyond the fixes below - the theme is that several code paths were *claiming* a result they had not actually verified, and one class of bug could damage state TunTop does not own.

### Fixed (teardown and recovery could damage a *working* tunnel)
- **The crash watchdog could declare a LIVE dashboard dead and tear down its tunnel.** `wait_for_exit`/`kill_pid` used `ctypes.windll.kernel32` and read the result with `ctypes.GetLastError()`. `ctypes.windll` does **not** set `use_last_error`, so that error value was meaningless: a "cannot open the process" result was treated as "the process is gone" for every reason except access-denied, and the watchdog proceeded to kill the helper and sweep the routes. It also declared no `restype`/`argtypes`, so a 64-bit `HANDLE` was sign-extended into a 32-bit int and `WaitForSingleObject` could be handed a different handle than the one just opened. Both are fixed by a `_kernel32()` factory that sets `use_last_error=True` and the 64-bit prototypes, by treating "access denied" as *alive*, and by treating any other unreadable result as "cannot tell" - which keeps polling to the deadline instead of declaring a possibly-live process gone. The sweep also now waits for the dashboard to exit with a **bounded** 15-minute timeout (it was an unbounded wait, so nothing downstream could ever run) and abandons the sweep rather than tearing down a running session.
- **A second TunTop window could destroy the first one's working tunnel.** There is no single-instance guard, and the crash marker's recorded PID was never checked for liveness, so launching TunTop twice made the second instance read the first's marker, conclude "crash", kill that instance's tun2socks, remove its Wintun adapter and sweep its routes. `startup_recovery.marker_is_live()` now probes the marker's PID (Sync + `WaitForSingleObject(0)` on Windows, `os.kill(pid, 0)` elsewhere) and returns `None` = *cannot tell* for the ambiguous cases, which callers must treat as live - skipping a needed cleanup is far cheaper than killing a running tunnel. The watchdog re-reads the marker immediately before its first destructive step, so a relaunch inside the 3-second grace period is also left alone.
- **A marker read error was treated as "the previous run exited cleanly".** `read_marker` collapsed a missing file, a truncated file and a permission error into `None`, and `scan()` reads "no marker" as clean - so any decode failure (the writer truncates before dumping) skipped the entire recovery sweep while routes stayed installed. The marker, the DNS-guard install record and the profile store are now written **atomically** (temp file in the same directory + `os.replace`), and a marker that is present but unreadable is reported rather than assumed clean.
- **`cleanup()` set `cleaned = True` before doing any work.** A single failure in the first second permanently disabled teardown for the process, so a later `atexit`/second-signal call returned immediately and a transient error became "no teardown at all". The flag now moves to the end, and each phase runs through `_step()`, which contains a failure to that phase: a raising `print` (the helper's stdout is a pipe, and the dashboard may be gone) or a `netsh` error can no longer skip the steps that follow.
- **A repeated Ctrl+C aborted the teardown it was meant to finish.** The signal handler re-entered, found `cleaned` already `True`, returned from `cleanup()` immediately and then called `os._exit(0)` - killing the process mid-sweep and leaving exactly the broken state `cleanup()` exists to prevent. A `_cleanup_in_progress` guard ignores repeats. The handler also declares the flag `global` (it was read as an unbound local, so the *first* signal raised `UnboundLocalError` out of the handler) and now exits non-zero if the teardown failed.
- **The geo install/re-point threads were only joined on the signal path.** On a normal exit they raced `cleanup()`: the ledger was snapshotted and cleared, then the thread installed a batch *after* the delete - routes in the table that no ledger and no later sweep could match. Both threads are now published and joined by `cleanup()`, and the re-point worker refuses to start once a teardown is under way.
- **A failed geo re-point silently orphaned its routes.** The receipt was removed from the ledger *before* the re-add, so a failed re-add left the old-gateway route installed in the OS and invisible to cleanup - permanently pinned to an egress that usually no longer exists. The receipt is now put back on failure, and the log line says so.
- **A `tun2socks` child could be orphaned and hold the adapter open forever.** `_fail()` returned/exited while the child was still running, and on the fatal path `sys.exit` raised *before* the caller's `tun_proc = ...` assignment completed - so the global stayed `None` and no teardown could ever kill it. `_fail` now terminates (then kills) the child it spawned.
- **The `SystemExit` family, again.** `self_heal_tunnel` called `get_ipv4_default()` inside `except Exception`; `SystemExit` is a `BaseException`, so one momentarily-absent IPv4 default route (a Wi-Fi roam, a DHCP renewal, a VPN flap - all routine) unwound out of self-heal, out of the monitor loop, and tore the whole tunnel down. `TunnelManager.start`/`request_stop` and the startup-recovery steps have the same fix, and a teardown that *raises* now transitions to `FAILED` instead of claiming a clean `STOPPED`.
- **The recovery engine could die permanently and silently.** A `BaseException` out of a ladder rung left `_in_attempt = True` forever, after which every `report_failure` returned early - auto-recovery was dead with nothing logged. The attempt body is now wrapped so the flag is always cleared. Reports that arrive *during* an attempt are no longer dropped (they are held and actioned once it finishes - the reader thread reports a dead helper only once, so discarding it left the tunnel down with nothing scheduled to fix it), and the ladder no longer re-arms while paused or stopping, which is what `shutdown()` promises. A successful repair now only resets the crash-loop counter after a **sustained** success: every ladder's verify is "the helper is still there" a second after launch, so a helper that came up and died 5 s later used to count as a verified success, reset the streak, and start a *fresh* incident at attempt 1 - the backoff never escalated, `max_attempts` was never exhausted, and the app sat in an infinite restart loop.

### Fixed (tunnels were broken, or traffic went somewhere it should not)
- **DoH was re-registered against the adapter's own address.** When the Wintun adapter was re-added, `_ensure_wintun_address` passed the just-re-added TUN4/TUN6 address to `_enable_doh_on_wintun` instead of the **resolver** - setting wintun's entire resolver list to itself. Every lookup went to `192.168.123.1` and nothing resolved. The resolver is now passed, per family.
- **A geoip CIDR with no prefix field became `0.0.0.0/0`.** `_geoip_parse_cidr` initialised `prefix = 0` rather than `None`, so a truncated or hand-edited `.dat` decoded a country range as a **default route** and routed the entire internet (or all of IPv6) to the direct egress. A missing or out-of-range prefix is now rejected outright - a default route is never a country range.
- **`geoip.dat` CIDRs are now rendered canonically.** IPv6 came out in the uncompressed eight-group form (`2001:db8:0:0:0:0:0:0/32`) while `Get-NetRoute` reports the compressed form (`2001:db8::/32`). Every IPv6 geo route therefore failed every string comparison against the live table and **survived every sweep** - the bypass intent stayed armed against a dead tunnel. All four places that compare CIDRs (the exit sweep, the watchdog's geo sweep, `sweeps.lan_victims`, `sweeps.geo_victims`) now compare `ipaddress.ip_network` objects.
- **The LAN sweep deleted routes TunTop did not create.** `lan_victims` accepted "a real next-hop from a previous network" as its own, on the argument that it deletes next-hop-exact. It is still a delete: a corporate static route (`10.0.0.0/8 -> 10.20.30.1` on Ethernet, a VPN split tunnel, a NAS subnet) is indistinguishable from a stale pin of ours, and the list goes straight into a `netsh -f` delete from both the `[Q]` sweep and the watchdog. Only the **current** gateway (or an on-link/empty next-hop spelling) is now selected. Genuinely-installed stale routes are tracked in the `RouteLedger` with their gateway and metric precisely so the exit sweep can remove exactly what *this* run installed.
- **The crashed-helper host-route sweep was unscoped.** It emitted `Remove-NetRoute -DestinationPrefix '<dest>'` with no `-InterfaceAlias`, and that form removes the prefix on **every** interface - the exact pattern `routing.py` documents as forbidden. It also removed a VPN-client-pinned `/32` for the same server. It is now scoped to the tunnel adapters, and `sweeps.host_route_stmts` can scope to any alias set.
- **The persistent-store route conversion could not succeed, and reported success anyway.** `netsh ... delete route` defaults to `store=active`, so a `PersistentStore` leftover was never actually converted; the re-add then hit the same persistent route, said "already exists", and the old `ok2 or "already exists" in msg2` returned **success**. The user saw "added"; after a reboot the old persistent `/32` via the old gateway was back and the new one absent. Both deletes now carry `store=`, and the fallback verifies our exact route rather than pattern-matching the one string that signals failure.
- **The IPv6 default-route fallback reintroduced the VPN hijack it exists to prevent.** The relaxed second block dropped the `$vpnAliases` clause entirely, so on a box with no native v6 default the first candidate *was* the connected Windows VPN - silently, with no log line.
- **PowerShell output was decoded as UTF-8 that was never produced.** `_ps` decodes with `encoding="utf-8"`, but Windows PowerShell 5.1 writes host output in `[Console]::OutputEncoding`, initialised from the console code page; with `CREATE_NO_WINDOW` that is the system OEM code page (and the `chcp 65001` in the `.bat`/`.ps1` launchers does not apply from Task Scheduler or a double-clicked exe). Every non-ASCII byte became U+FFFD: a Wi-Fi adapter named "WLAN 无线" came back as "WLAN ", the egress lookup returned that mojibake alias, `netsh` failed to match it, and the bypass **silently never installed** - while the scoped delete reported a same-prefix route "left untouched" because it was comparing a mangled name. Every script now sets `[Console]::OutputEncoding = UTF8`. The module already handled the input direction with a UTF-8 BOM; the output direction was the broken half.
- **A live `[N]` DNS choice could be discarded and never retried.** `poll_control_file` committed the file's mtime **before** parsing it; the dashboard writer truncates before dumping, so the 1 s monitor tick could read a partial file, mark the change as seen, and never retry it. The mtime is now committed only after a successful parse, control-file DNS values are validated as real addresses of the right family (a malformed one reached `netsh ... address=<garbage>` and the catch-all NRPT rule's `GenericDNSServers`, pinning all name resolution to a resolver that does not exist), and a rejected value is reported instead of silently applied.
- **`--proxy2-port` with no listening SOCKS5 left the geo installer raising `NameError`.** The `p2_v4`/`p2_v6` collections were only bound inside the "wintun2 pipe came up" branch, but the geo thread tests `args.proxy2_port is not None`, not whether the pipe came up - so no country bypass was installed at all, with an error naming a variable instead of the real cause. They are now bound before the branch.
- **The update checker followed redirects to any host.** `urlopen`'s default redirect handler accepts a 30x to any host and scheme, and the release metadata was verified for its own URL only. A redirect was followed transparently and whatever the redirector served was treated as the release asset - with `checksums.txt` fetched over the same redirectable transport, so it validated the redirector's copy too. Requests now carry a pinned TLS 1.2+ floor with hostname verification and a host allow-list enforced on **every** hop (plus a re-check of the final URL), and an `HTTPError` is no longer swallowed as "offline" - 403/404/500 were indistinguishable from no network, so the updater silently never updated, with no log line at all.
- **`Profile.from_snapshot` accepted anything and dropped `secret_ref`.** An explicit `hasattr` loop let a hand-edited or shared snapshot overwrite `name` (the key the profile is stored under) and assign a string to any list field, which then iterated per character. The snapshot round-trip also **omitted `secret_ref`**, so the first save/load cycle silently detached a profile from its protected (DPAPI) credential and orphaned the secret.
- **Reserved keys were only half-reserved.** `set_default_profile` checked `_default` but not `_ui`, so the UI-preferences blob could be marked as the auto-load profile; `get_default_profile` then returned `_ui` and the startup path fed it to `apply_to_args`, which sets `ns.server = []` and clears every bypass list - TunTop coming up with no server and no error. `delete_profile("_ui")` also succeeded, wiping the user's preferences through the profile path. All mutators now share one `RESERVED_KEYS` check.
- **A small but real geometry bug in the health panel:** `name[:name_budget - 3]` produced a name *longer* than the budget it was meant to fit (a negative slice takes from the *end*) for a 1-2 column panel.

### Security
- **`geoip.dat`'s decode cache was `pickle.load` on a user-writable file.** The cache is a deterministic SHA-256 of the source path/mtime/size in a directory the user can write, and it is read by the **elevated** helper - so any unprivileged process able to write next to the install got arbitrary code execution on the next `[S]`. The cache is now JSON (a list of CIDR strings), with the shape validated on read, so it stays useful with no deserialization risk.
- **`procguard` killed other applications' proxies.** Ownership rule 3 matched the *bare file name* `tun2socks-windows-amd64-v3.exe` - which is the **upstream xjasonlyu/tun2socks v2.7.0 release asset name** (see `Run_Helper.ps1` and `release.yml`, which download exactly that file). Any user who installed tun2socks from its own release, or any tool vendoring the same build, had a process whose basename matched exactly, so every TunTop teardown, startup recovery and watchdog sweep ran `taskkill /F /T` against a foreign proxy. The name is now only honoured together with a TunTop-controlled location (next to `TunTop.exe`, the app root, the CWD, or a PyInstaller `_MEI*` extraction dir) - which still covers the crash-recovery case rule 3 was written for, since a frozen run's child always runs from a per-run extraction dir. A generic `tun2socks.exe` from another tool matches no rule at all and is never touched.
- **The DNS-guard uninstall now fails closed.** Every cmdlet in the sweep runs `-ErrorAction SilentlyContinue`, so a non-elevated process (or an ACL-denied `DnsPolicyConfig` key) produced an empty enumeration and a cheerful `DNS_GUARD_REMOVED` while the `TunTop-*` keys were still there - pinning all name resolution to a tunnel that was being torn down. The script now proves it can **read** the store first, and an ambiguous result is a failure that keeps the install record so the next launch retries.
- **A multi-resolver NRPT pin was reported as a single resolver.** The detect line used `;` as its field separator, which is also the separator inside a `GenericDNSServers` list - so `servers=8.8.8.8;2606:4700:4700::1111` was split into a first field plus an orphan part that matched no branch and was dropped. Every diagnostic showed only the v4 half of the pin. The field separator is now `,`, which a resolver list can never contain.
- **A failed proxy teardown was reported as a clean stop.** `request_stop` had the transition in a `finally`, so the UI reported a clean `STOPPED` while the Wintun adapter, its routes and the NRPT rule were all still installed. `FAILED` is the honest state and it was already in the transition graph on an unreachable path.

### UI / UX and the messages shown to the user
- **Two DNS health rows were permanently red.** The probe targets the resolvers TunTop *configured*, but `launch` forwards only what the user chose - and the rows fell back to the display default, so with `--dns4 1.1.1.1` alone (no v6 resolver) `Find-NetRoute` selected the physical NIC for `2606:4700:4700::1111`, a resolver the tunnel never uses. One of the two was a CRITICAL row, so the top badge read **UNHEALTHY forever** with nothing the user could fix. Every DNS row is now gated on what is really configured.
- **Inconclusive checks were painted as failures.** `run_checks` did `bool(ok)`, collapsing the `None` that several checks already returned for "could not be determined" into a failure: the fail counter climbed and the badge went red for probes that had proven nothing. The tri-state is now preserved end to end - a grey `?` row, its own `n/a` count in the panel title and the metrics card, and no red frame.
- **The health panel had no scroll indicator.** The event log carries one; the checks panel did not, so a user scrolled back through a long list had no indication that newer rows existed below - and failures are appended at the *end* as each check completes, so the row that mattered was routinely off-screen with nothing on screen to say so.
- **Crash logs and `[D]` diagnostics were written into a directory deleted on exit.** Both used a `__file__`-relative path, which in a onefile build is the per-run `_MEIPASS` extraction dir. The crash handler printed *"saved to: ...\_MEIxxxxxx\TunTop_crash.log"* and `[D]` logged a `diagnostics_*.txt` path for files that no longer existed a moment later - **every** crash report and diagnostics export from the released exe was silently lost. They now use the same persistent-directory rule as the control file, the profile store and the geoip default.
- **A geo-bypass removal reported attempts as successes.** It counted matching routes in the live table and printed "N routes deleted"; `netsh` reports per-line failures in its output and still exits 0, so a denied or in-use route stayed installed while the UI announced the country's bypass as gone. Removal now re-reads the table and reports **verified** deletions, and on a shortfall says how many are still in the routing table and that country traffic may still follow the old bypass.
- **"Tunnel stopped" was printed after launching the new tunnel.** `[T]` clears the queued-start flag and then tested it, so the check was always false and the teardown line was logged a moment *after* the replacement helper started - announcing a teardown of the tunnel that was starting.
- **A rejected `[V]` left the settings disagreeing with the running helper.** Enabling VLESS-over-VPN sets `no_vpn_bypass = False` first, and the refusal (no connected Windows VPN) turned VLESS back off **without** restoring it - so the dashboard believed the VPN-endpoint bypass was on while the running helper was never told and kept it off, for the rest of the session.
- **A second DNS re-apply press was silently ignored; it now says so** - two workers racing each other both cleared the ledger and both bulk-deleted the same prefixes, so each orphaned the other's routes (country traffic blackholed, and on quit nothing was left to sweep, so thousands of geo routes survived).
- **A stale geoip CIDR set was cached across a country change.** Only the `[W]` download path invalidated it, so `[F] -> 4` "remove" deleted the *previous* country's routes while announcing the new one, the `[Q]` sweep swept the wrong prefixes, and the new country's routes were left installed.
- **A stale helper reader could drive the state machine for a newer tunnel.** `[S]` restarts while a stop's reader may still be draining the old pipe; that reader's tail then saw `[+] TUNNEL ACTIVE` and transitioned the *new* tunnel to RUNNING before a single route of it was installed, and its exit path forced `STOPPED` a moment later. Readers now carry a generation token and a superseded one drives nothing.
- **A proxy2 status line crashed the helper's own logging on a non-UTF-8 console.** The `proxy2` lines contained an em dash, and the helper prints to a pipe with the system code page - the `UnicodeEncodeError` landed in the middle of the teardown path. Those strings are ASCII now, and `--geoip-code` without `--geoip` (or vice versa) prints an explicit hint instead of being silently dropped.
- Smaller ones: the log panel's lines are snapshotted under a lock (worker threads append while `draw()` iterates); `events.recent(0)` returns nothing rather than the whole buffer; `TrafficStats` is lock-guarded; a route-table line containing a stray `|` no longer aborts the entire dump; `RouteResult` is falsy on failure (it had `__iter__` and no `__bool__`, so `if result:` was **always** true for one of the two classes in this codebase); a partial `RouteLedger` slice assignment is rejected instead of silently wiping the registry; and the health-panel name budget no longer produces an over-long name.

### Tests
- **876 passed, 6 skipped** (was 857/6). +19 cases pin the fixes specifically: the DoH re-add using the resolver, the `SystemExit` no longer escaping self-heal/startup-recovery/teardown, `marker_is_live` (live / dead / cannot-tell) and `scan` leaving a live session untouched, the watchdog's same-host redirect policy, the geo CIDR prefix rejection, `procguard` refusing an upstream-named binary in a `Downloads` folder while still accepting one next to the app, the DNS-guard `,` field separator and the fail-closed uninstall, `sweeps` CIDR-canonical matching and interface-scoped `host_route_stmts`, the updater's TLS floor / host allow-list / `HTTPError`-not-offline, `health` name-budget geometry, and the `human`/rollup of the log snapshot.

## [1.0.40] - 2026-09-27

### Fixed (the REAL DNS leak: Windows kept asking the physical adapter's resolver)
- **ROOT CAUSE: setting resolvers on `wintun` - even with a lower `InterfaceMetric` - never stopped Windows from querying the physical adapter's resolver in parallel.** v1.0.39 made Wintun the *preferred* DNS source, which is an ordering, not an exclusion. Windows enables **Smart Multi-Homed Name Resolution (SMHNR)** by default: the DNS client sends every query out over **all** connected interfaces that publish resolvers and takes the first answer. The metric only orders the server list. A DHCP-assigned router resolver (`192.168.1.1`) is **on-link**, so the tunnel's split-defaults (`0.0.0.0/1`, `::/1`) never capture it, and the router/ISP answer wins - while TunTop's own probes stayed green, because every one of them only tests the resolvers TunTop *knows about*. That is exactly the reported symptom: the in-app test says "no leak", dnsleaktest.com shows the ISP.
- **New: a catch-all NRPT rule pins the whole machine's name resolution to the tunnel resolvers while the tunnel is up** (`tuntop/network/dns_guard.py`, on by default). A Name Resolution Policy Table rule that claims the root namespace (`.`) with an override server list makes the Windows DNS client use **only** those servers - regardless of whether SMHNR is on or off. The rule lives in the local policy store under `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\TunTop-Match` (`Version`, `Name`, `GenericDNSServers`, `ConfigOptions=0x8`), installed after the TUN routes go live (not from `configure_tun()`, which runs before they exist and while this startup's own endpoint/proxy2 resolutions still need the physical resolver). The resolver cache is flushed so pre-guard answers cannot mask the change.
- **A `.local` exemption ships with the guard** (RFC 6762 multicast DNS must not be sent to a unicast resolver - printers/NAS would start answering NXDOMAIN). It is a second `TunTop-ExemptLocal` rule claiming `.local` with a **present-but-empty** `GenericDNSServers` and `ConfigOptions` still `0x8`; a *missing* value makes Windows discard the rule, which would leave the catch-all in charge of `.local`. Extra domains: `--dns-guard-exempt DOMAIN` (repeatable, in profiles).
- **Removal has four independent owners**, because a rule that outlives the tunnel would keep hijacking name resolution machine-wide: the helper's `cleanup()` (early, before the long route sweeps the OS can interrupt), the next launch's `startup_recovery` (new `dns_guard_present` / `remove_dns_guard` probes, reported even when the routing state looks clean, and removed *first*), the detached cleanup watchdog, and the dashboard's stop checklist + Ctrl-handler cleanup. A `.tuntop_dns_guard.json` install record next to the exe makes even a crash *mid-install* recoverable.
- **The guard is re-asserted where it can silently go stale**: a live `[N]` DNS change re-pins it to the new resolver (leaving the old pin would keep sending every query to the previous server), `self_heal_tunnel()` re-installs it, and the monitor loop cheaply re-checks it on a healthy cycle - another VPN client's NRPT rule, a Group Policy refresh or a third-party cleanup can wipe it mid-session, and without that check the leak returns while the tunnel still looks healthy.
- **The in-app tests can now CATCH this class of leak.** New health row **"DNS leak protection (catch-all NRPT rule)"**: PASS only when the rule exists *and* `Get-DnsClientNrptPolicy -Effective` carries the root namespace (a registry key alone proves nothing - Windows drops a malformed rule silently); the detail names the non-tunnel adapters still publishing resolvers, and only adapters that are currently **Up**. `run_dns_leak_probe` gained a third sub-check: if any non-tunnel adapter publishes resolvers *and* a catch-all rule is confirmed **not** to be in force, the verdict is `dns-leak` naming them; when the guard state cannot be read the verdict is `unknown` instead, so a failed probe is never reported as a leak (see the review fixes below).
- **The "DNS configuration" row no longer presents a broken probe as a leak.** `_dns_enforcement_check` returns `None` for "no route / probe failed"; the old code folded that into "not pinned". Unknown is now reported as *could not be verified* (and named), separately from a real misrouting.
- **Bug fix found in the same pass: a v6-only DNS choice never got DoH.** `configure_tun`'s DoH branch was gated on `dns4 and template`, so `--dns6 <ip>` alone (the supported "IPv6 DNS only" selection) registered nothing and silently stayed on raw UDP/53 - precisely the path that dies inside a TUN whose SOCKS proxy has no UDP relay. Every chosen family that has a known template is now registered, followed by ONE `Set-DnsClientServerAddress` (it REPLACES the whole list), and the log line names what was actually set.

### Fixed (bugs found reviewing 1.0.40's own guard, before release)
- **A failed rule removal was reported as a clean "removed" - and deleted the crash-safety record.** `uninstall()` destructured the PowerShell runner's result and **discarded its success flag**, so a run that never completed (PowerShell missing, timed out, non-zero exit) produced neither output marker, fell into the "nothing to remove" branch, called `clear_state()` and returned success. The net effect was the worst case the module is written to prevent: a catch-all NRPT rule left installed (every process on the machine resolving names through a dead tunnel) **and** the `.tuntop_dns_guard.json` record the next launch's recovery would have found it through. `uninstall()` now honours the runner's flag - a failed run is a failure, and the record survives. The removal script also **re-enumerates** after its (deliberately `SilentlyContinue`) sweep and reports the survivors as `DNS_GUARD_UNINSTALL_FAIL:still present: ...`, because a denied or in-use `Remove-Item` used to print `DNS_GUARD_REMOVED` regardless. Every teardown owner was affected and none could see it: the helper's `cleanup()`, the dashboard's stop/quit sweeps, and startup recovery's `_do_dns_guard` - which logged *"NRPT rule removed (name resolution is unpinned again)"* while the rule was still there.
- **A broken guard probe manufactured a confirmed `dns-leak`.** `run_dns_leak_probe`'s parallel-resolver sub-check collapsed three states into one boolean, so a `guard_in_force()` predicate that **raised** was indistinguishable from one that ran and said "not in force" - and the sub-check returns early, ahead of the real leak evidence. Any PowerShell hiccup on a healthy machine therefore produced a DNS-leak verdict against a tunnel that was doing nothing wrong, directly contradicting the function's own promise that a failed probe "never invents a leak verdict". The check is now tri-state: a probe that **ran and reported no pin** is a leak, a probe that **raised (or was not injected)** returns **`unknown`** naming the exposed adapters and the reason. `detail` carries `guard_in_force: True|False|None` so the distinction survives to the UI.
- **Disconnected adapters were counted as leak sources.** `foreign_resolvers_script()` listed everything `Get-DnsClientServerAddress` returns, which includes **disconnected** adapters - an unplugged Ethernet port keeps a stale static resolver indefinitely - while Windows' SMHNR only ever fans a query out over adapters that are **Up**. One dead NIC was enough to produce a false `DNS LEAK` on a machine that was not leaking, and the script contradicted the module's own docstring. The adapter list is now built from `Get-NetAdapter … Status -eq 'Up'` and the resolver query is gated on it; a `Get-NetAdapter` failure yields an empty list, so the probe degrades toward *no* finding rather than an invented one. Relatedly, the `127.0.0.1` loopback filter moved from per-adapter to **per-address**, so an adapter publishing loopback *and* a real resolver is no longer silently hidden.
- **A deliberate `--no-dns-guard` was reported as a health-check FAILURE.** `_dns_guard_check()` never received the setting, so a user who had explicitly opted out got the same red row and the same *"--no-dns-guard is active, or the install failed"* message as a genuine install failure - unfixable, and impossible to tell apart from a fault. It now takes `enabled` (threaded from `ns.dns_guard` in `build_checks`) and reports **"DISABLED by choice"** as a pass, while still naming the adapters that are exposed. This is the same mode-awareness the `[V]`/`[Y]` route checks already had. The enabled path still fails on a real missing rule, and its reason is now precise (*"the install failed, or the helper was started with --no-dns-guard"*).
- **A leftover `.local` exemption could read as a fully working guard.** `parse_detect()` derived `ok` from a count of **all** `TunTop-*` keys, and the exemption key claims no namespace at all. With only `TunTop-ExemptLocal` surviving (catch-all deleted by a Group Policy refresh or another tool) and any *foreign* managed catch-all making the root namespace effective, `ok` came back `True` with an empty `servers` - so the helper's monitor loop logged *"DNS leak guard: Windows DNS pinned to the tunnel resolvers"* and the health row went green on a dead pin. `detect_script()` now also emits a `match` count (the catch-all key alone) and `ok` requires that plus the effective policy. A line without the field still parses, falling back to the old behaviour.
- **`configure_tun` silently downgraded a DNS family when only one DoH registration succeeded.** The per-family refactor above replaced an all-or-nothing gate, so a v4 registration that failed next to a v6 one that succeeded still installed **both** resolvers on the adapter while printing only the v6 success line - the failed family was quietly left on raw UDP/53, i.e. exactly the failure mode the surrounding comment describes as dying inside a TUN with no UDP relay. Failed registrations are now collected and named explicitly.
- **An install whose record could not be written claimed success silently.** `install()` ignored `save_state()` returning `False` (read-only install directory), so the caller was told a clean pin with no crash-safety file on disk. Still a success - the rule *is* live - but the message now says no record was written.
- **`_wintun_up()` hardcoded the adapter name.** It decided tunnel-up vs *STALE rule*, i.e. half of the guard verdict, from a literal `'wintun'` while every sibling probe uses the shared `TUNNEL_ALIASES`/`TUN` constants. It now interpolates `TUN` through `ps_quote` (which also matters: `ps_quote` only *escapes*, it does not add the surrounding quotes, so a name containing a space or apostrophe would have produced a broken script).
- **`_StartupLogSink` could drop a line produced across `attach()`.** The staging thread writes from another thread while `main()` binds the dashboard. Unlocked, a producer could observe `_app is None`, then have `attach()` drain the buffer, then append to the already-drained list - and that line reached neither the console panel nor the replay. The sink is now lock-guarded (verified with real two-thread races), and a raising log panel no longer takes down the staging thread.
- `Profile.dns_guard_exempt` now takes its default from the `DEFAULT_DNS_GUARD_EXEMPT` constant it imports (copied, never shared by reference) instead of leaving that import unused.

### Changed (the update check moved to the initial startup block)
- **The release check now runs where the binary-integrity lines are printed.** It used to start as a silent background thread from `BTopTui.loop()`, so a new release was only visible if you went looking for it in the log panel. `main()` now calls `_startup_update_check(args)` immediately after the integrity lines, so the verdict prints inline next to them:
  `[*] Checking for a newer TunTop release...` then either
  `[i] Update check: already on the newest release (v1.0.40).` or
  `[+] Update 1.0.41 available - downloading the verified exe in the background.`
  A skip always says why (source run / `BTOP_NO_UPDATE` / `--no-update-check`).
- **Only the download continues in the background.** The inline check is bounded at 6 s (new optional `timeout=` on `updates.check_latest` / `_fetch` / `download_release` / `prepare_update`; the 20 s default still applies to the download), so a stalled or rate-limited feed can no longer look like a hung app. The staging result is reported through `_StartupLogSink`, which prints to the console and replays into the log panel once the dashboard exists - nothing is console-only, nothing is doubled. The running exe is never touched or launched; the verified `TunTop-<version>.exe` is staged next to it. `BTopTui._start_update_check`/`_update_check_worker` are gone (the check runs exactly once, at the beginning).

### Added
- `--dns-guard` (default) / `--no-dns-guard` and `--dns-guard-exempt DOMAIN` on both the dashboard and the helper, plumbed through profiles exactly like `--log-adapter-activity` (`DEFAULT_DNS_GUARD` / `DEFAULT_DNS_GUARD_EXEMPT`, `Profile.dns_guard` / `dns_guard_exempt`). `--no-dns-guard` restores the previous behaviour and actively removes any leftover rule; the `[C]` row reads **"DISABLED by choice"** rather than a red failure, so opting out is never mistaken for a broken guard.
- **`[D]` diagnostics now carry a "DNS GUARD (NRPT)" section**: the setting, the exemptions, whether `wintun` is up, the install record, how many rules exist and whether Windows' *effective* NRPT policy carries them, and which non-tunnel adapters still publish resolvers. A "my DNS still leaks" report is a property of the OS resolver's policy and was unanswerable from the route dump alone. A failed probe says so rather than reading as a clean system. The `dns_problem.md` issue template now asks for exactly this.

### Tests
- 857 passed, 6 skipped. New `tests/unit/test_dns_guard.py` (77 cases: rule identity, script text, exemption encoding, quote escaping, state round-trip, install/uninstall/ensure, the dashboard health row and its wiring, the `[D]` diagnostics section, helper integration), plus DNS-guard recovery/watchdog cases, the parallel-resolver leak sub-check, the unknown-vs-fail split, profile round-trips, and a rewritten update-check wiring suite. +24 cases cover the review fixes specifically: a failed removal runner must not read as success and must keep the record (including through `ensure_removed`, the wrapper every teardown owner calls), the removal script's post-sweep verification, the `match` key count and its back-compat parse, the `Up` filter and per-address loopback drop in the adapter script, the unwritable-record warning, the opt-out row (and that `build_checks` threads `ns.dns_guard` in, or the opt-out branch is unreachable in the real app), `_wintun_up`'s shared-and-quoted `TUN`, partial DoH registration naming the failed family, and the log-sink race driven with real threads. The offline suite never reaches the real registry: the control-file tests stub the guard install (an *elevated* test run would otherwise pin the machine's DNS to a tunnel that does not exist) and every dashboard probe goes through the dashboard's own `_ps` edge.

## [1.0.39] - 2026-09-26

### Fixed (Wintun as the preferred DNS source)
- **Wintun is now the OS-selected DNS source, not just a DNS-configured adapter.**
  Previously TunTop set DNS resolvers only on the `wintun` adapter and relied on
  the split-defaults (`0.0.0.0/1`, `::/1`) to pull the public resolvers through
  the tunnel - but nothing lowered Wintun's `InterfaceMetric`, so Windows's
  DNS-client server selection could still prefer a DHCP-assigned physical NIC
  (e.g. its on-link `192.168.1.1`) over the tunnel. `_set_wintun_interface_metric`
  is now generalized to lower **both** IPv4 and IPv6 `InterfaceMetric` on Wintun
  (to 2, below the VPN's ~25 and the physical adapter's typical ~4270) and is
  applied from `configure_tun()` - so it is set on every bring-up, re-applied by
  the DoH escalation in `wait_for_tunnel_stable`, and re-applied by
  `self_heal_tunnel()`. The originals are saved per-family and restored on
  cleanup. `tuntop/network/dns.py` is untouched: it remains a pure resolution
  library and never touches interfaces.
- **The "DNS configuration" health row now proves Wintun is selected, not just
  present.** It used to check `ServerAddresses.Count > 0` (green for any adapter
  with any DNS) - now it asserts `Find-NetRoute -RemoteIPAddress <resolver>`
  selects the `wintun` alias for every configured resolver, and reports the chosen
  interface so an accidental physical-NIC pick is visible. `[L]` remains the
  backstop proof that no DNS escapes the tunnel.

### Added (--log-adapter-activity)
- **Adapter-traffic activity logging.** The dashboard can now optionally log
  UDP/QUIC connections, ICMP counter deltas and Wintun throughput deltas to the
  structured event log (component ``ADAPTER``) while the tunnel is up. Enabled
  with ``--log-adapter-activity`` (``--no-log-adapter-activity`` to disable /
  the default). The flag is saved in and restored from profiles, just like
  ``--vless-over-vpn`` and ``--no-vpn-bypass``.
- UDP connections are polled via ``Get-NetUDPConnection`` and logged as color
  coded JSON records ``{"proto","src","sport","dst","dport","proc","pid"}``.
  UDP flows to remote port 443 are heuristically tagged ``proto=QUIC`` (true QUIC
  detection requires ETW and is out of scope; the heuristic is documented).
- Per-protocol dedup (``_seen_udp_conns``, ``_seen_icmp_conns``) keeps adapter
  lines from suppressing TCP entries and vice-versa. Per-destination rate
  limiting reuses the existing ``_net_rate`` map (one line per remote
  ``ip:port`` per 60 s; suppressed repeats are carried as a ``suppressed``
  count on the next UDP record).
- ICMP activity is sampled via ``netsh interface ipv4/ipv6 show icmpstats``
  and logged as ``[icmp] ipv4: in=… out=… | ipv6: in=… out=…`` counter deltas.
- Wintun throughput is sampled via ``Get-NetAdapterStatistics`` and logged as
  ``[adapter] wintun: rx=…B tx=…B`` deltas.
- All adapter polling shares the existing 5 s ``_poll_connections`` throttle so
  the extra PowerShell calls do not multiply on the 50 ms telemetry tick.
- Tests: 19 new coverage cases for UDP/QUIC parsing, ICMP delta tracking,
  throughput deltas, dedup, rate limiting, and the off-state.

### Tests
- 726 passed, 6 skipped.

## [1.0.38] - 2026-09-24

### Fixed (IPv6 on-link default routes filtered out - country and host bypass skipped on IPv6-only-default networks)
- **Gateway changes no longer create a Wintun traffic gap or a false throughput spike.** v1.0.37 re-pointed thousands of geo routes by deleting the old gateway routes before installing replacements. During that window, matching traffic could fall through the TUN and inflate the Wintun download graph. Replacements are now installed first, old routes are removed only after the full replacement batch is accepted, and a gateway transition resets the telemetry baseline. Implausible positive Wintun counter jumps are discarded as counter discontinuities.
- **ROOT CAUSE (proven on physical Wi-Fi): the IPv6 default-route lookup in helper.py and routing.py carried a `$_ -ne '::'` Where-Object filter copied from the IPv4 `0.0.0.0` pattern. On IPv6, an on-link route (NextHop = `::`) is the NORMAL form of a default route on a physical adapter — the next-hop is resolved via neighbor discovery, so there is no gateway address. Filtering these out made `get_ipv6_default()` return None whenever a system only had on-link IPv6 defaults, which silently skipped all IPv6 geo/host bypass installs.** The filter was removed from all four IPv6 default lookups (`get_ipv6_default`, `get_vpn_ipv6_default`, `_get_ipv6_default`, `_get_vpn_ipv6_default`) and the NextHop is normalized from `::` to `""` on all return paths. `add_v6()`'s same-gateway comparison was also fixed to normalize `::` vs `""` so an existing on-link route is recognized as already-correct instead of being treated as stale (redundant delete+re-add). The geo-bypass netsh format was adjusted to omit the gateway token entirely for on-link routes (was emitting a double-space that netsh rejected).
- **Geo startup output no longer implies that parsed IPv6 ranges were installed.** On an IPv4-only connection (Wi-Fi has IPv4 but no global IPv6 address or physical IPv6 default), the line now says `IPv6 skipped (no usable IPv6 egress ...)` and the install total contains only schedulable IPv4 routes. Previously it announced all parsed ranges under “Installing,” which made users believe missing routes were silently lost.
- **VLESS route health checks now test resolved endpoint IPs, not configured URLs/hostnames.** `Find-NetRoute -RemoteIPAddress` received values such as `dey.lnmarketplace.net`, which Windows cannot route, causing false “no route found” failures for both the server-route and proxy-loop rows. Checks now reuse startup/edit-server DNS results, validate every resolved A/AAAA address, keep the hostname in the row label, and report “not resolved yet” without performing an invalid hostname route lookup.

### Tests
- 705 passed, 6 skipped. Added coverage for safe gateway re-point ordering, partial-batch failure handling, telemetry baseline resets, counter-discontinuity filtering, on-link IPv6 defaults, and the related route/install behavior.


## [1.0.37] - 2026-09-24

### Fixed (VPN route persistence, optional PROXY2, and faster route-table handling)
- **VPN routes survive Wintun shadow installation.** Geo-splitting through a connected Windows VPN now installs lower-metric Wintun shadow routes without deleting the VPN client's persistent route. The original route remains available after the tunnel is stopped, and the dashboard route-snapshot diff correctly treats an intact persistent route as a no-op during restore.
- **An unavailable second SOCKS5 inbound no longer takes down the primary tunnel.** `--proxy2-port` is now optional: when that port is not listening, the helper skips only the second Wintun pipe and continues with the primary tunnel. The dashboard reports `PROXY2 down (proxy not running)` instead of showing a misleading green status.
- **Route-table dumps no longer use slow `ConvertTo-Json` serialization.** Full route listings and snapshot dumps now stream compact pipe-delimited PowerShell output, then parse it in Python. IPv4/IPv6 next hops and persistent-store fields remain preserved.
- **Shutdown avoids redundant full-table scans and teardown attempts.** After the first verification finds a clean route table, TunTop does not immediately dump and sweep thousands of routes again. It repeats those operations only while route or process cleanup remains.
- **Second-pipe startup state is consistent with cleanup.** When `--proxy2-port` was skipped at startup, the helper does not attempt a redundant second restart; normal endpoint bypass installation still follows the primary path.

### Tests
- 685 passed, 6 skipped. Added coverage for non-destructive VPN route shadowing, proxy2 optional startup/restart state, fast route parsing, clean shutdown verification, and persistent VPN route survival.


## [1.0.36] - 2026-09-23

### Fixed (the second black console window is REALLY gone - the cleanup watchdog owned it)
- **ROOT CAUSE (proven with an elevated window monitor, `monitor_windows2.py`):
  the second 'TunTop' console window belonged to the `--watchdog-child`
  process.** Timeline from the instrumented run: 0.3s dashboard console
  (pid 7568, the only one that should exist) -> 6.1s a SECOND
  `ConsoleWindowClass` window titled `...\dist\TunTop.exe` owned by
  pid 31100, whose command line is
  `TunTop.exe --watchdog-child --pid 55932 ...` - the detached cleanup
  watchdog, spawned at startup with
  `DETACHED_PROCESS | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP`.
  The assumption was that those flags forbid any console. They don't:
  DETACHED_PROCESS detaches the child from the PARENT's console but does not
  prevent the child from ALLOCATING one - and PyInstaller 6's onefile
  bootloader is TWO processes (a parent stub + the python child), so the
  flag reached python while the stub kept/created a visible console. The
  dashboard's integrity lines were the last output BEFORE the window
  appeared, and the watchdog spawn sits right after them - which is why the
  window always materialized "after the integrity check" and showed nothing
  (its stdout/stderr are DEVNULL). The in-child
  `GetConsoleWindow()/ShowWindow(SW_HIDE)` mitigation raced and lost.
- **Fix:** the watchdog is now spawned with `CREATE_NO_WINDOW |
  CREATE_NEW_PROCESS_GROUP` - the same flag pair as the (already clean)
  helper child, and the empirically windowless combination for a frozen
  child. Detachment is not needed: the watchdog is a console-app child of a
  console app, so it inherits no visible window with CREATE_NO_WINDOW, and
  nothing in it reads or writes a console (DEVNULL stdio, log-file
  diagnostics). The child-dispatch SW_HIDE stays as defense-in-depth.
  Verified by re-running the window monitor against the rebuilt exe: the
  only new `ConsoleWindowClass` window for the whole 40s session (including
  [S]/[T] presses) is the dashboard's own.

### Fixed (procguard normalization was platform-fake; CI was blind to non-Windows)

- **`procguard._norm()` was platform-fake.** It used
  `os.path.normcase(os.path.abspath(path))` - on non-Windows `normcase` is a
  no-op, so case and `\` separators were left intact. A Windows path like
  `C:\Tools\...\TUN2SOCKS-WINDOWS-AMD64-V3.EXE` therefore never matched the
  lower-cased configured path, and the vendored-name compare missed our own
  binary - so `test_exact_configured_path_is_owned` and
  `test_vendored_name_is_owned_regardless_of_dir` FAILED on Linux/macOS while
  passing on Windows. `_norm` now lowercases and treats BOTH `/` and `\` as
  separators on every OS and anchors relative paths to `os.getcwd()`, so the
  same input yields the same normalized string (and verdict) on Linux, macOS
  and Windows. The vendored-name compare routes `TUN2SOCKS_BINARY` through the
  same `_norm`. Windows runtime verdicts are unchanged (both sides of every
  comparison in `select_own` now flow through `_norm`).
- **CI blind-spot closed.** CI ran only on `windows-latest`, which is exactly
  why the platform-dependent `_norm` bug above was invisible. A new
  `tests-unix` job on `ubuntu-latest` runs `tests.unit.test_procguard` plus the
  egress-script drift suite (`tests.routing.test_egress_scripts_drift`,
  `tests.unit.test_egress_lookup_shared`) - the parts that are pure-Python /
  platform-independent - and compiles the touched modules. The behavioural PS
  branch (IfType/Tunnel media) only runs on real Windows and is covered there.
- **Behavioural secondary TUN classifier (supplements `TUN_DRIVER_RE`).** An
  adapter is now TUN if its description/alias matches `TUN_DRIVER_RE` OR its
  Windows interface characteristics report a software tunnel
  (`InterfaceType -eq 131` / `PhysicalMediaType -eq 'Tunnel'`). `TUN_DRIVER_RE`
  is RETAINED (it is the only reliable Wintun catch, whose IfType is not
  reliably 131) and the behavioural branch is OR'd on top - so an unknown
  foreign TUN (e.g. a new sing-box/clash kernel) whose description matches no
  keyword is still excluded from egress. Physical NICs (802.3/802.11, IfType
  6/71) and Windows VPN miniports (Shirazu-VPN, reza_U) report neither 131 nor
  'Tunnel' media and are never reclassified; the over-VPN deterministic pin
  (`get_egress_for(...) or (vless_iface, vless_gateway)`) makes the gate
  fail-safe there too. New coverage in
  `tests/routing/test_egress_scripts_drift.py`
  (`TestBehavioralTunClassifier` + `test_tun_preamble_includes_behavioral_filter`).

## [1.0.35] - 2026-09-22

### Fixed (field reports from the 1.0.34 test build)

- **"press [T] to start" typo** - the input-restored hint named [T], which is
  STOP; [S] starts the tunnel. The hint now reads "press [S] to start the
  tunnel again."
- **Empty phantom console window on start.** The helper was spawned with
  `CREATE_NEW_CONSOLE | CREATE_NO_WINDOW` - per MSDN, CREATE_NO_WINDOW is
  IGNORED when combined with CREATE_NEW_CONSOLE, so the helper got its own
  fresh console that just sat there empty (its stdout is piped, nothing is
  ever printed in it). The spawn now passes `CREATE_NO_WINDOW` alone - the
  same pattern every other TunTop child spawn already uses.
- **Endless false "LEAK DETECTED" with a geo bypass active** (the
  "LEAK: direct egress 107.150.19.3 != tunnel exit 107.175.209.186 ...
  it happens a lot" report). Root cause: the leak probe's echo race kept
  only the FIRST echo answer. With geoip:ir routed through the Windows VPN,
  an echo HOST whose own address falls inside an Iranian CIDR exits via the
  GEO route - a different egress than the tunnel exit - so whichever host
  answered first decided the whole verdict. The probe now collects EVERY
  direct answer; the verdict is a leak only when NO answer rode the tunnel
  (or its network). A tunnel exit that answered directly too is reported as
  same-exit/OK with the divergent answer(s) named as bypass-routed hosts.
  A genuine single-answer leak verdict is unchanged.
- **The EVENT LOG never resumed following after a scroll-up.** Scrolling up
  froze the log into a snapshot, but scrolling back down to the bottom did
  NOT resume it - the panel kept rendering the frozen history forever and
  new lines never appeared until [Space]/[End] was pressed. Bottom is now
  live again: reaching the newest entry releases the snapshot automatically.
- **geo bypass via the Windows VPN installed onto Wi-Fi instead** (the
  "[*] geoip:ir routed via connected Windows VPN (Shirazu-VPN)" followed by
  "Installing geoip:ir bypass ... via Wi-Fi" report). Root cause: in the
  live [R] re-apply worker, the winvpn/proxy2 branches resolved the egress,
  but a SECOND if/elif/else chain meant only for `target == "direct"` had an
  unconditional `else` that caught "winvpn" too and OVERWROTE the egress
  with the physical NIC. The fallback chain is now direct-only; winvpn and
  proxy2 keep the egress their branches resolved.

### Added

- Regression tests for all five fixes (`tests/unit/test_ux_fixes.py`) and
  the leak probe's multi-answer semantics.
- **DNS request/answer logging.** `tuntop/network/dns.py` now reports every
  resolution through the dashboard's structured event log: which hostname was
  queried, which path answered (system, `udp:<server>`, `doh:<endpoint>`,
  cache, or literal), and the IPs returned - so a silent fallback to UDP/53 or
  DoH is visible instead of only the final result. A `set_dns_log()` callback
  (exception-guarded, never raises) keeps `dns.py` a pure-stdlib leaf; the
  dashboard wires it to `event_log.log(_LOG_INFO, "DNS", msg)` once at startup,
  so all `_resolve_detail` callers are covered with no per-caller changes. The
  standalone helper's `resolve_all()` stdout logging is unchanged. Tests in
  `tests/unit/test_dns_logging.py`.


## [1.0.34] - 2026-09-23

### Fixed (VLESS server /32s pinned to Wi-Fi while [V] "VLESS via VPN" mode was active)

- **ROOT CAUSE: over-VPN mode trusted a Find-NetRoute egress lookup that
  cannot see VPN-client adapters.** In `--vless-over-vpn` mode the helper
  resolved every VLESS endpoint's egress with
  `get_egress_for(ip, exclude_vpn=False)`. That lookup's candidate list drops
  ANY adapter whose description matches `TUN_DRIVER_RE` - so VPN clients
  whose adapter matches it (SoftEther, OpenVPN, WireGuard-based clients...)
  are invisible even when riding them is the whole point - and low-metric
  races can let the physical NIC win as well. Either way the server /32 was
  pinned to Wi-Fi and the transport silently stopped riding the VPN
  ("VLESS server route (188.114.97.6) via Wi-Fi" while the VPN showed
  Connected). Over-VPN mode is now DETERMINISTIC: the /32s are pinned to the
  exact VPN interface/next-hop that was resolved and validated at startup
  (`vpn_default` -> `_live_mode["over"]`), in ALL FOUR install paths:
  - the startup install (helper `main()`),
  - the live [V] mode switch (`_live_switch_vless`),
  - a live [U] server change (`_live_apply_servers`),
  - the 15 s endpoint self-heal (`_heal_endpoint_routes`).
- **The self-heal now treats a server /32 on the WRONG interface as broken.**
  In over-VPN mode a route that resolved onto the physical NIC (Wi-Fi) is a
  mode violation: it is evicted and re-pointed onto the validated VPN
  egress, exactly like a TUN-pinned route always was (both IPv4 /32 and
  IPv6 /128). DIRECT mode semantics are unchanged.
- **The "VLESS server route" / "Proxy loop detection" health checks are
  mode-aware.** In [V] mode they now PASS only when the endpoint route
  resolves through the connected Windows VPN (Get-VpnConnection names, with
  the VPN-alias regex as fallback for clients Get-VpnConnection does not
  expose); "via Wi-Fi" is reported as a FAILURE with an actionable message
  instead of a green "bypassed through Wi-Fi". Both checks also filter
  Find-NetRoute's address row (no DestinationPrefix) so `select -First 1`
  can never name the wrong interface.
- **The TUN CONFIG panel no longer claims everything is routed "direct" in
  [V] mode** - the header now reads "ROUTED DIRECT - VLESS server(s) via
  Windows VPN".
- **VPN-flap re-point could skip cycles.** The monitor loop gated the VPN
  transport status poll on `int(now) % 10 == 0`; a drifting 1 s sleep can
  jump from 19.x to 21.x and silently SKIP a whole cycle (the exact window
  a flap can happen in). Replaced with a timestamp cadence
  (`_VPN_STATUS_EVERY`), consistent with the gateway and self-heal clocks.

### Security (CodeQL remediation)

- `py/insecure-protocol` (`tuntop/network/leak_probe.py`): the shared
  TLS context now pins the protocol floor TWICE and unconditionally -
  `minimum_version = TLSVersion.TLSv1_2` (no swallow-exception guard) plus
  `OP_NO_SSLv3 | OP_NO_TLSv1 | OP_NO_TLSv1_1` - so every IP-echo fetch
  refuses TLS 1.0/1.1/SSLv3 no matter which pin a given Python honours.
- `py/incomplete-url-substring-sanitization`
  (`tests/unit/test_updates.py`): the update-check fake now compares
  `urlparse(req.full_url).hostname == "api.github.com"` instead of a
  substring search, which can match the host at an arbitrary position.

## [1.0.33] - 2026-09-20

### Fixed (the server bypass was pinned onto TunTop's OWN wintun - "the server IP goes to the wintun")
- **ROOT CAUSE: the TUN filters were blind to our own adapter.** Every egress
  lookup (`ipv4_default_ps`, `egress_lookup_ps` - both processes) excluded
  tunnel adapters via `$tunAliases`, built ONLY from
  `InterfaceDescription -match TUN_DRIVER_RE`. The vendored tun2socks creates
  our adapter with a tunnelType whose description matches NEITHER 'wintun'
  nor any other alternative (the health panel even showed
  "Proxy loop detection ... bypassed through wintun" as PASSING - proof the
  description test was wrong). While the tunnel was up, the lookups therefore
  saw our own TUN's `0.0.0.0/0` + `0/1`+`128/1` routes as valid "physical"
  candidates and returned **wintun** as the egress - so every [A]/[U]/[R]/
  geo install and the 15 s self-heal pinned the server /32 ONTO our own
  wintun and the transport looped (the `192.168.123.1 -> server:443`
  connection rows). The preamble now:
  - always includes OUR adapter aliases (`wintun`, `wintun2`) by NAME;
  - matches the TUN driver on the adapter NAME as well as the description
    (a physical NIC is never named `wintun*`/`tun2socks*`);
  - `TUN_DRIVER_RE` also recognizes the vendored tun2socks' own
    `tun2socks` tunnelType text.
- **Fail-closed egress guards at the Python level** (`helper.get_egress_for`,
  `routing._get_egress_for`): a resolver answer naming a tunnel-family
  interface is refused (and in DIRECT mode, a VPN-pattern interface too), so
  callers fall back to the last-known-good physical egress instead of
  installing a looping route. In [V] vless-over-vpn mode the VPN interface
  stays a valid egress.
- **The "Proxy loop detection" health check no longer lies.** It matched only
  the adapter DESCRIPTION against 'Wintun' - with our own adapter's
  description not containing that word, it passed while the server route
  resolved through our own TUN ("VLESS endpoint bypassed through wintun" as a
  green check). It now fails loudly when the route resolves through ANY
  tunnel-family adapter - ours by alias, foreign by driver description -
  and names the looped interface.
- **A live [U] server change is now known to the helper.** The dashboard
  installed the new endpoints' host routes itself, but the helper's tracked
  endpoint list - the 15 s self-heal AND the gateway-change re-point -
  only covered routes the HELPER had installed. A server added/edited via
  [U] while the tunnel ran was invisible to both: after a later Wi-Fi
  change its /32 stayed pinned to the dead gateway and the transport
  looped ("the U ip goes to the wintun"). The [U] worker now hands the new
  server list plus the per-host resolutions to the helper through the
  existing live-reconfig control file (`servers` + `server_endpoints`);
  the helper reconciles its tracked list (drops servers that left,
  re-installs every current endpoint under its own tracking so gateway
  changes re-point them, never strips anything on a transient resolution
  failure).
- **Watchdog sweeps survive a vanished `_MEI` dir for real.** The frozen
  dashboard spawned `--watchdog-child` (and the helper child) with an
  inherited PyInstaller environment (`_MEIPASS2`/`_PYI_*`), so the child
  bootloader REUSED the parent's extraction dir instead of extracting its
  own. When the dashboard died, that dir was deleted and every later lazy
  import in the watchdog failed with
  `FileNotFoundError: ...\_MEIxxxxx\base_library.zip` - the geo/LAN sweeps
  no-op'd while the log still said "crash marker cleared - system is clean".
  Child processes now get a scrubbed environment (own extraction dir), the
  watchdog warms the lazily-imported codecs at startup, and a PARTIALLY
  FAILED sweep keeps the crash marker (plus the live-state sidecar) so the
  next launch re-runs the recovery instead of trusting a lie.
- The watchdog logged `geo sweep failed: no CIDR entries found for geoip
  code ''` on every sweep when a geoip file was configured without a country
  code - that is "geo bypass never active", now a quiet no-op.

## [1.0.33] - 2026-09-17

### Added
- **GitHub release auto-update (verified, staged - never auto-run).** The
  frozen exe checks the latest stable GitHub release ONCE per session in a
  background thread. A newer TunTop.exe is downloaded, size-capped, PE/x64
  -checked, SHA-256-verified against the release's own `checksums.txt`
  (single-sourced with `build_release.write_checksums`' format), and staged
  NEXT TO the running exe as `TunTop-<version>.exe`. The running exe is
  never overwritten, launched, or otherwise touched - the log names the
  staged file and applying the update stays a manual step. Opt out with
  `BTOP_NO_UPDATE=1` or `--no-update-check`; offline/up-to-date checks are
  quiet no-ops. Pure stdlib (`tuntop/config/updates.py`), 21 offline tests.

### Fixed
- **The second black console window on launch is gone.** The frozen exe
  auto-relaunched itself into Windows Terminal in a NEW window while the
  original conhost stayed open - two windows, one black. The dashboard now
  always runs in the console it was launched in.
- **The event log no longer auto-scrolls away from what you are reading.**
  `Space` pauses/resumes the log, scrolling up auto-freezes it into an
  immutable snapshot (new lines and the 200-line prune can't move the
  viewport), `End` resumes live tailing; the log title shows
  `[paused - Space resumes]`. A second keypress in the same input batch is
  no longer dropped.
- **Graph stats line was unreadable** ("0.39% 4 avg 0.0 peak 0.54"): rates
  now carry explicit units - `▼ 0.42 MiB/s (  7%)  avg 0.1 peak 1.95 MiB/s`.

## [1.0.32] - 2026-09-16

### Fixed (the server bypass STILL didn't work with a Windows VPN connected)
- **ROOT CAUSE: copy drift in the dashboard's egress resolver.**
  `network/routing._get_egress_for` - the dashboard-side copy of the helper's
  `get_egress_for` used by EVERY live bypass install ([A], [U], profiles) -
  filtered TUN adapters but **NOT VPN-pattern interfaces**. With a Windows VPN
  connected, `Find-NetRoute` resolved the server's egress onto the VPN
  adapter, the dashboard pinned the server's /32 bypass ONTO the VPN, and the
  "direct" bypass rode the VPN or looped back into the TUN - the exact
  "bypass doesn't work / ROUTED DIRECT but loops" report. The helper's copy
  had the exclusion; the mirror did not. The WHOLE per-IP egress script is now
  single-sourced (`egress_scripts.egress_lookup_ps`, consumed by BOTH
  processes) with a placeholder-substitution guard against the 1.0.28
  silent-no-op bug class; the helper's hand-built copy is gone.
- **Endpoint self-heal recognizes VPN-pinned bypasses** (helper): in DIRECT
  mode a /32 or /128 pinned onto a VPN-pattern interface is now evicted and
  re-installed via the physical egress, same as TUN-pinned ones. In [V]
  vless-over-vpn mode a VPN-pinned bypass stays healthy (riding the VPN is the
  point there).
- **Bypass pre-clean now evicts foreign-TUN routes** (dashboard): the
  same-prefix delete scope was "planned egress + our own adapters", so a stale
  /32 pinned to a foreign TUN (Throne's sing-tun owned 176.0.0.0/4) survived
  the pre-clean and outranked the fresh bypass. The scope now includes every
  LIVE tunnel-family adapter (`routing._tun_family_aliases`); foreign routes
  on physical interfaces are still preserved and reported.
- **The BYPASS LIST no longer lies about ROUTED DIRECT** (dashboard): the
  resolver only re-installed routes when the resolved IPs CHANGED; if the
  route silently vanished (or got TUN-pinned) the panel kept claiming ROUTED
  DIRECT forever. The 300 s refresh now verifies the routes still exist
  outside tunnel-family adapters (`_bypass_routes_healthy`) and re-installs +
  logs `[HEAL]` when they don't. Verification is best effort - it can never
  block the resolver.
- `routing._get_vpn_ipv4_default` ran its PowerShell script TWICE (a
  duplicated `ok, out = _ps(ps)` line) - doubled latency and process churn on
  every [V]-mode lookup.

### Build (AV kept deleting TunTop.exe)
- **build_release.py survives AV quarantine properly**: the guarded window is
  12 s -> 45 s; BOTH protected copies (the versioned sibling AND the
  outside-dist standalone) are written the MOMENT the exe lands (previously
  the standalone only appeared at timeout, after AV could have eaten
  everything); ANY vanished copy is restored from whichever survives,
  repeatedly, with a 5 s settle re-check (AV verdicts land 5-30 s after the
  write, not instantly); the build now returns the best surviving artifact
  instead of a bare None, so checksums still get written.
- **New `--onedir` build**: `python build_release.py --with-exe --onedir`
  produces dist/TunTop/ (exe + support files) instead of the self-extracting
  onefile - no temp-dir payload drop at startup means dramatically fewer AV
  false positives (the spec's own comment calls onefile the #1 trigger).
- **New `--defender-exclude`**: best-effort Add-MpPreference of the repo +
  dist/ before building (elevated shell); prints the manual commands when
  not elevated.

### Tests
- +9 `tests/unit/test_egress_lookup_shared.py`: both processes emit the
  IDENTICAL egress script (per exclude_vpn variant), the VPN exclusion is
  present by default and only the primary lookup relaxes in over-vpn mode,
  IP quoting incl. hostile input, no unsubstituted placeholders, no VPN regex
  re-fragmented into consumers; `is_vpn_iface` matches VPN aliases and never
  physical NICs.
- +2 `tests/unit/test_endpoint_heal.py`: VPN-pinned bypass evicted in DIRECT
  mode; VPN-pinned bypass left alone in [V] mode.
- +13 `tests/unit/test_bypass_resilience.py`: route-health verification
  (physical healthy / TUN-pinned and missing unhealthy, /128 mapping,
  never blocks the resolver), pre-clean scope includes + dedupes TUN aliases,
  `_tun_family_aliases` parsing and fail-soft, `_route_rows` parsing,
  VPN-default lookup runs once.

## [1.0.31] - 2026-09-13

### Fixed (the VLESS server bypass vanished - "192.168.123.1 -> server:443
### loops" while BYPASS LIST claims ROUTED DIRECT)
- **ROOT CAUSE (diagnosed live): Throne's `sing-tun Tunnel` adapter owns
  `176.0.0.0/4` - a quarter of the IPv4 space, covering Cloudflare server
  IPs like 188.114.97.6.** The foreign-TUN filter only matched the
  "Wintun" DRIVER description, so `Find-NetRoute` resolved the server's
  egress ONTO throne-tun, the "bypass" /32 got pinned to it, and vanished
  when the adapter churned. With no /32 left, the server's traffic fell
  into TunTop's own Wintun - the loop visible in the connections panel -
  while the config panel kept showing "ROUTED DIRECT" (it displays the
  configured list, not verified routes).
- **Fix 1 - foreign-TUN detection broadened** (single source
  `egress_scripts.TUN_DRIVER_RE`, shared by EVERY egress lookup in both
  processes): now matches sing-tun, WireGuard, Tailscale, OpenVPN,
  TAP/Tunnel-family descriptions and more. Live-verified on the reporter's
  machine: `throne-tun (sing-tun Tunnel)` and `VeePN-TAP` are now detected
  as TUNs; physical NICs and plain-named Windows VPNs stay egress-eligible.
- **Fix 2 - endpoint bypass self-heal** (`_heal_endpoint_routes`, every
  15 s in the monitor loop): every tracked VLESS and VPN endpoint route is
  identity-checked; a MISSING or TUN-pinned bypass is evicted and
  re-installed via the mode-appropriate egress (physical, or the VPN in
  [V] mode) and reported as `[HEAL] ...` in the log. Healthy routes are
  left untouched; no route is ever added without a usable egress.
- **Tests** (+10: `tests/unit/test_endpoint_heal.py`): detector matches
  sing-tun/WireGuard/Tailscale/OpenVPN/TAP and never physical NICs or
  plain-named VPNs; heal re-installs missing routes, evicts TUN-pinned
  ones, respects [V] mode, heals VPN endpoints, keeps retrying without a
  usable egress, and never touches healthy routes.
- **Fix 3 - [U] edit-servers route installation now uses DNS fallback**
  (`tuntop/ui/dashboard.py`). The [A] bypass path resolves with
  `_resolve_detail(entry, use_cache=False, fallback=_allow_fb)` (UDP/53 +
  DoH fallback, policy-gated by `_dns_fallback_allowed`), but the [U]
  edit-servers path and the startup/profile-load re-resolution used bare
  `_resolve(srv)` → `use_cache=True, fallback=False`. When system DNS
  failed (e.g. Windows resolver pointed at a dead tunnel), those paths
  returned a stale 120 s cache or empty, so the server's /32//128 host
  route was never installed and the VLESS transport looped into the TUN
  even though the config panel showed the server as configured. All four
  call sites (startup display, [U] re-resolve, [U] route-install worker,
  profile load) now use the same `_resolve_detail(..., use_cache=False,
  fallback=...)` pattern as [A]. IP-literal servers are unaffected
  (`ipaddress.ip_address` short-circuits before cache/fallback).

## [1.0.30] - 2026-09-13

### Fixed (the VPN's own server traffic went into the TUN - "the server
### (reza_U) traffic is not bypassed")
- **A Windows VPN connecting AFTER tunnel start never got its endpoint
  bypass.** Startup resolves only the VPNs that are ALREADY connected
  (`get_active_windows_vpn_servers()` at start), and the only other path
  that installed the VPN endpoint bypass was the manual [Y] toggle. The
  dashboard's `_on_vpn_arrived` reconciliation (fires within ~5 s of a VPN
  appearing) re-applied the dashboard's own [vpn] bypass entries and
  geo-via-VPN - but never told the helper. So for the typical "start
  TunTop, then connect `reza_U`" order, the VPN's server
  (`vpn.shirazu.ac.ir`) had NO /32 bypass, the Wintun split-defaults
  (0.0.0.0/1 + 128.0.0.0/1) captured the VPN's own control/data traffic,
  and the VPN died inside the tunnel. The endpoint IP visible in the
  startup/health logs was the bypass that never existed.
- **Fix (both ends of the existing control channel):**
  - dashboard `_on_vpn_arrived` writes a one-shot
    `{"vpn_endpoint_reapply": true}` control-file key (skipped when [Y]
    disabled the bypass or [V] rides the VPN);
  - helper `poll_control_file` consumes it by running the enable side of
    the [Y] toggle - resolve every CURRENTLY connected VPN's ServerAddress,
    install /32+/128 bypasses via the physical egress (idempotent), and
    re-establish the sole-egress shadowing exactly as startup would have.
    Gated on the same startup conditions.
- **Tests** (`tests/unit/test_live_mode_channel.py`, +7): the key triggers
  `_live_apply_vpn_bypass_routes(True)` + shadow; shadow refusal alone does
  not cancel the apply; both mode gates skip it; the dashboard writes the
  key on arrival and stays silent in the two excluded modes.

### Note (antivirus)
- The v1.0.29 `TunTop.exe` was reported deleted by antivirus. This is the
  classic false positive for an UNSIGNED PyInstaller onefile build - the
  1.0.29 exe was built by CI and shipped with a version resource and
  SHA-256 checksums (`checksums.txt`), nothing changed in the vendored
  binaries. Long term: sign the exe or submit the false positive to
  Microsoft; short term: restore from quarantine / add an exclusion for
  the folder you run it from.

## [1.0.29] - 2026-09-13

### Fixed (the server bypass looped into the TUN)
- **`get_ipv4_default()`'s CIM fallback had a literal `'%s'` where the
  VPN-alias regex belonged** - the `%`-substitution was never applied, and
  as a PowerShell regex `'%s'` matches nothing, so the "exclude VPN
  interfaces" filter in that fallback was a silent NO-OP. With a
  full-tunnel Windows VPN connected (which deletes the physical default
  route), the fallback happily returned the **VPN adapter's gateway** as
  the "physical" egress. The VLESS **server** `/32` bypass then rode the
  VPN, the server transport was captured by the tunnel and looped back
  into 127.0.0.1 - "the server traffic isn't bypassed, it wants to go into
  the TUN". The dashboard mirror (routing `_get_ipv4_default`) carried the
  CORRECT predicate all along: pure copy drift between the two processes.

### Changed (finish the 1.0.28 single-sourcing)
- **The full physical-IPv4-default lookup script body now lives in
  `tuntop/network/egress_scripts.py` (`ipv4_default_ps()`)** alongside the
  preambles: both `helper.get_ipv4_default()` and the dashboard mirror
  `routing._get_ipv4_default()` run ONE byte-identical script. 1.0.28
  shared only the preambles/filters and left the bodies copy-pasted - the
  exact drift class it set out to kill. The drift-guard test
  (`tests/routing/test_egress_scripts_drift.py`) now pins the body too:
  both consumers must reference `ipv4_default_ps()`, the emitted script
  must contain the real VPN exclusion in the CIM fallback, and no
  `'%s'`/placeholder leftovers may ever return. The stale no-op
  `.replace("__VPN_IFACE_RE__", ...)` in routing.py is gone with the
  duplicated body.

## [1.0.28] - 2026-09-12

### Changed (architecture: one source for the egress script text)
- **New `tuntop/network/egress_scripts.py`** - the PowerShell preambles and
  filters every default-route / egress lookup emits (`$tunAliases` by
  DRIVER, `$vpnAliases` by Get-VpnConnection correlation, the v4 default
  filter) now live in exactly ONE module, imported by both the helper
  process and the dashboard mirror. They had been copy-pasted twice since
  the restructure and every 1.0.x fix (the '^wintun' -> driver switch in
  1.0.26 most recently) had to be applied twice - the exact drift class
  this ends. `tests/routing/test_egress_scripts_drift.py` now fails the
  suite if a copy-paste reappears (identical-text assertions + a
  no-hardcoded-VPN-regex source scan).

### Fixed
- **routing.py `_get_ipv4_default`/`_get_ipv6_default` still sorted by the
  SEPARATE `RouteMetric, InterfaceMetric`** - 1.0.25 fixed the effective
  metric sum only in the helper's copy, so the dashboard could still pick
  a Wi-Fi RM=0 route over a VPN RM=1/IM=25 one. Now both sum.

### Added (DNS policy - honest leak semantics)
- **`--dns-policy availability|strict`** (CLI, profile, model, control
  channel - the helper stores and live-updates it). The README said
  "DNS leak protection with UDP/53 and DoH fallback" - true of detection,
  false of the fallback stack, which by design escapes to the physical
  NIC when the tunnel's resolution path dies. That default stays
  ('availability'), but 'strict' now flips the trade: while a tunnel is
  up (or supposed to be), the dashboard's bypass resolver NEVER sends
  UDP/53 or DoH queries - a failed lookup is reported instead. Bootstrap
  with the tunnel down always allows fallback.
- README feature line rewritten to "resolution fallback with active leak
  detection"; FAQ gained "Is my DNS leaking?" and "Traffic isn't going
  through the tunnel" entries (competing TUN, stale-pin history); the
  auto-download trust model is documented honestly: binaries verify
  against repo-pinned SHA-256, geoip.dat updates are TOFU (checksum from
  the same release channel).

## [1.0.27] - 2026-09-12

### Fixed (route transactions now verify ROUTES, not prefixes)
- **Prefix-only verification proved nothing** - `RouteTransaction` accepted
  an add as "verified" if ANY route with the destination prefix existed,
  and failed a delete if one still did. Windows keeps several routes per
  prefix, so: a foreign same-prefix route on a better-metric interface
  made a half-dead bypass "verify OK"; and deleting our /32 while a
  foreign /32 survived was reported as a failed delete (and rolled back).
  `Backend` now takes optional identity-aware `verify_*(dest, iface,
  gateway, metric)` and `table_*(dest)` primitives (pure fallback to the
  legacy prefix probe for old custom backends - every existing test
  passes unchanged).
- **Shadowed installs detected**: for HOST routes (/32, /128 - never for
  default/split routes, whose coexistence is the design), after adding we
  rank all same-prefix routes by EFFECTIVE metric (RouteMetric +
  InterfaceMetric) and FAIL the transaction if a foreign route owns the
  traffic. Previously a VLESS /32 silently losing to the VPN's own /32 was
  invisible: dashboard green, traffic dead.
- **Failed ops no longer leak routes**: the op that failed mid-
  transaction (verified-present but shadowed) is now itself removed before
  rollback of the earlier ones - all-or-nothing really means it.
- **`Backend.remove` bug**: the Windows delete primitive returns a
  `(removed, foreign)` tuple; `bool(tuple)` was ALWAYS True, so a fully
  failed delete could only be caught by the (wrong) prefix check. The
  tuple is now unpacked and the identity verify decides.
- **helper `add_v4/add_v6` verify their own installs**: after netsh says
  OK, host-route (/32, /128) adds confirm the EXACT route (interface +
  next-hop + metric) is live before recording it in the ledger - the
  half-installs that used to be recorded as successes now return False
  and the caller's failure path runs. (Default/LAN/split adds skip the
  per-add check: they are polled continuously by the monitor instead.)
- **`add_v4` appeared-during-add race branch** no longer leaks a ledger
  entry: the recovered route is now recorded like any other success.
- New primitives: `routing._route_matches_v4/v6` (exact identity),
  `routing._route_table_v4/v6` (all same-prefix routes ranked by effective
  metric). 24 new tests (`tests/routing/test_route_identity.py`) on a
  multi-slot `FakeExactRouter` covering shadowing, ties, misdirected
  adds, foreign-preserving deletes, idempotent removes and rollback.

## [1.0.26] - 2026-09-12

### Fixed (foreign-TUN exclusion by driver, not alias)
- **v2rayN's `xray_tun` slipped past every tunnel filter** - 1.0.24/1.0.25
  excluded "any tunnel" by alias prefix (`^wintun`), but xray names its own
  adapter `xray_tun` (description "Wintun Tunnel"). Live-verified on this
  machine: with v2rayN's TUN up, `get_egress_for()` answered
  `('xray_tun', '0.0.0.0')` for every VLESS server - so bypass/VPN pins
  landed inside the foreign tunnel and the dashboard's "RUNNING" tunnel
  carried nothing. All egress lookups (helper + dashboard-side mirror)
  now build the exclusion from the DRIVER
  (`InterfaceDescription -match 'Wintun'` -> `$tunAliases`), which no
  adapter rename can defeat; verified live that every lookup returns Wi-Fi
  again with `xray_tun` up.
- The competing-TUN warning, VPN-default fallbacks, geo conflict sweep and
  the proxy-loop health check all use the same driver test now.

## [1.0.25] - 2026-09-12

### Fixed (VLESS-over-VPN actually rides the VPN)
- **[V] mode switch was a silent no-op while our own stale /32 existed** -
  the VLESS endpoint host routes are pinned via `get_egress_for()` →
  `Find-NetRoute`, which answers with the LONGEST match first: the previous
  mode's /32 itself. Re-resolving an endpoint that was already pinned to
  Wi-Fi therefore returned Wi-Fi again, `add_v4` saw "already correct", and
  the table kept VLESS on Wi-Fi while the dashboard claimed "VLESS via VPN"
  (live-verified: VPN connected, all three /32s still `Wi-Fi/10.x`, server
  198.51.100.1:443 timing out). Every install path (startup VLESS/extra-
  bypass loops, `_live_switch_vless`) now deletes existing host routes for
  the destination BEFORE resolving the new egress.
- **Egress tiebreak used RouteMetric alone, not the EFFECTIVE metric** -
  full-tunnel Windows VPNs inject `0.0.0.0/0` at RouteMetric 1 +
  InterfaceMetric ~25 (Shirazu-VPN: effective 26) while Wi-Fi sits at
  RouteMetric 0 + InterfaceMetric 4270 (effective 4270). Sorting by
  `RouteMetric, InterfaceMetric` separately made Wi-Fi win the tie;
  `get_egress_for` (helper) and `_get_egress_for` (dashboard/routing) now
  sort by `RouteMetric + InterfaceMetric` summed - how Windows itself
  picks. This was also why a FRESH over-vpn start pinned to Wi-Fi.
- **VPN transport flaps no longer blackhole the tunnel** - when the VPN
  drops while `--vless-over-vpn` is active, the /32s point into a gateway
  that no longer exists: the tunnel runs but nothing flows. The helper's
  status poll now re-points VLESS to the physical egress on disconnect and
  rides the VPN again automatically when it reconnects (the DESIRED mode
  from the launch flags is preserved; only the routed egress moves).

## [1.0.24] - 2026-09-12

### Fixed (competing TUN programs + [V] mode self-sabotage)
- **Foreign Wintun adapters defeated every egress decision** - all
  "exclude the tunnel adapter" route lookups compared the alias EXACTLY to
  `wintun`/`wintun2`. v2rayN/xray in TUN mode create an adapter named
  `Wintun Tunnel` (next-hop `172.18.0.1`, usually with a metric-0 default
  route): it was invisible to those filters, so TunTop could treat another
  program's dead tunnel as the physical egress - pinning VLESS/VPN/LAN
  bypass routes into it while the browser's traffic went there too. Every
  exclusion now matches the whole `^wintun` family
  (`config/defaults.py: WINTUN_FAMILY_RE`, `tunnel/helper.py`,
  `network/routing.py`, `ui/dashboard.py`); the VPN-adapter fallback scans
  in `get_vpn_ipv4_default` explicitly reject wintun aliases so a foreign
  tunnel is never mistaken for the Windows VPN.
- **[V] VLESS-over-VPN killed the VPN it needs to ride** -
  `_toggle_vless_over_vpn` auto-set `no_vpn_bypass = True` (meaning "install
  NO bypass") while its comment promised the opposite: the press tore down
  the VPN-endpoint bypass, the VPN transport fell into the TUN, the VPN
  dropped, and the helper's next VPN-route check refused - leaving the UI
  showing "VLESS via VPN" while every VLESS route stayed on Wi-Fi. It now
  sets the bypass correctly (`False` = bypass enabled).
- **Startup now warns when another TUN program is live** - the helper
  reports any foreign Wintun adapter and whether it owns a default route
  (read-only; foreign adapters are never touched), and the dashboard gained
  a "No competing TUN adapter" health check that FAILS (red) while e.g.
  v2rayN TUN mode steals the default route - the "RUNNING but the browser
  gets nothing" state is now self-explaining instead of a mystery.
- **Per-server "Proxy loop detection" accepted a foreign tunnel** -
  `-ne 'wintun'` passed a server bypassed through v2rayN's `Wintun Tunnel`;
  the check now rejects any `^wintun` egress.

## [1.0.23] - 2026-09-12

### Fixed (exit-path correctness)
- **Clean-exit detection was inverted** - `clear_marker()` (and the watchdog
  sidecar retirement) ran only in the atexit FAILURE branch, so every clean
  quit left the crash marker behind: the detached watchdog classified clean
  exits as unclean and ran pointless (and potentially racy) post-exit
  sweeps, while a genuinely FAILED cleanup cleared the marker and hid itself
  from the next launch's recovery. Now the success path clears the marker
  and retires the sidecar; the failure path deliberately keeps it.
- **atexit never stopped the helper child** - the final atexit pass now
  signals the helper (CTRL_BREAK, bounded wait, then terminate) BEFORE
  sweeping, so its self-heal loop can no longer re-assert default/split
  routes behind the dashboard's cleanup.
- **Alt+F4 handler serialized with [Q]/[T]** - the console-close handler
  used to run its sweeps regardless of an in-flight teardown; two
  concurrent teardowns (and two snapshot-restore passes resurrecting each
  other's deletes) could fight over the table. The handler now waits for
  an in-flight teardown, or claims the same teardown lock a [T] worker
  would, and restores the route snapshot LAST - same ordering as [Q].
- **`geoip_added` is now lock-guarded everywhere** - the background geo
  install registers routes under a state lock, the gateway re-point
  rewrites its tracking under the same lock, and cleanup() snapshots +
  clears under it. A signal during an install sets a cancel flag (the
  installer skips its remaining netsh sub-batches) and joins the install
  thread briefly, so a half-installed country can no longer leak untracked
  routes on teardown.
- **`lifecycle.make_teardown()` called a nonexistent
  `helper.cleanup_and_exit`** (latent AttributeError) - it now calls
  `helper.cleanup()` and returns, as the TunnelManager contract requires.

### Changed (architecture)
- **Route tracking ledger** (`tuntop.network.routeops`) - the helper's
  tracking lists are now thread-safe `RouteLedger` registries that keep
  FULL fidelity (metric + store, not just prefix/iface/next-hop). A LAN
  bypass installed at metric 10 survives a gateway re-point at metric 10;
  the old hardcoded metric=1 re-point is gone.
- **One sweep-rule implementation** - LAN victims, geo victims and the
  endpoint host-route statement builder live in
  `tuntop.network.routeops.sweeps`; the dashboard's exit sweeps and the
  detached watchdog share them instead of carrying drifting copies.
- **`add_geoip_bypass()` returns the rows it registered** - the dashboard's
  live geo re-apply takes ownership from the return value; the UI no longer
  reads/slices/rebinds the helper module's `geoip_added` global.
- **Single source for shared constants** (`tuntop.config.defaults`) - the
  LAN prefix list (was 3 hand-synced copies), the VPN interface regex (was
  7 inline copies), TUN adapter names/addresses/subnets, geo batch tuning
  (was 3 divergent copies) and the default ports are defined once and
  imported everywhere.
- **State-free exec primitives extracted** (`tuntop.tunnel.exec`) -
  `run`/`ps_json`/`run_ps`/`_clean_err` moved out of helper.py; the
  geo-install `sys.exit()` failure mode is wrapped as a RouteResult for
  library callers (the monitor loop no longer needs `except SystemExit`).

## [1.0.22] - 2026-09-12

### Added
- **Auto re-route on Wi-Fi/network change** - the helper's monitor loop now
  polls the physical default gateway every few seconds. When the network
  changes under a running tunnel (Wi-Fi roam, DHCP renew, dock/undock), every
  route pinned to the old gateway - the VLESS endpoint /32+/128s, the LAN
  bypasses, the [A] bypass IPs, the proxy2 server bypasses and (on a worker
  thread) the whole geoip country set - is re-pointed at the new gateway
  without touching the TUN routes or restarting tun2socks. The change is
  debounced (confirmed twice, 2s apart) so a mid-DHCP transition is never
  mistaken for the final state, and the physical-interface metric lowering
  is re-armed on the new adapter. `[GATEWAY]` markers in the log surface the
  transition - and the dashboard reacts to them: routes IT installed live
  ([A]-added bypass entries and live geo re-apply routes, which the helper
  does not track) are re-pointed to the new egress too, batched, so nothing
  keeps steering traffic at the dead gateway.

### Fixed
- **Alt+F4 left the SERVER routes behind** - the helper's `cleanup()` ran the
  slow bulk geo delete FIRST, so an OS kill inside the ~5s close window
  skipped everything after it: exactly the endpoint /32+/128 host routes and
  the VPN-override undo ("the servers I added stay in the routing table").
  `cleanup()` now removes every small CRITICAL route group first (VPN
  overrides, endpoint/LAN/TUN routes - also clearing its tracking list) and
  leaves the long geo bulk delete for last, so a mid-cleanup kill can only
  ever leave geo routes behind (which the sweeps + watchdog still remove by
  CIDR). The close handler also runs the batched endpoint host-route sweep
  and LAN sweep itself now, so the table is clean even when the helper hangs.
- **[Q] no longer drifts the routing table** - the pre-session table is
  snapshotted at launch, and every exit path ([Q], [T], atexit, window
  close) restores the diff: entries the session removed or replaced (the
  helper's `add_v4` "stale-route replacement", the geo conflict sweep) are
  re-created with their original interface/next-hop/metric/store, and a
  modified copy left in place is deleted first. Windows-managed noise
  (defaults, multicast, link-local, wintun) never participates.
- **Stale-gateway LAN leftovers after switching networks** - the LAN sweep
  only matched routes via the CURRENT gateway, so routes pinned to the old
  network's gateway on the same adapter survived every cleanup and kept
  blackholing RFC1918 traffic on the new network (the "Wi-Fi changed and the
  routing prevents internet" report). The sweep now also removes LAN-prefix
  routes on the current physical adapter whose real next-hop is NOT the
  current gateway, at startup and on every exit.

## [1.0.21] - 2026-09-11

### Fixed
- **Routes survived Alt+F4** - closing the window ([X] / Alt+F4) never asked
  the HELPER child to clean up: it owns the server-endpoint /32+/128 routes,
  the LAN bypass and (at startup) the geo routes, and its own console-close
  handling could race the OS's ~5s kill window. The close handler now
  signals the helper (CTRL_BREAK) so its `cleanup()` runs - overlapped with
  the dashboard's own sweeps - then gives it a bounded window before the
  force-quit; the detached watchdog sweeps whatever is left as before.

### Changed
- **[V] / [Y] now apply LIVE** - toggling VLESS-over-VPN or the VPN endpoint
  bypass no longer stops and restarts the tunnel (no more TUN reset). The
  dashboard pushes the new modes through the helper's live-reconfig control
  file (the same channel the [N] DNS handoff uses); the helper re-points its
  endpoint /32+/128 routes at the new egress, installs/removes the VPN
  endpoint bypasses and undoes/re-establishes the VPN-route shadowing, all
  while tun2socks keeps running. The dashboard re-points its own live-added
  bypass routes to match and invalidates its stale egress cache (a [V] flip
  used to leave [A] adding routes through the OLD egress). A switch to
  VLESS-over-VPN with no connected Windows VPN is refused on both sides -
  the old mode stays active instead of silently failing after a restart.

### Added
- **DNS leak test** - [L] now runs the DNS half of the leak test alongside
  the IP-egress probe: (1) the system resolver's public identity
  (whoami.akamai.net) compared against the direct (ISP) egress, and
  (2) a forced UDP/53 query to public resolvers whose echoed egress IP is
  compared against the tunnel exit. A passing IP test with leaking name
  queries is now reported as `DNS LEAK` with the fix hint.

### Fixed (UI)
- **The last theme is remembered** - [M] saves the choice under a reserved
  `_ui` key in MyTunTopProfile.json and the very first frame comes up in
  that palette on the next start. The `_ui` key is never offered as a
  profile, never saved as one, and never counted in the "N profile(s)"
  messages.

## [1.0.20] - 2026-09-11

### Fixed
- **Process kills are ownership-scoped now** - every cleanup path (helper
  preflight, `routing._teardown_wintun`, the startup-recovery probes, the
  dashboard's teardown loop and its "tun2socks process" health check) used
  to kill/count BY PROCESS NAME (`ProcessName -like 'tun2socks*'`). Since
  tun2socks is a generic open-source tool other software legitimately
  runs, TunTop's cleanup/watchdog could terminate a foreign tun2socks.exe
  it never started. All of those paths now go through the new
  `tuntop.network.procguard`, which selects only processes that are
  provably TunTop's: PIDs recorded from its own launches, the exact
  configured `--tun2socks` path, or the distinctive vendored binary name
  (`tun2socks-windows-amd64-v3.exe`). A generic `tun2socks.exe` from
  another tool is never killed, never counted.
- **Route-delete fallback is interface-scoped now** - when netsh delete
  failed with parameter drift, `_del_route_v4/_v6` fell back to a
  prefix-wide `Remove-NetRoute` (no interface, no gateway), which could
  delete a same-prefix route the user or a corporate VPN client installed
  on an adapter TunTop never touched. The fallback now deletes the prefix
  ONLY from the tunnel adapters (`wintun`, `wintun2`) plus the interface
  the route was installed on (`routing._del_route_scoped`); a same-prefix
  route surviving on any other interface is reported as foreign and left
  alone (the live-bypass pre-clean and removal paths warn in the log).
  All `_del_route_*` helpers now return `(removed, foreign)`.
- **TunnelManager is actually wired up** - the Core-layer lifecycle
  facade existed and was tested, but the dashboard never used it (the
  "architecture on paper" gap). It is now constructed in the dashboard and
  every start path ([S], queued start after a stop, recovery restart,
  port-change restart, bypass-change restart) goes through
  `TunnelManager.request_start`, which enforces the state graph: a start
  while another lifecycle phase is in flight is rejected instead of
  spawning a second helper. A machine stranded mid-sequence by a dead
  helper is reset (loudly) so a manual start always works.
  `request_start` gained `verify_immediately=False` for async starts so
  the manager doesn't swallow the reader thread's real phase
  announcements.
- **Release zip excludes the real profile filename** - the exclusion list
  said `profiles.json` but the actual store is `MyTunTopProfile.json`
  (legacy `profiles.json` stays excluded too). The file holds only
  settings (no credentials), so this was a hygiene fix, not a leak.

## [1.0.19] - 2026-09-08

### Fixed
- **Watchdog sweeps are now import-proof** - 1.0.18 pre-loaded the sweep
  dependencies in `main()`, but the sweeps still performed in-function
  imports (`tempfile`, `json`) and the `tuntop.network.dns` chain
  (`socket`, `threading`) could first-load from `_MEI`/`base_library.zip`
  at sweep time. Everything now imports at module top / before the wait,
  so no sweep-path import ever touches the filesystem after the parent
  dies (field: Errno 2 on `base_library.zip` still appeared in 12:49 log).
- **Sweep failures now log the full traceback** (`.cleanup_watchdog.log`)
  so a future failure names the exact missing module instead of a bare
  Errno 2.

## [1.0.18] - 2026-09-07

### Fixed
- **Alt+F4 cleanup actually works now** - the watchdog's geo/LAN sweeps
  imported `tuntop.network.routing` lazily, AFTER the dashboard died; in
  the frozen exe the import chain reads `base_library.zip` out of the
  per-run `_MEI` extraction dir, which was already gone -> both sweeps
  died with Errno 2, the crash marker was still cleared, and every live
  geo/LAN bypass route stayed on the system (field-observed: 2,028 IR
  routes + 7 LAN routes left behind). All sweep dependencies are now
  eager-imported before the watchdog starts waiting, so the sweep needs
  no filesystem at run time.
- **`.cleanup_watchdog_state.json` lifecycle** - the sidecar is now
  deleted after the sweep that consumed it (pid-matched) and on clean
  exits; it no longer lingers in the exe folder forever.

## [1.0.17] - 2026-09-07

### Fixed
- **Geo routes left on the system after an Alt+F4-style exit**: the
  Ctrl-close fast path now (a) refreshes the watchdog sidecar FIRST, then
  (b) deletes the tracked live routes AND (c) runs the batched
  geo-CIDR sweep in the same ~5s window - geo routes the HELPER installed
  at startup were never in the dashboard's live-route tracking, and they
  sit on the physical adapter where the Wintun teardown cannot see them.
  The detached watchdog still sweeps whatever the close window could not
  finish. Its diary now also lands next to TunTop.exe when frozen
  (it used to vanish into a throwaway extraction dir, making every
  unclean-exit sweep undiagnosable).
- **Dashboard unresponsive + typed keys echoed after the TUN dies
  (VPN change)**: the per-frame console-mode watchdog now also covers
  sessions WITHOUT mouse support (it restores the original input mode,
  not just the mouse dashboard mode), and the tunnel-down transition
  (STOPPED/FAILED) actively restores the input mode AND flushes the
  console input buffer - the garbage keys typed while the app looked
  dead can no longer leak into the UI ("adadassdasd" on the status bar).
  The log points at [T] to start the tunnel again.

### Added
- **Profile management in the [I] picker**: **X** deletes a saved
  profile (press twice to confirm; deleting the default also clears
  auto-load), **D** marks/clears the **DEFAULT profile** - the default is
  applied to the startup args automatically on every TunTop start, so
  the saved setup comes up with zero keypresses. The default profile is
  starred in the list.
- **[E] server editor**: new mode choice - 1=REPLACE all servers (the old
  behaviour) or 2=ADD to the current servers (dedup case-insensitive;
  only the new servers get live host routes, existing ones untouched).
- **[F] Geo Manager**: option 1 is now "Change geoip.dat location" (the
  file path, verified to exist); Apply/Re-apply moved to option 5.

## [1.0.16] - 2026-09-07

### Fixed
- **Leak test crashed: "error: Error -3 while decompressing data:
  incorrect header check"** - the [L] test died on a `zlib.error` that
  came from the threading machinery itself, not from any endpoint: in the
  frozen exe the FIRST `concurrent.futures.thread` import happens inside
  `run_leak_probe` (lazy module `__getattr__`), and PyInstaller's importer
  zlib-decompresses the PYZ entry there - a damaged/tampered archive
  raised exactly there, outside every per-endpoint handler. `run_leak_probe`
  now catches a failed threaded race and re-runs BOTH legs SEQUENTIALLY
  (thread-free), so the leak test always returns a verdict; the
  mixed-family IPv4 re-probe inside the verdict uses the same resilient
  wrapper. The echo requests also pin `Accept-Encoding: identity` so no
  middlebox can compress the body the IP is parsed from.

## [1.0.15] - 2026-09-07

### Fixed
- **Black background cells behind the status dots (VPN / GEO / bypass
  rows)**: the dot constants (●) embedded the shared span-end reset that
  was captured at STARTUP - before the first frame ever armed the theme
  background - so every row that begins with a dot repainted a
  terminal-default black cell from the glyph up to the next reset, in
  every theme that sets a background (and stayed on the startup theme
  after an [M] switch). `_arm_bg()` now rebuilds the dots each frame so
  they always re-arm the ACTIVE theme's background.

## [1.0.14] - 2026-09-07

### Added
- **geoip.dat startup bootstrap** - the geo database now gets the same
  treatment as tun2socks/wintun: on first run of the packaged exe it is
  downloaded (v2fly source, SHA-256 verified, atomic install) into the
  exe's own folder BEFORE the dashboard opens, and `--geoip` defaults to
  that file. Geo features work on the very first run with no manual step.
- **geoip auto-update** - at dashboard start, if the configured geoip.dat
  is older than 14 days it is refreshed once per session in the
  background (same SHA-256-verified pipeline); stale databases can no
  longer silently misroute. [W] still force-updates on demand.

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
- **Routes left on the system after Alt+F4**: in the packaged exe the
  watchdog's live-session sidecar (`.cleanup_watchdog_state.json`) was
  written to and read from per-run PyInstaller extraction dirs - the
  detached watchdog could never see the dashboard's live-added hosts
  (bypass entries, geo config), so its post-unclean-exit sweep missed
  them. Both sides now park the sidecar next to TunTop.exe (same rule as
  the crash marker). The Ctrl-close handler also runs the fast batched
  route deletes first, so a close that outruns its ~5s budget cannot cut
  the important part short.
- **CodeQL alerts**: explicit shared TLS context (TLS 1.2+ minimum,
  system CAs, hostname verification) for the leak probe's echo fetches;
  `permissions: contents: read` added to the CI workflow.
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

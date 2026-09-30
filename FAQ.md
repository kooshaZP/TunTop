# Frequently Asked Questions

## General

### What is TunTop?
TunTop routes all Windows traffic through any local SOCKS5 proxy (v2rayN, Xray, sing-box, Clash Meta, ...) system-wide using a Wintun TUN adapter. It includes a live btop-style dashboard with throughput graphs, health monitoring, and instant bypass controls.

### Do I need to install anything?
Just Python 3.10+ and a SOCKS5-capable proxy client. TunTop has zero pip dependencies — it uses only the Python standard library. The `tun2socks.exe` and `wintun.dll` binaries are auto-downloaded on first run.

### Does it work with Windows 10?
Yes, Windows 10 version 1803 or later.

## Setup

### The proxy isn't running / SOCKS port is wrong
TunTop connects to your proxy client's local SOCKS5 inbound (default port 10808). Make sure the proxy client is running and the SOCKS inbound is enabled. Press `[P]` in the dashboard to change the port if yours uses a different one.

### How do I run as Administrator?
Right-click `Run_Helper.ps1` → "Run with PowerShell" → confirm the UAC prompt. Or open an Administrator PowerShell and run `.\Run_Helper.ps1`.

## Tunnel

### Is traffic actually going through the tunnel?
Run a leak test with `[L]` inside the dashboard. It compares your direct exit IP with the tunneled exit IP. If they **match**, all traffic — including "direct" traffic — is riding the tunnel (no leak). If the direct IP **differs** from the tunnel exit, direct traffic is escaping outside the tunnel (a leak). The tunnel's monitor loop runs this check automatically every cycle and logs the result as `[MONITOR] leak check ...` lines.

### Traffic isn't going through the tunnel
Two common culprits. First: another TUN program (v2rayN's own TUN mode, for
example) cannot run alongside TunTop - whichever tunnel owns the lowest
default-route metric steals all browser traffic. Turn the other TUN off and
keep only its SOCKS port; TunTop also warns at startup and runs a "No
competing TUN adapter" health check for exactly this. Second: if the
dashboard's VLESS-server checks report "via Wi-Fi" while VPN mode says it
rides the VPN, the VPN transport routes were resolved against a stale
entry - 1.0.27+ re-point and verify host routes by exact identity, and the
helper now falls back to Wi-Fi (and re-rides the VPN) automatically when
the VPN flaps.

### Is my DNS leaking?
Two different things can leak, and TunTop now handles both.

**1. Windows asking somebody else (the real one).** Making Wintun the preferred
DNS source is an *ordering*, not an exclusion: Windows enables Smart Multi-Homed
Name Resolution (SMHNR) by default, so the DNS client sends each query out over
**every** connected interface that publishes resolvers and takes the first
answer. A DHCP-assigned router resolver (`192.168.1.1`) is on-link, so the
tunnel's split-default routes never capture it — the router/ISP answer can win.
Browser leak tests see exactly that; TunTop's older probes could not, because
they only tested the resolvers TunTop itself knows about.

So while a tunnel is up TunTop installs a **catch-all Name Resolution Policy
Table (NRPT) rule** that claims the root namespace and pins every name to the
tunnel resolvers (`TunTop-Match` under
`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`).
That stops the fan-out whether or not SMHNR is on. A `.local` exemption ships
with it so mDNS printers/NAS keep working.

- Check it any time: the `[C]` row **"DNS leak protection (catch-all NRPT
  rule)"**. It passes only when the rule exists *and* Windows' own effective
  NRPT policy carries it, and on failure it names the adapters still publishing
  resolvers (`Wi-Fi=192.168.1.1`, …). The adjacent "DNS configuration (Wintun is
  selected source)" row proves the *configured* resolvers ride the TUN.
- `[L]`'s DNS test also catches this case, naming the adapters. It only reports
  a confirmed **DNS leak** when it can actually establish that no catch-all rule
  is in force; if the guard state cannot be read (PowerShell missing, probe
  failed) it reports **DNS leak UNKNOWN** and says why, rather than blaming a
  healthy tunnel. Only adapters that are currently **Up** count — a stale
  resolver on an unplugged NIC is not a leak source, because Windows never
  queries a disconnected adapter.
- The rule is removed by **every** exit path: a normal stop, the `[X]`/close
  button, Ctrl-C, a crash (the next launch and the detached cleanup watchdog
  both remove it before anything else). If a removal cannot complete, it is
  reported as a *failure* and the install record is kept, so the next launch
  retries instead of a stale pin being quietly forgotten.
- It lives only as long as the tunnel. If you quit TunTop and your DNS breaks,
  a rule survived - start TunTop again (startup recovery removes it) and report
  it.
- Escape hatches: `--no-dns-guard` turns the pin off (and removes any leftover
  rule) - the `[C]` row then reads "DISABLED by choice" rather than a red
  failure, so opting out is never mistaken for a broken guard;
  `--dns-guard-exempt home.example` keeps a domain resolvable by the LAN
  resolver while the guard is up (repeatable, and `.local` is always exempt).

**2. TunTop's own fallback stack.** For resolution itself, the fallback stack
(UDP/53 and DoH) prioritizes availability over privacy: if the system resolver
fails while the tunnel is up, those fallback queries can leave over the physical
NIC. That is deliberate (a dead lookup helps nobody) - run with
`--dns-policy strict` if you want the opposite trade: while a tunnel is live,
resolution that cannot stay inside the tunnel is simply reported as failed
instead of escaping. `[L]` is the backstop proof that no DNS escaped the tunnel
even in the fallback modes.

### Health scan shows failing probes
Press `[D]` to export diagnostics — it captures your config, routes, logs, and the last scan. Attach it to a GitHub issue for fastest help.

### How do I add a bypass?
Press `[A]` and enter an IP address. Routes are installed instantly without restarting the tunnel. Press `[X]` to remove a bypass.

### Can I use geo-based routing?
Yes. Press `[F]` to configure geo bypass. Requires a `geoip.dat` file (from v2rayN or Xray-core). Press `[R]` to re-apply the geo bypass live.

### Running alongside another VPN
Enable VPN mode with `[V]` and VPN bypass with `[Y]`. This lets TunTop ride your existing VPN connection instead of fighting for the default route.

## Troubleshooting

### Dashboard won't start
Ensure you're running as Administrator. TunTop needs admin rights to manage the Windows route table.

### Tunnel drops after sleep/wake
TunTop's self-healing should auto-recover. If it doesn't, press `[T]` to stop and `[S]` to restart. If the problem persists, export diagnostics with `[D]`.

### How do I report a bug?
Open a GitHub issue and attach the diagnostics file from `[D]`. It contains everything needed to diagnose the problem.

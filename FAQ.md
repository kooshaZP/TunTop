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

### Traffic isn't going through the tunnel
Run a leak test with `[L]` inside the dashboard. It compares your direct exit IP with the tunneled exit IP. If they **match**, all traffic — including "direct" traffic — is riding the tunnel (no leak). If the direct IP **differs** from the tunnel exit, direct traffic is escaping outside the tunnel (a leak). The tunnel's monitor loop runs this check automatically every cycle and logs the result as `[MONITOR] leak check ...` lines.

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

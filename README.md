# TunMood

[![CI](https://github.com/kooshaZP/tun-mood/actions/workflows/ci.yml/badge.svg)](https://github.com/kooshaZP/tun-mood/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-blue)](#requirements)
[![Python](https://img.shields.io/badge/python-3.10%2B-informational)](#requirements)

**Route all of your Windows traffic through any VLESS proxy — and watch it
happen live in a btop-style dashboard.**

TunMood drives a Wintun TUN adapter from your v2rayN (VLESS) proxy so every
app on the PC is tunneled, not just the browser: throughput graphs, a ~30-probe
health suite, instant bypass add/remove, geoip country splitting, profiles,
leak tests and one-key diagnostics — with **zero pip dependencies**.

> The dashboard builds and owns the tunnel itself; never run
> `tunmood/helper.py` directly.

<!-- Screenshots: drop images into docs/ and uncomment
![Dashboard](docs/dashboard.png)
-->

## ✨ Features

- **Full-tunnel routing** via Wintun + tun2socks (IPv4 *and* IPv6), VPN-proof split defaults
- **Live btop-style UI**: gradient area/line/braille throughput graphs, metric cards, health-check suite with ~30 probes, colored event log, 7 color themes, mouse support
- **Instant bypass add/remove** (`[A]`/`[X]`) — installs/deletes `/32`+`/128` routes live in a background thread; the tunnel keeps running
- **Geo bypass** — route a whole country direct from `geoip.dat` (live re-apply with `[R]`)
- **Everything editable at runtime**: servers `[U]`, VPN mode `[V]`, VPN bypass `[Y]`, geo `[F]`, SOCKS port `[P]`, DNS `[N]`, endpoint port `[E]`
- **Profiles** — save/load complete setups with `[O]` / `[I]`
- **Leak test `[L]`** — compares direct vs tunneled exit IPs; instantly proves the tunnel works
- **Diagnostics export `[D]`** — config + routes + logs + last scan in one file for bug reports
- **Self-healing helper** — monitors the tunnel and re-applies routes/DNS on failure
- **Clean teardown** — quitting verifies the route table is actually clear before exiting

## 🚀 Quick start

1. Install [v2rayN](https://github.com/2dust/v2rayN), add your VLESS server, enable the local SOCKS inbound (default `127.0.0.1:10808`).
2. Run **`Run_Helper.ps1`** from a terminal (`powershell -ExecutionPolicy Bypass -File Run_Helper.ps1`) or right-click → *Run with PowerShell* → confirm the UAC prompt.
   First run auto-downloads `tun2socks.exe` and `wintun.dll` if missing.
3. Pick VPN mode / glyph mode / geo bypass in the menus — the dashboard starts automatically.
4. Press **`[C]`** inside the dashboard to run the health scan and confirm everything passes.

### Requirements

| What | Why |
|------|-----|
| Windows 10 1803+ / 11 | `curl.exe`, Wintun |
| Python 3.10+ | only stdlib used |
| Administrator | route management |
| v2rayN running | provides the SOCKS5 inbound |

## ⌨️ Key reference

| Key | Action |
|-----|--------|
| `[C]` / `[S]` / `[T]` / `[Q]` | Health scan / start / stop / quit (verifies cleanup) |
| `[A]` / `[X]` | Add/remove bypass **instantly** (no tunnel restart) |
| `[B]` `[Z]` | Bypass panel · legacy restart-mode toggle |
| `[L]` `[D]` | Leak test · export diagnostics |
| `[O]` `[I]` | Save / load profile |
| `[U]` `[V]` `[Y]` `[F]` | Servers · VPN mode · VPN bypass · geo config |
| `[P]` `[N]` `[E]` | SOCKS port · DNS · endpoint port |
| `[R]` | Re-apply geoip country bypass live |
| `[G]` `[M]` `[H]` | Graph mode · theme · hide help |
| `1–6`, `0` | Hide/show panels |

## 📁 Files

```
Run_Helper.ps1            <- launcher + one-click installer (PowerShell)
tunmood/
  dashboard.py            <- the btop-style dashboard (owns the tunnel)
  helper.py               <- tunnel builder + self-heal monitor
  routing.py              <- netsh/PowerShell route engine (add/delete/verify)
  netdns.py               <- resolver: cache, UDP/53 + DoH fallbacks
  geoip.py                <- geoip.dat / JSON country-range parser
profiles.json             <- created when you save profiles
test_bypass_resolve.py    <- offline test suite (~70 checks)
test_bypass_remove.py     <- removal test suite (18 checks)
```

`tun2socks.exe` and `wintun.dll` are auto-downloaded on first run.

## 🧪 Tests

```powershell
python test_bypass_resolve.py      # fully offline, mocked DNS/routes
python test_bypass_remove.py
python test_bypass_resolve.py --live   # adds real DNS lookups
```

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Short version: run both test suites,
keep the UI stdlib-only, and include `diagnostics_[...].txt` ([D]) in bug reports.

## 📄 License

[MIT](LICENSE)

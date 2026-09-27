# DNS Problem

**What's happening?**
Describe the DNS issue (name resolution failing, DNS leaking outside the tunnel, wrong resolver, DoH/DoH failures, etc.).

**DNS leak guard (check this first)**
Since 1.0.40 TunTop installs a catch-all NRPT rule while a tunnel is up, pinning all name resolution to the tunnel resolvers. A leak test that still shows your ISP means the rule is missing, ineffective, or something wiped it. Please paste the result of:

- `[C]` → the row **"DNS leak protection (catch-all NRPT rule)"**
  (if it says *DISABLED by choice*, that is `--no-dns-guard` working as intended, not a fault)
- PowerShell (admin): `Get-DnsClientNrptPolicy -Effective`
- Did you start with `--no-dns-guard`, and is any of your own domains in `--dns-guard-exempt`?

**What did `[L]`'s DNS test say?**
- `no DNS leak` / `DNS LEAK: ...` → a real verdict. `DNS LEAK` naming an adapter means no catch-all rule was in force.
- `DNS leak UNKNOWN: ...` → TunTop could not read the guard state (PowerShell unavailable or the probe failed). This is **not** a confirmed leak; the message says which adapters are exposed and why the check was inconclusive. Please include the full line — an UNKNOWN is a probe problem, not a leak, and the two are reported differently on purpose.

**Diagnostics**
Attach the diagnostics file from `[D]` — it includes your DNS resolver state, adapter config, and the last health scan.

**Your setup:**
- Which DNS mode are you using? [Default / Custom / DoH — see `[N]`]
- Did `[C]` health scan show DNS as ✓ or ✗?
- Running alongside another VPN or custom resolver? [Yes/No]
- IPv6 enabled on your network? [Yes/No/Unknown]

**What you tried:**
- Did you press `[N]` to switch DNS servers?
- Did you run a leak test `[L]`? Did DNS leak, or did it report UNKNOWN?
- Did the health scan `[C]` pass?
- Did you try restarting the tunnel with `[T]` then `[S]`?

# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in TunTop, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, email the maintainer directly or use GitHub's private vulnerability reporting feature.

## What qualifies as a security issue

- TunTop runs as Administrator and modifies the Windows routing table. Any bug that could allow unintended route changes, traffic interception, or privilege escalation is a security issue.
- The binary integrity check (`tuntop/integrity.py`) verifies vendored `tun2socks.exe` and `wintun.dll` against pinned SHA-256 hashes. Bypassing or weakening this check is a security concern.
- The DNS leak guard (`tuntop/network/dns_guard.py`) writes a catch-all NRPT rule into `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig` while a tunnel is up. Two properties matter: it must only ever touch `TunTop-*` keys (a foreign rule — a corporate VPN's, DirectAccess's — must never be deleted), and it must be removed on every exit path, because a surviving rule keeps rewriting name resolution for every process on the machine. Failing either is a security issue; `--no-dns-guard` exists for users who opt out deliberately.
- Profile files (`MyTunTopProfile.json`) intentionally contain no secrets — only server addresses, ports, and settings. If sensitive data ever ends up in profiles, that is a bug.
- The geoip decode cache written next to the install is **plain JSON, never pickle** (`tuntop/geo/geoip.py`). It is read by the elevated helper from a directory the user can write, so any deserialization primitive there is privilege escalation. A geo CIDR decoding to a `/0` is rejected — a tampered database can misroute traffic, never take over the process.
- The auto-updater (`tuntop/config/updates.py`) pins TLS 1.2+ with hostname verification and enforces a GitHub host allow-list on **every redirect hop**, and re-checks the final URL. The release exe and its `checksums.txt` travel over the same allow-listed path, so a redirect cannot substitute either — nor the checksum that "verifies" the other.
- Process and route ownership: `tuntop/network/procguard.py` may only kill a `tun2socks` that this session spawned, that is the exact configured path, or that is the vendored file name **inside a TunTop-controlled directory**. The vendored name is also the upstream tun2socks release asset name, so a bare name match is not proof of ownership — killing a foreign proxy is a security issue. Route deletion is likewise scoped: a same-prefix route on an adapter outside TunTop's own scope is foreign and must survive.
- Teardown must never damage a *working* session: the crash watchdog re-checks the session marker **and its PID's liveness** immediately before its first destructive step, and refuses to sweep a dashboard that is still running.

## Scope

TunTop is a routing tool, not a cryptography tool. It relies on v2rayN for VLESS encryption. Security issues in v2rayN, tun2socks, or Wintun should be reported to their respective projects.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.0.x   | Yes       |
| < 1.0   | No        |

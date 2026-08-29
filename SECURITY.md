# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in TunTop, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, email the maintainer directly or use GitHub's private vulnerability reporting feature.

## What qualifies as a security issue

- TunTop runs as Administrator and modifies the Windows routing table. Any bug that could allow unintended route changes, traffic interception, or privilege escalation is a security issue.
- The binary integrity check (`tuntop/integrity.py`) verifies vendored `tun2socks.exe` and `wintun.dll` against pinned SHA-256 hashes. Bypassing or weakening this check is a security concern.
- Profile files (`profiles.json`) intentionally contain no secrets — only server addresses, ports, and settings. If sensitive data ever ends up in profiles, that is a bug.

## Scope

TunTop is a routing tool, not a cryptography tool. It relies on v2rayN for VLESS encryption. Security issues in v2rayN, tun2socks, or Wintun should be reported to their respective projects.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.0.x   | Yes       |
| < 1.0   | No        |

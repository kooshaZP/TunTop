# Known bugs and edge cases — v1.0 register (Phase 0)

Statuses: **OPEN** (affects users) / **COSMETIC** (no functional impact) /
**FIXED** (kept for history — do not delete rows).

| # | Severity | Status | Area | Description | Workaround |
|---|----------|--------|------|-------------|------------|
| 1 | blocker | FIXED | geo | `geo/geoip.py` lost `_read_varint`/`_read_bytes` in the package restructure — any `.dat` parse raised `NameError`. | — |
| 2 | blocker | FIXED | helper | `tunnel/helper.py:1487` called `_clean_err()` which was never defined in the helper process — geo route-batch failures crashed instead of reporting. | — |
| 3 | blocker | FIXED | profiles | `config/profiles.py:apply_to_args()` referenced undefined `_host_from_url` — loading a saved profile with bypass entries crashed. | — |
| 4 | blocker | FIXED | helper | GeoIP parse helpers `_read_varint`/`_read_bytes` were missing from the extracted `geo/geoip.py`. | — |
| 5 | cosmetic | OPEN | dashboard | Several unused imports/locals remain from the verbatim refactor (pyflakes clean except these). Intentionally left to keep the refactor diff minimal. | none needed |
| 6 | cosmetic | OPEN | compat | Tier facade modules (`tunnel/socks.py`, `network/vpn.py`, `monitor/leak.py`, `ui/widgets.py`, …) re-export via `import *` from the engine modules. Intentional compat layer; makes pyflakes unable to analyze them. | none needed |
| 7 | minor | OPEN | helper | `global vpn_override_routes` / `global vpn_saved_routes` declared but never assigned in that scope (dead declarations at helper.py:1133-area). | none needed |

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
- **Sleep/wake**: adapters can vanish and routes can be flushed by Windows.
  The next health poll must classify this as ADAPTER/ROUTES failure and
  recover with backoff.
- **Laptop with metered Wi-Fi**: geo `.dat` download (~10 MB) honors HTTP(S)
  proxies but has no "ask before downloading" prompt yet.

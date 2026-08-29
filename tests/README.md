# TunTop test suite

Pure-stdlib tests (`unittest`), zero pip dependencies, runnable on any OS.
Most tiers fake the Windows edges, so the whole suite runs without admin
rights, without a TUN adapter, and without touching the real network.

## Run

```bash
# everything except the live-network tier (what CI runs)
python -m unittest discover -s tests -t . -v

# one tier
python -m unittest discover -s tests/unit -t . -v

# including the real-network tier (needs Internet access)
TUNTOP_NET_TESTS=1 python -m unittest discover -s tests -t . -v
```

## Tiers

| Tier | What it covers | Fakes the network? |
|---|---|---|
| `unit/` | Pure logic: the tunnel state machine, dashboard text/layout helpers | fully |
| `routing/` | DNS wire format, transactional route changes, helper parsing (geoip varints, PowerShell quoting, routable-CIDR filter) | fully (in-memory routing table) |
| `recovery/` | The recovery engine, startup crash recovery, the full crash-loop storyline | fully |
| `integration/` | Several modules working together, incl. the dashboard's **real** bypass-install method with only the Windows edges patched out | Windows edges only |
| `network/` | Real DNS (system/UDP/DoH), real TCP egress | **no** - skipped unless `TUNTOP_NET_TESTS=1` |

## Conventions

* Test doubles live in `tests/fakes.py` (e.g. `FakeRouter`, the in-memory
  routing table) so every tier fakes Windows the same way.
* Anything that would modify the real system (kill processes, change
  routes) belongs in the `network/` tier or behind an env-var gate.
* The recovery engine's tests use `delay_scale=0.0` so backoff schedules
  are exercised instantly and deterministically; worker-thread timing is
  absorbed by `wait_for(...)` polling, never by fixed sleeps.
* `integration/check_tunnel_lifecycle.py` is a runnable script (not a
  unittest) that prints the state-machine event log for a simulated
  session - handy for eyeballing what the event panel would show:

  ```bash
  python tests/integration/check_tunnel_lifecycle.py
  ```

## CI

`.github/workflows/ci.yml` syntax-checks every module and runs the full
suite (minus the live-network tier) on Windows for Python 3.10-3.12.

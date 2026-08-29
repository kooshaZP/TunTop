# Contributing

Thanks for helping improve the v2ray TUN dashboard!

## Ground rules

1. **Standard library only.** The project deliberately has zero pip
   dependencies so it stays a one-click download. If you truly need a package,
   discuss it in an issue first.
2. **The UI must never block.** DNS, PowerShell and route operations belong on
   background threads; the draw loop and key handling stay instant.
3. **Cleanup is sacred.** Every feature that adds routes must be removable at
   exit, including when the helper child is force-killed.

## Workflow

```bash
# run the full test suite before every commit (no admin, no network needed)
python -m unittest discover -s tests -t . -v

# with the live-network tier included (needs Internet access)
TUNTOP_NET_TESTS=1 python -m unittest discover -s tests -t . -v
```

See `tests/README.md` for the tier layout (unit / routing / recovery /
integration / network). New features need tests in the matching tier;
bug fixes need a test that reproduces the bug first.

- Keep PRs focused: one feature or fix per PR.
- For UI changes, include a screenshot or GIF (the dashboard renders great in
  Windows Terminal).
- For bug reports, attach the file produced by the dashboard's `[D]`
  diagnostics export — it contains config, routes, logs and the last scan.

## Code style

- Python 3.10+, no type-checker enforced but keep annotations where they help.
- Comments explain *why*, not *what*.
- Match the existing naming (`_snake_case` helpers, `_blog` for thread-safe logs).

## Adding a health check

Health checks live in `build_checks()` (`tuntop/dashboard.py`). Each entry is
`(name, callable)` returning `(ok: bool, detail: str)`. PowerShell snippets are
fine; keep them under ~5 s and never raise.

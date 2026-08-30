"""Leak-test reporting (Monitor layer).

The actual probe logic runs inside the dashboard's health monitors; this
module re-exports the relevant helpers so the Monitor layer owns the
"did traffic escape the tunnel?" interface rather than the UI reaching into
the dashboard directly.
"""
from tuntop.ui.dashboard import *  # noqa: F401,F403

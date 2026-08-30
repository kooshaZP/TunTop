"""DNS resolution layer (Network layer).

The resolver implementation lives in ``tuntop.network.dns``; this module is
the public name the plan's layout uses for it (``resolver`` vs ``dns``), so
both import paths resolve to the same code.
"""
from tuntop.network.dns import *  # noqa: F401,F403

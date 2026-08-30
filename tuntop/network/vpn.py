"""VPN detection / coexistence logic (Network layer).

The Windows-side implementation lives in ``tuntop.tunnel.helper``; this name
is re-exported here so the layering reads Network -> Tunnel rather than the
UI reaching straight into the helper.
"""
from tuntop.tunnel.helper import *  # noqa: F401,F403

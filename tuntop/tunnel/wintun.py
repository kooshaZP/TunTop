"""Wintun adapter management (Tunnel layer).

Re-exported from ``tuntop.tunnel.helper`` where the Windows-side adapter
code lives. UI code should reach this through the Network/Core layers, not
by importing helper internals directly.
"""
from tuntop.tunnel.helper import *  # noqa: F401,F403

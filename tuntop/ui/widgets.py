"""Dashboard widgets / theme text (UI layer).

Re-exported from ``tuntop.ui.themes`` so the UI layer owns the rendering
primitives (box drawing, gradients, colour palettes) rather than the UI
reaching into the top-level ``ui_text`` module by its old name.
"""
from tuntop.ui.themes import *  # noqa: F401,F403

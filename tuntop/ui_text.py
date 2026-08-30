# Backward-compatibility shim: this module moved to tuntop.ui.themes.
# tuntop.themes is now an alias of tuntop.ui.themes (see Phase 1 restructure).
import sys
from tuntop.ui import themes as _tuntop_real
sys.modules[__name__] = _tuntop_real


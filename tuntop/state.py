# Backward-compatibility shim: this module moved to tuntop.core.state.
# tuntop.state is now an alias of tuntop.core.state (see Phase 1 restructure).
import sys
from tuntop.core import state as _tuntop_real
sys.modules[__name__] = _tuntop_real


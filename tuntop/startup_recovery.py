# Backward-compatibility shim: this module moved to tuntop.core.startup_recovery.
# tuntop.startup_recovery is now an alias of tuntop.core.startup_recovery (see Phase 1 restructure).
import sys
from tuntop.core import startup_recovery as _tuntop_real
sys.modules[__name__] = _tuntop_real


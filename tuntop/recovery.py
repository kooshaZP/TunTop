# Backward-compatibility shim: this module moved to tuntop.core.recovery.
# tuntop.recovery is now an alias of tuntop.core.recovery (see Phase 1 restructure).
import sys
from tuntop.core import recovery as _tuntop_real
sys.modules[__name__] = _tuntop_real


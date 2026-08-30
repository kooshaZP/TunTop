# Backward-compatibility shim: this module moved to tuntop.core.integrity.
# tuntop.integrity is now an alias of tuntop.core.integrity (see Phase 1 restructure).
import sys
from tuntop.core import integrity as _tuntop_real
sys.modules[__name__] = _tuntop_real


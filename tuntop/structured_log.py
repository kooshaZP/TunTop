# Backward-compatibility shim: this module moved to tuntop.core.events.
# tuntop.structured_log is now an alias of tuntop.core.events (see Phase 1 restructure).
import sys
from tuntop.core import events as _tuntop_real
sys.modules[__name__] = _tuntop_real


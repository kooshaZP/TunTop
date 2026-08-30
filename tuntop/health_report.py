# Backward-compatibility shim: this module moved to tuntop.monitor.health.
# tuntop.health is now an alias of tuntop.monitor.health (see Phase 1 restructure).
import sys
from tuntop.monitor import health as _tuntop_real
sys.modules[__name__] = _tuntop_real


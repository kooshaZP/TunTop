# Backward-compatibility shim: this module moved to tuntop.network.routing.
# tuntop.routing is now an alias of tuntop.network.routing (see Phase 1 restructure).
import sys
from tuntop.network import routing as _tuntop_real
sys.modules[__name__] = _tuntop_real


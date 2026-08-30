# Backward-compatibility shim: this module moved to tuntop.network.dns.
# tuntop.dns is now an alias of tuntop.network.dns (see Phase 1 restructure).
import sys
from tuntop.network import dns as _tuntop_real
sys.modules[__name__] = _tuntop_real


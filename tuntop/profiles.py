# Backward-compatibility shim: this module moved to tuntop.config.profiles.
# tuntop.profiles is now an alias of tuntop.config.profiles (see Phase 1 restructure).
import sys
from tuntop.config import profiles as _tuntop_real
sys.modules[__name__] = _tuntop_real


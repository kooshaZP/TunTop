# Backward-compatibility shim: this module moved to tuntop.geo.geoip.
# tuntop.geoip is now an alias of tuntop.geo.geoip (see Phase 1 restructure).
import sys
from tuntop.geo import geoip as _tuntop_real
sys.modules[__name__] = _tuntop_real


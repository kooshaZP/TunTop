# Backward-compatibility shim: this module moved to tuntop.core.routes_txn.
# tuntop.routes_txn is now an alias of tuntop.core.routes_txn (see Phase 1 restructure).
import sys
from tuntop.core import routes_txn as _tuntop_real
sys.modules[__name__] = _tuntop_real


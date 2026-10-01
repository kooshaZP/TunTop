"""Residue record - the crash-recoverable list of what this session left behind.

Two of TunTop's network edits cannot be undone from a ledger in memory, because
the process holding that ledger may simply be gone when the machine is inspected:

  * the MACHINE-WIDE DoH templates `Add-DnsClientDohServer` writes under
    `HKLM\\...\\DNSClient\\DnsPolicyConfig`-adjacent registry storage. The mapping
    outlives the adapter it was registered for and outlives the process that
    registered it;
  * the physical adapter's `InterfaceMetric`, lowered by
    `ensure_physical_metric_below_vpn()` so geo bypass routes beat a connected
    Windows VPN's identical-prefix routes. The original value used to live in a
    module global (`helper.phys_bypass_metric_saved`), so a hard kill - Task
    Manager, power loss - left the machine's Wi-Fi at a metric TunTop chose,
    forever, with no record of what it had been.

Both are written here instead, atomically, so the next owner that runs - the
helper's own `cleanup()`, the dashboard's exit sweeps, startup recovery, or the
detached cleanup watchdog - can undo them even when none of them is the process
that made the change.

WHY A SEPARATE FILE AND NOT THE WATCHDOG SIDECAR
-------------------------------------------------
`.cleanup_watchdog_state.json` is rewritten WHOLESALE by the dashboard on every
`[A]`/`[F]`/`[R]` change, and appended to by the helper running concurrently. Two
writers, one of which does not read before it writes, means one of them loses
data on every race - and the data lost is exactly the residue this module exists
to remember. So the helper-owned records live in their own file with a
read-modify-write that cannot clobber a concurrent writer's keys.

OWNERSHIP
---------
Every write stamps the owner's pid AND its creation time. A reader that finds a
record naming a LIVE process (the same identity test `dns_guard` uses for its
install record) must not "restore" it out from under a running session: that
would undo the live tunnel's own settings mid-flight. A record whose pid is
dead, or whose creation time no longer matches, is unambiguously abandoned and
is acted on.

Pure stdlib. Windows-only commands live in the callers; this module is file and
JSON handling and unit-tests anywhere.
"""
from __future__ import annotations

import json
import os
import sys
import time
from typing import Optional

from tuntop import procidentity

__all__ = [
    "RESIDUE_FILE", "residue_path", "load", "save_doh_servers", "clear_doh_servers",
    "load_doh_servers", "save_physical_metric", "clear_physical_metric",
    "load_physical_metric", "record_owner_alive", "stamp", "merge",
]

#: Where the record lives. Frozen exe: next to TunTop.exe, so every process
#: launched from the same install agrees on the path (the helper child and the
#: watchdog child each get their own throwaway `_MEI` extraction dir, so
#: `__file__` is not a usable anchor there). Source run: next to this module -
#: the same rule `dns_guard.STATE_FILE` and `startup_recovery.MARKER_FILE` use.
RESIDUE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            ".tuntop_residue.json")
if getattr(sys, "frozen", False):
    RESIDUE_FILE = os.path.join(
        os.path.dirname(os.path.abspath(sys.executable)),
        ".tuntop_residue.json")

RECORD_VERSION = 1


def residue_path() -> str:
    """The record's path, read through a function so a test can redirect the
    module global without touching the filesystem."""
    return RESIDUE_FILE


# ── Atomic read-modify-write ────────────────────────────────────────────────

def _atomic_write(path: str, payload: dict) -> bool:
    """Write JSON so a concurrent reader never observes a partial file.

    `open(path, "w")` truncates to zero before the first write lands, and every
    reader here runs in a DIFFERENT process (the dashboard, the helper, the
    watchdog). A reader landing in that window got "", json.load raised, and it
    concluded "nothing to clean up" - while a DoH template or a lowered metric
    was still on the machine. Same reasoning, and the same `os.replace`
    (atomic on Windows for same-volume paths), as `dns_guard.save_state` and
    `startup_recovery._atomic_write_json`.

    The unique temp name matters for the same reason: the helper and the
    dashboard can both be writing this file at once, and a shared `.tmp` would
    make them overwrite each other's partial write.
    """
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        return True
    except Exception:
        return False
    finally:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except OSError:
            pass


def stamp(payload: Optional[dict] = None) -> dict:
    """Return `payload` (or a fresh dict) stamped with this process's identity
    and the record version."""
    data = dict(payload or {})
    data["version"] = RECORD_VERSION
    pid = os.getpid()
    data["pid"] = pid
    data["started"] = procidentity.process_start_time(pid)
    data["since"] = time.time()
    return data


def merge(path: str, key: str, value) -> bool:
    """Set `key` to `value` in the record at `path`, keeping every other key,
    and re-stamp ownership. Never raises; returns whether it was written.

    Read-modify-write, with the write retried once: the dashboard rewrites its
    own sidecar wholesale in a tight loop on some UI paths, so a lost update here
    is a real possibility and a single retry makes it vanishingly unlikely
    without needing a lock file. A key set to `None` is DROPPED rather than
    stored - an explicit "nothing to clean up for this category" must not leave
    a stale value behind that a later reader would act on.
    """
    for attempt in (0, 1):
        current = load(path) or {}
        if value is None:
            current.pop(key, None)
        else:
            current[key] = value
        if _atomic_write(path, stamp(current)):
            return True
        if attempt:
            return False
    return False


def load(path: Optional[str] = None) -> dict:
    """The record as a dict, or {} when absent/corrupt/not a dict.

    A corrupt record is treated as absent on purpose: the entries it held are
    residue we would like to remove, but guessing at their contents could remove
    something we never installed. Losing the record costs a leftover; acting on a
    half-read one could cost the user a setting.
    """
    target = path or residue_path()
    try:
        with open(target, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


# ── DoH templates ───────────────────────────────────────────────────────────

def load_doh_servers(path: Optional[str] = None) -> list:
    """The resolver addresses THIS project registered DoH for.

    Only entries this project wrote are ever named here, so a user's own
    pre-existing DoH mapping for the same address (they configured it for their
    browser, say) is not in the list and is never removed."""
    raw = load(path).get("doh_servers")
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw:
        s = str(item or "").strip()
        if s and s not in out:
            out.append(s)
    return out


def save_doh_servers(servers, path: Optional[str] = None) -> bool:
    """Record the DoH mappings we just registered. `None`/empty clears them."""
    addrs = [str(s).strip() for s in (servers or []) if str(s).strip()]
    return merge(path or residue_path(), "doh_servers",
                 addrs or None)


def clear_doh_servers(path: Optional[str] = None) -> None:
    save_doh_servers(None, path=path)


# ── Physical adapter InterfaceMetric ────────────────────────────────────────

def load_physical_metric(path: Optional[str] = None) -> Optional[tuple]:
    """`(iface, metric)` to restore, or None.

    The metric must be a plain int. A record carrying anything else - a string
    from an older version, a float, a truncated write - is discarded rather than
    passed to `Set-NetIPInterface -InterfaceMetric`, which would either reject
    the command or write a nonsense metric onto a live adapter."""
    entry = load(path).get("physical_metric")
    if not isinstance(entry, dict):
        return None
    iface = str(entry.get("iface") or "").strip()
    metric = entry.get("metric")
    if not iface or not isinstance(metric, int) or isinstance(metric, bool):
        return None
    return iface, metric


def save_physical_metric(iface, metric, path: Optional[str] = None) -> bool:
    """Record the physical adapter's original InterfaceMetric."""
    if not iface or not isinstance(metric, int) or isinstance(metric, bool):
        return False
    return merge(path or residue_path(), "physical_metric",
                 {"iface": str(iface).strip(), "metric": int(metric)})


def clear_physical_metric(path: Optional[str] = None) -> None:
    merge(path or residue_path(), "physical_metric", None)


# ── Ownership ───────────────────────────────────────────────────────────────

def record_owner_alive(record: Optional[dict]) -> bool:
    """True when the record names a live process that is NOT us.

    The multi-instance hazard, identical in shape to
    `dns_guard.record_owner_alive`: a second TunTop's recovery pass must not
    "restore" a metric or strip a DoH mapping out from under a first TunTop that
    is still running with a live tunnel - that would change its DNS transport
    mid-session.

    The pid alone cannot answer this - it is a recycled slot - so a record
    carrying `started` is honoured only when the live process demonstrably IS
    the recorded one. A mismatch (or an unreadable creation time) means the
    number now belongs to somebody else, and the answer is False: the leftover
    is then actionable, which is the direction every recovery path wants.
    """
    if not isinstance(record, dict):
        return False
    pid = record.get("pid")
    if pid is None:
        return False
    try:
        if int(pid) == os.getpid():
            return False
    except (TypeError, ValueError):
        return False
    if record.get("started") is not None and \
            not procidentity.same_process(pid, record.get("started")):
        return False
    return procidentity.process_alive(pid)

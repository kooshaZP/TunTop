"""Process IDENTITY, not just process liveness - a stdlib leaf.

A bare PID answers "is a process running?", never "is it the SAME process?".
PIDs are slots in a table the OS recycles: after a reboot, or a hard crash
that skipped every teardown, yesterday's PID is plausibly alive today as
something entirely unrelated. Several records on disk outlive the process
that wrote them (the DNS guard's install record, the crash marker the
cleanup watchdog reads), and three of them decide whether to DELETE or
FORCE-KILL something on the strength of that number alone.

This module is the one place that knows how to ask the second question, so
a fix cannot land in one copy and silently miss the other. It is a pure
stdlib leaf with zero tuntop imports - the same pattern as
tuntop/psshell.py - because both the Network layer (dns_guard) and the Core
layer (startup_recovery) need it and neither may import the other.

Every function here NEVER raises. A probe that cannot answer returns None or
False; callers decide what an unknown means, which is a policy decision and
does not belong in the plumbing.
"""
from __future__ import annotations

import os
import time
from typing import Optional

__all__ = ["process_start_time", "same_process", "process_alive"]

#: Windows FILETIME counts 100 ns ticks from 1601-01-01; the Unix epoch is
#: 11644473600 seconds later. Kept as an int so the conversion is exact.
_EPOCH_DELTA_TICKS = 116444736000000000

_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_STILL_ACTIVE = 259


def process_start_time(pid) -> Optional[int]:
    """`pid`'s creation time as whole seconds since the Unix epoch, or None
    when it cannot be determined.

    Compare this against a previously recorded value to establish identity:
    equal means the same process, different means the PID was recycled. None
    means UNKNOWN, which every caller must treat as unproven rather than as
    a match.

    Windows: GetProcessTimes. Linux: /proc/<pid>/stat plus the system boot
    time. Anything else (macOS exposes no portable equivalent) returns None.
    """
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return None
    if pid <= 0:
        return None
    if os.name == "nt":
        return _win_start_time(pid)
    return _procfs_start_time(pid)


def _win_start_time(pid: int) -> Optional[int]:
    try:
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.windll.kernel32
        k32.OpenProcess.restype = wintypes.HANDLE
        k32.GetProcessTimes.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME)]
        h = k32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            return None
        try:
            created = wintypes.FILETIME()
            exit_, kernel, user = (wintypes.FILETIME() for _ in range(3))
            if not k32.GetProcessTimes(h, ctypes.byref(created),
                                       ctypes.byref(exit_), ctypes.byref(kernel),
                                       ctypes.byref(user)):
                return None
            ticks = (created.dwHighDateTime << 32) | created.dwLowDateTime
            return (ticks - _EPOCH_DELTA_TICKS) // 10_000_000
        finally:
            k32.CloseHandle(h)
    except Exception:
        return None


def _procfs_start_time(pid: int) -> Optional[int]:
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            blob = f.read()
        with open("/proc/uptime", "rb") as f:
            uptime = float(f.read().split()[0])
        # comm (field 2) is parenthesised and may itself contain spaces and
        # parentheses, so split after the LAST ')' to keep later fields in
        # their real positions. starttime is field 22, i.e. tail index 19.
        tail = blob[blob.rindex(b")") + 2:].split()
        starttime = int(tail[19])
        hz = os.sysconf("SC_CLK_TCK")
        return int((time.time() - uptime) - starttime / float(hz))
    except Exception:
        return None


def same_process(pid, recorded_start) -> bool:
    """True only when `pid` is demonstrably the process that recorded
    `recorded_start`.

    Fail CLOSED, deliberately. An unreadable creation time, a missing record
    (an old on-disk record written before start times were tracked), or a
    mismatched value all return False: nothing here should ever authorise
    killing a process on a bare number. A caller that genuinely must act on
    an unprovable PID belongs in the code that owns that PID, not here.
    """
    if recorded_start is None:
        return False
    try:
        recorded_start = int(recorded_start)
    except (TypeError, ValueError):
        return False
    live = process_start_time(pid)
    if live is None:
        return False
    return live == recorded_start


def process_alive(pid) -> bool:
    """True when `pid` is a RUNNING process. Unknown reads as DEAD.

    That direction is chosen by the callers, and it is the right one for
    both: a false "dead" only means a leftover gets cleaned up, while a
    false "alive" strands a machine-wide DNS pin or protects a crashed
    session's state forever. This process is trivially alive.

    A BOOL IS NOT A PID. `int(True)` is 1, so the coercion below used to turn
    a stray `True` into a liveness question about PID 1 - which is alive on
    every POSIX host, so the function answered "yes, PID 1 is running" and a
    caller asking about a malformed record was told the owner was alive. That
    is the dangerous direction this docstring exists to prevent, and it was
    invisible on Windows only because OpenProcess on PID 1 fails there for an
    unrelated reason. Reject the type rather than answer about a PID the
    caller never named.
    """
    if isinstance(pid, bool):
        return False
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    if pid == os.getpid():
        return True
    if os.name != "nt":
        return _procfs_start_time(pid) is not None
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            # ERROR_ACCESS_DENIED (5) does mean a process exists, but the
            # owner being unreadable is not evidence it is the one the record
            # names - and this function's contract is "unknown means dead".
            return False
        try:
            code = ctypes.c_ulong(0)
            if not k32.GetExitCodeProcess(h, ctypes.byref(code)):
                return False
            return code.value == _STILL_ACTIVE
        finally:
            k32.CloseHandle(h)
    except Exception:
        return False

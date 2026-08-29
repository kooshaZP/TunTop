"""Structured logging for TunTop.

Every event is a LogRecord with timestamp, severity, component, message,
and optional state/details.  A LogRing keeps the last N records in memory
for the dashboard's event panel and the diagnostics export.

Usage:
    from tuntop.logging import LogRing, DEBUG, INFO, WARNING, ERROR

    ring = LogRing(capacity=200)
    ring.log(INFO, "ROUTING", "default route installed")
    ring.log(INFO, "TUNNEL", "tun2socks connected", state="RUNNING")
    ring.log(ERROR, "DNS", "DoH timeout", details="https://dns.google/resolve?...")

    # Render for the dashboard event panel
    for line in ring.format_recent(10):
        print(line)

    # Render for diagnostics export
    text = ring.dump_text()

    # JSON snapshot
    data = ring.snapshot_json()

Pure stdlib, zero pip dependencies.
"""
from __future__ import annotations

import json
import threading
import time
from collections import deque
from enum import IntEnum


class Severity(IntEnum):
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40


# Convenience aliases
DEBUG = Severity.DEBUG
INFO = Severity.INFO
WARNING = Severity.WARNING
ERROR = Severity.ERROR

_SEV_LABELS = {
    Severity.DEBUG: "DEBUG",
    Severity.INFO: "INFO",
    Severity.WARNING: "WARN",
    Severity.ERROR: "ERROR",
}


class LogRecord:
    """One structured log entry."""
    __slots__ = ("ts", "severity", "component", "message",
                 "state", "details")

    def __init__(self, severity: Severity, component: str, message: str,
                 state: str | None = None, details: str | None = None):
        self.ts = time.time()
        self.severity = severity
        self.component = component
        self.message = message
        self.state = state
        self.details = details

    def format(self, use_unicode: bool = True) -> str:
        """Human-readable line: '12:42:11 INFO  ROUTING  default route installed'."""
        ts_str = time.strftime("%H:%M:%S", time.localtime(self.ts))
        sev = _SEV_LABELS.get(self.severity, "?")
        comp = self.component.ljust(10)
        line = f"{ts_str} {sev}  {comp} {self.message}"
        if self.state:
            line += f" [{self.state}]"
        if not use_unicode:
            line = "".join(ch if 32 <= ord(ch) < 127 or ch in "\t" else "."
                           for ch in line)
        return line

    def to_dict(self) -> dict:
        """JSON-safe dict."""
        d = {
            "ts": self.ts,
            "ts_human": time.strftime("%Y-%m-%d %H:%M:%S",
                                      time.localtime(self.ts)),
            "severity": _SEV_LABELS.get(self.severity, "?"),
            "component": self.component,
            "message": self.message,
        }
        if self.state:
            d["state"] = self.state
        if self.details:
            d["details"] = self.details
        return d


class LogRing:
    """Bounded ring buffer of LogRecords, thread-safe.

    The dashboard's event panel reads the most recent N records;
    the diagnostics export dumps everything.
    """

    def __init__(self, capacity: int = 200):
        self._cap = capacity
        self._buf: deque[LogRecord] = deque(maxlen=capacity)
        self._lock = threading.Lock()

    def log(self, severity: Severity, component: str, message: str,
            state: str | None = None, details: str | None = None) -> LogRecord:
        """Append a record and return it."""
        rec = LogRecord(severity, component, message, state, details)
        with self._lock:
            self._buf.append(rec)
        return rec

    def recent(self, n: int | None = None) -> list[LogRecord]:
        """Return the last N records (or all if n is None), newest last."""
        with self._lock:
            items = list(self._buf)
        if n is not None:
            items = items[-n:]
        return items

    def format_recent(self, n: int = 20, use_unicode: bool = True) -> list[str]:
        """Format the last N records as displayable strings."""
        return [r.format(use_unicode) for r in self.recent(n)]

    def dump_text(self, use_unicode: bool = True) -> str:
        """Full log as a single text block (for diagnostics export)."""
        return "\n".join(r.format(use_unicode) for r in self.recent())

    def snapshot_json(self) -> str:
        """JSON dump of all records (for structured diagnostics)."""
        return json.dumps([r.to_dict() for r in self.recent()],
                          indent=1, default=str)

    def clear(self):
        """Drop all records."""
        with self._lock:
            self._buf.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._buf)

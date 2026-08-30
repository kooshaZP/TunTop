"""Live traffic statistics (Monitor layer).

A small, self-contained ring of throughput samples the dashboard feeds from
its telemetry thread. Kept dependency-free so it can be unit-tested without
a running tunnel.
"""
from __future__ import annotations

import collections
import time


class TrafficStats:
    """Rolling window of download/upload byte counters."""

    def __init__(self, window: int = 60):
        self._window = window
        self._samples = collections.deque()   # (ts, rx_bytes, tx_bytes)

    def record(self, rx_bytes: int, tx_bytes: int, ts: float = None) -> None:
        ts = ts if ts is not None else time.time()
        self._samples.append((ts, rx_bytes, tx_bytes))
        while self._samples and ts - self._samples[0][0] > self._window:
            self._samples.popleft()

    def rate(self) -> tuple:
        """Return (rx_bytes_per_s, tx_bytes_per_s) over the window."""
        if len(self._samples) < 2:
            return (0, 0)
        t0, r0, x0 = self._samples[0]
        t1, r1, x1 = self._samples[-1]
        dt = max(t1 - t0, 1e-6)
        return ((r1 - r0) / dt, (x1 - x0) / dt)

    def __len__(self) -> int:
        return len(self._samples)

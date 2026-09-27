"""Live traffic statistics (Monitor layer).

A small, self-contained ring of throughput samples the dashboard feeds from
its telemetry thread. Kept dependency-free so it can be unit-tested without
a running tunnel.
"""
from __future__ import annotations

import collections
import threading
import time


class TrafficStats:
    """Rolling window of download/upload byte counters.

    record() runs on the telemetry thread and rate() on the UI thread, so the
    deque is guarded: without it, a telemetry pass that trims the whole
    window between rate()'s len() check and its two index reads raised
    IndexError inside the dashboard's draw path.
    """

    def __init__(self, window: int = 60):
        self._window = window
        self._samples = collections.deque()   # (ts, rx_bytes, tx_bytes)
        self._lock = threading.Lock()

    def record(self, rx_bytes: int, tx_bytes: int, ts: float = None) -> None:
        ts = ts if ts is not None else time.time()
        with self._lock:
            self._samples.append((ts, rx_bytes, tx_bytes))
            while self._samples and ts - self._samples[0][0] > self._window:
                self._samples.popleft()

    def rate(self) -> tuple:
        """Return (rx_bytes_per_s, tx_bytes_per_s) over the window.

        A counter reset (interface index change, adapter restart) shows up
        as a smaller value than the previous sample; the resulting negative
        rate is clamped to 0 rather than plotted as a spike downwards.
        """
        with self._lock:
            if len(self._samples) < 2:
                return (0, 0)
            t0, r0, x0 = self._samples[0]
            t1, r1, x1 = self._samples[-1]
        dt = max(t1 - t0, 1e-6)
        return (max(r1 - r0, 0) / dt, max(x1 - x0, 0) / dt)

    def __len__(self) -> int:
        with self._lock:
            return len(self._samples)

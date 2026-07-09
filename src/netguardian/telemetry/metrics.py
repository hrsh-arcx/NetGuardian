"""
netguardian.telemetry.metrics — In-Memory Metrics Collector

Thread-safe counters, gauges, and histograms for tracking proxy
performance. Designed to be queried by the StatsExporter on a
periodic interval without locking the hot path.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class HistogramBucket:
    """Accumulates values for percentile calculation."""
    values: List[float] = field(default_factory=list)
    max_samples: int = 10000

    def record(self, value: float) -> None:
        if len(self.values) >= self.max_samples:
            # Ring-buffer style: drop oldest 20% to bound memory
            self.values = self.values[self.max_samples // 5:]
        self.values.append(value)

    def percentile(self, p: float) -> float:
        if not self.values:
            return 0.0
        sorted_vals = sorted(self.values)
        idx = int(len(sorted_vals) * p / 100)
        return sorted_vals[min(idx, len(sorted_vals) - 1)]

    def mean(self) -> float:
        return sum(self.values) / len(self.values) if self.values else 0.0

    def count(self) -> int:
        return len(self.values)

    def reset(self) -> None:
        self.values.clear()


class MetricsCollector:
    """
    Central metrics store. All proxy subsystems report here.

    Three metric types:
      - Counters: monotonically increasing (e.g., total_connections)
      - Gauges: current point-in-time value (e.g., active_connections)
      - Histograms: distribution of values (e.g., request_latency_ms)
    """

    def __init__(self):
        self._lock = asyncio.Lock()
        self._counters: Dict[str, int] = defaultdict(int)
        self._gauges: Dict[str, float] = defaultdict(float)
        self._histograms: Dict[str, HistogramBucket] = defaultdict(HistogramBucket)
        self._start_time = time.monotonic()

    # ── Counters ──

    async def increment(self, name: str, value: int = 1) -> None:
        async with self._lock:
            self._counters[name] += value

    def increment_sync(self, name: str, value: int = 1) -> None:
        """Non-async variant for use in callbacks and signal handlers."""
        self._counters[name] += value

    async def get_counter(self, name: str) -> int:
        async with self._lock:
            return self._counters[name]

    # ── Gauges ──

    async def set_gauge(self, name: str, value: float) -> None:
        async with self._lock:
            self._gauges[name] = value

    async def adjust_gauge(self, name: str, delta: float) -> None:
        async with self._lock:
            self._gauges[name] += delta

    async def get_gauge(self, name: str) -> float:
        async with self._lock:
            return self._gauges[name]

    # ── Histograms ──

    async def record(self, name: str, value: float) -> None:
        async with self._lock:
            self._histograms[name].record(value)

    async def get_histogram(self, name: str) -> Optional[HistogramBucket]:
        async with self._lock:
            return self._histograms.get(name)

    # ── Snapshots ──

    async def snapshot(self) -> Dict:
        """
        Frozen copy of all metrics. Safe to serialize or display
        without holding the lock.
        """
        async with self._lock:
            uptime = time.monotonic() - self._start_time
            hist_snap = {}
            for name, bucket in self._histograms.items():
                hist_snap[name] = {
                    "count": bucket.count(),
                    "mean": round(bucket.mean(), 3),
                    "p50": round(bucket.percentile(50), 3),
                    "p95": round(bucket.percentile(95), 3),
                    "p99": round(bucket.percentile(99), 3),
                }
            return {
                "uptime_seconds": round(uptime, 2),
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "histograms": hist_snap,
            }

    async def reset(self) -> None:
        """Clear all metrics (useful in tests)."""
        async with self._lock:
            self._counters.clear()
            self._gauges.clear()
            for h in self._histograms.values():
                h.reset()
            self._start_time = time.monotonic()

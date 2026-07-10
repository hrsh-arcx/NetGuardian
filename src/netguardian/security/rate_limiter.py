"""
netguardian.security.rate_limiter — Token Bucket Rate Limiter

Limits requests per source IP using the token bucket algorithm.
Each IP gets its own bucket that refills at a constant rate.
Stale buckets are periodically cleaned up to bound memory.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class RateLimitResult:
    """Result of a rate limit check."""
    allowed: bool
    remaining_tokens: float
    source_ip: str


@dataclass
class _Bucket:
    """Internal token bucket for a single source IP."""
    tokens: float
    last_refill: float
    max_tokens: float
    refill_rate: float  # tokens per second

    def consume(self) -> bool:
        """Try to consume one token. Returns True if allowed."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.max_tokens, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class RateLimiter:
    """
    Per-IP token bucket rate limiter.

    Each source IP gets a bucket with `burst_size` max tokens that
    refills at `requests_per_second` tokens/sec. When a bucket is
    empty, requests are denied until tokens refill.
    """

    def __init__(
        self,
        requests_per_second: float = 50,
        burst_size: int = 100,
        cleanup_interval: int = 60,
    ):
        self._rps = requests_per_second
        self._burst = float(burst_size)
        self._cleanup_interval = cleanup_interval
        self._buckets: Dict[str, _Bucket] = {}
        self._cleanup_task: Optional[asyncio.Task] = None

    def check(self, source_ip: str) -> RateLimitResult:
        """Check if a request from `source_ip` is allowed."""
        bucket = self._buckets.get(source_ip)
        if bucket is None:
            bucket = _Bucket(
                tokens=self._burst,
                last_refill=time.monotonic(),
                max_tokens=self._burst,
                refill_rate=self._rps,
            )
            self._buckets[source_ip] = bucket

        allowed = bucket.consume()
        return RateLimitResult(
            allowed=allowed,
            remaining_tokens=max(0, bucket.tokens),
            source_ip=source_ip,
        )

    async def start_cleanup(self) -> None:
        """Launch background task to prune stale buckets."""
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def stop_cleanup(self) -> None:
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

    async def _cleanup_loop(self) -> None:
        while True:
            await asyncio.sleep(self._cleanup_interval)
            self._prune_stale()

    def _prune_stale(self) -> None:
        """Remove buckets that have been full (idle) for too long."""
        now = time.monotonic()
        stale_threshold = self._cleanup_interval * 2
        stale_ips = [
            ip for ip, bucket in self._buckets.items()
            if (now - bucket.last_refill) > stale_threshold
        ]
        for ip in stale_ips:
            del self._buckets[ip]

    def stats(self) -> dict:
        return {
            "tracked_ips": len(self._buckets),
            "requests_per_second": self._rps,
            "burst_size": self._burst,
        }

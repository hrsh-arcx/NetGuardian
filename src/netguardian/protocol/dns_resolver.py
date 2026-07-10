"""
netguardian.protocol.dns_resolver — Async DNS with LRU Cache

Wraps asyncio.getaddrinfo with a time-limited cache so repeated
requests to the same host don't hit the OS resolver every time.
Cache entries expire after a configurable TTL.
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from typing import List, Optional, Tuple


class DnsResolver:
    """Async DNS resolver with TTL-based LRU cache."""

    def __init__(self, cache_size: int = 256, ttl: int = 300, retries: int = 2):
        self._cache_size = cache_size
        self._ttl = ttl
        self._retries = retries
        # OrderedDict for LRU eviction: key → (addresses, expiry_time)
        self._cache: OrderedDict[str, Tuple[List[str], float]] = OrderedDict()

    async def resolve(self, hostname: str, port: int = 80) -> List[str]:
        """
        Resolve hostname to a list of IP addresses.
        Returns cached result if still valid, otherwise queries the OS.
        """
        now = time.monotonic()

        # Check cache
        if hostname in self._cache:
            addresses, expiry = self._cache[hostname]
            if now < expiry:
                self._cache.move_to_end(hostname)  # LRU touch
                return addresses
            else:
                del self._cache[hostname]  # expired

        # Resolve with retries
        last_error: Optional[Exception] = None
        for attempt in range(self._retries + 1):
            try:
                infos = await asyncio.get_running_loop().getaddrinfo(
                    hostname, port,
                    family=0,  # AF_UNSPEC — both IPv4 and IPv6
                    type=asyncio.streams.socket.SOCK_STREAM,
                )
                addresses = list({info[4][0] for info in infos})
                if not addresses:
                    raise OSError(f"No addresses found for {hostname}")

                # Cache the result
                self._cache[hostname] = (addresses, now + self._ttl)
                self._cache.move_to_end(hostname)

                # Evict oldest if cache is full
                while len(self._cache) > self._cache_size:
                    self._cache.popitem(last=False)

                return addresses

            except OSError as e:
                last_error = e
                if attempt < self._retries:
                    await asyncio.sleep(0.1 * (attempt + 1))  # backoff

        raise OSError(f"DNS resolution failed for {hostname}: {last_error}")

    def cache_stats(self) -> dict:
        """Return cache statistics for telemetry."""
        now = time.monotonic()
        valid = sum(1 for _, (_, exp) in self._cache.items() if now < exp)
        return {
            "total_entries": len(self._cache),
            "valid_entries": valid,
            "expired_entries": len(self._cache) - valid,
            "max_size": self._cache_size,
        }

    def clear_cache(self) -> None:
        self._cache.clear()

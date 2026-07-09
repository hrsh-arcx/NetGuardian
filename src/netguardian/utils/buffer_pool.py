"""
netguardian.utils.buffer_pool — Reusable Byte Buffer Pool

Key optimization:
    - Buffers are `bytearray` objects, which are mutable (unlike `bytes`).
    - `memoryview` slices avoid copying when you only need part of a buffer.
    - The pool has a fixed capacity; if exhausted, callers wait (backpressure).

"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator


class BufferPool:

    def __init__(self, buffer_size: int = 65536, pool_size: int = 128):
        if buffer_size <= 0:
            raise ValueError(f"buffer_size must be positive, got {buffer_size}")
        if pool_size <= 0:
            raise ValueError(f"pool_size must be positive, got {pool_size}")

        self.buffer_size = buffer_size #Size of each buffer in bytes
        self.pool_size = pool_size     #Maximum number of buffers in the pool
        self.allocated = 0             #Total buffers created so far (for metrics)
        self.in_use = 0                #Number of buffers currently checked out.

        self._pool: asyncio.Queue[bytearray] = asyncio.Queue(maxsize=pool_size)

        # Pre-allocate all buffers up front so allocation cost is paid once
        self._preallocate()

    def _preallocate(self) -> None:
        for _ in range(self.pool_size):
            buf = bytearray(self.buffer_size)
            self._pool.put_nowait(buf)
            self.allocated += 1

    async def acquire(self, timeout: float = 5.0) -> bytearray:
        #Get a buffer from the pool,If the pool is empty, waits up to `timeout` seconds for one to be released.  
        
        try:
            buf = await asyncio.wait_for(self._pool.get(), timeout=timeout)
        except asyncio.TimeoutError:
            raise TimeoutError(
                f"BufferPool exhausted: all {self.pool_size} buffers are in use. "
                f"Consider increasing pool_size or reducing concurrency."
            )

        # Zero the buffer before handing it out
        for i in range(len(buf)):
            buf[i] = 0

        self.in_use += 1
        return buf

    def release(self, buf: bytearray) -> None:
        #return the buffer
        if len(buf) != self.buffer_size:
            raise ValueError(
                f"Buffer size mismatch: expected {self.buffer_size}, "
                f"got {len(buf)}. Only return buffers from this pool."
            )
        self.in_use -= 1
        try:
            self._pool.put_nowait(buf)
        except asyncio.QueueFull:
            pass

    @asynccontextmanager
    async def checkout(self, timeout: float = 5.0) -> AsyncIterator[bytearray]:
        
        #Context manager for acquiring and auto-releasing a buffer.
        buf = await self.acquire(timeout=timeout)
        try:
            yield buf
        finally:
            self.release(buf)

    @property
    def available(self) -> int:
        return self._pool.qsize()

    @property
    def utilization(self) -> float:
        if self.pool_size == 0:
            return 0.0
        return self.in_use / self.pool_size

    def stats(self) -> dict:

        return {
            "buffer_size": self.buffer_size,
            "pool_size": self.pool_size,
            "allocated": self.allocated,
            "in_use": self.in_use,
            "available": self.available,
            "utilization": round(self.utilization, 3),
        }

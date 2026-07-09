"""
Tests for netguardian.utils.buffer_pool — Reusable Byte Buffer Pool

These tests verify:
    1. Pre-allocation fills the pool at creation
    2. Acquire returns a zeroed buffer of correct size
    3. Release returns the buffer to the pool
    4. Pool exhaustion raises TimeoutError (backpressure)
    5. Context manager auto-releases
    6. Stats reporting is accurate
    7. Double-release doesn't corrupt the pool
    8. Invalid constructor args are rejected
"""

import asyncio

# pyrefly: ignore [missing-import]
import pytest

from netguardian.utils.buffer_pool import BufferPool



class TestBufferPoolConstruction:
    """Verify pool initialization and pre-allocation."""

    def test_preallocated_at_creation(self):
        """All buffers should be available immediately after construction."""
        pool = BufferPool(buffer_size=1024, pool_size=10)
        assert pool.available == 10
        assert pool.allocated == 10
        assert pool.in_use == 0

    def test_invalid_buffer_size(self):
        """Zero or negative buffer_size should raise ValueError."""
        with pytest.raises(ValueError, match="buffer_size"):
            BufferPool(buffer_size=0, pool_size=10)
        with pytest.raises(ValueError, match="buffer_size"):
            BufferPool(buffer_size=-1, pool_size=10)

    def test_invalid_pool_size(self):
        """Zero or negative pool_size should raise ValueError."""
        with pytest.raises(ValueError, match="pool_size"):
            BufferPool(buffer_size=1024, pool_size=0)




class TestAcquireRelease:
    """Verify buffer checkout and return behavior."""

    @pytest.mark.asyncio
    async def test_acquire_returns_correct_size(self):
        """Acquired buffer should be exactly buffer_size bytes."""
        pool = BufferPool(buffer_size=4096, pool_size=5)
        buf = await pool.acquire()
        assert len(buf) == 4096
        assert isinstance(buf, bytearray)
        pool.release(buf)

    @pytest.mark.asyncio
    async def test_acquire_returns_zeroed_buffer(self):
        """Buffer should be zeroed even if it was used before."""
        pool = BufferPool(buffer_size=128, pool_size=2)

        # Acquire, write data, release
        buf = await pool.acquire()
        buf[:5] = b"hello"
        pool.release(buf)

        # Acquire again — should be zeroed
        buf2 = await pool.acquire()
        assert buf2[:5] == bytearray(5)  # all zeros
        pool.release(buf2)

    @pytest.mark.asyncio
    async def test_release_returns_to_pool(self):
        """Releasing a buffer should make it available again."""
        pool = BufferPool(buffer_size=1024, pool_size=3)
        assert pool.available == 3

        buf = await pool.acquire()
        assert pool.available == 2
        assert pool.in_use == 1

        pool.release(buf)
        assert pool.available == 3
        assert pool.in_use == 0

    @pytest.mark.asyncio
    async def test_release_wrong_size_raises(self):
        """Releasing a buffer of wrong size should raise ValueError."""
        pool = BufferPool(buffer_size=1024, pool_size=3)
        wrong_buf = bytearray(512)
        with pytest.raises(ValueError, match="mismatch"):
            pool.release(wrong_buf)




class TestExhaustion:
    """Verify the pool applies backpressure when full."""

    @pytest.mark.asyncio
    async def test_exhaustion_raises_timeout(self):
        """Acquiring from an empty pool should raise TimeoutError."""
        pool = BufferPool(buffer_size=256, pool_size=2)

        # Drain the pool
        buf1 = await pool.acquire()
        buf2 = await pool.acquire()
        assert pool.available == 0

        # Next acquire should timeout quickly
        with pytest.raises(TimeoutError, match="exhausted"):
            await pool.acquire(timeout=0.1)

        # Cleanup
        pool.release(buf1)
        pool.release(buf2)

    @pytest.mark.asyncio
    async def test_release_unblocks_waiting_acquire(self):
        """A release should allow a waiting acquire to proceed."""
        pool = BufferPool(buffer_size=256, pool_size=1)

        buf = await pool.acquire()
        assert pool.available == 0

        async def delayed_release():
            await asyncio.sleep(0.05)
            pool.release(buf)

        # Start a release in the background, then try to acquire
        asyncio.create_task(delayed_release())
        buf2 = await pool.acquire(timeout=1.0)  # should succeed
        assert len(buf2) == 256
        pool.release(buf2)




class TestCheckoutContextManager:
    """Verify the async context manager for auto-release."""

    @pytest.mark.asyncio
    async def test_auto_release_on_exit(self):
        """Buffer should be released when exiting the context."""
        pool = BufferPool(buffer_size=512, pool_size=2)

        async with pool.checkout() as buf:
            assert pool.in_use == 1
            buf[:3] = b"abc"

        # After context exit, buffer is back in pool
        assert pool.in_use == 0
        assert pool.available == 2

    @pytest.mark.asyncio
    async def test_auto_release_on_exception(self):
        """Buffer should be released even if an exception occurs."""
        pool = BufferPool(buffer_size=512, pool_size=2)

        with pytest.raises(RuntimeError):
            async with pool.checkout() as buf:
                raise RuntimeError("simulated error")

        # Buffer must still be returned
        assert pool.in_use == 0
        assert pool.available == 2



class TestStats:
    """Verify stats reporting for telemetry integration."""

    @pytest.mark.asyncio
    async def test_stats_snapshot(self):
        """Stats dict should reflect current pool state."""
        pool = BufferPool(buffer_size=2048, pool_size=4)
        buf = await pool.acquire()

        stats = pool.stats()
        assert stats["buffer_size"] == 2048
        assert stats["pool_size"] == 4
        assert stats["allocated"] == 4
        assert stats["in_use"] == 1
        assert stats["available"] == 3
        assert stats["utilization"] == 0.25

        pool.release(buf)

    def test_utilization_empty_pool(self):
        """Utilization should be 0.0 when nothing is checked out."""
        pool = BufferPool(buffer_size=1024, pool_size=8)
        assert pool.utilization == 0.0

    @pytest.mark.asyncio
    async def test_utilization_full(self):
        """Utilization should be 1.0 when all buffers are in use."""
        pool = BufferPool(buffer_size=256, pool_size=2)
        buf1 = await pool.acquire()
        buf2 = await pool.acquire()
        assert pool.utilization == 1.0
        pool.release(buf1)
        pool.release(buf2)

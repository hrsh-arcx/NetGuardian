"""
Tests for netguardian.telemetry.metrics — Counters, Gauges & Histograms
"""

import pytest
from netguardian.telemetry.metrics import MetricsCollector, HistogramBucket


class TestHistogramBucket:

    def test_record_and_mean(self):
        h = HistogramBucket()
        h.record(10.0)
        h.record(20.0)
        h.record(30.0)
        assert h.mean() == 20.0
        assert h.count() == 3

    def test_percentile_p50(self):
        h = HistogramBucket()
        for v in range(1, 101):
            h.record(float(v))
        # Floor-index percentile: idx = int(100 * 0.5) = 50 → value 51
        assert 49.0 <= h.percentile(50) <= 52.0

    def test_percentile_p99(self):
        h = HistogramBucket()
        for v in range(1, 101):
            h.record(float(v))
        assert h.percentile(99) >= 99.0

    def test_empty_histogram(self):
        h = HistogramBucket()
        assert h.mean() == 0.0
        assert h.percentile(50) == 0.0
        assert h.count() == 0

    def test_memory_bounded(self):
        h = HistogramBucket(max_samples=100)
        for i in range(200):
            h.record(float(i))
        # Should have evicted oldest 20% at least once
        assert h.count() <= 100 + 1  # small tolerance for eviction timing

    def test_reset(self):
        h = HistogramBucket()
        h.record(5.0)
        h.reset()
        assert h.count() == 0


class TestMetricsCollectorCounters:

    @pytest.mark.asyncio
    async def test_increment_default(self):
        m = MetricsCollector()
        await m.increment("requests")
        assert await m.get_counter("requests") == 1

    @pytest.mark.asyncio
    async def test_increment_by_value(self):
        m = MetricsCollector()
        await m.increment("bytes_in", 1024)
        await m.increment("bytes_in", 2048)
        assert await m.get_counter("bytes_in") == 3072

    @pytest.mark.asyncio
    async def test_unset_counter_is_zero(self):
        m = MetricsCollector()
        assert await m.get_counter("nonexistent") == 0

    def test_sync_increment(self):
        m = MetricsCollector()
        m.increment_sync("sync_counter", 5)
        m.increment_sync("sync_counter", 3)
        assert m._counters["sync_counter"] == 8


class TestMetricsCollectorGauges:

    @pytest.mark.asyncio
    async def test_set_and_get(self):
        m = MetricsCollector()
        await m.set_gauge("active_conns", 42.0)
        assert await m.get_gauge("active_conns") == 42.0

    @pytest.mark.asyncio
    async def test_adjust_gauge(self):
        m = MetricsCollector()
        await m.set_gauge("active_conns", 10.0)
        await m.adjust_gauge("active_conns", 5.0)
        await m.adjust_gauge("active_conns", -3.0)
        assert await m.get_gauge("active_conns") == 12.0

    @pytest.mark.asyncio
    async def test_unset_gauge_is_zero(self):
        m = MetricsCollector()
        assert await m.get_gauge("nonexistent") == 0.0


class TestMetricsCollectorHistograms:

    @pytest.mark.asyncio
    async def test_record_and_retrieve(self):
        m = MetricsCollector()
        await m.record("latency_ms", 15.0)
        await m.record("latency_ms", 25.0)
        h = await m.get_histogram("latency_ms")
        assert h is not None
        assert h.count() == 2

    @pytest.mark.asyncio
    async def test_nonexistent_histogram(self):
        m = MetricsCollector()
        assert await m.get_histogram("nope") is None


class TestMetricsSnapshot:

    @pytest.mark.asyncio
    async def test_snapshot_structure(self):
        m = MetricsCollector()
        await m.increment("total_reqs", 10)
        await m.set_gauge("pool_usage", 0.75)
        await m.record("latency", 50.0)

        snap = await m.snapshot()

        assert "uptime_seconds" in snap
        assert snap["counters"]["total_reqs"] == 10
        assert snap["gauges"]["pool_usage"] == 0.75
        assert snap["histograms"]["latency"]["count"] == 1
        assert snap["histograms"]["latency"]["mean"] == 50.0

    @pytest.mark.asyncio
    async def test_snapshot_is_frozen_copy(self):
        """Modifying the snapshot dict should not affect the collector."""
        m = MetricsCollector()
        await m.increment("x", 1)
        snap = await m.snapshot()
        snap["counters"]["x"] = 999
        assert await m.get_counter("x") == 1  # original unchanged

    @pytest.mark.asyncio
    async def test_reset_clears_all(self):
        m = MetricsCollector()
        await m.increment("a", 5)
        await m.set_gauge("b", 10.0)
        await m.record("c", 1.0)
        await m.reset()

        snap = await m.snapshot()
        assert snap["counters"] == {}
        assert snap["gauges"] == {}

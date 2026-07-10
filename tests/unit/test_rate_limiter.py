"""
Tests for netguardian.security.rate_limiter — Token Bucket Algorithm
"""

import time
import pytest
from netguardian.security.rate_limiter import RateLimiter


class TestBasicRateLimiting:

    def test_first_request_allowed(self):
        rl = RateLimiter(requests_per_second=10, burst_size=5)
        result = rl.check("1.2.3.4")
        assert result.allowed is True

    def test_burst_allows_multiple(self):
        """All requests within burst_size should be allowed."""
        rl = RateLimiter(requests_per_second=10, burst_size=5)
        results = [rl.check("1.2.3.4") for _ in range(5)]
        assert all(r.allowed for r in results)

    def test_exceeding_burst_denied(self):
        """Requests beyond burst_size should be denied."""
        rl = RateLimiter(requests_per_second=1, burst_size=3)
        for _ in range(3):
            rl.check("1.2.3.4")
        result = rl.check("1.2.3.4")
        assert result.allowed is False

    def test_remaining_tokens_decreases(self):
        rl = RateLimiter(requests_per_second=10, burst_size=10)
        r1 = rl.check("1.2.3.4")
        r2 = rl.check("1.2.3.4")
        assert r2.remaining_tokens < r1.remaining_tokens


class TestPerIPIsolation:

    def test_different_ips_independent(self):
        """Each IP gets its own bucket."""
        rl = RateLimiter(requests_per_second=1, burst_size=2)
        # Drain IP A
        rl.check("10.0.0.1")
        rl.check("10.0.0.1")
        assert rl.check("10.0.0.1").allowed is False
        # IP B should still be fine
        assert rl.check("10.0.0.2").allowed is True


class TestTokenRefill:

    def test_tokens_refill_over_time(self):
        rl = RateLimiter(requests_per_second=1000, burst_size=1)
        rl.check("1.1.1.1")  # consume the 1 token
        assert rl.check("1.1.1.1").allowed is False
        # Simulate time passing by manipulating the bucket directly
        bucket = rl._buckets["1.1.1.1"]
        bucket.last_refill -= 1.0  # pretend 1 second passed
        assert rl.check("1.1.1.1").allowed is True


class TestCleanup:

    def test_prune_stale_buckets(self):
        rl = RateLimiter(requests_per_second=10, burst_size=10, cleanup_interval=1)
        rl.check("1.1.1.1")
        rl.check("2.2.2.2")
        assert rl.stats()["tracked_ips"] == 2

        # Make buckets stale
        for bucket in rl._buckets.values():
            bucket.last_refill -= 300  # 5 minutes ago
        rl._prune_stale()
        assert rl.stats()["tracked_ips"] == 0

    def test_active_buckets_not_pruned(self):
        rl = RateLimiter(requests_per_second=10, burst_size=10, cleanup_interval=1)
        rl.check("1.1.1.1")  # fresh bucket
        rl._prune_stale()
        assert rl.stats()["tracked_ips"] == 1


class TestStats:

    def test_stats_report(self):
        rl = RateLimiter(requests_per_second=50, burst_size=100)
        rl.check("a.b.c.d")
        s = rl.stats()
        assert s["tracked_ips"] == 1
        assert s["requests_per_second"] == 50
        assert s["burst_size"] == 100

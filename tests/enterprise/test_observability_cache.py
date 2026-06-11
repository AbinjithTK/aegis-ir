"""Tests for ObservabilityAggregator accuracy trend caching layer.

Validates that:
- Repeated calls within 60 seconds return cached results without querying Phoenix
- Cache expires after 60 seconds and triggers a fresh Phoenix query
- Different (tenant_id, days) keys are cached independently
- clear_cache() invalidates all cached entries
- Concurrent callers are serialized via asyncio lock (no duplicate queries)

Requirements: 2.1
"""

from __future__ import annotations

import asyncio
import time
from datetime import date, datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest

from sift_defender.enterprise.observability.aggregator import (
    AccuracyTrend,
    ObservabilityAggregator,
)


# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def mock_client():
    """Create a mock Phoenix client."""
    return MagicMock()


@pytest.fixture
def aggregator(mock_client):
    """Create an ObservabilityAggregator with a mock client."""
    return ObservabilityAggregator(phoenix_client=mock_client, tenant_id="tenant-cache")


def _make_guardrail_span(action: str, span_date: date) -> dict:
    """Create a guardrail span dict for testing."""
    start = datetime.combine(span_date, datetime.min.time(), tzinfo=timezone.utc)
    return {
        "name": "guardrail_pipeline",
        "start_time": start,
        "end_time": start + timedelta(seconds=1),
        "attributes.guardrail_action": action,
        "context.span_id": f"span-{action}-{span_date.isoformat()}",
    }


def _spans_to_dataframe(spans: list[dict]) -> pd.DataFrame:
    """Convert a list of span dicts to a DataFrame."""
    return pd.DataFrame(spans)


# ─── Cache Hit Tests ──────────────────────────────────────────────────────────


class TestCacheHit:
    """Test that cached results are returned without re-querying Phoenix."""

    @pytest.mark.asyncio
    async def test_second_call_uses_cache(self, aggregator, mock_client):
        """Second call within TTL returns cached result; Phoenix queried only once."""
        today = date.today()
        spans = [_make_guardrail_span("APPROVE", today)]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        result1 = await aggregator.get_accuracy_trend(days=30)
        result2 = await aggregator.get_accuracy_trend(days=30)

        # Phoenix should only be called once
        assert mock_client.query_spans.call_count == 1
        # Both results should be identical
        assert result1 is result2

    @pytest.mark.asyncio
    async def test_cache_returns_same_object(self, aggregator, mock_client):
        """Cached result is the exact same object (not a copy)."""
        today = date.today()
        spans = [_make_guardrail_span("BLOCK", today)]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        result1 = await aggregator.get_accuracy_trend(days=7)
        result2 = await aggregator.get_accuracy_trend(days=7)

        assert result1 is result2

    @pytest.mark.asyncio
    async def test_multiple_calls_within_ttl(self, aggregator, mock_client):
        """Multiple calls all within TTL only trigger one Phoenix query."""
        today = date.today()
        spans = [_make_guardrail_span("APPROVE", today)]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        for _ in range(5):
            await aggregator.get_accuracy_trend(days=30)

        assert mock_client.query_spans.call_count == 1


# ─── Cache Expiry Tests ───────────────────────────────────────────────────────


class TestCacheExpiry:
    """Test that cache entries expire after 60 seconds."""

    @pytest.mark.asyncio
    async def test_expired_cache_triggers_fresh_query(self, aggregator, mock_client):
        """After TTL expires, a new Phoenix query is made."""
        today = date.today()
        spans = [_make_guardrail_span("APPROVE", today)]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        # First call populates cache
        await aggregator.get_accuracy_trend(days=30)
        assert mock_client.query_spans.call_count == 1

        # Simulate cache expiry by backdating the entry timestamp
        cache_key = ("tenant-cache", 30)
        entry = aggregator._accuracy_cache[cache_key]
        entry.timestamp = time.monotonic() - 61  # Expired (> 60s)

        # Second call should trigger a fresh query
        await aggregator.get_accuracy_trend(days=30)
        assert mock_client.query_spans.call_count == 2

    @pytest.mark.asyncio
    async def test_cache_within_ttl_does_not_expire(self, aggregator, mock_client):
        """Entry just under TTL is still valid."""
        today = date.today()
        spans = [_make_guardrail_span("APPROVE", today)]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        await aggregator.get_accuracy_trend(days=30)

        # Backdate to 59 seconds ago — still within TTL
        cache_key = ("tenant-cache", 30)
        entry = aggregator._accuracy_cache[cache_key]
        entry.timestamp = time.monotonic() - 59

        await aggregator.get_accuracy_trend(days=30)
        # Should still be only 1 call (cache hit)
        assert mock_client.query_spans.call_count == 1

    @pytest.mark.asyncio
    async def test_expired_cache_returns_fresh_data(self, aggregator, mock_client):
        """After expiry, returned data reflects the new Phoenix response."""
        today = date.today()

        # First response: all APPROVE
        spans_v1 = [_make_guardrail_span("APPROVE", today)]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans_v1)

        result1 = await aggregator.get_accuracy_trend(days=30)
        assert result1.days[0].approved_count == 1

        # Expire cache
        cache_key = ("tenant-cache", 30)
        aggregator._accuracy_cache[cache_key].timestamp = time.monotonic() - 61

        # Second response: all BLOCK
        spans_v2 = [
            _make_guardrail_span("BLOCK", today),
            _make_guardrail_span("BLOCK", today),
        ]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans_v2)

        result2 = await aggregator.get_accuracy_trend(days=30)
        assert result2.days[0].blocked_count == 2
        assert result2.days[0].approved_count == 0


# ─── Cache Key Isolation Tests ────────────────────────────────────────────────


class TestCacheKeyIsolation:
    """Test that different (tenant_id, days) combos are cached independently."""

    @pytest.mark.asyncio
    async def test_different_days_cached_separately(self, aggregator, mock_client):
        """Requests with different days parameter use separate cache entries."""
        today = date.today()
        spans = [_make_guardrail_span("APPROVE", today)]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        await aggregator.get_accuracy_trend(days=7)
        await aggregator.get_accuracy_trend(days=30)

        # Two different cache keys, so Phoenix should be called twice
        assert mock_client.query_spans.call_count == 2

    @pytest.mark.asyncio
    async def test_different_tenants_cached_separately(self, mock_client):
        """Different tenant aggregators maintain independent caches."""
        today = date.today()
        spans = [_make_guardrail_span("APPROVE", today)]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        agg1 = ObservabilityAggregator(phoenix_client=mock_client, tenant_id="tenant-a")
        agg2 = ObservabilityAggregator(phoenix_client=mock_client, tenant_id="tenant-b")

        await agg1.get_accuracy_trend(days=30)
        await agg2.get_accuracy_trend(days=30)

        # Each aggregator has its own cache, so Phoenix called for each
        assert mock_client.query_spans.call_count == 2


# ─── clear_cache() Tests ─────────────────────────────────────────────────────


class TestClearCache:
    """Test manual cache invalidation."""

    @pytest.mark.asyncio
    async def test_clear_cache_forces_refetch(self, aggregator, mock_client):
        """clear_cache() causes next call to query Phoenix again."""
        today = date.today()
        spans = [_make_guardrail_span("APPROVE", today)]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        await aggregator.get_accuracy_trend(days=30)
        assert mock_client.query_spans.call_count == 1

        aggregator.clear_cache()

        await aggregator.get_accuracy_trend(days=30)
        assert mock_client.query_spans.call_count == 2

    @pytest.mark.asyncio
    async def test_clear_cache_removes_all_entries(self, aggregator, mock_client):
        """clear_cache() removes entries for all days parameters."""
        today = date.today()
        spans = [_make_guardrail_span("APPROVE", today)]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        await aggregator.get_accuracy_trend(days=7)
        await aggregator.get_accuracy_trend(days=30)

        aggregator.clear_cache()

        assert len(aggregator._accuracy_cache) == 0

    def test_clear_cache_on_empty_cache(self, aggregator):
        """clear_cache() on empty cache does not raise."""
        aggregator.clear_cache()  # Should not raise
        assert len(aggregator._accuracy_cache) == 0


# ─── Concurrency Tests ────────────────────────────────────────────────────────


class TestConcurrency:
    """Test that concurrent callers are serialized via asyncio lock."""

    @pytest.mark.asyncio
    async def test_concurrent_calls_only_query_once(self, aggregator, mock_client):
        """Multiple simultaneous calls result in only one Phoenix query."""
        today = date.today()
        spans = [_make_guardrail_span("APPROVE", today)]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        # Launch multiple concurrent calls
        tasks = [
            asyncio.create_task(aggregator.get_accuracy_trend(days=30))
            for _ in range(10)
        ]
        results = await asyncio.gather(*tasks)

        # Only one Phoenix query should have been made
        assert mock_client.query_spans.call_count == 1
        # All results should be the same object
        for r in results:
            assert r is results[0]

    @pytest.mark.asyncio
    async def test_lock_prevents_race_condition(self, aggregator, mock_client):
        """Lock ensures no duplicate queries even with slow Phoenix response."""
        today = date.today()
        spans = [_make_guardrail_span("APPROVE", today)]

        call_count = 0

        def slow_query(**kwargs):
            nonlocal call_count
            call_count += 1
            return _spans_to_dataframe(spans)

        mock_client.query_spans.side_effect = slow_query

        tasks = [
            asyncio.create_task(aggregator.get_accuracy_trend(days=30))
            for _ in range(5)
        ]
        await asyncio.gather(*tasks)

        assert call_count == 1


# ─── TTL Configuration Tests ─────────────────────────────────────────────────


class TestCacheTTLConfiguration:
    """Test that the cache TTL is set to 60 seconds."""

    def test_default_ttl_is_60_seconds(self, aggregator):
        """The default TTL is 60 seconds."""
        assert aggregator._cache_ttl == 60.0

    @pytest.mark.asyncio
    async def test_cache_respects_custom_ttl(self, mock_client):
        """A modified TTL is respected for cache expiry."""
        agg = ObservabilityAggregator(phoenix_client=mock_client, tenant_id="t")
        agg._cache_ttl = 10.0  # Custom short TTL for testing

        today = date.today()
        spans = [_make_guardrail_span("APPROVE", today)]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        await agg.get_accuracy_trend(days=30)

        # Backdate 11 seconds — should be expired with 10s TTL
        cache_key = ("t", 30)
        agg._accuracy_cache[cache_key].timestamp = time.monotonic() - 11

        await agg.get_accuracy_trend(days=30)
        assert mock_client.query_spans.call_count == 2

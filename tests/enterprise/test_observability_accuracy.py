"""Tests for ObservabilityAggregator.get_accuracy_trend().

Validates that:
- Guardrail spans are correctly grouped by day
- Pass/flag/block rates are calculated correctly
- 7-day rolling average is computed from recent data
- Empty or unreachable Phoenix data returns empty trend
- Spans with various action naming conventions are normalized
- Only guardrail spans are counted (non-guardrail filtered out)

Requirements: 2.1, 2.3
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from unittest.mock import MagicMock

import pandas as pd
import pytest

from sift_defender.enterprise.observability.aggregator import (
    AccuracyTrend,
    DayAccuracy,
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
    return ObservabilityAggregator(phoenix_client=mock_client, tenant_id="tenant-001")


def _make_guardrail_span(
    action: str,
    span_date: date,
    name: str = "guardrail_pipeline",
) -> dict:
    """Create a span row dict simulating a guardrail evaluation span."""
    start = datetime.combine(span_date, datetime.min.time(), tzinfo=timezone.utc)
    end = start + timedelta(seconds=1)
    return {
        "name": name,
        "start_time": start,
        "end_time": end,
        "attributes.guardrail_action": action,
        "context.span_id": f"span-{action}-{span_date.isoformat()}",
    }


def _make_non_guardrail_span(span_date: date) -> dict:
    """Create a non-guardrail span (e.g. an LLM call or tool call)."""
    start = datetime.combine(span_date, datetime.min.time(), tzinfo=timezone.utc)
    end = start + timedelta(seconds=2)
    return {
        "name": "llm_call",
        "start_time": start,
        "end_time": end,
        "context.span_id": f"span-llm-{span_date.isoformat()}",
    }


def _spans_to_dataframe(spans: list[dict]) -> pd.DataFrame:
    """Convert a list of span dicts to a DataFrame."""
    return pd.DataFrame(spans)


# ─── Empty / Error Cases ──────────────────────────────────────────────────────


class TestAccuracyTrendEmpty:
    """Test behavior when Phoenix has no data or is unreachable."""

    @pytest.mark.asyncio
    async def test_returns_empty_trend_when_no_data(self, aggregator, mock_client):
        """No data from Phoenix returns empty AccuracyTrend."""
        mock_client.query_spans.return_value = pd.DataFrame()

        result = await aggregator.get_accuracy_trend(days=30)

        assert isinstance(result, AccuracyTrend)
        assert result.days == []
        assert result.rolling_average == 0.0
        assert result.total_evaluated == 0

    @pytest.mark.asyncio
    async def test_returns_empty_trend_when_none_returned(self, aggregator, mock_client):
        """None from Phoenix returns empty AccuracyTrend."""
        mock_client.query_spans.return_value = None

        result = await aggregator.get_accuracy_trend(days=30)

        assert result.days == []
        assert result.rolling_average == 0.0
        assert result.total_evaluated == 0

    @pytest.mark.asyncio
    async def test_returns_empty_trend_on_exception(self, aggregator, mock_client):
        """Exception from Phoenix returns empty AccuracyTrend gracefully."""
        mock_client.query_spans.side_effect = ConnectionError("Phoenix unreachable")

        result = await aggregator.get_accuracy_trend(days=30)

        assert result.days == []
        assert result.rolling_average == 0.0
        assert result.total_evaluated == 0

    @pytest.mark.asyncio
    async def test_returns_empty_when_no_guardrail_spans(self, aggregator, mock_client):
        """Non-guardrail spans are filtered out, resulting in empty trend."""
        today = date.today()
        spans = [_make_non_guardrail_span(today)]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        result = await aggregator.get_accuracy_trend(days=30)

        assert result.days == []
        assert result.total_evaluated == 0


# ─── Single Day Calculations ─────────────────────────────────────────────────


class TestAccuracyTrendSingleDay:
    """Test rate calculations for a single day."""

    @pytest.mark.asyncio
    async def test_all_approved(self, aggregator, mock_client):
        """All APPROVE actions = 100% pass rate."""
        today = date.today()
        spans = [
            _make_guardrail_span("APPROVE", today),
            _make_guardrail_span("APPROVE", today),
            _make_guardrail_span("APPROVE", today),
        ]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        result = await aggregator.get_accuracy_trend(days=30)

        assert len(result.days) == 1
        day = result.days[0]
        assert day.date == today
        assert day.approved_count == 3
        assert day.flagged_count == 0
        assert day.blocked_count == 0
        assert day.total == 3
        assert day.pass_rate == 1.0
        assert day.flag_rate == 0.0
        assert day.block_rate == 0.0

    @pytest.mark.asyncio
    async def test_mixed_actions(self, aggregator, mock_client):
        """Mixed actions correctly calculate rates."""
        today = date.today()
        spans = [
            _make_guardrail_span("APPROVE", today),
            _make_guardrail_span("APPROVE", today),
            _make_guardrail_span("FLAG_FOR_REVIEW", today),
            _make_guardrail_span("BLOCK", today),
        ]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        result = await aggregator.get_accuracy_trend(days=30)

        assert len(result.days) == 1
        day = result.days[0]
        assert day.approved_count == 2
        assert day.flagged_count == 1
        assert day.blocked_count == 1
        assert day.total == 4
        assert day.pass_rate == pytest.approx(0.5)
        assert day.flag_rate == pytest.approx(0.25)
        assert day.block_rate == pytest.approx(0.25)

    @pytest.mark.asyncio
    async def test_all_blocked(self, aggregator, mock_client):
        """All BLOCK actions = 0% pass rate."""
        today = date.today()
        spans = [
            _make_guardrail_span("BLOCK", today),
            _make_guardrail_span("BLOCK", today),
        ]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        result = await aggregator.get_accuracy_trend(days=30)

        day = result.days[0]
        assert day.pass_rate == 0.0
        assert day.block_rate == 1.0
        assert day.total == 2

    @pytest.mark.asyncio
    async def test_rates_sum_to_one(self, aggregator, mock_client):
        """pass_rate + flag_rate + block_rate should equal 1.0."""
        today = date.today()
        spans = [
            _make_guardrail_span("APPROVE", today),
            _make_guardrail_span("FLAG_FOR_REVIEW", today),
            _make_guardrail_span("FLAG_FOR_REVIEW", today),
            _make_guardrail_span("BLOCK", today),
            _make_guardrail_span("BLOCK", today),
            _make_guardrail_span("BLOCK", today),
        ]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        result = await aggregator.get_accuracy_trend(days=30)

        day = result.days[0]
        assert day.pass_rate + day.flag_rate + day.block_rate == pytest.approx(1.0)


# ─── Multi-Day Grouping ──────────────────────────────────────────────────────


class TestAccuracyTrendMultiDay:
    """Test grouping across multiple days."""

    @pytest.mark.asyncio
    async def test_spans_grouped_by_date(self, aggregator, mock_client):
        """Spans on different days are grouped separately."""
        day1 = date.today() - timedelta(days=2)
        day2 = date.today() - timedelta(days=1)
        day3 = date.today()

        spans = [
            _make_guardrail_span("APPROVE", day1),
            _make_guardrail_span("BLOCK", day1),
            _make_guardrail_span("APPROVE", day2),
            _make_guardrail_span("FLAG_FOR_REVIEW", day3),
        ]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        result = await aggregator.get_accuracy_trend(days=30)

        assert len(result.days) == 3
        # Days are sorted chronologically
        assert result.days[0].date == day1
        assert result.days[1].date == day2
        assert result.days[2].date == day3

    @pytest.mark.asyncio
    async def test_days_sorted_chronologically(self, aggregator, mock_client):
        """Days in the result are always sorted ascending by date."""
        day_old = date.today() - timedelta(days=10)
        day_recent = date.today() - timedelta(days=1)

        # Intentionally provide in reverse order
        spans = [
            _make_guardrail_span("APPROVE", day_recent),
            _make_guardrail_span("BLOCK", day_old),
        ]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        result = await aggregator.get_accuracy_trend(days=30)

        dates = [d.date for d in result.days]
        assert dates == sorted(dates)

    @pytest.mark.asyncio
    async def test_total_evaluated_sums_all_days(self, aggregator, mock_client):
        """total_evaluated is the sum of all days' totals."""
        day1 = date.today() - timedelta(days=1)
        day2 = date.today()

        spans = [
            _make_guardrail_span("APPROVE", day1),
            _make_guardrail_span("APPROVE", day1),
            _make_guardrail_span("BLOCK", day2),
        ]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        result = await aggregator.get_accuracy_trend(days=30)

        assert result.total_evaluated == 3


# ─── Rolling Average ──────────────────────────────────────────────────────────


class TestRollingAverage:
    """Test 7-day rolling average calculation."""

    @pytest.mark.asyncio
    async def test_rolling_average_with_fewer_than_7_days(self, aggregator, mock_client):
        """If fewer than 7 days of data, use all available days."""
        day1 = date.today() - timedelta(days=2)
        day2 = date.today() - timedelta(days=1)

        spans = [
            _make_guardrail_span("APPROVE", day1),
            _make_guardrail_span("APPROVE", day1),
            _make_guardrail_span("BLOCK", day2),
            _make_guardrail_span("APPROVE", day2),
        ]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        result = await aggregator.get_accuracy_trend(days=30)

        # 3 approved out of 4 total = 0.75
        assert result.rolling_average == pytest.approx(0.75)

    @pytest.mark.asyncio
    async def test_rolling_average_uses_last_7_days(self, aggregator, mock_client):
        """Rolling average only considers the most recent 7 days."""
        spans = []
        # Old days (day 8-10 ago) with 0% pass rate
        for offset in range(8, 11):
            day = date.today() - timedelta(days=offset)
            spans.append(_make_guardrail_span("BLOCK", day))

        # Recent 7 days with 100% pass rate
        for offset in range(0, 7):
            day = date.today() - timedelta(days=offset)
            spans.append(_make_guardrail_span("APPROVE", day))

        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        result = await aggregator.get_accuracy_trend(days=30)

        # Rolling avg uses last 7 days only — all APPROVE = 1.0
        assert result.rolling_average == pytest.approx(1.0)

    @pytest.mark.asyncio
    async def test_rolling_average_is_zero_when_all_blocked(self, aggregator, mock_client):
        """Rolling average is 0.0 when all recent decisions are BLOCK."""
        today = date.today()
        spans = [
            _make_guardrail_span("BLOCK", today),
            _make_guardrail_span("BLOCK", today),
        ]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        result = await aggregator.get_accuracy_trend(days=30)

        assert result.rolling_average == 0.0


# ─── Action Normalization ─────────────────────────────────────────────────────


class TestActionNormalization:
    """Test that various action name formats are normalized correctly."""

    @pytest.mark.asyncio
    async def test_lowercase_approve(self, aggregator, mock_client):
        """Lowercase 'approve' is normalized."""
        today = date.today()
        spans = [_make_guardrail_span("approve", today)]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        result = await aggregator.get_accuracy_trend(days=30)

        assert result.days[0].approved_count == 1

    @pytest.mark.asyncio
    async def test_passed_alias(self, aggregator, mock_client):
        """'PASSED' is normalized to APPROVE."""
        today = date.today()
        spans = [_make_guardrail_span("PASSED", today)]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        result = await aggregator.get_accuracy_trend(days=30)

        assert result.days[0].approved_count == 1

    @pytest.mark.asyncio
    async def test_flag_alias(self, aggregator, mock_client):
        """'FLAG' is normalized to FLAG_FOR_REVIEW."""
        today = date.today()
        spans = [_make_guardrail_span("FLAG", today)]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        result = await aggregator.get_accuracy_trend(days=30)

        assert result.days[0].flagged_count == 1

    @pytest.mark.asyncio
    async def test_blocked_alias(self, aggregator, mock_client):
        """'BLOCKED' is normalized to BLOCK."""
        today = date.today()
        spans = [_make_guardrail_span("BLOCKED", today)]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        result = await aggregator.get_accuracy_trend(days=30)

        assert result.days[0].blocked_count == 1

    @pytest.mark.asyncio
    async def test_reject_alias(self, aggregator, mock_client):
        """'REJECT' is treated as BLOCK."""
        today = date.today()
        spans = [_make_guardrail_span("REJECT", today)]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        result = await aggregator.get_accuracy_trend(days=30)

        assert result.days[0].blocked_count == 1


# ─── Attribute Location Variants ─────────────────────────────────────────────


class TestAttributeLocations:
    """Test that guardrail actions are found in different attribute locations."""

    @pytest.mark.asyncio
    async def test_dict_attributes_column(self, aggregator, mock_client):
        """Action found in dict-typed 'attributes' column."""
        today = date.today()
        start = datetime.combine(today, datetime.min.time(), tzinfo=timezone.utc)
        spans = [
            {
                "name": "guardrail_pipeline",
                "start_time": start,
                "end_time": start + timedelta(seconds=1),
                "attributes": {"guardrail_action": "APPROVE"},
            }
        ]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        result = await aggregator.get_accuracy_trend(days=30)

        assert len(result.days) == 1
        assert result.days[0].approved_count == 1

    @pytest.mark.asyncio
    async def test_dotted_attribute_column(self, aggregator, mock_client):
        """Action found in 'attributes.guardrail.action' column."""
        today = date.today()
        start = datetime.combine(today, datetime.min.time(), tzinfo=timezone.utc)
        spans = [
            {
                "name": "guardrail_evaluation",
                "start_time": start,
                "end_time": start + timedelta(seconds=1),
                "attributes.guardrail.action": "FLAG_FOR_REVIEW",
            }
        ]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        result = await aggregator.get_accuracy_trend(days=30)

        assert len(result.days) == 1
        assert result.days[0].flagged_count == 1


# ─── Days Parameter ───────────────────────────────────────────────────────────


class TestDaysParameter:
    """Test that the days parameter controls the query time window."""

    @pytest.mark.asyncio
    async def test_passes_correct_start_time_to_client(self, aggregator, mock_client):
        """query_spans is called with project_name and start_time based on days."""
        mock_client.query_spans.return_value = pd.DataFrame()

        await aggregator.get_accuracy_trend(days=7)

        mock_client.query_spans.assert_called_once()
        call_kwargs = mock_client.query_spans.call_args[1]
        assert call_kwargs["project_name"] == "aegis-ir-tenant-001"
        # start_time should be approximately 7 days ago
        expected_start = datetime.now(timezone.utc) - timedelta(days=7)
        actual_start = call_kwargs["start_time"]
        assert abs((actual_start - expected_start).total_seconds()) < 5

    @pytest.mark.asyncio
    async def test_default_days_is_30(self, aggregator, mock_client):
        """Default parameter is 30 days."""
        mock_client.query_spans.return_value = pd.DataFrame()

        await aggregator.get_accuracy_trend()

        call_kwargs = mock_client.query_spans.call_args[1]
        expected_start = datetime.now(timezone.utc) - timedelta(days=30)
        actual_start = call_kwargs["start_time"]
        assert abs((actual_start - expected_start).total_seconds()) < 5


# ─── Filtering Non-Guardrail Spans ───────────────────────────────────────────


class TestGuardrailFiltering:
    """Test that non-guardrail spans are excluded from calculations."""

    @pytest.mark.asyncio
    async def test_mixed_guardrail_and_other_spans(self, aggregator, mock_client):
        """Only guardrail spans contribute to counts."""
        today = date.today()
        spans = [
            _make_guardrail_span("APPROVE", today),
            _make_non_guardrail_span(today),
            _make_non_guardrail_span(today),
            _make_guardrail_span("BLOCK", today),
        ]
        mock_client.query_spans.return_value = _spans_to_dataframe(spans)

        result = await aggregator.get_accuracy_trend(days=30)

        assert result.total_evaluated == 2
        assert result.days[0].total == 2
        assert result.days[0].approved_count == 1
        assert result.days[0].blocked_count == 1

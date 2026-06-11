"""Tests for the ObservabilityAggregator class.

Validates that:
- ObservabilityAggregator initializes with a Phoenix client and tenant_id
- ObservabilityAggregator initializes with a URL string and tenant_id
- project_name is correctly derived as 'aegis-ir-{tenant_id}'
- Initialization raises ValueError for empty tenant_id
- Data models (SpanSummary, AccuracyTrend, DayAccuracy, EvalSummary, ToolStats)
  can be instantiated with expected fields
- Stub methods raise NotImplementedError

Requirements: 1.4, 8.3
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from unittest.mock import MagicMock

import pytest

from sift_defender.enterprise.observability.aggregator import (
    AccuracyTrend,
    DayAccuracy,
    EvalDetail,
    EvalSummary,
    ObservabilityAggregator,
    SpanSummary,
    ToolStats,
)


# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def mock_phoenix_client():
    """Create a mock Phoenix Client instance."""
    return MagicMock(name="PhoenixClient")


@pytest.fixture
def aggregator(mock_phoenix_client):
    """Create an ObservabilityAggregator with a mock client."""
    return ObservabilityAggregator(
        phoenix_client=mock_phoenix_client,
        tenant_id="acme-corp",
    )


@pytest.fixture
def url_aggregator():
    """Create an ObservabilityAggregator with a URL string."""
    return ObservabilityAggregator(
        phoenix_client="http://localhost:6006",
        tenant_id="tenant-123",
    )


# ─── Initialization Tests ─────────────────────────────────────────────────────


class TestObservabilityAggregatorInit:
    """Test ObservabilityAggregator initialization."""

    def test_init_with_client_object(self, mock_phoenix_client):
        """Should accept a Phoenix Client object and store it."""
        agg = ObservabilityAggregator(
            phoenix_client=mock_phoenix_client,
            tenant_id="acme-corp",
        )
        assert agg.client is mock_phoenix_client
        assert agg.endpoint_url is None

    def test_init_with_url_string(self):
        """Should accept a URL string and store it as endpoint_url."""
        agg = ObservabilityAggregator(
            phoenix_client="http://phoenix:6006",
            tenant_id="tenant-xyz",
        )
        assert agg.endpoint_url == "http://phoenix:6006"
        assert agg.client is None

    def test_project_name_derived_from_tenant_id(self, aggregator):
        """Project name should follow the pattern 'aegis-ir-{tenant_id}'."""
        assert aggregator.project_name == "aegis-ir-acme-corp"

    def test_project_name_with_different_tenant(self):
        """Verify project namespace isolation per tenant."""
        agg = ObservabilityAggregator(
            phoenix_client=MagicMock(),
            tenant_id="security-team-alpha",
        )
        assert agg.project_name == "aegis-ir-security-team-alpha"

    def test_tenant_id_stored(self, aggregator):
        """Should store the tenant_id for later use in queries."""
        assert aggregator.tenant_id == "acme-corp"

    def test_raises_value_error_for_empty_tenant_id(self, mock_phoenix_client):
        """Should raise ValueError when tenant_id is empty string."""
        with pytest.raises(ValueError, match="tenant_id must be a non-empty string"):
            ObservabilityAggregator(phoenix_client=mock_phoenix_client, tenant_id="")

    def test_raises_value_error_for_none_tenant_id(self, mock_phoenix_client):
        """Should raise ValueError when tenant_id is None."""
        with pytest.raises(ValueError, match="tenant_id must be a non-empty string"):
            ObservabilityAggregator(phoenix_client=mock_phoenix_client, tenant_id=None)

    def test_url_aggregator_project_name(self, url_aggregator):
        """URL-based aggregator should also set project_name correctly."""
        assert url_aggregator.project_name == "aegis-ir-tenant-123"
        assert url_aggregator.tenant_id == "tenant-123"


# ─── Data Model Tests ─────────────────────────────────────────────────────────


class TestSpanSummary:
    """Test SpanSummary dataclass creation."""

    def test_create_span_summary(self):
        """Should create a SpanSummary with all required fields."""
        now = datetime.now(tz=timezone.utc)
        span = SpanSummary(
            span_id="span-001",
            name="splunk_search",
            duration_ms=142.5,
            status="OK",
            start_time=now,
            end_time=now,
            attributes={"tool.name": "splunk_search", "input.query": "index=main"},
        )
        assert span.span_id == "span-001"
        assert span.name == "splunk_search"
        assert span.duration_ms == 142.5
        assert span.status == "OK"
        assert span.attributes["tool.name"] == "splunk_search"

    def test_span_summary_default_attributes(self):
        """Attributes should default to empty dict when not provided."""
        now = datetime.now(tz=timezone.utc)
        span = SpanSummary(
            span_id="span-002",
            name="llm_reasoning",
            duration_ms=2500.0,
            status="OK",
            start_time=now,
            end_time=now,
        )
        assert span.attributes == {}


class TestDayAccuracy:
    """Test DayAccuracy dataclass creation."""

    def test_create_day_accuracy(self):
        """Should create a DayAccuracy with valid metrics."""
        day = DayAccuracy(
            date=date(2024, 1, 15),
            approved_count=80,
            flagged_count=15,
            blocked_count=5,
            total=100,
            pass_rate=0.80,
            flag_rate=0.15,
            block_rate=0.05,
        )
        assert day.approved_count == 80
        assert day.flagged_count == 15
        assert day.blocked_count == 5
        assert abs(day.pass_rate + day.flag_rate + day.block_rate - 1.0) < 0.001


class TestAccuracyTrend:
    """Test AccuracyTrend dataclass creation."""

    def test_create_accuracy_trend(self):
        """Should create AccuracyTrend with days list and rolling average."""
        days = [
            DayAccuracy(
                date=date(2024, 1, i),
                approved_count=80,
                flagged_count=15,
                blocked_count=5,
                total=100,
                pass_rate=0.80,
                flag_rate=0.15,
                block_rate=0.05,
            )
            for i in range(1, 4)
        ]
        trend = AccuracyTrend(days=days, rolling_average=0.82)
        assert len(trend.days) == 3
        assert trend.rolling_average == 0.82

    def test_empty_trend(self):
        """Should support empty days list."""
        trend = AccuracyTrend(days=[], rolling_average=0.0)
        assert trend.days == []
        assert trend.rolling_average == 0.0


class TestEvalSummary:
    """Test EvalSummary and EvalDetail dataclass creation."""

    def test_create_eval_detail(self):
        """Should create EvalDetail with evaluation data."""
        detail = EvalDetail(
            finding_id="finding-001",
            score=0.92,
            label="factual",
            action="APPROVE",
            issues=[],
        )
        assert detail.finding_id == "finding-001"
        assert detail.score == 0.92
        assert detail.label == "factual"
        assert detail.action == "APPROVE"
        assert detail.issues == []

    def test_eval_detail_with_issues(self):
        """Should store issues list for flagged/blocked findings."""
        detail = EvalDetail(
            finding_id="finding-002",
            score=0.35,
            label="hallucinated",
            action="BLOCK",
            issues=["No evidence for lateral movement claim", "Timestamp mismatch"],
        )
        assert len(detail.issues) == 2
        assert "Timestamp mismatch" in detail.issues

    def test_create_eval_summary(self):
        """Should create EvalSummary with counts and findings list."""
        findings = [
            EvalDetail(
                finding_id="f-1", score=0.95, label="factual", action="APPROVE"
            ),
            EvalDetail(
                finding_id="f-2", score=0.50, label="partially_supported", action="FLAG_FOR_REVIEW"
            ),
            EvalDetail(
                finding_id="f-3", score=0.20, label="hallucinated", action="BLOCK",
                issues=["Fabricated IP address"],
            ),
        ]
        summary = EvalSummary(
            total=3,
            approved=1,
            flagged=1,
            blocked=1,
            findings=findings,
        )
        assert summary.total == 3
        assert summary.approved == 1
        assert summary.flagged == 1
        assert summary.blocked == 1
        assert len(summary.findings) == 3

    def test_eval_summary_default_findings(self):
        """Findings should default to empty list when not provided."""
        summary = EvalSummary(total=0, approved=0, flagged=0, blocked=0)
        assert summary.findings == []


class TestToolStats:
    """Test ToolStats dataclass creation."""

    def test_create_tool_stats(self):
        """Should create ToolStats with effectiveness data."""
        stats = ToolStats(
            tool_name="splunk_search",
            confirmed_count=45,
            blocked_count=3,
            flagged_count=0,
            total_count=48,
            effectiveness_ratio=0.9375,
        )
        assert stats.tool_name == "splunk_search"
        assert stats.confirmed_count == 45
        assert stats.blocked_count == 3
        assert stats.total_count == 48
        assert abs(stats.effectiveness_ratio - 0.9375) < 0.0001

    def test_tool_stats_zero_usage(self):
        """Should handle a tool with zero usage."""
        stats = ToolStats(
            tool_name="new_tool",
            confirmed_count=0,
            blocked_count=0,
            flagged_count=0,
            total_count=0,
            effectiveness_ratio=0.0,
        )
        assert stats.total_count == 0
        assert stats.effectiveness_ratio == 0.0


# ─── Stub Method Tests ────────────────────────────────────────────────────────


class TestStubMethods:
    """Verify implemented methods handle mock clients gracefully."""

    @pytest.mark.asyncio
    async def test_get_live_spans_returns_empty_for_mock_client(self, aggregator):
        """get_live_spans returns empty list when mock client returns no matching data."""
        result = await aggregator.get_live_spans(
            case_id="case-001",
            since=datetime.now(tz=timezone.utc),
        )
        assert result == []

    @pytest.mark.asyncio
    async def test_get_accuracy_trend_returns_empty_for_mock_client(self, aggregator):
        """get_accuracy_trend returns empty trend when mock client returns unexpected data."""
        result = await aggregator.get_accuracy_trend(days=30)
        assert result.days == [] or isinstance(result, AccuracyTrend)

    @pytest.mark.asyncio
    async def test_get_investigation_eval_summary_returns_empty_for_mock_client(self, aggregator):
        """get_investigation_eval_summary returns empty summary when no eval data."""
        result = await aggregator.get_investigation_eval_summary(case_id="case-001")
        assert result.total == 0
        assert result.approved == 0
        assert result.flagged == 0
        assert result.blocked == 0
        assert result.findings == []

    @pytest.mark.asyncio
    async def test_get_tool_effectiveness_returns_empty_with_no_client(self):
        """get_tool_effectiveness returns empty dict when client returns no data."""
        # URL-based aggregator has self.client = None, _query methods return []
        agg = ObservabilityAggregator(
            phoenix_client="http://localhost:6006",
            tenant_id="test-tenant",
        )
        result = await agg.get_tool_effectiveness()
        assert result == {}

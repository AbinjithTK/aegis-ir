"""Tests for ObservabilityAggregator.get_tool_effectiveness().

Validates that tool effectiveness metrics correctly correlate tool spans
with guardrail outcomes (APPROVE/FLAG_FOR_REVIEW/BLOCK) from Phoenix data.

Requirements: 15.4
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pandas as pd
import pytest

from sift_defender.enterprise.observability.aggregator import (
    ObservabilityAggregator,
    ToolStats,
)


# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def mock_phoenix_client():
    """Create a mock Phoenix Client."""
    return MagicMock()


@pytest.fixture
def aggregator(mock_phoenix_client):
    """Create an ObservabilityAggregator with a mocked Phoenix client."""
    return ObservabilityAggregator(
        phoenix_client=mock_phoenix_client,
        tenant_id="tenant-001",
    )


def _make_tool_spans_df(spans: list[dict]) -> pd.DataFrame:
    """Build a DataFrame mimicking Phoenix tool span query results."""
    if not spans:
        return pd.DataFrame()
    return pd.DataFrame(spans)


def _make_guardrail_spans_df(spans: list[dict]) -> pd.DataFrame:
    """Build a DataFrame mimicking Phoenix guardrail span query results."""
    if not spans:
        return pd.DataFrame()
    return pd.DataFrame(spans)


# ─── Basic Functionality ──────────────────────────────────────────────────────


class TestGetToolEffectiveness:
    """Test get_tool_effectiveness correlates tools with guardrail outcomes."""

    @pytest.mark.asyncio
    async def test_returns_empty_dict_when_no_spans(self, aggregator, mock_phoenix_client):
        """When Phoenix returns no spans, result should be an empty dict."""
        mock_phoenix_client.get_spans_dataframe.return_value = pd.DataFrame()

        result = await aggregator.get_tool_effectiveness()

        assert result == {}

    @pytest.mark.asyncio
    async def test_single_tool_all_approved(self, aggregator, mock_phoenix_client):
        """A tool whose findings are all approved should have ratio 1.0."""
        tool_spans = _make_tool_spans_df([
            {
                "context.span_id": "span-1",
                "context.trace_id": "trace-1",
                "name": "fls",
                "attributes.tool.name": "fls",
                "parent_id": "parent-1",
                "start_time": "2024-01-01T00:00:00Z",
            },
            {
                "context.span_id": "span-2",
                "context.trace_id": "trace-2",
                "name": "fls",
                "attributes.tool.name": "fls",
                "parent_id": "parent-2",
                "start_time": "2024-01-01T00:01:00Z",
            },
        ])

        guardrail_spans = _make_guardrail_spans_df([
            {
                "context.span_id": "gs-1",
                "context.trace_id": "trace-1",
                "name": "guardrail_pipeline",
                "attributes.guardrail.action": "APPROVE",
                "parent_id": "parent-1",
            },
            {
                "context.span_id": "gs-2",
                "context.trace_id": "trace-2",
                "name": "guardrail_pipeline",
                "attributes.guardrail.action": "APPROVE",
                "parent_id": "parent-2",
            },
        ])

        # First call returns tool spans, second returns guardrail spans
        mock_phoenix_client.get_spans_dataframe.side_effect = [
            tool_spans, guardrail_spans
        ]

        result = await aggregator.get_tool_effectiveness()

        assert "fls" in result
        assert result["fls"].confirmed_count == 2
        assert result["fls"].blocked_count == 0
        assert result["fls"].flagged_count == 0
        assert result["fls"].total_count == 2
        assert result["fls"].effectiveness_ratio == 1.0

    @pytest.mark.asyncio
    async def test_single_tool_all_blocked(self, aggregator, mock_phoenix_client):
        """A tool whose findings are all blocked should have ratio 0.0."""
        tool_spans = _make_tool_spans_df([
            {
                "context.span_id": "span-1",
                "context.trace_id": "trace-1",
                "name": "strings",
                "attributes.tool.name": "strings",
                "parent_id": "parent-1",
                "start_time": "2024-01-01T00:00:00Z",
            },
        ])

        guardrail_spans = _make_guardrail_spans_df([
            {
                "context.span_id": "gs-1",
                "context.trace_id": "trace-1",
                "name": "guardrail_pipeline",
                "attributes.guardrail.action": "BLOCK",
                "parent_id": "parent-1",
            },
        ])

        mock_phoenix_client.get_spans_dataframe.side_effect = [
            tool_spans, guardrail_spans
        ]

        result = await aggregator.get_tool_effectiveness()

        assert "strings" in result
        assert result["strings"].confirmed_count == 0
        assert result["strings"].blocked_count == 1
        assert result["strings"].total_count == 1
        assert result["strings"].effectiveness_ratio == 0.0

    @pytest.mark.asyncio
    async def test_multiple_tools_ranked_by_effectiveness(
        self, aggregator, mock_phoenix_client
    ):
        """Tools should be sorted by effectiveness_ratio descending."""
        tool_spans = _make_tool_spans_df([
            # fls in trace-1 (approved) and trace-2 (approved) → ratio 1.0
            {
                "context.span_id": "s1",
                "context.trace_id": "trace-1",
                "name": "fls",
                "attributes.tool.name": "fls",
                "parent_id": "p1",
                "start_time": "2024-01-01T00:00:00Z",
            },
            {
                "context.span_id": "s2",
                "context.trace_id": "trace-2",
                "name": "fls",
                "attributes.tool.name": "fls",
                "parent_id": "p2",
                "start_time": "2024-01-01T00:01:00Z",
            },
            # strings in trace-3 (blocked) → ratio 0.0
            {
                "context.span_id": "s3",
                "context.trace_id": "trace-3",
                "name": "strings",
                "attributes.tool.name": "strings",
                "parent_id": "p3",
                "start_time": "2024-01-01T00:02:00Z",
            },
            # sha256sum in trace-1 (approved) and trace-3 (blocked) → ratio 0.5
            {
                "context.span_id": "s4",
                "context.trace_id": "trace-1",
                "name": "sha256sum",
                "attributes.tool.name": "sha256sum",
                "parent_id": "p4",
                "start_time": "2024-01-01T00:00:30Z",
            },
            {
                "context.span_id": "s5",
                "context.trace_id": "trace-3",
                "name": "sha256sum",
                "attributes.tool.name": "sha256sum",
                "parent_id": "p5",
                "start_time": "2024-01-01T00:02:30Z",
            },
        ])

        guardrail_spans = _make_guardrail_spans_df([
            {
                "context.span_id": "gs-1",
                "context.trace_id": "trace-1",
                "name": "guardrail_pipeline",
                "attributes.guardrail.action": "APPROVE",
                "parent_id": "gp-1",
            },
            {
                "context.span_id": "gs-2",
                "context.trace_id": "trace-2",
                "name": "guardrail_pipeline",
                "attributes.guardrail.action": "APPROVE",
                "parent_id": "gp-2",
            },
            {
                "context.span_id": "gs-3",
                "context.trace_id": "trace-3",
                "name": "guardrail_pipeline",
                "attributes.guardrail.action": "BLOCK",
                "parent_id": "gp-3",
            },
        ])

        mock_phoenix_client.get_spans_dataframe.side_effect = [
            tool_spans, guardrail_spans
        ]

        result = await aggregator.get_tool_effectiveness()

        # Verify ranking: fls (1.0) > sha256sum (0.5) > strings (0.0)
        tool_names = list(result.keys())
        assert tool_names == ["fls", "sha256sum", "strings"]
        assert result["fls"].effectiveness_ratio == 1.0
        assert result["sha256sum"].effectiveness_ratio == 0.5
        assert result["strings"].effectiveness_ratio == 0.0

    @pytest.mark.asyncio
    async def test_tool_with_mixed_outcomes(self, aggregator, mock_phoenix_client):
        """A tool with a mix of APPROVE, FLAG, and BLOCK should calculate ratio correctly."""
        tool_spans = _make_tool_spans_df([
            {
                "context.span_id": "s1",
                "context.trace_id": "trace-1",
                "name": "regripper",
                "attributes.tool.name": "regripper",
                "parent_id": "p1",
                "start_time": "2024-01-01T00:00:00Z",
            },
            {
                "context.span_id": "s2",
                "context.trace_id": "trace-2",
                "name": "regripper",
                "attributes.tool.name": "regripper",
                "parent_id": "p2",
                "start_time": "2024-01-01T00:01:00Z",
            },
            {
                "context.span_id": "s3",
                "context.trace_id": "trace-3",
                "name": "regripper",
                "attributes.tool.name": "regripper",
                "parent_id": "p3",
                "start_time": "2024-01-01T00:02:00Z",
            },
            {
                "context.span_id": "s4",
                "context.trace_id": "trace-4",
                "name": "regripper",
                "attributes.tool.name": "regripper",
                "parent_id": "p4",
                "start_time": "2024-01-01T00:03:00Z",
            },
        ])

        guardrail_spans = _make_guardrail_spans_df([
            {
                "context.span_id": "gs-1",
                "context.trace_id": "trace-1",
                "name": "guardrail_pipeline",
                "attributes.guardrail.action": "APPROVE",
                "parent_id": "gp-1",
            },
            {
                "context.span_id": "gs-2",
                "context.trace_id": "trace-2",
                "name": "guardrail_pipeline",
                "attributes.guardrail.action": "APPROVE",
                "parent_id": "gp-2",
            },
            {
                "context.span_id": "gs-3",
                "context.trace_id": "trace-3",
                "name": "guardrail_pipeline",
                "attributes.guardrail.action": "FLAG_FOR_REVIEW",
                "parent_id": "gp-3",
            },
            {
                "context.span_id": "gs-4",
                "context.trace_id": "trace-4",
                "name": "guardrail_pipeline",
                "attributes.guardrail.action": "BLOCK",
                "parent_id": "gp-4",
            },
        ])

        mock_phoenix_client.get_spans_dataframe.side_effect = [
            tool_spans, guardrail_spans
        ]

        result = await aggregator.get_tool_effectiveness()

        assert "regripper" in result
        stats = result["regripper"]
        assert stats.confirmed_count == 2
        assert stats.flagged_count == 1
        assert stats.blocked_count == 1
        assert stats.total_count == 4
        assert stats.effectiveness_ratio == 0.5  # 2/4

    @pytest.mark.asyncio
    async def test_multiple_guardrail_outcomes_in_same_trace(
        self, aggregator, mock_phoenix_client
    ):
        """Multiple findings in same trace should each count toward the tool."""
        tool_spans = _make_tool_spans_df([
            {
                "context.span_id": "s1",
                "context.trace_id": "trace-1",
                "name": "fls",
                "attributes.tool.name": "fls",
                "parent_id": "p1",
                "start_time": "2024-01-01T00:00:00Z",
            },
        ])

        guardrail_spans = _make_guardrail_spans_df([
            {
                "context.span_id": "gs-1",
                "context.trace_id": "trace-1",
                "name": "guardrail_pipeline",
                "attributes.guardrail.action": "APPROVE",
                "parent_id": "gp-1",
            },
            {
                "context.span_id": "gs-2",
                "context.trace_id": "trace-1",
                "name": "guardrail_pipeline",
                "attributes.guardrail.action": "BLOCK",
                "parent_id": "gp-2",
            },
        ])

        mock_phoenix_client.get_spans_dataframe.side_effect = [
            tool_spans, guardrail_spans
        ]

        result = await aggregator.get_tool_effectiveness()

        assert "fls" in result
        assert result["fls"].confirmed_count == 1
        assert result["fls"].blocked_count == 1
        assert result["fls"].total_count == 2
        assert result["fls"].effectiveness_ratio == 0.5


# ─── Edge Cases ───────────────────────────────────────────────────────────────


class TestToolEffectivenessEdgeCases:
    """Edge case handling for tool effectiveness calculation."""

    @pytest.mark.asyncio
    async def test_phoenix_unreachable_returns_empty(
        self, aggregator, mock_phoenix_client
    ):
        """When Phoenix client raises, return empty dict gracefully."""
        mock_phoenix_client.get_spans_dataframe.side_effect = Exception(
            "Connection refused"
        )

        result = await aggregator.get_tool_effectiveness()

        assert result == {}

    @pytest.mark.asyncio
    async def test_tool_spans_without_matching_guardrail(
        self, aggregator, mock_phoenix_client
    ):
        """Tools in traces with no guardrail spans are excluded from results."""
        tool_spans = _make_tool_spans_df([
            {
                "context.span_id": "s1",
                "context.trace_id": "trace-orphan",
                "name": "volatility",
                "attributes.tool.name": "volatility",
                "parent_id": "p1",
                "start_time": "2024-01-01T00:00:00Z",
            },
        ])

        guardrail_spans = _make_guardrail_spans_df([
            # No guardrail span for trace-orphan
            {
                "context.span_id": "gs-1",
                "context.trace_id": "trace-other",
                "name": "guardrail_pipeline",
                "attributes.guardrail.action": "APPROVE",
                "parent_id": "gp-1",
            },
        ])

        mock_phoenix_client.get_spans_dataframe.side_effect = [
            tool_spans, guardrail_spans
        ]

        result = await aggregator.get_tool_effectiveness()

        # volatility had no guardrail outcomes in its trace, so no stats
        assert "volatility" not in result

    @pytest.mark.asyncio
    async def test_guardrail_spans_without_tool_spans(
        self, aggregator, mock_phoenix_client
    ):
        """Guardrail spans in traces with no tool spans produce no results."""
        tool_spans = _make_tool_spans_df([])

        guardrail_spans = _make_guardrail_spans_df([
            {
                "context.span_id": "gs-1",
                "context.trace_id": "trace-1",
                "name": "guardrail_pipeline",
                "attributes.guardrail.action": "APPROVE",
                "parent_id": "gp-1",
            },
        ])

        mock_phoenix_client.get_spans_dataframe.side_effect = [
            tool_spans, guardrail_spans
        ]

        result = await aggregator.get_tool_effectiveness()

        assert result == {}

    @pytest.mark.asyncio
    async def test_returns_tool_stats_model_instances(
        self, aggregator, mock_phoenix_client
    ):
        """All values in the result dict should be ToolStats instances."""
        tool_spans = _make_tool_spans_df([
            {
                "context.span_id": "s1",
                "context.trace_id": "trace-1",
                "name": "fls",
                "attributes.tool.name": "fls",
                "parent_id": "p1",
                "start_time": "2024-01-01T00:00:00Z",
            },
        ])

        guardrail_spans = _make_guardrail_spans_df([
            {
                "context.span_id": "gs-1",
                "context.trace_id": "trace-1",
                "name": "guardrail_pipeline",
                "attributes.guardrail.action": "APPROVE",
                "parent_id": "gp-1",
            },
        ])

        mock_phoenix_client.get_spans_dataframe.side_effect = [
            tool_spans, guardrail_spans
        ]

        result = await aggregator.get_tool_effectiveness()

        for tool_name, stats in result.items():
            assert isinstance(stats, ToolStats)
            assert stats.tool_name == tool_name

    @pytest.mark.asyncio
    async def test_effectiveness_ratio_never_exceeds_one(
        self, aggregator, mock_phoenix_client
    ):
        """Effectiveness ratio must be between 0.0 and 1.0 inclusive."""
        tool_spans = _make_tool_spans_df([
            {
                "context.span_id": "s1",
                "context.trace_id": "trace-1",
                "name": "fls",
                "attributes.tool.name": "fls",
                "parent_id": "p1",
                "start_time": "2024-01-01T00:00:00Z",
            },
            {
                "context.span_id": "s2",
                "context.trace_id": "trace-2",
                "name": "strings",
                "attributes.tool.name": "strings",
                "parent_id": "p2",
                "start_time": "2024-01-01T00:01:00Z",
            },
        ])

        guardrail_spans = _make_guardrail_spans_df([
            {
                "context.span_id": "gs-1",
                "context.trace_id": "trace-1",
                "name": "guardrail_pipeline",
                "attributes.guardrail.action": "APPROVE",
                "parent_id": "gp-1",
            },
            {
                "context.span_id": "gs-2",
                "context.trace_id": "trace-2",
                "name": "guardrail_pipeline",
                "attributes.guardrail.action": "BLOCK",
                "parent_id": "gp-2",
            },
        ])

        mock_phoenix_client.get_spans_dataframe.side_effect = [
            tool_spans, guardrail_spans
        ]

        result = await aggregator.get_tool_effectiveness()

        for stats in result.values():
            assert 0.0 <= stats.effectiveness_ratio <= 1.0

    @pytest.mark.asyncio
    async def test_total_equals_sum_of_counts(self, aggregator, mock_phoenix_client):
        """total_count must equal confirmed_count + blocked_count + flagged_count."""
        tool_spans = _make_tool_spans_df([
            {
                "context.span_id": "s1",
                "context.trace_id": "trace-1",
                "name": "regripper",
                "attributes.tool.name": "regripper",
                "parent_id": "p1",
                "start_time": "2024-01-01T00:00:00Z",
            },
            {
                "context.span_id": "s2",
                "context.trace_id": "trace-2",
                "name": "regripper",
                "attributes.tool.name": "regripper",
                "parent_id": "p2",
                "start_time": "2024-01-01T00:01:00Z",
            },
            {
                "context.span_id": "s3",
                "context.trace_id": "trace-3",
                "name": "regripper",
                "attributes.tool.name": "regripper",
                "parent_id": "p3",
                "start_time": "2024-01-01T00:02:00Z",
            },
        ])

        guardrail_spans = _make_guardrail_spans_df([
            {
                "context.span_id": "gs-1",
                "context.trace_id": "trace-1",
                "name": "guardrail_pipeline",
                "attributes.guardrail.action": "APPROVE",
                "parent_id": "gp-1",
            },
            {
                "context.span_id": "gs-2",
                "context.trace_id": "trace-2",
                "name": "guardrail_pipeline",
                "attributes.guardrail.action": "FLAG_FOR_REVIEW",
                "parent_id": "gp-2",
            },
            {
                "context.span_id": "gs-3",
                "context.trace_id": "trace-3",
                "name": "guardrail_pipeline",
                "attributes.guardrail.action": "BLOCK",
                "parent_id": "gp-3",
            },
        ])

        mock_phoenix_client.get_spans_dataframe.side_effect = [
            tool_spans, guardrail_spans
        ]

        result = await aggregator.get_tool_effectiveness()

        for stats in result.values():
            assert stats.total_count == (
                stats.confirmed_count + stats.blocked_count + stats.flagged_count
            )

    @pytest.mark.asyncio
    async def test_uses_tenant_project_namespace(
        self, aggregator, mock_phoenix_client
    ):
        """Queries should use the tenant-scoped project name."""
        mock_phoenix_client.get_spans_dataframe.return_value = pd.DataFrame()

        await aggregator.get_tool_effectiveness()

        # Both calls should use the tenant-specific project name
        calls = mock_phoenix_client.get_spans_dataframe.call_args_list
        for call in calls:
            assert call.kwargs.get("project_name") == "aegis-ir-tenant-001"

"""Tests for ObservabilityAggregator.get_live_spans().

Validates Requirement 1.1: Real-time trace timeline showing spans within
2 seconds of span completion.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pandas as pd
import pytest

from sift_defender.enterprise.observability.aggregator import (
    ObservabilityAggregator,
    SpanSummary,
)


# --- Fixtures ---


def _make_phoenix_client(df: pd.DataFrame | None = None) -> MagicMock:
    """Create a mock Phoenix client returning the given DataFrame."""
    client = MagicMock()
    client.query_spans.return_value = df
    return client


def _make_spans_df(
    spans: list[dict],
) -> pd.DataFrame:
    """Create a DataFrame mimicking Phoenix span query results."""
    return pd.DataFrame(spans)


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --- Tests: Basic Functionality ---


class TestGetLiveSpansBasic:
    """Test basic get_live_spans functionality."""

    @pytest.mark.asyncio
    async def test_returns_span_summaries_for_matching_case(self):
        """Spans matching the case_id are returned as SpanSummary objects."""
        now = _now()
        spans_data = [
            {
                "context.span_id": "span-001",
                "name": "tool_call:memory_analysis",
                "start_time": now - timedelta(seconds=10),
                "end_time": now - timedelta(seconds=5),
                "status": "OK",
                "metadata.case_id": "case-abc",
            },
            {
                "context.span_id": "span-002",
                "name": "llm_reasoning",
                "start_time": now - timedelta(seconds=5),
                "end_time": now,
                "status": "OK",
                "metadata.case_id": "case-abc",
            },
        ]
        df = _make_spans_df(spans_data)
        client = _make_phoenix_client(df)
        aggregator = ObservabilityAggregator(client, tenant_id="tenant-1")

        result = await aggregator.get_live_spans("case-abc", since=now - timedelta(minutes=1))

        assert len(result) == 2
        assert all(isinstance(s, SpanSummary) for s in result)
        assert result[0].span_id == "span-001"
        assert result[1].span_id == "span-002"

    @pytest.mark.asyncio
    async def test_filters_out_spans_for_other_cases(self):
        """Only spans matching the requested case_id are returned."""
        now = _now()
        spans_data = [
            {
                "context.span_id": "span-001",
                "name": "tool_call:disk_analysis",
                "start_time": now - timedelta(seconds=10),
                "end_time": now - timedelta(seconds=5),
                "status": "OK",
                "metadata.case_id": "case-abc",
            },
            {
                "context.span_id": "span-002",
                "name": "tool_call:network_scan",
                "start_time": now - timedelta(seconds=5),
                "end_time": now,
                "status": "ERROR",
                "metadata.case_id": "case-xyz",
            },
        ]
        df = _make_spans_df(spans_data)
        client = _make_phoenix_client(df)
        aggregator = ObservabilityAggregator(client, tenant_id="tenant-1")

        result = await aggregator.get_live_spans("case-abc", since=now - timedelta(minutes=1))

        assert len(result) == 1
        assert result[0].span_id == "span-001"
        assert result[0].name == "tool_call:disk_analysis"

    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_spans_match(self):
        """Returns empty list when no spans match the case_id."""
        now = _now()
        spans_data = [
            {
                "context.span_id": "span-001",
                "name": "tool_call:analyze",
                "start_time": now - timedelta(seconds=10),
                "end_time": now - timedelta(seconds=5),
                "status": "OK",
                "metadata.case_id": "case-other",
            },
        ]
        df = _make_spans_df(spans_data)
        client = _make_phoenix_client(df)
        aggregator = ObservabilityAggregator(client, tenant_id="tenant-1")

        result = await aggregator.get_live_spans("case-abc", since=now - timedelta(minutes=1))

        assert result == []

    @pytest.mark.asyncio
    async def test_returns_empty_list_when_phoenix_returns_empty_df(self):
        """Returns empty list when Phoenix returns an empty DataFrame."""
        client = _make_phoenix_client(pd.DataFrame())
        aggregator = ObservabilityAggregator(client, tenant_id="tenant-1")

        result = await aggregator.get_live_spans(
            "case-abc", since=_now() - timedelta(minutes=1)
        )

        assert result == []

    @pytest.mark.asyncio
    async def test_returns_empty_list_when_phoenix_returns_none(self):
        """Returns empty list when Phoenix returns None."""
        client = _make_phoenix_client(None)
        aggregator = ObservabilityAggregator(client, tenant_id="tenant-1")

        result = await aggregator.get_live_spans(
            "case-abc", since=_now() - timedelta(minutes=1)
        )

        assert result == []


# --- Tests: Sorting ---


class TestGetLiveSpansSorting:
    """Test that spans are returned sorted by start_time ascending."""

    @pytest.mark.asyncio
    async def test_spans_sorted_chronologically(self):
        """Spans are returned in chronological order for timeline rendering."""
        now = _now()
        # Provide spans in reverse order to verify sorting
        spans_data = [
            {
                "context.span_id": "span-003",
                "name": "step_3",
                "start_time": now - timedelta(seconds=2),
                "end_time": now,
                "status": "OK",
                "metadata.case_id": "case-abc",
            },
            {
                "context.span_id": "span-001",
                "name": "step_1",
                "start_time": now - timedelta(seconds=10),
                "end_time": now - timedelta(seconds=8),
                "status": "OK",
                "metadata.case_id": "case-abc",
            },
            {
                "context.span_id": "span-002",
                "name": "step_2",
                "start_time": now - timedelta(seconds=5),
                "end_time": now - timedelta(seconds=3),
                "status": "OK",
                "metadata.case_id": "case-abc",
            },
        ]
        df = _make_spans_df(spans_data)
        client = _make_phoenix_client(df)
        aggregator = ObservabilityAggregator(client, tenant_id="tenant-1")

        result = await aggregator.get_live_spans("case-abc", since=now - timedelta(minutes=1))

        assert len(result) == 3
        assert result[0].span_id == "span-001"
        assert result[1].span_id == "span-002"
        assert result[2].span_id == "span-003"


# --- Tests: SpanSummary Field Mapping ---


class TestSpanSummaryFields:
    """Test that SpanSummary fields are correctly populated."""

    @pytest.mark.asyncio
    async def test_duration_ms_calculated_correctly(self):
        """Duration in ms is calculated from end_time - start_time."""
        now = _now()
        spans_data = [
            {
                "context.span_id": "span-001",
                "name": "guardrail_eval",
                "start_time": now - timedelta(milliseconds=1500),
                "end_time": now,
                "status": "OK",
                "metadata.case_id": "case-abc",
            },
        ]
        df = _make_spans_df(spans_data)
        client = _make_phoenix_client(df)
        aggregator = ObservabilityAggregator(client, tenant_id="tenant-1")

        result = await aggregator.get_live_spans(
            "case-abc", since=now - timedelta(minutes=1)
        )

        assert len(result) == 1
        assert abs(result[0].duration_ms - 1500.0) < 1.0  # Within 1ms tolerance

    @pytest.mark.asyncio
    async def test_status_normalized_to_ok(self):
        """Various OK-like statuses normalize to 'OK'."""
        now = _now()
        spans_data = [
            {
                "context.span_id": "span-001",
                "name": "span_ok",
                "start_time": now - timedelta(seconds=1),
                "end_time": now,
                "status": "STATUS_CODE_OK",
                "metadata.case_id": "case-abc",
            },
        ]
        df = _make_spans_df(spans_data)
        client = _make_phoenix_client(df)
        aggregator = ObservabilityAggregator(client, tenant_id="tenant-1")

        result = await aggregator.get_live_spans(
            "case-abc", since=now - timedelta(minutes=1)
        )

        assert result[0].status == "OK"

    @pytest.mark.asyncio
    async def test_status_normalized_to_error(self):
        """Error statuses normalize to 'ERROR'."""
        now = _now()
        spans_data = [
            {
                "context.span_id": "span-001",
                "name": "span_err",
                "start_time": now - timedelta(seconds=1),
                "end_time": now,
                "status": "error",
                "metadata.case_id": "case-abc",
            },
        ]
        df = _make_spans_df(spans_data)
        client = _make_phoenix_client(df)
        aggregator = ObservabilityAggregator(client, tenant_id="tenant-1")

        result = await aggregator.get_live_spans(
            "case-abc", since=now - timedelta(minutes=1)
        )

        assert result[0].status == "ERROR"

    @pytest.mark.asyncio
    async def test_status_defaults_to_unset(self):
        """Unknown statuses default to 'UNSET'."""
        now = _now()
        spans_data = [
            {
                "context.span_id": "span-001",
                "name": "span_unknown",
                "start_time": now - timedelta(seconds=1),
                "end_time": now,
                "status": "SOMETHING_ELSE",
                "metadata.case_id": "case-abc",
            },
        ]
        df = _make_spans_df(spans_data)
        client = _make_phoenix_client(df)
        aggregator = ObservabilityAggregator(client, tenant_id="tenant-1")

        result = await aggregator.get_live_spans(
            "case-abc", since=now - timedelta(minutes=1)
        )

        assert result[0].status == "UNSET"

    @pytest.mark.asyncio
    async def test_attributes_extracted_from_dict_column(self):
        """Attributes are extracted when stored as a dict column."""
        now = _now()
        spans_data = [
            {
                "context.span_id": "span-001",
                "name": "tool_call",
                "start_time": now - timedelta(seconds=1),
                "end_time": now,
                "status": "OK",
                "attributes": {
                    "case_id": "case-abc",
                    "tool": "volatility",
                    "target": "mem.raw",
                },
            },
        ]
        df = _make_spans_df(spans_data)
        client = _make_phoenix_client(df)
        aggregator = ObservabilityAggregator(client, tenant_id="tenant-1")

        result = await aggregator.get_live_spans(
            "case-abc", since=now - timedelta(minutes=1)
        )

        assert len(result) == 1
        assert result[0].attributes["tool"] == "volatility"
        assert result[0].attributes["target"] == "mem.raw"


# --- Tests: Alternative Column Naming ---


class TestAlternativeColumnNaming:
    """Test that different Phoenix column naming conventions are handled."""

    @pytest.mark.asyncio
    async def test_attributes_case_id_column(self):
        """Handles 'attributes.case_id' column for filtering."""
        now = _now()
        spans_data = [
            {
                "context.span_id": "span-001",
                "name": "tool_call",
                "start_time": now - timedelta(seconds=1),
                "end_time": now,
                "status": "OK",
                "attributes.case_id": "case-abc",
            },
        ]
        df = _make_spans_df(spans_data)
        client = _make_phoenix_client(df)
        aggregator = ObservabilityAggregator(client, tenant_id="tenant-1")

        result = await aggregator.get_live_spans(
            "case-abc", since=now - timedelta(minutes=1)
        )

        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_span_id_alternate_column(self):
        """Handles 'span_id' column name instead of 'context.span_id'."""
        now = _now()
        spans_data = [
            {
                "span_id": "span-alt-001",
                "name": "alt_span",
                "start_time": now - timedelta(seconds=1),
                "end_time": now,
                "status": "OK",
                "metadata.case_id": "case-abc",
            },
        ]
        df = _make_spans_df(spans_data)
        client = _make_phoenix_client(df)
        aggregator = ObservabilityAggregator(client, tenant_id="tenant-1")

        result = await aggregator.get_live_spans(
            "case-abc", since=now - timedelta(minutes=1)
        )

        assert len(result) == 1
        assert result[0].span_id == "span-alt-001"


# --- Tests: Error Handling ---


class TestGetLiveSpansErrorHandling:
    """Test graceful error handling when Phoenix is unreachable."""

    @pytest.mark.asyncio
    async def test_returns_empty_list_on_phoenix_connection_error(self):
        """Returns empty list and logs warning when Phoenix raises an exception."""
        client = MagicMock()
        client.query_spans.side_effect = ConnectionError("Phoenix unreachable")
        aggregator = ObservabilityAggregator(client, tenant_id="tenant-1")

        result = await aggregator.get_live_spans(
            "case-abc", since=_now() - timedelta(minutes=1)
        )

        assert result == []

    @pytest.mark.asyncio
    async def test_returns_empty_list_on_timeout(self):
        """Returns empty list on timeout exceptions."""
        client = MagicMock()
        client.query_spans.side_effect = TimeoutError("Request timed out")
        aggregator = ObservabilityAggregator(client, tenant_id="tenant-1")

        result = await aggregator.get_live_spans(
            "case-abc", since=_now() - timedelta(minutes=1)
        )

        assert result == []

    @pytest.mark.asyncio
    async def test_returns_empty_list_on_generic_exception(self):
        """Returns empty list on any unexpected exception."""
        client = MagicMock()
        client.query_spans.side_effect = RuntimeError("Unexpected failure")
        aggregator = ObservabilityAggregator(client, tenant_id="tenant-1")

        result = await aggregator.get_live_spans(
            "case-abc", since=_now() - timedelta(minutes=1)
        )

        assert result == []


# --- Tests: Phoenix Client Injection ---


class TestPhoenixClientInjection:
    """Test that the Phoenix client is properly injectable."""

    @pytest.mark.asyncio
    async def test_client_receives_correct_project_name(self):
        """The client is called with the tenant-scoped project name."""
        now = _now()
        client = _make_phoenix_client(pd.DataFrame())
        aggregator = ObservabilityAggregator(client, tenant_id="tenant-42")

        await aggregator.get_live_spans("case-abc", since=now)

        client.query_spans.assert_called_once_with(
            project_name="aegis-ir-tenant-42",
            start_time=now,
        )

    @pytest.mark.asyncio
    async def test_different_tenant_uses_different_project(self):
        """Different tenants query different Phoenix project namespaces."""
        now = _now()
        client_a = _make_phoenix_client(pd.DataFrame())
        client_b = _make_phoenix_client(pd.DataFrame())
        agg_a = ObservabilityAggregator(client_a, tenant_id="acme-corp")
        agg_b = ObservabilityAggregator(client_b, tenant_id="globex-inc")

        await agg_a.get_live_spans("case-1", since=now)
        await agg_b.get_live_spans("case-2", since=now)

        client_a.query_spans.assert_called_once_with(
            project_name="aegis-ir-acme-corp",
            start_time=now,
        )
        client_b.query_spans.assert_called_once_with(
            project_name="aegis-ir-globex-inc",
            start_time=now,
        )

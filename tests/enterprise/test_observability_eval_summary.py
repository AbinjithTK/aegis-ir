"""Tests for ObservabilityAggregator.get_investigation_eval_summary().

Validates that:
- Returns EvalSummary with correct approved, flagged, blocked counts
- Collects per-finding EvalDetail entries with score, label, action, issues
- Handles empty results from Phoenix gracefully
- Handles Phoenix connection failures gracefully
- Filters spans correctly by case_id
- Correctly aggregates mixed evaluation results

Requirements: 3.4
"""

from __future__ import annotations

from unittest.mock import MagicMock, PropertyMock, patch

import pandas as pd
import pytest

from sift_defender.enterprise.observability.aggregator import (
    EvalDetail,
    EvalSummary,
    ObservabilityAggregator,
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


def make_eval_dataframe(
    rows: list[dict],
    case_id_column: str = "attributes.case_id",
) -> pd.DataFrame:
    """Helper to create a DataFrame mimicking Phoenix guardrail evaluation spans.

    Args:
        rows: List of dicts with evaluation data.
        case_id_column: Column name for the case_id attribute.

    Returns:
        A pandas DataFrame matching Phoenix span output format.
    """
    records = []
    for row in rows:
        record = {
            case_id_column: row.get("case_id", ""),
            "attributes.finding_id": row.get("finding_id", ""),
            "attributes.evaluator_score": row.get("evaluator_score", 0.0),
            "attributes.label": row.get("label", ""),
            "attributes.guardrail_action": row.get("guardrail_action", ""),
            "attributes.issues": row.get("issues", []),
        }
        records.append(record)
    return pd.DataFrame(records)


# ─── Tests: Basic Aggregation ─────────────────────────────────────────────────


class TestGetInvestigationEvalSummary:
    """Test get_investigation_eval_summary() aggregation logic."""

    @pytest.mark.asyncio
    async def test_returns_eval_summary_type(self, aggregator, mock_phoenix_client):
        """Should return an EvalSummary instance."""
        df = make_eval_dataframe([
            {
                "case_id": "case-001",
                "finding_id": "f-1",
                "evaluator_score": 0.95,
                "label": "factual",
                "guardrail_action": "APPROVE",
                "issues": [],
            }
        ])
        mock_phoenix_client.get_spans_dataframe.return_value = df

        result = await aggregator.get_investigation_eval_summary("case-001")

        assert isinstance(result, EvalSummary)

    @pytest.mark.asyncio
    async def test_counts_approved_findings(self, aggregator, mock_phoenix_client):
        """Should count APPROVE actions correctly."""
        df = make_eval_dataframe([
            {
                "case_id": "case-001",
                "finding_id": "f-1",
                "evaluator_score": 0.92,
                "label": "factual",
                "guardrail_action": "APPROVE",
                "issues": [],
            },
            {
                "case_id": "case-001",
                "finding_id": "f-2",
                "evaluator_score": 0.88,
                "label": "factual",
                "guardrail_action": "APPROVE",
                "issues": [],
            },
        ])
        mock_phoenix_client.get_spans_dataframe.return_value = df

        result = await aggregator.get_investigation_eval_summary("case-001")

        assert result.approved == 2
        assert result.flagged == 0
        assert result.blocked == 0
        assert result.total == 2

    @pytest.mark.asyncio
    async def test_counts_flagged_findings(self, aggregator, mock_phoenix_client):
        """Should count FLAG_FOR_REVIEW actions correctly."""
        df = make_eval_dataframe([
            {
                "case_id": "case-002",
                "finding_id": "f-10",
                "evaluator_score": 0.55,
                "label": "partially_supported",
                "guardrail_action": "FLAG_FOR_REVIEW",
                "issues": ["Weak evidence"],
            },
        ])
        mock_phoenix_client.get_spans_dataframe.return_value = df

        result = await aggregator.get_investigation_eval_summary("case-002")

        assert result.flagged == 1
        assert result.approved == 0
        assert result.blocked == 0
        assert result.total == 1

    @pytest.mark.asyncio
    async def test_counts_blocked_findings(self, aggregator, mock_phoenix_client):
        """Should count BLOCK actions correctly."""
        df = make_eval_dataframe([
            {
                "case_id": "case-003",
                "finding_id": "f-20",
                "evaluator_score": 0.15,
                "label": "hallucinated",
                "guardrail_action": "BLOCK",
                "issues": ["Fabricated evidence", "No supporting data"],
            },
        ])
        mock_phoenix_client.get_spans_dataframe.return_value = df

        result = await aggregator.get_investigation_eval_summary("case-003")

        assert result.blocked == 1
        assert result.approved == 0
        assert result.flagged == 0
        assert result.total == 1

    @pytest.mark.asyncio
    async def test_mixed_evaluation_results(self, aggregator, mock_phoenix_client):
        """Should correctly aggregate mixed APPROVE, FLAG_FOR_REVIEW, BLOCK results."""
        df = make_eval_dataframe([
            {
                "case_id": "case-100",
                "finding_id": "f-a",
                "evaluator_score": 0.95,
                "label": "factual",
                "guardrail_action": "APPROVE",
                "issues": [],
            },
            {
                "case_id": "case-100",
                "finding_id": "f-b",
                "evaluator_score": 0.60,
                "label": "partially_supported",
                "guardrail_action": "FLAG_FOR_REVIEW",
                "issues": ["Timestamp inconsistency"],
            },
            {
                "case_id": "case-100",
                "finding_id": "f-c",
                "evaluator_score": 0.10,
                "label": "hallucinated",
                "guardrail_action": "BLOCK",
                "issues": ["No evidence"],
            },
            {
                "case_id": "case-100",
                "finding_id": "f-d",
                "evaluator_score": 0.91,
                "label": "factual",
                "guardrail_action": "APPROVE",
                "issues": [],
            },
            {
                "case_id": "case-100",
                "finding_id": "f-e",
                "evaluator_score": 0.22,
                "label": "hallucinated",
                "guardrail_action": "BLOCK",
                "issues": ["Fabricated IP"],
            },
        ])
        mock_phoenix_client.get_spans_dataframe.return_value = df

        result = await aggregator.get_investigation_eval_summary("case-100")

        assert result.total == 5
        assert result.approved == 2
        assert result.flagged == 1
        assert result.blocked == 2


# ─── Tests: Per-Finding Detail Collection ─────────────────────────────────────


class TestEvalSummaryFindings:
    """Test that per-finding EvalDetail entries are collected correctly."""

    @pytest.mark.asyncio
    async def test_findings_list_populated(self, aggregator, mock_phoenix_client):
        """Should populate findings list with EvalDetail instances."""
        df = make_eval_dataframe([
            {
                "case_id": "case-001",
                "finding_id": "f-1",
                "evaluator_score": 0.85,
                "label": "factual",
                "guardrail_action": "APPROVE",
                "issues": [],
            },
            {
                "case_id": "case-001",
                "finding_id": "f-2",
                "evaluator_score": 0.40,
                "label": "partially_supported",
                "guardrail_action": "FLAG_FOR_REVIEW",
                "issues": ["Unverified claim"],
            },
        ])
        mock_phoenix_client.get_spans_dataframe.return_value = df

        result = await aggregator.get_investigation_eval_summary("case-001")

        assert len(result.findings) == 2
        assert all(isinstance(f, EvalDetail) for f in result.findings)

    @pytest.mark.asyncio
    async def test_finding_detail_fields(self, aggregator, mock_phoenix_client):
        """Should correctly extract all EvalDetail fields."""
        df = make_eval_dataframe([
            {
                "case_id": "case-001",
                "finding_id": "finding-xyz",
                "evaluator_score": 0.73,
                "label": "partially_supported",
                "guardrail_action": "FLAG_FOR_REVIEW",
                "issues": ["Missing corroboration", "Time gap"],
            },
        ])
        mock_phoenix_client.get_spans_dataframe.return_value = df

        result = await aggregator.get_investigation_eval_summary("case-001")

        detail = result.findings[0]
        assert detail.finding_id == "finding-xyz"
        assert detail.score == 0.73
        assert detail.label == "partially_supported"
        assert detail.action == "FLAG_FOR_REVIEW"
        assert detail.issues == ["Missing corroboration", "Time gap"]

    @pytest.mark.asyncio
    async def test_finding_with_no_issues(self, aggregator, mock_phoenix_client):
        """Approved findings typically have empty issues list."""
        df = make_eval_dataframe([
            {
                "case_id": "case-001",
                "finding_id": "f-clean",
                "evaluator_score": 0.98,
                "label": "factual",
                "guardrail_action": "APPROVE",
                "issues": [],
            },
        ])
        mock_phoenix_client.get_spans_dataframe.return_value = df

        result = await aggregator.get_investigation_eval_summary("case-001")

        assert result.findings[0].issues == []

    @pytest.mark.asyncio
    async def test_finding_score_range(self, aggregator, mock_phoenix_client):
        """Score should preserve float precision from Phoenix."""
        df = make_eval_dataframe([
            {
                "case_id": "case-001",
                "finding_id": "f-1",
                "evaluator_score": 0.123456,
                "label": "factual",
                "guardrail_action": "APPROVE",
                "issues": [],
            },
        ])
        mock_phoenix_client.get_spans_dataframe.return_value = df

        result = await aggregator.get_investigation_eval_summary("case-001")

        assert abs(result.findings[0].score - 0.123456) < 1e-6


# ─── Tests: Case Filtering ────────────────────────────────────────────────────


class TestEvalSummaryCaseFiltering:
    """Test that evaluation spans are filtered correctly by case_id."""

    @pytest.mark.asyncio
    async def test_filters_by_case_id(self, aggregator, mock_phoenix_client):
        """Should only include evaluation spans matching the requested case_id."""
        df = make_eval_dataframe([
            {
                "case_id": "case-001",
                "finding_id": "f-1",
                "evaluator_score": 0.90,
                "label": "factual",
                "guardrail_action": "APPROVE",
                "issues": [],
            },
            {
                "case_id": "case-002",
                "finding_id": "f-2",
                "evaluator_score": 0.80,
                "label": "factual",
                "guardrail_action": "APPROVE",
                "issues": [],
            },
            {
                "case_id": "case-001",
                "finding_id": "f-3",
                "evaluator_score": 0.30,
                "label": "hallucinated",
                "guardrail_action": "BLOCK",
                "issues": ["Fabricated"],
            },
        ])
        mock_phoenix_client.get_spans_dataframe.return_value = df

        result = await aggregator.get_investigation_eval_summary("case-001")

        # Only case-001 spans should be counted
        assert result.total == 2
        assert result.approved == 1
        assert result.blocked == 1
        assert len(result.findings) == 2

    @pytest.mark.asyncio
    async def test_no_spans_for_case(self, aggregator, mock_phoenix_client):
        """Should return zero counts when no spans match the case_id."""
        df = make_eval_dataframe([
            {
                "case_id": "case-other",
                "finding_id": "f-1",
                "evaluator_score": 0.95,
                "label": "factual",
                "guardrail_action": "APPROVE",
                "issues": [],
            },
        ])
        mock_phoenix_client.get_spans_dataframe.return_value = df

        result = await aggregator.get_investigation_eval_summary("case-nonexistent")

        assert result.total == 0
        assert result.approved == 0
        assert result.flagged == 0
        assert result.blocked == 0
        assert result.findings == []


# ─── Tests: Error Handling ────────────────────────────────────────────────────


class TestEvalSummaryErrorHandling:
    """Test graceful handling of Phoenix errors and edge cases."""

    @pytest.mark.asyncio
    async def test_phoenix_returns_empty_dataframe(
        self, aggregator, mock_phoenix_client
    ):
        """Should return empty summary when Phoenix returns no data."""
        mock_phoenix_client.get_spans_dataframe.return_value = pd.DataFrame()

        result = await aggregator.get_investigation_eval_summary("case-001")

        assert result.total == 0
        assert result.approved == 0
        assert result.flagged == 0
        assert result.blocked == 0
        assert result.findings == []

    @pytest.mark.asyncio
    async def test_phoenix_returns_none(self, aggregator, mock_phoenix_client):
        """Should return empty summary when Phoenix returns None."""
        mock_phoenix_client.get_spans_dataframe.return_value = None

        result = await aggregator.get_investigation_eval_summary("case-001")

        assert result.total == 0
        assert result.approved == 0
        assert result.flagged == 0
        assert result.blocked == 0
        assert result.findings == []

    @pytest.mark.asyncio
    async def test_phoenix_raises_exception(self, aggregator, mock_phoenix_client):
        """Should return empty summary when Phoenix raises an exception."""
        mock_phoenix_client.get_spans_dataframe.side_effect = ConnectionError(
            "Phoenix unreachable"
        )

        result = await aggregator.get_investigation_eval_summary("case-001")

        assert result.total == 0
        assert result.approved == 0
        assert result.flagged == 0
        assert result.blocked == 0
        assert result.findings == []

    @pytest.mark.asyncio
    async def test_url_based_aggregator_returns_empty(self):
        """URL-based aggregator (no client object) should return empty summary."""
        aggregator = ObservabilityAggregator(
            phoenix_client="http://localhost:6006",
            tenant_id="tenant-abc",
        )

        result = await aggregator.get_investigation_eval_summary("case-001")

        assert result.total == 0
        assert result.findings == []

    @pytest.mark.asyncio
    async def test_queries_correct_project_name(
        self, aggregator, mock_phoenix_client
    ):
        """Should query Phoenix with tenant-scoped project name."""
        mock_phoenix_client.get_spans_dataframe.return_value = pd.DataFrame()

        await aggregator.get_investigation_eval_summary("case-001")

        mock_phoenix_client.get_spans_dataframe.assert_called_once_with(
            project_name="aegis-ir-acme-corp",
            filter_condition="name == 'guardrail_evaluation'",
        )

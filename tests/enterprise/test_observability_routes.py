"""Tests for observability API routes.

Validates requirements:
    2.1 - Accuracy trend endpoint returns pass/flag/block rates
    4.1 - RBAC enforcement: IR_Lead and CISO can access, SOC_Analyst cannot
"""

from __future__ import annotations

from datetime import date
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sift_defender.enterprise.auth.jwt import create_access_token
from sift_defender.enterprise.observability.aggregator import (
    AccuracyTrend,
    DayAccuracy,
)
from sift_defender.enterprise.observability.routes import router


# Use a fixed secret for deterministic tests
TEST_SECRET = "test-jwt-secret-for-unit-tests"


@pytest.fixture(autouse=True)
def set_jwt_secret(monkeypatch):
    """Set a consistent JWT secret for all tests."""
    monkeypatch.setenv("JWT_SECRET", TEST_SECRET)


@pytest.fixture
def app():
    """Create a test FastAPI app with the observability router."""
    app = FastAPI()
    app.include_router(router)
    return app


@pytest.fixture
def client(app):
    """Create a test client for the observability routes."""
    return TestClient(app)


@pytest.fixture
def sample_accuracy_trend():
    """Create a sample AccuracyTrend for mocking."""
    return AccuracyTrend(
        days=[
            DayAccuracy(
                date=date(2024, 1, 15),
                approved_count=8,
                flagged_count=1,
                blocked_count=1,
                total=10,
                pass_rate=0.8,
                flag_rate=0.1,
                block_rate=0.1,
            ),
            DayAccuracy(
                date=date(2024, 1, 16),
                approved_count=9,
                flagged_count=0,
                blocked_count=1,
                total=10,
                pass_rate=0.9,
                flag_rate=0.0,
                block_rate=0.1,
            ),
        ],
        rolling_average=0.85,
        total_evaluated=20,
    )


class TestAccuracyTrendEndpointAccess:
    """Tests for RBAC enforcement on the accuracy-trend endpoint."""

    @patch(
        "sift_defender.enterprise.observability.routes.ObservabilityAggregator.get_accuracy_trend",
        new_callable=AsyncMock,
    )
    def test_ir_lead_can_access(self, mock_get_trend, client, sample_accuracy_trend):
        """IR_Lead should have access to accuracy-trend endpoint."""
        mock_get_trend.return_value = sample_accuracy_trend

        token = create_access_token("user-lead", "tenant-1", ["ir_lead"])
        response = client.get(
            "/api/observability/accuracy-trend",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200

    @patch(
        "sift_defender.enterprise.observability.routes.ObservabilityAggregator.get_accuracy_trend",
        new_callable=AsyncMock,
    )
    def test_ciso_can_access(self, mock_get_trend, client, sample_accuracy_trend):
        """CISO should have access to accuracy-trend endpoint."""
        mock_get_trend.return_value = sample_accuracy_trend

        token = create_access_token("user-ciso", "tenant-1", ["ciso"])
        response = client.get(
            "/api/observability/accuracy-trend",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200

    @patch(
        "sift_defender.enterprise.audit.service.AuditLogService.record",
        new_callable=AsyncMock,
    )
    def test_soc_analyst_denied(self, mock_record, client):
        """SOC_Analyst should be denied access (no AUDIT_VIEW permission)."""
        mock_record.return_value = "event-id"

        token = create_access_token("user-analyst", "tenant-1", ["soc_analyst"])
        response = client.get(
            "/api/observability/accuracy-trend",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403
        assert response.json()["detail"] == "Insufficient permissions"

    def test_unauthenticated_returns_401(self, client):
        """Missing auth should return 401."""
        response = client.get("/api/observability/accuracy-trend")
        assert response.status_code == 401


class TestAccuracyTrendEndpointResponse:
    """Tests for the accuracy-trend endpoint response format."""

    @patch(
        "sift_defender.enterprise.observability.routes.ObservabilityAggregator.get_accuracy_trend",
        new_callable=AsyncMock,
    )
    def test_returns_correct_structure(self, mock_get_trend, client, sample_accuracy_trend):
        """Response should contain days list, rolling_average, and total_evaluated."""
        mock_get_trend.return_value = sample_accuracy_trend

        token = create_access_token("user-lead", "tenant-1", ["ir_lead"])
        response = client.get(
            "/api/observability/accuracy-trend",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()

        assert "days" in data
        assert "rolling_average" in data
        assert "total_evaluated" in data
        assert len(data["days"]) == 2
        assert data["rolling_average"] == 0.85
        assert data["total_evaluated"] == 20

    @patch(
        "sift_defender.enterprise.observability.routes.ObservabilityAggregator.get_accuracy_trend",
        new_callable=AsyncMock,
    )
    def test_day_entries_have_correct_fields(self, mock_get_trend, client, sample_accuracy_trend):
        """Each day entry should have date, counts, and rates."""
        mock_get_trend.return_value = sample_accuracy_trend

        token = create_access_token("user-lead", "tenant-1", ["ir_lead"])
        response = client.get(
            "/api/observability/accuracy-trend",
            headers={"Authorization": f"Bearer {token}"},
        )
        day = response.json()["days"][0]

        assert day["date"] == "2024-01-15"
        assert day["approved_count"] == 8
        assert day["flagged_count"] == 1
        assert day["blocked_count"] == 1
        assert day["total"] == 10
        assert day["pass_rate"] == 0.8
        assert day["flag_rate"] == 0.1
        assert day["block_rate"] == 0.1

    @patch(
        "sift_defender.enterprise.observability.routes.ObservabilityAggregator.get_accuracy_trend",
        new_callable=AsyncMock,
    )
    def test_empty_trend_returns_empty_days(self, mock_get_trend, client):
        """Empty trend should return empty days list with zero values."""
        mock_get_trend.return_value = AccuracyTrend(
            days=[], rolling_average=0.0, total_evaluated=0
        )

        token = create_access_token("user-lead", "tenant-1", ["ir_lead"])
        response = client.get(
            "/api/observability/accuracy-trend",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["days"] == []
        assert data["rolling_average"] == 0.0
        assert data["total_evaluated"] == 0


class TestAccuracyTrendEndpointParams:
    """Tests for query parameter validation."""

    @patch(
        "sift_defender.enterprise.observability.routes.ObservabilityAggregator.get_accuracy_trend",
        new_callable=AsyncMock,
    )
    def test_default_days_is_30(self, mock_get_trend, client):
        """Default days parameter should be 30."""
        mock_get_trend.return_value = AccuracyTrend(
            days=[], rolling_average=0.0, total_evaluated=0
        )

        token = create_access_token("user-lead", "tenant-1", ["ir_lead"])
        client.get(
            "/api/observability/accuracy-trend",
            headers={"Authorization": f"Bearer {token}"},
        )
        mock_get_trend.assert_called_once_with(days=30)

    @patch(
        "sift_defender.enterprise.observability.routes.ObservabilityAggregator.get_accuracy_trend",
        new_callable=AsyncMock,
    )
    def test_custom_days_parameter(self, mock_get_trend, client):
        """Custom days parameter should be passed to aggregator."""
        mock_get_trend.return_value = AccuracyTrend(
            days=[], rolling_average=0.0, total_evaluated=0
        )

        token = create_access_token("user-lead", "tenant-1", ["ir_lead"])
        client.get(
            "/api/observability/accuracy-trend?days=7",
            headers={"Authorization": f"Bearer {token}"},
        )
        mock_get_trend.assert_called_once_with(days=7)

    def test_days_exceeds_max_returns_422(self, client):
        """Days > 90 should return 422 validation error."""
        token = create_access_token("user-lead", "tenant-1", ["ir_lead"])
        response = client.get(
            "/api/observability/accuracy-trend?days=91",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422

    def test_days_below_min_returns_422(self, client):
        """Days < 1 should return 422 validation error."""
        token = create_access_token("user-lead", "tenant-1", ["ir_lead"])
        response = client.get(
            "/api/observability/accuracy-trend?days=0",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422

    @patch(
        "sift_defender.enterprise.observability.routes.ObservabilityAggregator.get_accuracy_trend",
        new_callable=AsyncMock,
    )
    def test_days_at_max_boundary(self, mock_get_trend, client):
        """Days = 90 should be accepted."""
        mock_get_trend.return_value = AccuracyTrend(
            days=[], rolling_average=0.0, total_evaluated=0
        )

        token = create_access_token("user-lead", "tenant-1", ["ir_lead"])
        response = client.get(
            "/api/observability/accuracy-trend?days=90",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        mock_get_trend.assert_called_once_with(days=90)


class TestAccuracyTrendTenantScoping:
    """Tests verifying tenant isolation in the accuracy-trend endpoint."""

    @patch(
        "sift_defender.enterprise.observability.routes.ObservabilityAggregator.__init__",
        return_value=None,
    )
    @patch(
        "sift_defender.enterprise.observability.routes.ObservabilityAggregator.get_accuracy_trend",
        new_callable=AsyncMock,
    )
    def test_aggregator_uses_user_tenant(self, mock_get_trend, mock_init, client):
        """Aggregator should be initialized with the authenticated user's tenant_id."""
        mock_get_trend.return_value = AccuracyTrend(
            days=[], rolling_average=0.0, total_evaluated=0
        )

        token = create_access_token("user-lead", "tenant-xyz", ["ir_lead"])
        client.get(
            "/api/observability/accuracy-trend",
            headers={"Authorization": f"Bearer {token}"},
        )

        # Verify tenant_id is correctly passed from authenticated user
        mock_init.assert_called_once()
        call_kwargs = mock_init.call_args[1]
        assert call_kwargs["tenant_id"] == "tenant-xyz"


# --- Tests for GET /api/observability/traces/{case_id} ---
# Validates requirements:
#     1.1 - Real-time trace timeline for active investigations
#     1.4 - Phoenix query using Client SDK with project identifier
#     4.2 - RBAC enforcement (INVESTIGATE_VIEW required)


from datetime import datetime, timedelta, timezone

from sift_defender.enterprise.observability.aggregator import SpanSummary


class TestTracesEndpointAccess:
    """Tests for RBAC enforcement on the traces endpoint."""

    @patch(
        "sift_defender.enterprise.observability.routes.ObservabilityAggregator.get_live_spans",
        new_callable=AsyncMock,
    )
    def test_soc_analyst_can_access(self, mock_get_spans, client):
        """SOC_Analyst has INVESTIGATE_VIEW and can access traces."""
        mock_get_spans.return_value = []

        token = create_access_token("user-analyst", "tenant-1", ["soc_analyst"])
        response = client.get(
            "/api/observability/traces/case-001",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200

    @patch(
        "sift_defender.enterprise.observability.routes.ObservabilityAggregator.get_live_spans",
        new_callable=AsyncMock,
    )
    def test_ir_lead_can_access(self, mock_get_spans, client):
        """IR_Lead has INVESTIGATE_VIEW and can access traces."""
        mock_get_spans.return_value = []

        token = create_access_token("user-lead", "tenant-1", ["ir_lead"])
        response = client.get(
            "/api/observability/traces/case-001",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200

    @patch(
        "sift_defender.enterprise.observability.routes.ObservabilityAggregator.get_live_spans",
        new_callable=AsyncMock,
    )
    def test_ciso_can_access(self, mock_get_spans, client):
        """CISO has INVESTIGATE_VIEW and can access traces."""
        mock_get_spans.return_value = []

        token = create_access_token("user-ciso", "tenant-1", ["ciso"])
        response = client.get(
            "/api/observability/traces/case-001",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200

    def test_unauthenticated_returns_401(self, client):
        """Missing auth should return 401."""
        response = client.get("/api/observability/traces/case-001")
        assert response.status_code == 401

    @patch(
        "sift_defender.enterprise.audit.service.AuditLogService.record",
        new_callable=AsyncMock,
    )
    def test_no_permission_returns_403(self, mock_record, client):
        """User without INVESTIGATE_VIEW gets 403."""
        mock_record.return_value = "event-id"

        # Create a token with no roles (no permissions)
        token = create_access_token("user-none", "tenant-1", [])
        response = client.get(
            "/api/observability/traces/case-001",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403
        assert response.json()["detail"] == "Insufficient permissions"


class TestTracesEndpointResponse:
    """Tests for the traces endpoint response format."""

    @patch(
        "sift_defender.enterprise.observability.routes.ObservabilityAggregator.get_live_spans",
        new_callable=AsyncMock,
    )
    def test_returns_spans_as_json_list(self, mock_get_spans, client):
        """Endpoint returns a list of span summaries as JSON."""
        now = datetime.now(timezone.utc)
        mock_get_spans.return_value = [
            SpanSummary(
                span_id="span-001",
                name="tool_call:memory_analysis",
                duration_ms=150.5,
                status="OK",
                start_time=now - timedelta(seconds=10),
                end_time=now - timedelta(seconds=9),
                attributes={"tool": "volatility"},
            ),
            SpanSummary(
                span_id="span-002",
                name="llm_reasoning",
                duration_ms=2000.0,
                status="OK",
                start_time=now - timedelta(seconds=8),
                end_time=now - timedelta(seconds=6),
                attributes={},
            ),
        ]

        token = create_access_token("user-analyst", "tenant-1", ["soc_analyst"])
        response = client.get(
            "/api/observability/traces/case-abc",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        assert data[0]["span_id"] == "span-001"
        assert data[0]["name"] == "tool_call:memory_analysis"
        assert data[0]["duration_ms"] == 150.5
        assert data[0]["status"] == "OK"
        assert data[0]["attributes"]["tool"] == "volatility"
        assert data[1]["span_id"] == "span-002"
        assert data[1]["name"] == "llm_reasoning"

    @patch(
        "sift_defender.enterprise.observability.routes.ObservabilityAggregator.get_live_spans",
        new_callable=AsyncMock,
    )
    def test_returns_empty_list_when_no_spans(self, mock_get_spans, client):
        """Returns empty list when no spans match."""
        mock_get_spans.return_value = []

        token = create_access_token("user-analyst", "tenant-1", ["soc_analyst"])
        response = client.get(
            "/api/observability/traces/case-empty",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        assert response.json() == []

    @patch(
        "sift_defender.enterprise.observability.routes.ObservabilityAggregator.get_live_spans",
        new_callable=AsyncMock,
    )
    def test_span_response_includes_timestamps(self, mock_get_spans, client):
        """Span responses include start_time and end_time as ISO strings."""
        now = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        mock_get_spans.return_value = [
            SpanSummary(
                span_id="span-001",
                name="test_span",
                duration_ms=100.0,
                status="OK",
                start_time=now,
                end_time=now + timedelta(milliseconds=100),
                attributes={},
            ),
        ]

        token = create_access_token("user-analyst", "tenant-1", ["soc_analyst"])
        response = client.get(
            "/api/observability/traces/case-001",
            headers={"Authorization": f"Bearer {token}"},
        )

        data = response.json()
        assert "2024-06-15" in data[0]["start_time"]
        assert "2024-06-15" in data[0]["end_time"]


class TestTracesEndpointParams:
    """Tests for the since query parameter behavior."""

    @patch(
        "sift_defender.enterprise.observability.routes.ObservabilityAggregator.get_live_spans",
        new_callable=AsyncMock,
    )
    def test_since_defaults_to_5_minutes_ago(self, mock_get_spans, client):
        """When since is not provided, defaults to approximately 5 minutes ago."""
        mock_get_spans.return_value = []

        token = create_access_token("user-analyst", "tenant-1", ["soc_analyst"])
        before_call = datetime.now(timezone.utc)
        client.get(
            "/api/observability/traces/case-001",
            headers={"Authorization": f"Bearer {token}"},
        )
        after_call = datetime.now(timezone.utc)

        mock_get_spans.assert_called_once()
        call_kwargs = mock_get_spans.call_args[1]
        since_value = call_kwargs["since"]

        # since should be approximately 5 minutes before the call
        expected_earliest = before_call - timedelta(minutes=5, seconds=2)
        expected_latest = after_call - timedelta(minutes=5) + timedelta(seconds=2)
        assert expected_earliest <= since_value <= expected_latest

    @patch(
        "sift_defender.enterprise.observability.routes.ObservabilityAggregator.get_live_spans",
        new_callable=AsyncMock,
    )
    def test_accepts_custom_since_parameter(self, mock_get_spans, client):
        """Custom since ISO datetime is passed to the aggregator."""
        mock_get_spans.return_value = []

        token = create_access_token("user-analyst", "tenant-1", ["soc_analyst"])
        response = client.get(
            "/api/observability/traces/case-001?since=2024-01-15T10:00:00Z",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        call_kwargs = mock_get_spans.call_args[1]
        since_value = call_kwargs["since"]
        assert since_value.year == 2024
        assert since_value.month == 1
        assert since_value.day == 15
        assert since_value.hour == 10

    @patch(
        "sift_defender.enterprise.observability.routes.ObservabilityAggregator.get_live_spans",
        new_callable=AsyncMock,
    )
    def test_passes_case_id_to_aggregator(self, mock_get_spans, client):
        """The case_id path parameter is passed to get_live_spans."""
        mock_get_spans.return_value = []

        token = create_access_token("user-analyst", "tenant-1", ["soc_analyst"])
        client.get(
            "/api/observability/traces/case-xyz-123",
            headers={"Authorization": f"Bearer {token}"},
        )

        call_kwargs = mock_get_spans.call_args[1]
        assert call_kwargs["case_id"] == "case-xyz-123"


class TestTracesTenantScoping:
    """Tests verifying tenant isolation in the traces endpoint."""

    @patch(
        "sift_defender.enterprise.observability.routes.ObservabilityAggregator.__init__",
        return_value=None,
    )
    @patch(
        "sift_defender.enterprise.observability.routes.ObservabilityAggregator.get_live_spans",
        new_callable=AsyncMock,
    )
    def test_aggregator_uses_user_tenant(self, mock_get_spans, mock_init, client):
        """Aggregator should be initialized with the authenticated user's tenant_id."""
        mock_get_spans.return_value = []

        token = create_access_token("user-analyst", "tenant-abc", ["soc_analyst"])
        client.get(
            "/api/observability/traces/case-001",
            headers={"Authorization": f"Bearer {token}"},
        )

        mock_init.assert_called_once()
        call_kwargs = mock_init.call_args[1]
        assert call_kwargs["tenant_id"] == "tenant-abc"

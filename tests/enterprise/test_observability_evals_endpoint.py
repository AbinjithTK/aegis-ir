"""Tests for GET /api/observability/investigation/{id}/evals endpoint.

Validates:
- Returns evaluation summary with total, approved, flagged, blocked counts
- Returns per-finding evaluation details (score, label, action, issues)
- Requires INVESTIGATE_VIEW permission (403 for unauthorized users)
- Returns empty summary when no evaluation data exists
- Scopes queries to the authenticated user's tenant

Requirements: 3.1, 3.2
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sift_defender.enterprise.auth.dependencies import (
    User,
    get_current_user,
    require_permission,
)
from sift_defender.enterprise.auth.rbac import Permission
from sift_defender.enterprise.observability.aggregator import (
    EvalDetail,
    EvalSummary,
)
from sift_defender.enterprise.observability.routes import (
    _get_aggregator,
    observability_router,
)


# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def soc_analyst() -> User:
    """A SOC analyst user with INVESTIGATE_VIEW permission."""
    return User(
        id="user-soc-001",
        email="analyst@acme.com",
        tenant_id="tenant-acme",
        roles=["soc_analyst"],
        is_active=True,
    )


@pytest.fixture
def unauthorized_user() -> User:
    """A user without INVESTIGATE_VIEW permission."""
    return User(
        id="user-noperm",
        email="noperm@acme.com",
        tenant_id="tenant-acme",
        roles=[],
        is_active=True,
    )


@pytest.fixture
def sample_eval_summary() -> EvalSummary:
    """A sample EvalSummary with mixed results."""
    return EvalSummary(
        total=4,
        approved=2,
        flagged=1,
        blocked=1,
        findings=[
            EvalDetail(
                finding_id="f-001",
                score=0.95,
                label="factual",
                action="APPROVE",
                issues=[],
            ),
            EvalDetail(
                finding_id="f-002",
                score=0.88,
                label="factual",
                action="APPROVE",
                issues=[],
            ),
            EvalDetail(
                finding_id="f-003",
                score=0.55,
                label="partially_supported",
                action="FLAG_FOR_REVIEW",
                issues=["Weak evidence link"],
            ),
            EvalDetail(
                finding_id="f-004",
                score=0.12,
                label="hallucinated",
                action="BLOCK",
                issues=["Fabricated evidence", "No supporting data"],
            ),
        ],
    )


@pytest.fixture
def empty_eval_summary() -> EvalSummary:
    """An empty EvalSummary (no findings evaluated)."""
    return EvalSummary(
        total=0,
        approved=0,
        flagged=0,
        blocked=0,
        findings=[],
    )


def _make_app_with_user(user: User) -> FastAPI:
    """Create a FastAPI test app with auth bypassed for the given user.

    Overrides get_current_user so all permission checks resolve with
    the provided user object and its roles.
    """
    app = FastAPI()
    app.include_router(observability_router)
    app.dependency_overrides[get_current_user] = lambda: user
    return app


# ─── Tests: Successful Response ───────────────────────────────────────────────


class TestEvalsEndpointSuccess:
    """Test the /api/observability/investigation/{id}/evals endpoint success cases."""

    @pytest.mark.asyncio
    async def test_returns_evaluation_summary(self, soc_analyst, sample_eval_summary):
        """Should return evaluation summary with correct counts."""
        app = _make_app_with_user(soc_analyst)

        mock_aggregator = MagicMock()
        mock_aggregator.get_investigation_eval_summary = AsyncMock(
            return_value=sample_eval_summary
        )

        with patch(
            "sift_defender.enterprise.observability.routes._get_aggregator",
            return_value=mock_aggregator,
        ):
            client = TestClient(app)
            response = client.get(
                "/api/observability/investigation/case-001/evals"
            )

        assert response.status_code == 200
        data = response.json()
        assert data["investigation_id"] == "case-001"
        assert data["total"] == 4
        assert data["approved"] == 2
        assert data["flagged"] == 1
        assert data["blocked"] == 1

    @pytest.mark.asyncio
    async def test_returns_per_finding_details(self, soc_analyst, sample_eval_summary):
        """Should return per-finding evaluation details."""
        app = _make_app_with_user(soc_analyst)

        mock_aggregator = MagicMock()
        mock_aggregator.get_investigation_eval_summary = AsyncMock(
            return_value=sample_eval_summary
        )

        with patch(
            "sift_defender.enterprise.observability.routes._get_aggregator",
            return_value=mock_aggregator,
        ):
            client = TestClient(app)
            response = client.get(
                "/api/observability/investigation/case-001/evals"
            )

        data = response.json()
        findings = data["findings"]
        assert len(findings) == 4

        # Check first finding (APPROVE)
        assert findings[0]["finding_id"] == "f-001"
        assert findings[0]["score"] == 0.95
        assert findings[0]["label"] == "factual"
        assert findings[0]["action"] == "APPROVE"
        assert findings[0]["issues"] == []

        # Check flagged finding
        assert findings[2]["finding_id"] == "f-003"
        assert findings[2]["score"] == 0.55
        assert findings[2]["label"] == "partially_supported"
        assert findings[2]["action"] == "FLAG_FOR_REVIEW"
        assert findings[2]["issues"] == ["Weak evidence link"]

        # Check blocked finding
        assert findings[3]["finding_id"] == "f-004"
        assert findings[3]["score"] == 0.12
        assert findings[3]["label"] == "hallucinated"
        assert findings[3]["action"] == "BLOCK"
        assert findings[3]["issues"] == ["Fabricated evidence", "No supporting data"]

    @pytest.mark.asyncio
    async def test_empty_evaluation_summary(self, soc_analyst, empty_eval_summary):
        """Should return zero counts when no evaluations exist."""
        app = _make_app_with_user(soc_analyst)

        mock_aggregator = MagicMock()
        mock_aggregator.get_investigation_eval_summary = AsyncMock(
            return_value=empty_eval_summary
        )

        with patch(
            "sift_defender.enterprise.observability.routes._get_aggregator",
            return_value=mock_aggregator,
        ):
            client = TestClient(app)
            response = client.get(
                "/api/observability/investigation/nonexistent/evals"
            )

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["approved"] == 0
        assert data["flagged"] == 0
        assert data["blocked"] == 0
        assert data["findings"] == []

    @pytest.mark.asyncio
    async def test_investigation_id_passed_to_aggregator(self, soc_analyst):
        """Should pass the investigation_id path parameter to the aggregator."""
        app = _make_app_with_user(soc_analyst)

        mock_aggregator = MagicMock()
        mock_aggregator.get_investigation_eval_summary = AsyncMock(
            return_value=EvalSummary(
                total=0, approved=0, flagged=0, blocked=0, findings=[]
            )
        )

        with patch(
            "sift_defender.enterprise.observability.routes._get_aggregator",
            return_value=mock_aggregator,
        ):
            client = TestClient(app)
            client.get(
                "/api/observability/investigation/CASE-20240115-143000/evals"
            )

        mock_aggregator.get_investigation_eval_summary.assert_called_once_with(
            "CASE-20240115-143000"
        )


# ─── Tests: Permission Enforcement ───────────────────────────────────────────


class TestEvalsEndpointPermissions:
    """Test RBAC enforcement on the evals endpoint."""

    @pytest.mark.asyncio
    async def test_requires_investigate_view_permission(self, unauthorized_user):
        """Should return 403 when user lacks INVESTIGATE_VIEW permission."""
        app = _make_app_with_user(unauthorized_user)

        client = TestClient(app)
        response = client.get(
            "/api/observability/investigation/case-001/evals"
        )

        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_unauthenticated_returns_401(self):
        """Should return 401 when no auth token is provided."""
        app = FastAPI()
        app.include_router(observability_router)

        # No dependency overrides — will require real auth
        client = TestClient(app)
        response = client.get(
            "/api/observability/investigation/case-001/evals"
        )

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_soc_analyst_role_has_access(self, soc_analyst):
        """SOC analyst role should have INVESTIGATE_VIEW permission."""
        app = _make_app_with_user(soc_analyst)

        mock_aggregator = MagicMock()
        mock_aggregator.get_investigation_eval_summary = AsyncMock(
            return_value=EvalSummary(
                total=0, approved=0, flagged=0, blocked=0, findings=[]
            )
        )

        with patch(
            "sift_defender.enterprise.observability.routes._get_aggregator",
            return_value=mock_aggregator,
        ):
            client = TestClient(app)
            response = client.get(
                "/api/observability/investigation/case-001/evals"
            )

        assert response.status_code == 200


# ─── Tests: Tenant Scoping ────────────────────────────────────────────────────


class TestEvalsEndpointTenantScoping:
    """Test that the endpoint creates a tenant-scoped aggregator."""

    @pytest.mark.asyncio
    async def test_aggregator_uses_user_tenant_id(self, soc_analyst):
        """Should create an aggregator scoped to the authenticated user's tenant."""
        app = _make_app_with_user(soc_analyst)

        with patch(
            "sift_defender.enterprise.observability.routes._get_aggregator"
        ) as mock_get_agg:
            mock_agg = MagicMock()
            mock_agg.get_investigation_eval_summary = AsyncMock(
                return_value=EvalSummary(
                    total=0, approved=0, flagged=0, blocked=0, findings=[]
                )
            )
            mock_get_agg.return_value = mock_agg

            client = TestClient(app)
            client.get("/api/observability/investigation/case-001/evals")

            mock_get_agg.assert_called_once_with(soc_analyst)

    @pytest.mark.asyncio
    async def test_different_tenants_get_different_aggregators(self):
        """Different tenant users should result in different aggregator instances."""
        tenant_a_user = User(
            id="user-a",
            tenant_id="tenant-alpha",
            roles=["soc_analyst"],
        )
        tenant_b_user = User(
            id="user-b",
            tenant_id="tenant-beta",
            roles=["soc_analyst"],
        )

        agg_a = _get_aggregator(tenant_a_user)
        agg_b = _get_aggregator(tenant_b_user)

        assert agg_a.tenant_id == "tenant-alpha"
        assert agg_b.tenant_id == "tenant-beta"
        assert agg_a.project_name == "aegis-ir-tenant-alpha"
        assert agg_b.project_name == "aegis-ir-tenant-beta"

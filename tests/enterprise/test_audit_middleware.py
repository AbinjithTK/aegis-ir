"""Tests for AuditMiddleware — automatic API request audit logging.

Validates:
- Middleware captures request method, path, user_id, tenant_id, response status
- JWT bearer token extraction and decoding for user identification
- Excluded paths (health, static, audit) are not logged
- Asynchronous fire-and-forget recording does not block responses
- Unauthenticated requests (no tenant_id) are skipped gracefully

Requirements: 7.1, 7.2
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from sift_defender.enterprise.audit.middleware import (
    SKIP_PATHS,
    SKIP_PREFIXES,
    AuditMiddleware,
    _extract_bearer_token,
    _extract_resource_type,
    _extract_user_from_token,
    _should_skip,
)
from sift_defender.enterprise.audit.service import AuditEvent, AuditEventType
from sift_defender.enterprise.auth.jwt import (
    TokenPayload,
    create_access_token,
)


# --- Helper fixtures ---


def _make_app(audit_service: AsyncMock | None = None) -> Starlette:
    """Create a minimal Starlette app with the AuditMiddleware for testing."""

    async def homepage(request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    async def cases_list(request: Request) -> JSONResponse:
        return JSONResponse({"cases": []})

    async def health(request: Request) -> PlainTextResponse:
        return PlainTextResponse("healthy")

    async def api_status(request: Request) -> JSONResponse:
        return JSONResponse({"status": "running"})

    async def audit_endpoint(request: Request) -> JSONResponse:
        return JSONResponse({"logs": []})

    app = Starlette(
        routes=[
            Route("/", homepage),
            Route("/api/cases", cases_list),
            Route("/api/cases/{case_id}", cases_list),
            Route("/health", health),
            Route("/api/status", api_status),
            Route("/api/audit", audit_endpoint),
            Route("/api/audit/search", audit_endpoint),
        ]
    )

    mock_service = audit_service or AsyncMock()
    if audit_service is None:
        mock_service.record = AsyncMock(return_value="event-id-123")

    app.add_middleware(AuditMiddleware, audit_service=mock_service)
    return app


@pytest.fixture
def mock_audit_service():
    """Mock AuditLogService with async record method."""
    service = AsyncMock()
    service.record = AsyncMock(return_value="event-id-123")
    return service


@pytest.fixture
def app(mock_audit_service):
    """Starlette app with AuditMiddleware and mock service."""
    return _make_app(mock_audit_service)


@pytest.fixture
def client(app):
    """Test client for the Starlette app."""
    return TestClient(app)


@pytest.fixture
def valid_token():
    """Create a valid JWT access token for testing."""
    return create_access_token(
        user_id="user-001",
        tenant_id="tenant-001",
        roles=["soc_analyst"],
    )


# --- Unit tests for helper functions ---


class TestShouldSkip:
    """Test the _should_skip helper for path exclusion logic."""

    def test_skips_health(self):
        assert _should_skip("/health") is True

    def test_skips_api_status(self):
        assert _should_skip("/api/status") is True

    def test_skips_audit_endpoint(self):
        assert _should_skip("/api/audit") is True

    def test_skips_audit_trailing_slash(self):
        assert _should_skip("/api/audit/") is True

    def test_skips_static_prefix(self):
        assert _should_skip("/static/js/app.js") is True

    def test_skips_audit_sub_routes(self):
        assert _should_skip("/api/audit/search") is True

    def test_does_not_skip_cases(self):
        assert _should_skip("/api/cases") is False

    def test_does_not_skip_investigations(self):
        assert _should_skip("/api/investigations") is False

    def test_does_not_skip_root(self):
        assert _should_skip("/") is False


class TestExtractBearerToken:
    """Test JWT bearer token extraction from Authorization header."""

    def test_extracts_valid_bearer(self):
        assert _extract_bearer_token("Bearer abc123") == "abc123"

    def test_extracts_bearer_case_insensitive(self):
        assert _extract_bearer_token("bearer abc123") == "abc123"

    def test_returns_none_for_missing_header(self):
        assert _extract_bearer_token(None) is None

    def test_returns_none_for_empty_header(self):
        assert _extract_bearer_token("") is None

    def test_returns_none_for_basic_auth(self):
        assert _extract_bearer_token("Basic abc123") is None

    def test_handles_token_with_dots(self):
        token = "eyJhbGciOiJIUzI1NiJ9.payload.signature"
        assert _extract_bearer_token(f"Bearer {token}") == token


class TestExtractUserFromToken:
    """Test JWT decoding for user extraction."""

    def test_extracts_valid_token(self, valid_token):
        payload = _extract_user_from_token(valid_token)
        assert payload is not None
        assert payload.sub == "user-001"
        assert payload.tenant_id == "tenant-001"

    def test_returns_none_for_invalid_token(self):
        assert _extract_user_from_token("invalid.token.here") is None

    def test_returns_none_for_empty_string(self):
        assert _extract_user_from_token("") is None


class TestExtractResourceType:
    """Test resource type extraction from URL path."""

    def test_extracts_from_api_prefix(self):
        assert _extract_resource_type("/api/cases/123") == "cases"

    def test_extracts_from_api_no_id(self):
        assert _extract_resource_type("/api/investigations") == "investigations"

    def test_extracts_auth_segment(self):
        assert _extract_resource_type("/api/auth/login") == "auth"

    def test_extracts_non_api_path(self):
        assert _extract_resource_type("/dashboard") == "dashboard"

    def test_returns_none_for_empty_path(self):
        assert _extract_resource_type("/") is None

    def test_returns_none_for_truly_empty(self):
        assert _extract_resource_type("") is None


# --- Integration tests with TestClient ---


class TestAuditMiddlewareIntegration:
    """Test AuditMiddleware end-to-end with Starlette TestClient."""

    def test_authenticated_request_records_audit(self, client, valid_token, mock_audit_service):
        """Authenticated request triggers audit record with user info."""
        response = client.get(
            "/api/cases",
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert response.status_code == 200

        # Give fire-and-forget task time to complete
        mock_audit_service.record.assert_called_once()
        event: AuditEvent = mock_audit_service.record.call_args[0][0]

        assert event.event_type == AuditEventType.API_REQUEST
        assert event.user_id == "user-001"
        assert event.tenant_id == "tenant-001"
        assert event.resource_type == "cases"
        assert event.details["method"] == "GET"
        assert event.details["path"] == "/api/cases"
        assert event.details["status_code"] == 200

    def test_unauthenticated_request_skips_audit(self, client, mock_audit_service):
        """Request without token does not record audit (no tenant_id)."""
        response = client.get("/api/cases")
        assert response.status_code == 200

        mock_audit_service.record.assert_not_called()

    def test_health_endpoint_not_audited(self, client, valid_token, mock_audit_service):
        """Health check endpoint is excluded from audit logging."""
        response = client.get(
            "/health",
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert response.status_code == 200
        mock_audit_service.record.assert_not_called()

    def test_api_status_not_audited(self, client, valid_token, mock_audit_service):
        """API status endpoint is excluded from audit logging."""
        response = client.get(
            "/api/status",
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert response.status_code == 200
        mock_audit_service.record.assert_not_called()

    def test_audit_endpoint_not_audited(self, client, valid_token, mock_audit_service):
        """Audit endpoint itself is excluded (prevents infinite recursion)."""
        response = client.get(
            "/api/audit",
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert response.status_code == 200
        mock_audit_service.record.assert_not_called()

    def test_audit_search_not_audited(self, client, valid_token, mock_audit_service):
        """Audit sub-routes are excluded."""
        response = client.get(
            "/api/audit/search",
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert response.status_code == 200
        mock_audit_service.record.assert_not_called()

    def test_captures_query_params(self, client, valid_token, mock_audit_service):
        """Query parameters are included in audit details."""
        response = client.get(
            "/api/cases?page=1&size=10",
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert response.status_code == 200

        mock_audit_service.record.assert_called_once()
        event: AuditEvent = mock_audit_service.record.call_args[0][0]
        assert "query_params" in event.details
        assert "page=1" in event.details["query_params"]

    def test_invalid_token_skips_audit(self, client, mock_audit_service):
        """Invalid JWT results in no audit record (no tenant_id available)."""
        response = client.get(
            "/api/cases",
            headers={"Authorization": "Bearer invalid.jwt.token"},
        )
        assert response.status_code == 200
        mock_audit_service.record.assert_not_called()

    def test_response_not_delayed_on_audit_failure(self, mock_audit_service, valid_token):
        """Audit recording failure does not block or error the response."""
        mock_audit_service.record = AsyncMock(side_effect=RuntimeError("DB down"))

        app = _make_app(mock_audit_service)
        client = TestClient(app)

        response = client.get(
            "/api/cases",
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        # Response should still succeed even though audit failed
        assert response.status_code == 200

    def test_captures_different_http_methods(self, valid_token, mock_audit_service):
        """Different HTTP methods are captured correctly."""
        app = _make_app(mock_audit_service)

        # Add POST route
        async def create_case(request: Request) -> JSONResponse:
            return JSONResponse({"id": "new-case"}, status_code=201)

        app.routes.append(Route("/api/cases", create_case, methods=["POST"]))
        client = TestClient(app)

        response = client.post(
            "/api/cases",
            headers={"Authorization": f"Bearer {valid_token}"},
            json={"name": "Test case"},
        )
        assert response.status_code == 201

        mock_audit_service.record.assert_called()
        event: AuditEvent = mock_audit_service.record.call_args[0][0]
        assert event.details["method"] == "POST"
        assert event.details["status_code"] == 201


class TestAuditEventTypeApiRequest:
    """Test that API_REQUEST event type was added to AuditEventType."""

    def test_api_request_exists(self):
        assert AuditEventType.API_REQUEST == "api.request"

    def test_api_request_is_string_enum(self):
        assert isinstance(AuditEventType.API_REQUEST.value, str)

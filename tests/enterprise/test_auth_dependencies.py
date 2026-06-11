"""Tests for FastAPI authentication dependencies.

Validates requirements:
    4.2 - RBAC session association with tenant via identity provider claims
    8.2 - Tenant association on authentication via JWT claims
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient

from sift_defender.enterprise.auth.dependencies import (
    User,
    get_current_active_user,
    get_current_user,
    oauth2_scheme,
)
from sift_defender.enterprise.auth.jwt import (
    create_access_token,
    create_refresh_token,
)


# Use a fixed secret for deterministic tests
TEST_SECRET = "test-jwt-secret-for-unit-tests"


@pytest.fixture(autouse=True)
def set_jwt_secret(monkeypatch):
    """Set a consistent JWT secret for all tests."""
    monkeypatch.setenv("JWT_SECRET", TEST_SECRET)


# --- Test app setup ---

def create_test_app() -> FastAPI:
    """Create a minimal FastAPI app with protected endpoints for testing."""
    app = FastAPI()

    @app.get("/protected")
    async def protected_route(user: User = Depends(get_current_user)):
        return {
            "id": user.id,
            "tenant_id": user.tenant_id,
            "roles": user.roles,
            "is_active": user.is_active,
        }

    @app.get("/active-only")
    async def active_only_route(user: User = Depends(get_current_active_user)):
        return {"id": user.id, "tenant_id": user.tenant_id}

    return app


@pytest.fixture
def app():
    """Create a test FastAPI application."""
    return create_test_app()


@pytest.fixture
def client(app):
    """Create a test client for the FastAPI application."""
    return TestClient(app)


# --- User Model Tests ---


class TestUserModel:
    """Tests for the User Pydantic model."""

    def test_create_user_with_all_fields(self):
        """Should create a User with all fields populated."""
        user = User(
            id="user-123",
            email="analyst@acme.com",
            tenant_id="tenant-abc",
            roles=["soc_analyst"],
            is_active=True,
        )
        assert user.id == "user-123"
        assert user.email == "analyst@acme.com"
        assert user.tenant_id == "tenant-abc"
        assert user.roles == ["soc_analyst"]
        assert user.is_active is True

    def test_create_user_with_defaults(self):
        """Should create a User with default values for optional fields."""
        user = User(id="user-1", tenant_id="tenant-1")
        assert user.email is None
        assert user.roles == []
        assert user.is_active is True

    def test_create_user_multiple_roles(self):
        """Should support multiple roles."""
        user = User(
            id="user-1",
            tenant_id="tenant-1",
            roles=["soc_analyst", "ir_lead"],
        )
        assert user.roles == ["soc_analyst", "ir_lead"]


# --- get_current_user Dependency Tests ---


class TestGetCurrentUser:
    """Tests for the get_current_user dependency."""

    def test_valid_access_token_returns_user(self, client):
        """A valid access token should return a User with correct claims."""
        token = create_access_token("user-42", "tenant-xyz", ["soc_analyst", "ir_lead"])
        response = client.get(
            "/protected", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == "user-42"
        assert data["tenant_id"] == "tenant-xyz"
        assert data["roles"] == ["soc_analyst", "ir_lead"]
        assert data["is_active"] is True

    def test_missing_authorization_header_returns_401(self, client):
        """Missing Authorization header should return 401."""
        response = client.get("/protected")
        assert response.status_code == 401

    def test_invalid_token_returns_401(self, client):
        """An invalid/malformed token should return 401."""
        response = client.get(
            "/protected", headers={"Authorization": "Bearer not-a-real-token"}
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "Could not validate credentials"

    def test_expired_token_returns_401(self, client):
        """An expired access token should return 401."""
        token = create_access_token(
            "user-1", "tenant-1", ["soc_analyst"], expires_delta=timedelta(seconds=-1)
        )
        response = client.get(
            "/protected", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "Could not validate credentials"

    def test_refresh_token_rejected_for_access(self, client):
        """A refresh token should be rejected when access token is expected."""
        token = create_refresh_token("user-1", "tenant-1")
        response = client.get(
            "/protected", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "Could not validate credentials"

    def test_tenant_id_extracted_from_token(self, client):
        """The tenant_id should be correctly extracted from JWT claims."""
        token = create_access_token("user-1", "tenant-isolated", ["ciso"])
        response = client.get(
            "/protected", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        assert response.json()["tenant_id"] == "tenant-isolated"

    def test_empty_roles_from_token(self, client):
        """A token with empty roles should return a user with empty roles list."""
        token = create_access_token("user-1", "tenant-1", [])
        response = client.get(
            "/protected", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        assert response.json()["roles"] == []

    def test_www_authenticate_header_on_401(self, client):
        """401 responses should include WWW-Authenticate: Bearer header."""
        response = client.get(
            "/protected", headers={"Authorization": "Bearer bad-token"}
        )
        assert response.status_code == 401
        assert response.headers.get("www-authenticate") == "Bearer"


# --- get_current_active_user Dependency Tests ---


class TestGetCurrentActiveUser:
    """Tests for the get_current_active_user dependency."""

    def test_active_user_passes(self, client):
        """An active user should pass the active user check."""
        token = create_access_token("user-active", "tenant-1", ["soc_analyst"])
        response = client.get(
            "/active-only", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        assert response.json()["id"] == "user-active"

    def test_invalid_token_returns_401(self, client):
        """An invalid token should still return 401 (get_current_user fails first)."""
        response = client.get(
            "/active-only", headers={"Authorization": "Bearer invalid"}
        )
        assert response.status_code == 401

    def test_missing_auth_returns_401(self, client):
        """Missing auth should return 401."""
        response = client.get("/active-only")
        assert response.status_code == 401


class TestGetCurrentActiveUserInactive:
    """Tests for inactive user rejection via get_current_active_user."""

    def test_inactive_user_rejected(self):
        """An inactive user should be rejected with 401."""
        app = FastAPI()

        # Override the dependency to simulate an inactive user
        async def mock_get_current_user():
            return User(
                id="user-disabled",
                tenant_id="tenant-1",
                roles=["soc_analyst"],
                is_active=False,
            )

        app.dependency_overrides[get_current_user] = mock_get_current_user

        @app.get("/active-only")
        async def active_route(user: User = Depends(get_current_active_user)):
            return {"id": user.id}

        client = TestClient(app)
        response = client.get("/active-only")
        assert response.status_code == 401
        assert response.json()["detail"] == "Inactive user"


# --- OAuth2 Scheme Tests ---


class TestOAuth2Scheme:
    """Tests for the OAuth2PasswordBearer scheme configuration."""

    def test_scheme_configured_with_token_url(self):
        """The OAuth2 scheme should be configured with the login endpoint."""
        assert oauth2_scheme.model.flows.password.tokenUrl == "/api/auth/login"

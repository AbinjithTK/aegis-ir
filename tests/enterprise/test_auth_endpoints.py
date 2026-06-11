"""Tests for authentication endpoints (login and refresh).

Validates requirements:
    4.1 - RBAC default roles (login returns JWT with role claims)
    14.1 - SOC Analyst investigation workflow (login is the entry point)
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from jose import jwt

from sift_defender.enterprise.auth.jwt import (
    JWT_ALGORITHM,
    create_access_token,
    create_refresh_token,
    verify_token,
)
from sift_defender.enterprise.auth.passwords import hash_password, verify_password


# Use a fixed secret for deterministic tests
TEST_SECRET = "test-jwt-secret-for-unit-tests"


@pytest.fixture(autouse=True)
def set_jwt_secret(monkeypatch):
    """Set a consistent JWT secret for all tests."""
    monkeypatch.setenv("JWT_SECRET", TEST_SECRET)


# --- Password Hashing Tests ---


class TestHashPassword:
    """Tests for password hashing utility."""

    def test_hash_returns_string(self):
        """hash_password should return a bcrypt hash string."""
        hashed = hash_password("my-secret-password")
        assert isinstance(hashed, str)
        assert hashed.startswith("$2b$")

    def test_hash_differs_from_plaintext(self):
        """Hashed password must not equal plaintext."""
        plain = "my-secret-password"
        hashed = hash_password(plain)
        assert hashed != plain

    def test_hash_produces_unique_values(self):
        """Hashing the same password twice should produce different hashes (different salts)."""
        plain = "same-password"
        hash1 = hash_password(plain)
        hash2 = hash_password(plain)
        assert hash1 != hash2

    def test_hash_empty_password_raises(self):
        """Empty password should raise ValueError."""
        with pytest.raises(ValueError, match="must not be empty"):
            hash_password("")

    def test_hash_handles_unicode(self):
        """Should handle unicode passwords correctly."""
        hashed = hash_password("pässwörd-日本語")
        assert isinstance(hashed, str)
        assert hashed.startswith("$2b$")


class TestVerifyPassword:
    """Tests for password verification utility."""

    def test_verify_correct_password(self):
        """Correct password should verify as True."""
        plain = "correct-horse-battery-staple"
        hashed = hash_password(plain)
        assert verify_password(plain, hashed) is True

    def test_verify_wrong_password(self):
        """Wrong password should verify as False."""
        hashed = hash_password("correct-password")
        assert verify_password("wrong-password", hashed) is False

    def test_verify_empty_plain_returns_false(self):
        """Empty plaintext should return False."""
        hashed = hash_password("some-password")
        assert verify_password("", hashed) is False

    def test_verify_empty_hash_returns_false(self):
        """Empty hash should return False."""
        assert verify_password("some-password", "") is False

    def test_verify_invalid_hash_returns_false(self):
        """Invalid hash string should return False without raising."""
        assert verify_password("password", "not-a-valid-bcrypt-hash") is False

    def test_verify_roundtrip(self):
        """hash_password then verify_password should always succeed."""
        for pwd in ["short", "a" * 72, "sp3c!@l#$%^&*()", "unicode-пароль"]:
            hashed = hash_password(pwd)
            assert verify_password(pwd, hashed) is True


# --- Login Endpoint Tests ---


class TestLoginEndpoint:
    """Tests for POST /api/auth/login endpoint logic."""

    @pytest.fixture
    def user_id(self):
        return uuid.uuid4()

    @pytest.fixture
    def tenant_id(self):
        return uuid.uuid4()

    @pytest.fixture
    def password_hash(self):
        return hash_password("valid-password-123")

    @pytest.fixture
    def mock_conn(self, user_id, tenant_id, password_hash):
        """Create a mock connection that returns user and role data."""
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(
            return_value={
                "id": user_id,
                "tenant_id": tenant_id,
                "email": "analyst@example.com",
                "password_hash": password_hash,
                "is_active": True,
            }
        )
        conn.fetch = AsyncMock(
            return_value=[
                {"name": "soc_analyst"},
            ]
        )
        return conn

    @pytest.mark.asyncio
    async def test_login_success(self, mock_conn, user_id, tenant_id):
        """Successful login should return access_token and refresh_token."""
        from sift_defender.enterprise.auth.endpoints import login, LoginRequest

        body = LoginRequest(email="analyst@example.com", password="valid-password-123")

        with patch(
            "sift_defender.enterprise.auth.endpoints.get_connection"
        ) as mock_get_conn:
            mock_get_conn.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_get_conn.return_value.__aexit__ = AsyncMock(return_value=False)

            response = await login(body)

        assert response.token_type == "bearer"
        assert response.access_token
        assert response.refresh_token

        # Verify access token has correct claims
        payload = jwt.decode(response.access_token, TEST_SECRET, algorithms=[JWT_ALGORITHM])
        assert payload["sub"] == str(user_id)
        assert payload["tenant_id"] == str(tenant_id)
        assert payload["roles"] == ["soc_analyst"]
        assert payload["token_type"] == "access"

        # Verify refresh token
        refresh_payload = jwt.decode(
            response.refresh_token, TEST_SECRET, algorithms=[JWT_ALGORITHM]
        )
        assert refresh_payload["sub"] == str(user_id)
        assert refresh_payload["token_type"] == "refresh"

    @pytest.mark.asyncio
    async def test_login_unknown_email(self):
        """Unknown email should return 401."""
        from sift_defender.enterprise.auth.endpoints import login, LoginRequest

        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value=None)

        body = LoginRequest(email="unknown@example.com", password="any-password")

        with patch(
            "sift_defender.enterprise.auth.endpoints.get_connection"
        ) as mock_get_conn:
            mock_get_conn.return_value.__aenter__ = AsyncMock(return_value=conn)
            mock_get_conn.return_value.__aexit__ = AsyncMock(return_value=False)

            from fastapi import HTTPException

            with pytest.raises(HTTPException) as exc_info:
                await login(body)

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Invalid credentials"

    @pytest.mark.asyncio
    async def test_login_wrong_password(self, user_id, tenant_id):
        """Wrong password should return 401."""
        from sift_defender.enterprise.auth.endpoints import login, LoginRequest

        conn = AsyncMock()
        conn.fetchrow = AsyncMock(
            return_value={
                "id": user_id,
                "tenant_id": tenant_id,
                "email": "analyst@example.com",
                "password_hash": hash_password("correct-password"),
                "is_active": True,
            }
        )

        body = LoginRequest(email="analyst@example.com", password="wrong-password")

        with patch(
            "sift_defender.enterprise.auth.endpoints.get_connection"
        ) as mock_get_conn:
            mock_get_conn.return_value.__aenter__ = AsyncMock(return_value=conn)
            mock_get_conn.return_value.__aexit__ = AsyncMock(return_value=False)

            from fastapi import HTTPException

            with pytest.raises(HTTPException) as exc_info:
                await login(body)

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Invalid credentials"

    @pytest.mark.asyncio
    async def test_login_inactive_user(self, user_id, tenant_id):
        """Inactive user should return 401."""
        from sift_defender.enterprise.auth.endpoints import login, LoginRequest

        conn = AsyncMock()
        conn.fetchrow = AsyncMock(
            return_value={
                "id": user_id,
                "tenant_id": tenant_id,
                "email": "analyst@example.com",
                "password_hash": hash_password("valid-password"),
                "is_active": False,
            }
        )

        body = LoginRequest(email="analyst@example.com", password="valid-password")

        with patch(
            "sift_defender.enterprise.auth.endpoints.get_connection"
        ) as mock_get_conn:
            mock_get_conn.return_value.__aenter__ = AsyncMock(return_value=conn)
            mock_get_conn.return_value.__aexit__ = AsyncMock(return_value=False)

            from fastapi import HTTPException

            with pytest.raises(HTTPException) as exc_info:
                await login(body)

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Invalid credentials"

    @pytest.mark.asyncio
    async def test_login_multiple_roles(self, user_id, tenant_id, password_hash):
        """User with multiple roles should get all roles in access token."""
        from sift_defender.enterprise.auth.endpoints import login, LoginRequest

        conn = AsyncMock()
        conn.fetchrow = AsyncMock(
            return_value={
                "id": user_id,
                "tenant_id": tenant_id,
                "email": "lead@example.com",
                "password_hash": password_hash,
                "is_active": True,
            }
        )
        conn.fetch = AsyncMock(
            return_value=[
                {"name": "soc_analyst"},
                {"name": "ir_lead"},
            ]
        )

        body = LoginRequest(email="lead@example.com", password="valid-password-123")

        with patch(
            "sift_defender.enterprise.auth.endpoints.get_connection"
        ) as mock_get_conn:
            mock_get_conn.return_value.__aenter__ = AsyncMock(return_value=conn)
            mock_get_conn.return_value.__aexit__ = AsyncMock(return_value=False)

            response = await login(body)

        payload = jwt.decode(response.access_token, TEST_SECRET, algorithms=[JWT_ALGORITHM])
        assert sorted(payload["roles"]) == ["ir_lead", "soc_analyst"]


# --- Refresh Endpoint Tests ---


class TestRefreshEndpoint:
    """Tests for POST /api/auth/refresh endpoint logic."""

    @pytest.fixture
    def user_id(self):
        return str(uuid.uuid4())

    @pytest.fixture
    def tenant_id(self):
        return str(uuid.uuid4())

    @pytest.mark.asyncio
    async def test_refresh_success(self, user_id, tenant_id):
        """Valid refresh token should return new token pair with fresh roles."""
        from sift_defender.enterprise.auth.endpoints import refresh, RefreshRequest

        refresh_token = create_refresh_token(user_id, tenant_id)

        conn = AsyncMock()
        conn.fetchrow = AsyncMock(
            return_value={
                "id": user_id,
                "tenant_id": tenant_id,
                "is_active": True,
            }
        )
        conn.fetch = AsyncMock(
            return_value=[
                {"name": "ir_lead"},
            ]
        )

        body = RefreshRequest(refresh_token=refresh_token)

        with patch(
            "sift_defender.enterprise.auth.endpoints.get_connection"
        ) as mock_get_conn:
            mock_get_conn.return_value.__aenter__ = AsyncMock(return_value=conn)
            mock_get_conn.return_value.__aexit__ = AsyncMock(return_value=False)

            response = await refresh(body)

        assert response.token_type == "bearer"
        assert response.access_token
        assert response.refresh_token

        # Verify the new access token has fresh roles
        payload = jwt.decode(response.access_token, TEST_SECRET, algorithms=[JWT_ALGORITHM])
        assert payload["sub"] == user_id
        assert payload["tenant_id"] == tenant_id
        assert payload["roles"] == ["ir_lead"]

    @pytest.mark.asyncio
    async def test_refresh_expired_token(self, user_id, tenant_id):
        """Expired refresh token should return 401."""
        from sift_defender.enterprise.auth.endpoints import refresh, RefreshRequest

        expired_token = create_refresh_token(
            user_id, tenant_id, expires_delta=timedelta(seconds=-1)
        )

        body = RefreshRequest(refresh_token=expired_token)

        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            await refresh(body)

        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_refresh_invalid_token(self):
        """Invalid token string should return 401."""
        from sift_defender.enterprise.auth.endpoints import refresh, RefreshRequest

        body = RefreshRequest(refresh_token="not-a-valid-token")

        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            await refresh(body)

        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_refresh_with_access_token_fails(self, user_id, tenant_id):
        """Using an access token for refresh should fail (wrong type)."""
        from sift_defender.enterprise.auth.endpoints import refresh, RefreshRequest

        access_token = create_access_token(user_id, tenant_id, ["soc_analyst"])

        body = RefreshRequest(refresh_token=access_token)

        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            await refresh(body)

        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_refresh_inactive_user(self, user_id, tenant_id):
        """Refresh for an inactive user should return 401."""
        from sift_defender.enterprise.auth.endpoints import refresh, RefreshRequest

        refresh_token = create_refresh_token(user_id, tenant_id)

        conn = AsyncMock()
        conn.fetchrow = AsyncMock(
            return_value={
                "id": user_id,
                "tenant_id": tenant_id,
                "is_active": False,
            }
        )

        body = RefreshRequest(refresh_token=refresh_token)

        with patch(
            "sift_defender.enterprise.auth.endpoints.get_connection"
        ) as mock_get_conn:
            mock_get_conn.return_value.__aenter__ = AsyncMock(return_value=conn)
            mock_get_conn.return_value.__aexit__ = AsyncMock(return_value=False)

            from fastapi import HTTPException

            with pytest.raises(HTTPException) as exc_info:
                await refresh(body)

        assert exc_info.value.status_code == 401
        assert "no longer active" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_refresh_deleted_user(self, user_id, tenant_id):
        """Refresh for a deleted user (not found) should return 401."""
        from sift_defender.enterprise.auth.endpoints import refresh, RefreshRequest

        refresh_token = create_refresh_token(user_id, tenant_id)

        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value=None)

        body = RefreshRequest(refresh_token=refresh_token)

        with patch(
            "sift_defender.enterprise.auth.endpoints.get_connection"
        ) as mock_get_conn:
            mock_get_conn.return_value.__aenter__ = AsyncMock(return_value=conn)
            mock_get_conn.return_value.__aexit__ = AsyncMock(return_value=False)

            from fastapi import HTTPException

            with pytest.raises(HTTPException) as exc_info:
                await refresh(body)

        assert exc_info.value.status_code == 401

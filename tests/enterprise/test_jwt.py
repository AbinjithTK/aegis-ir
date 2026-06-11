"""Tests for JWT token generation and validation module.

Validates requirements:
    4.2 - RBAC session association with tenant via identity provider claims
    8.2 - Tenant association on authentication via JWT claims
"""

from __future__ import annotations

import os
import time
from datetime import timedelta, datetime, timezone
from unittest.mock import patch

import pytest
from jose import jwt

from sift_defender.enterprise.auth.jwt import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    JWT_ALGORITHM,
    REFRESH_TOKEN_EXPIRE_DAYS,
    InvalidTokenError,
    TokenExpiredError,
    TokenPayload,
    create_access_token,
    create_refresh_token,
    decode_token,
    verify_token,
)


# Use a fixed secret for deterministic tests
TEST_SECRET = "test-jwt-secret-for-unit-tests"


@pytest.fixture(autouse=True)
def set_jwt_secret(monkeypatch):
    """Set a consistent JWT secret for all tests."""
    monkeypatch.setenv("JWT_SECRET", TEST_SECRET)


class TestCreateAccessToken:
    """Tests for access token creation."""

    def test_creates_valid_token(self):
        """Access token should be a decodable JWT string."""
        token = create_access_token("user-123", "tenant-abc", ["soc_analyst"])
        assert isinstance(token, str)
        assert len(token) > 0

    def test_token_contains_correct_claims(self):
        """Access token payload should contain all required claims."""
        token = create_access_token("user-456", "tenant-xyz", ["ir_lead", "soc_analyst"])
        payload = jwt.decode(token, TEST_SECRET, algorithms=[JWT_ALGORITHM])

        assert payload["sub"] == "user-456"
        assert payload["tenant_id"] == "tenant-xyz"
        assert payload["roles"] == ["ir_lead", "soc_analyst"]
        assert payload["token_type"] == "access"
        assert "exp" in payload
        assert "iat" in payload

    def test_default_expiry_is_15_minutes(self):
        """Access token should expire in 15 minutes by default."""
        token = create_access_token("user-1", "tenant-1", ["soc_analyst"])
        payload = jwt.decode(token, TEST_SECRET, algorithms=[JWT_ALGORITHM])

        iat = payload["iat"]
        exp = payload["exp"]
        # Allow 2 second tolerance for test execution time
        assert abs((exp - iat) - (ACCESS_TOKEN_EXPIRE_MINUTES * 60)) <= 2

    def test_custom_expiry_delta(self):
        """Access token should respect custom expiry delta."""
        token = create_access_token(
            "user-1", "tenant-1", ["soc_analyst"], expires_delta=timedelta(minutes=30)
        )
        payload = jwt.decode(token, TEST_SECRET, algorithms=[JWT_ALGORITHM])

        iat = payload["iat"]
        exp = payload["exp"]
        assert abs((exp - iat) - (30 * 60)) <= 2

    def test_tenant_id_in_payload(self):
        """Access token must include tenant_id claim for multi-tenant isolation."""
        token = create_access_token("user-1", "tenant-multi", ["ciso"])
        payload = jwt.decode(token, TEST_SECRET, algorithms=[JWT_ALGORITHM])
        assert payload["tenant_id"] == "tenant-multi"

    def test_empty_roles_list(self):
        """Access token should handle empty roles list."""
        token = create_access_token("user-1", "tenant-1", [])
        payload = jwt.decode(token, TEST_SECRET, algorithms=[JWT_ALGORITHM])
        assert payload["roles"] == []


class TestCreateRefreshToken:
    """Tests for refresh token creation."""

    def test_creates_valid_token(self):
        """Refresh token should be a decodable JWT string."""
        token = create_refresh_token("user-123", "tenant-abc")
        assert isinstance(token, str)
        assert len(token) > 0

    def test_token_type_is_refresh(self):
        """Refresh token should have token_type='refresh'."""
        token = create_refresh_token("user-1", "tenant-1")
        payload = jwt.decode(token, TEST_SECRET, algorithms=[JWT_ALGORITHM])
        assert payload["token_type"] == "refresh"

    def test_default_expiry_is_7_days(self):
        """Refresh token should expire in 7 days by default."""
        token = create_refresh_token("user-1", "tenant-1")
        payload = jwt.decode(token, TEST_SECRET, algorithms=[JWT_ALGORITHM])

        iat = payload["iat"]
        exp = payload["exp"]
        expected_seconds = REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
        assert abs((exp - iat) - expected_seconds) <= 2

    def test_refresh_token_has_empty_roles(self):
        """Refresh tokens should not contain roles (resolved fresh on access token issuance)."""
        token = create_refresh_token("user-1", "tenant-1")
        payload = jwt.decode(token, TEST_SECRET, algorithms=[JWT_ALGORITHM])
        assert payload["roles"] == []

    def test_tenant_id_in_payload(self):
        """Refresh token must include tenant_id claim."""
        token = create_refresh_token("user-1", "tenant-refresh")
        payload = jwt.decode(token, TEST_SECRET, algorithms=[JWT_ALGORITHM])
        assert payload["tenant_id"] == "tenant-refresh"

    def test_custom_expiry_delta(self):
        """Refresh token should respect custom expiry delta."""
        token = create_refresh_token("user-1", "tenant-1", expires_delta=timedelta(days=14))
        payload = jwt.decode(token, TEST_SECRET, algorithms=[JWT_ALGORITHM])

        iat = payload["iat"]
        exp = payload["exp"]
        expected_seconds = 14 * 24 * 60 * 60
        assert abs((exp - iat) - expected_seconds) <= 2


class TestDecodeToken:
    """Tests for token decoding."""

    def test_decode_valid_access_token(self):
        """Should decode a valid access token into a TokenPayload."""
        token = create_access_token("user-decode", "tenant-decode", ["soc_analyst", "ir_lead"])
        payload = decode_token(token)

        assert isinstance(payload, TokenPayload)
        assert payload.sub == "user-decode"
        assert payload.tenant_id == "tenant-decode"
        assert payload.roles == ["soc_analyst", "ir_lead"]
        assert payload.token_type == "access"

    def test_decode_valid_refresh_token(self):
        """Should decode a valid refresh token into a TokenPayload."""
        token = create_refresh_token("user-refresh", "tenant-refresh")
        payload = decode_token(token)

        assert isinstance(payload, TokenPayload)
        assert payload.sub == "user-refresh"
        assert payload.tenant_id == "tenant-refresh"
        assert payload.token_type == "refresh"

    def test_decode_expired_token_raises_error(self):
        """Should raise TokenExpiredError for expired tokens."""
        token = create_access_token(
            "user-1", "tenant-1", ["soc_analyst"], expires_delta=timedelta(seconds=-1)
        )
        with pytest.raises(TokenExpiredError, match="expired"):
            decode_token(token)

    def test_decode_invalid_signature_raises_error(self):
        """Should raise InvalidTokenError for tokens signed with wrong secret."""
        token = jwt.encode(
            {"sub": "user-1", "tenant_id": "t1", "roles": [], "exp": 9999999999, "iat": 1, "token_type": "access"},
            "wrong-secret",
            algorithm=JWT_ALGORITHM,
        )
        with pytest.raises(InvalidTokenError, match="Invalid token"):
            decode_token(token)

    def test_decode_malformed_token_raises_error(self):
        """Should raise InvalidTokenError for non-JWT strings."""
        with pytest.raises(InvalidTokenError, match="Invalid token"):
            decode_token("not-a-valid-jwt-token")

    def test_decode_token_missing_claims_raises_error(self):
        """Should raise InvalidTokenError when required claims are missing."""
        # Create a token missing tenant_id
        token = jwt.encode(
            {"sub": "user-1", "exp": 9999999999, "iat": 1, "token_type": "access"},
            TEST_SECRET,
            algorithm=JWT_ALGORITHM,
        )
        with pytest.raises(InvalidTokenError, match="missing required claims"):
            decode_token(token)


class TestVerifyToken:
    """Tests for token verification with type checking."""

    def test_verify_access_token(self):
        """Should verify an access token successfully."""
        token = create_access_token("user-v", "tenant-v", ["ciso"])
        payload = verify_token(token, expected_type="access")

        assert payload.sub == "user-v"
        assert payload.token_type == "access"

    def test_verify_refresh_token(self):
        """Should verify a refresh token successfully."""
        token = create_refresh_token("user-v", "tenant-v")
        payload = verify_token(token, expected_type="refresh")

        assert payload.sub == "user-v"
        assert payload.token_type == "refresh"

    def test_verify_wrong_type_raises_error(self):
        """Should raise InvalidTokenError when token type doesn't match expected."""
        token = create_access_token("user-1", "tenant-1", ["soc_analyst"])
        with pytest.raises(InvalidTokenError, match="Expected token type 'refresh'"):
            verify_token(token, expected_type="refresh")

    def test_verify_without_type_check(self):
        """Should verify any token when expected_type is None."""
        access_token = create_access_token("user-1", "tenant-1", ["soc_analyst"])
        refresh_token = create_refresh_token("user-1", "tenant-1")

        # Both should pass without type constraint
        payload_a = verify_token(access_token)
        payload_r = verify_token(refresh_token)

        assert payload_a.token_type == "access"
        assert payload_r.token_type == "refresh"

    def test_verify_expired_token(self):
        """Should raise TokenExpiredError for expired tokens."""
        token = create_access_token(
            "user-1", "tenant-1", ["soc_analyst"], expires_delta=timedelta(seconds=-1)
        )
        with pytest.raises(TokenExpiredError):
            verify_token(token, expected_type="access")


class TestTokenPayloadModel:
    """Tests for the TokenPayload Pydantic model."""

    def test_valid_payload_creation(self):
        """Should create a valid TokenPayload instance."""
        payload = TokenPayload(
            sub="user-1",
            tenant_id="tenant-1",
            roles=["soc_analyst"],
            exp=9999999999,
            iat=1000000000,
            token_type="access",
        )
        assert payload.sub == "user-1"
        assert payload.tenant_id == "tenant-1"
        assert payload.roles == ["soc_analyst"]
        assert payload.token_type == "access"

    def test_default_roles_empty_list(self):
        """Should default roles to empty list if not provided."""
        payload = TokenPayload(
            sub="user-1",
            tenant_id="tenant-1",
            exp=9999999999,
            iat=1000000000,
            token_type="refresh",
        )
        assert payload.roles == []

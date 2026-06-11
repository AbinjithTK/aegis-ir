"""JWT token generation and validation module.

Provides access token (15-minute expiry) and refresh token (7-day expiry) creation
and verification with tenant-scoped claims for multi-tenant isolation.

Requirements:
    4.2 - RBAC session association with tenant via identity provider claims
    8.2 - Tenant association on authentication via JWT claims
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import ExpiredSignatureError, JWTError, jwt
from pydantic import BaseModel, Field

# Configuration
JWT_SECRET_KEY = os.environ.get("JWT_SECRET", "aegis-ir-dev-secret-change-in-production")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7


class TokenPayload(BaseModel):
    """Structured representation of a decoded JWT token payload.

    Attributes:
        sub: The user ID (subject claim).
        tenant_id: The tenant this token is scoped to.
        roles: List of role names assigned to the user.
        exp: Token expiration timestamp (Unix epoch).
        iat: Token issued-at timestamp (Unix epoch).
        token_type: Either "access" or "refresh".
    """

    sub: str
    tenant_id: str
    roles: list[str] = Field(default_factory=list)
    exp: int
    iat: int
    token_type: str


class TokenError(Exception):
    """Base exception for token-related errors."""

    pass


class TokenExpiredError(TokenError):
    """Raised when a token has expired."""

    pass


class InvalidTokenError(TokenError):
    """Raised when a token is malformed or has an invalid signature."""

    pass


def _get_secret_key() -> str:
    """Retrieve the JWT secret key from environment.

    Returns:
        The secret key string used for signing and verifying tokens.
    """
    return os.environ.get("JWT_SECRET", JWT_SECRET_KEY)


def create_access_token(
    user_id: str,
    tenant_id: str,
    roles: list[str],
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a short-lived access token with user identity and role claims.

    Args:
        user_id: The unique identifier for the user (becomes 'sub' claim).
        tenant_id: The tenant this user belongs to.
        roles: List of role names assigned to the user.
        expires_delta: Custom expiration duration. Defaults to 15 minutes.

    Returns:
        An encoded JWT string.
    """
    now = datetime.now(timezone.utc)
    if expires_delta is None:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    expire = now + expires_delta

    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "roles": roles,
        "exp": expire,
        "iat": now,
        "token_type": "access",
    }

    return jwt.encode(payload, _get_secret_key(), algorithm=JWT_ALGORITHM)


def create_refresh_token(
    user_id: str,
    tenant_id: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a long-lived refresh token for session renewal.

    Refresh tokens do not contain roles — they are only used to obtain
    new access tokens. Roles are resolved fresh on each access token issuance.

    Args:
        user_id: The unique identifier for the user (becomes 'sub' claim).
        tenant_id: The tenant this user belongs to.
        expires_delta: Custom expiration duration. Defaults to 7 days.

    Returns:
        An encoded JWT string.
    """
    now = datetime.now(timezone.utc)
    if expires_delta is None:
        expires_delta = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    expire = now + expires_delta

    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "roles": [],
        "exp": expire,
        "iat": now,
        "token_type": "refresh",
    }

    return jwt.encode(payload, _get_secret_key(), algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> TokenPayload:
    """Decode a JWT token and return a structured payload.

    Validates the token signature and expiration, then parses the claims
    into a TokenPayload model.

    Args:
        token: The encoded JWT string.

    Returns:
        A TokenPayload instance with the decoded claims.

    Raises:
        TokenExpiredError: If the token has expired.
        InvalidTokenError: If the token signature is invalid or the token is malformed.
    """
    try:
        payload = jwt.decode(token, _get_secret_key(), algorithms=[JWT_ALGORITHM])
    except ExpiredSignatureError:
        raise TokenExpiredError("Token has expired.")
    except JWTError as e:
        raise InvalidTokenError(f"Invalid token: {e}")

    # Validate required fields
    required_fields = {"sub", "tenant_id", "token_type", "exp", "iat"}
    missing = required_fields - set(payload.keys())
    if missing:
        raise InvalidTokenError(f"Token missing required claims: {missing}")

    return TokenPayload(
        sub=payload["sub"],
        tenant_id=payload["tenant_id"],
        roles=payload.get("roles", []),
        exp=payload["exp"],
        iat=payload["iat"],
        token_type=payload["token_type"],
    )


def verify_token(token: str, expected_type: Optional[str] = None) -> TokenPayload:
    """Verify a JWT token's validity, optionally checking token type.

    This is a higher-level function that decodes the token and performs
    additional validation beyond signature and expiration checks.

    Args:
        token: The encoded JWT string.
        expected_type: If provided, verifies the token_type claim matches.
            Should be "access" or "refresh".

    Returns:
        A TokenPayload instance with the decoded claims.

    Raises:
        TokenExpiredError: If the token has expired.
        InvalidTokenError: If the token is invalid or the type doesn't match.
    """
    payload = decode_token(token)

    if expected_type is not None and payload.token_type != expected_type:
        raise InvalidTokenError(
            f"Expected token type '{expected_type}', got '{payload.token_type}'."
        )

    return payload

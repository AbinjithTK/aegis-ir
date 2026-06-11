"""Authentication API endpoints.

Provides login (local credentials) and token refresh endpoints for the
AEGIS-IR enterprise platform. Returns JWT access/refresh token pairs.

Requirements:
    4.1 - RBAC default roles (authenticates users for role enforcement)
    14.1 - SOC Analyst investigation workflow (login is the entry point)
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, EmailStr

from sift_defender.enterprise.auth.jwt import (
    InvalidTokenError,
    TokenExpiredError,
    create_access_token,
    create_refresh_token,
    verify_token,
)
from sift_defender.enterprise.auth.passwords import verify_password
from sift_defender.enterprise.db import get_connection

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["auth"])


# --- Request / Response Models ---


class LoginRequest(BaseModel):
    """Login request body.

    Attributes:
        email: User's email address.
        password: Plaintext password to verify against stored hash.
    """

    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    """Successful authentication response.

    Attributes:
        access_token: Short-lived JWT for API access (15 min).
        refresh_token: Long-lived JWT for obtaining new access tokens (7 days).
        token_type: Always "bearer".
    """

    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    """Token refresh request body.

    Attributes:
        refresh_token: A valid refresh JWT to exchange for a new token pair.
    """

    refresh_token: str


# --- Endpoints ---


@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    responses={401: {"description": "Invalid credentials"}},
)
async def login(body: LoginRequest) -> LoginResponse:
    """Authenticate user with email and password, returning a JWT pair.

    For MVP, queries user by email across all tenants (in production,
    a tenant identifier or email domain would scope the lookup).

    Steps:
        1. Query users table for matching email (must be active)
        2. Verify password against stored bcrypt hash
        3. Fetch user roles from user_roles JOIN roles
        4. Generate access token (with roles) and refresh token
        5. Return token pair
    """
    async with get_connection() as conn:
        # Look up user by email (MVP: cross-tenant lookup)
        user_row = await conn.fetchrow(
            """
            SELECT id, tenant_id, email, password_hash, is_active
            FROM users
            WHERE email = $1
            LIMIT 1
            """,
            body.email,
        )

        if user_row is None:
            logger.warning("Login attempt for unknown email: %s", body.email)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )

        if not user_row["is_active"]:
            logger.warning("Login attempt for inactive user: %s", body.email)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )

        # Verify password
        if not verify_password(body.password, user_row["password_hash"]):
            logger.warning("Invalid password for user: %s", body.email)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )

        user_id = str(user_row["id"])
        tenant_id = str(user_row["tenant_id"])

        # Fetch roles
        role_rows = await conn.fetch(
            """
            SELECT r.name
            FROM user_roles ur
            JOIN roles r ON r.id = ur.role_id
            WHERE ur.user_id = $1
            """,
            user_row["id"],
        )
        roles = [row["name"] for row in role_rows]

    # Generate token pair
    access_token = create_access_token(user_id, tenant_id, roles)
    refresh_token = create_refresh_token(user_id, tenant_id)

    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post(
    "/refresh",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    responses={401: {"description": "Invalid or expired refresh token"}},
)
async def refresh(body: RefreshRequest) -> LoginResponse:
    """Exchange a valid refresh token for a new access/refresh token pair.

    Steps:
        1. Decode and verify the refresh token (must be type "refresh")
        2. Verify the user still exists and is active
        3. Fetch fresh roles (may have changed since last login)
        4. Issue new access + refresh tokens
    """
    try:
        payload = verify_token(body.refresh_token, expected_type="refresh")
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired",
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    async with get_connection() as conn:
        # Verify user still exists and is active
        user_row = await conn.fetchrow(
            """
            SELECT id, tenant_id, is_active
            FROM users
            WHERE id = $1
            """,
            payload.sub,
        )

        if user_row is None or not user_row["is_active"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is no longer active",
            )

        user_id = str(user_row["id"])
        tenant_id = str(user_row["tenant_id"])

        # Fetch fresh roles
        role_rows = await conn.fetch(
            """
            SELECT r.name
            FROM user_roles ur
            JOIN roles r ON r.id = ur.role_id
            WHERE ur.user_id = $1
            """,
            user_row["id"],
        )
        roles = [row["name"] for row in role_rows]

    # Issue new token pair
    access_token = create_access_token(user_id, tenant_id, roles)
    refresh_token = create_refresh_token(user_id, tenant_id)

    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
    )

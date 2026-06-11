"""FastAPI authentication dependencies for AEGIS-IR Enterprise Platform.

Provides get_current_user and get_current_active_user dependencies that extract
Bearer tokens from the Authorization header, decode JWTs, and hydrate User objects
with tenant and role information. Also provides require_permission() for endpoint-level
RBAC enforcement with audit logging of denied attempts.

Requirements:
    4.2 - RBAC session association with tenant via identity provider claims
    7.1 - Record every user action and agent decision with full context
    8.2 - Tenant association on authentication via JWT claims
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field

from sift_defender.enterprise.auth.jwt import (
    InvalidTokenError,
    TokenExpiredError,
    TokenPayload,
    verify_token,
)

logger = logging.getLogger(__name__)

# OAuth2 scheme that extracts the Bearer token from the Authorization header.
# tokenUrl points to the login endpoint that issues tokens.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


class User(BaseModel):
    """Authenticated user model hydrated from JWT claims.

    Attributes:
        id: The user's unique identifier (from JWT 'sub' claim).
        email: The user's email address (optional, may not be in token).
        tenant_id: The tenant this user belongs to (from JWT 'tenant_id' claim).
        roles: List of role names assigned to the user.
        is_active: Whether the user account is active.
    """

    id: str
    email: Optional[str] = None
    tenant_id: str
    roles: list[str] = Field(default_factory=list)
    is_active: bool = True


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """FastAPI dependency that decodes a JWT and returns the authenticated User.

    Extracts the Bearer token from the Authorization header using OAuth2PasswordBearer,
    verifies it as a valid access token, and hydrates a User object from the claims.

    Args:
        token: The Bearer token extracted by OAuth2PasswordBearer.

    Returns:
        A User instance populated from the token claims.

    Raises:
        HTTPException: 401 if the token is expired, invalid, or missing required claims.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload: TokenPayload = verify_token(token, expected_type="access")
    except (TokenExpiredError, InvalidTokenError):
        raise credentials_exception

    if not payload.sub or not payload.tenant_id:
        raise credentials_exception

    user = User(
        id=payload.sub,
        tenant_id=payload.tenant_id,
        roles=payload.roles,
        is_active=True,
    )

    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """FastAPI dependency that ensures the authenticated user is active.

    Wraps get_current_user and adds an is_active check. Use this for endpoints
    that should reject disabled/deactivated users.

    Args:
        current_user: The user resolved by get_current_user.

    Returns:
        The same User instance if active.

    Raises:
        HTTPException: 401 if the user is inactive.
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Inactive user",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return current_user


# ─── Permission Resolution & Enforcement ─────────────────────────────────────


def _resolve_permissions_from_roles(role_names: list[str]) -> set:
    """Resolve the effective permission set from a list of role names.

    Uses the DEFAULT_ROLES mapping for fast in-memory lookup without requiring
    a database query on every request. Unknown role names are silently skipped.

    Args:
        role_names: List of role name strings (e.g., ["soc_analyst", "ir_lead"]).

    Returns:
        A set of Permission enum values representing the union of all permissions
        across the provided roles.
    """
    from sift_defender.enterprise.auth.rbac import DEFAULT_ROLES, Permission

    permissions: set = set()
    for role_name in role_names:
        role_perms = DEFAULT_ROLES.get(role_name)
        if role_perms is not None:
            permissions.update(role_perms)
    return permissions


def require_permission(permission) -> Callable:
    """Create a FastAPI dependency that enforces a specific permission.

    Returns a dependency function that:
    1. Extracts the authenticated user from the JWT via get_current_user
    2. Resolves the user's effective permissions from their roles using
       DEFAULT_ROLES mapping (no DB query needed per request)
    3. Checks whether the required permission is in the resolved set
    4. If denied: logs a PERMISSION_DENIED audit event and raises HTTP 403
    5. If granted: returns the authenticated User object

    Usage:
        @router.get("/api/playbooks")
        async def list_playbooks(
            user: User = Depends(require_permission(Permission.PLAYBOOK_VIEW))
        ):
            ...

    Args:
        permission: The Permission enum value required for the endpoint.

    Returns:
        A FastAPI-compatible dependency function.

    Requirements:
        4.2 - RBAC permission enforcement at request time
        7.1 - Audit logging of permission denial events
    """

    async def _permission_dependency(
        user: User = Depends(get_current_user),
    ) -> User:
        effective_permissions = _resolve_permissions_from_roles(user.roles)

        if permission not in effective_permissions:
            # Log denial to audit log (fire-and-forget, don't block request)
            try:
                from sift_defender.enterprise.audit.service import (
                    AuditEvent,
                    AuditEventType,
                    AuditLogService,
                )

                audit_service = AuditLogService()
                audit_event = AuditEvent(
                    tenant_id=user.tenant_id,
                    event_type=AuditEventType.PERMISSION_DENIED,
                    user_id=user.id,
                    resource_type="permission",
                    resource_id=str(permission.value) if hasattr(permission, "value") else str(permission),
                    details={
                        "required_permission": str(permission.value) if hasattr(permission, "value") else str(permission),
                        "user_roles": user.roles,
                    },
                )
                await audit_service.record(audit_event)
            except Exception:
                # Audit logging failure must not prevent the 403 response
                logger.warning(
                    "Failed to record PERMISSION_DENIED audit event",
                    extra={
                        "user_id": user.id,
                        "tenant_id": user.tenant_id,
                        "permission": str(permission),
                    },
                )

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )

        return user

    return _permission_dependency

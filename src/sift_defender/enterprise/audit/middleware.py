"""FastAPI audit middleware — automatically logs every API request.

Captures request method, path, user_id, tenant_id, and response status for
every incoming HTTP request. User identity is extracted directly from the
JWT Bearer token in the Authorization header (middleware runs before
FastAPI dependencies).

Audit events are recorded asynchronously (fire-and-forget) so they do not
add latency to the response path.

Requirements:
    7.1 - Record every user action with timestamp, user identity, action type, resource
    7.2 - Record every agent decision with associated trace span ID
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from sift_defender.enterprise.audit.service import (
    AuditEvent,
    AuditEventType,
    AuditLogService,
)
from sift_defender.enterprise.auth.jwt import (
    InvalidTokenError,
    TokenExpiredError,
    TokenPayload,
    decode_token,
)

logger = logging.getLogger(__name__)

# Paths that should NOT be audit-logged to avoid noise or infinite recursion.
SKIP_PATHS: set[str] = {
    "/health",
    "/api/status",
    "/api/audit",
    "/api/audit/",
}

# Path prefixes to skip (static files, audit sub-routes).
SKIP_PREFIXES: tuple[str, ...] = (
    "/static/",
    "/api/audit/",
)


def _should_skip(path: str) -> bool:
    """Determine whether a request path should be excluded from audit logging.

    Skips:
    - Health check endpoints (/health, /api/status)
    - Static file requests (/static/...)
    - The audit log endpoint itself (prevents infinite recursion)
    """
    if path in SKIP_PATHS:
        return True
    if path.startswith(SKIP_PREFIXES):
        return True
    return False


def _extract_bearer_token(authorization: Optional[str]) -> Optional[str]:
    """Extract the token value from a 'Bearer <token>' header.

    Returns None if the header is missing or not in Bearer format.
    """
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def _extract_user_from_token(token: str) -> Optional[TokenPayload]:
    """Attempt to decode the JWT to extract user_id and tenant_id.

    Returns None if the token is expired, invalid, or unparseable.
    We intentionally swallow errors — unauthenticated requests are still
    logged, just without user context.
    """
    try:
        return decode_token(token)
    except (TokenExpiredError, InvalidTokenError, Exception):
        return None


def _extract_resource_type(path: str) -> Optional[str]:
    """Extract the primary resource type from the URL path.

    Heuristic: takes the first meaningful path segment after /api/.
    Examples:
        /api/cases/123        -> "cases"
        /api/investigations   -> "investigations"
        /api/auth/login       -> "auth"
        /dashboard            -> "dashboard"
    """
    segments = [s for s in path.split("/") if s]
    if not segments:
        return None
    # If path starts with /api/, take the segment after "api"
    if len(segments) >= 2 and segments[0] == "api":
        return segments[1]
    # Otherwise return the first segment
    return segments[0]


class AuditMiddleware(BaseHTTPMiddleware):
    """Starlette middleware that records an audit event for every API request.

    Usage:
        app.add_middleware(AuditMiddleware, audit_service=AuditLogService())

    The middleware:
    1. Extracts user identity from the JWT Bearer token (if present).
    2. Lets the request proceed through the stack.
    3. After the response is produced, fires off an async audit record
       (fire-and-forget) with method, path, status, user, and tenant info.
    """

    def __init__(self, app, audit_service: Optional[AuditLogService] = None):
        super().__init__(app)
        self.audit_service = audit_service or AuditLogService()

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """Process the request and record an audit event."""
        path = request.url.path

        # Skip excluded paths
        if _should_skip(path):
            return await call_next(request)

        # Extract user info from JWT (best-effort, won't block request)
        user_payload: Optional[TokenPayload] = None
        authorization = request.headers.get("authorization")
        token = _extract_bearer_token(authorization)
        if token:
            user_payload = _extract_user_from_token(token)

        # Process the request
        response = await call_next(request)

        # Fire-and-forget audit logging
        asyncio.ensure_future(
            self._record_audit_event(
                method=request.method,
                path=path,
                query_params=str(request.query_params) if request.query_params else None,
                status_code=response.status_code,
                user_payload=user_payload,
            )
        )

        return response

    async def _record_audit_event(
        self,
        method: str,
        path: str,
        query_params: Optional[str],
        status_code: int,
        user_payload: Optional[TokenPayload],
    ) -> None:
        """Record the audit event asynchronously.

        Errors during recording are logged but never propagated — audit
        failures must not disrupt the API.
        """
        try:
            user_id = user_payload.sub if user_payload else None
            tenant_id = user_payload.tenant_id if user_payload else None

            # Cannot record without a tenant_id (audit log is tenant-scoped)
            if not tenant_id:
                logger.debug(
                    "Skipping audit record for unauthenticated request: %s %s",
                    method,
                    path,
                )
                return

            details: dict = {
                "method": method,
                "path": path,
                "status_code": status_code,
            }
            if query_params:
                details["query_params"] = query_params

            resource_type = _extract_resource_type(path)

            event = AuditEvent(
                tenant_id=tenant_id,
                event_type=AuditEventType.API_REQUEST,
                user_id=user_id,
                resource_type=resource_type,
                details=details,
            )

            await self.audit_service.record(event)

        except Exception as exc:
            # Never let audit recording failures affect the response
            logger.warning(
                "Failed to record audit event: %s %s — %s",
                method,
                path,
                str(exc),
            )

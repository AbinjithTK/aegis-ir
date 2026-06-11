"""WebSocket authentication module for AEGIS-IR Enterprise Platform.

Provides JWT-based authentication for WebSocket connections with:
- Token extraction from query params or headers
- Tenant scoping on WebSocket connections
- Background token expiry monitoring with warning and disconnect

Requirements:
    1.1 - Real-time trace timeline via WebSocket (authenticated connections)
    14.2 - Live investigation feed via WebSocket real-time updates
"""

from __future__ import annotations

import asyncio
import time
from typing import Optional

from fastapi import WebSocket, WebSocketDisconnect

from sift_defender.enterprise.auth.dependencies import User
from sift_defender.enterprise.auth.jwt import (
    InvalidTokenError,
    TokenExpiredError,
    TokenPayload,
    verify_token,
)

# WebSocket close codes for authentication failures
WS_CLOSE_AUTH_FAILED = 4001
WS_CLOSE_TOKEN_EXPIRED = 4002

# Seconds before expiry to send a warning
TOKEN_EXPIRY_WARNING_SECONDS = 30


class WebSocketAuthenticator:
    """Authenticates WebSocket connections using JWT tokens.

    Extracts the JWT from either the query parameter `?token=...` or the
    WebSocket headers (`Authorization: Bearer <token>`), validates it,
    and returns a User object with tenant scoping.

    Usage:
        authenticator = WebSocketAuthenticator()
        user = await authenticator.authenticate(websocket)
    """

    def _extract_token(self, websocket: WebSocket) -> Optional[str]:
        """Extract JWT token from query params or headers.

        Priority:
            1. Query parameter `token`
            2. Authorization header (Bearer scheme)

        Args:
            websocket: The WebSocket connection to extract the token from.

        Returns:
            The token string if found, None otherwise.
        """
        # Try query parameter first
        token = websocket.query_params.get("token")
        if token:
            return token

        # Try Authorization header
        auth_header = websocket.headers.get("authorization")
        if auth_header and auth_header.lower().startswith("bearer "):
            return auth_header[7:]

        return None

    async def authenticate(self, websocket: WebSocket) -> User:
        """Authenticate a WebSocket connection using JWT.

        Extracts the token, validates it as an access token, and returns
        a User object populated from the token claims including tenant_id
        for data scoping.

        Args:
            websocket: The WebSocket connection to authenticate.

        Returns:
            A User instance with tenant_id for scoped data access.

        Raises:
            WebSocketDisconnect: If authentication fails (code 4001) or
                token is expired (code 4002).
        """
        token = self._extract_token(websocket)

        if not token:
            await websocket.close(code=WS_CLOSE_AUTH_FAILED, reason="Missing authentication token")
            raise WebSocketDisconnect(code=WS_CLOSE_AUTH_FAILED)

        try:
            payload: TokenPayload = verify_token(token, expected_type="access")
        except TokenExpiredError:
            await websocket.close(code=WS_CLOSE_TOKEN_EXPIRED, reason="Token expired")
            raise WebSocketDisconnect(code=WS_CLOSE_TOKEN_EXPIRED)
        except InvalidTokenError:
            await websocket.close(code=WS_CLOSE_AUTH_FAILED, reason="Invalid token")
            raise WebSocketDisconnect(code=WS_CLOSE_AUTH_FAILED)

        if not payload.sub or not payload.tenant_id:
            await websocket.close(code=WS_CLOSE_AUTH_FAILED, reason="Missing required claims")
            raise WebSocketDisconnect(code=WS_CLOSE_AUTH_FAILED)

        return User(
            id=payload.sub,
            tenant_id=payload.tenant_id,
            roles=payload.roles,
            is_active=True,
        )


async def get_websocket_user(websocket: WebSocket) -> User:
    """FastAPI WebSocket dependency for authenticated connections.

    Use this as a dependency in WebSocket route handlers to require
    authentication and obtain the current user with tenant scoping.

    Example:
        @app.websocket("/ws/live/{case_id}")
        async def live_feed(websocket: WebSocket, user: User = Depends(get_websocket_user)):
            # user.tenant_id is available for data filtering
            ...

    Args:
        websocket: The WebSocket connection (injected by FastAPI).

    Returns:
        A User instance with tenant_id for scoped data access.

    Raises:
        WebSocketDisconnect: If authentication fails or token is invalid.
    """
    authenticator = WebSocketAuthenticator()
    return await authenticator.authenticate(websocket)


async def monitor_token_expiry(websocket: WebSocket, token_exp: int) -> None:
    """Background task that monitors token expiry and disconnects on expiration.

    Runs alongside the WebSocket connection. When the token is within
    TOKEN_EXPIRY_WARNING_SECONDS of expiry, sends a warning message.
    When the token expires, disconnects the WebSocket with code 4002.

    This function is designed to be launched as an asyncio task:
        task = asyncio.create_task(monitor_token_expiry(websocket, payload.exp))

    Args:
        websocket: The active WebSocket connection to monitor.
        token_exp: The token expiration timestamp (Unix epoch seconds).
    """
    try:
        warning_sent = False

        while True:
            now = time.time()
            time_remaining = token_exp - now

            # Token has expired — disconnect immediately
            if time_remaining <= 0:
                try:
                    await websocket.send_json({
                        "type": "token_expired",
                        "message": "Authentication token has expired. Connection will be closed.",
                    })
                except Exception:
                    pass  # Connection may already be closing
                await websocket.close(code=WS_CLOSE_TOKEN_EXPIRED, reason="Token expired")
                return

            # Token approaching expiry — send warning
            if time_remaining <= TOKEN_EXPIRY_WARNING_SECONDS and not warning_sent:
                try:
                    await websocket.send_json({
                        "type": "token_expiring",
                        "message": "Authentication token is about to expire. Please refresh.",
                        "expires_in_seconds": int(time_remaining),
                    })
                    warning_sent = True
                except Exception:
                    return  # Connection is dead

            # Check every 5 seconds or when expiry is imminent
            sleep_time = min(5.0, max(1.0, time_remaining - TOKEN_EXPIRY_WARNING_SECONDS))
            await asyncio.sleep(sleep_time)

    except asyncio.CancelledError:
        # Task was cancelled (e.g., WebSocket disconnected normally)
        return
    except Exception:
        # Unexpected error — don't crash the connection
        return

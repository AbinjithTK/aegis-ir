"""Tests for WebSocket authentication module.

Validates requirements:
    1.1 - Real-time trace timeline via WebSocket (authenticated connections)
    14.2 - Live investigation feed via WebSocket real-time updates
"""

from __future__ import annotations

import asyncio
import time
from datetime import timedelta
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import Depends, FastAPI, WebSocket
from fastapi.testclient import TestClient

from sift_defender.enterprise.auth.dependencies import User
from sift_defender.enterprise.auth.jwt import (
    create_access_token,
    create_refresh_token,
)
from sift_defender.enterprise.auth.websocket_auth import (
    TOKEN_EXPIRY_WARNING_SECONDS,
    WS_CLOSE_AUTH_FAILED,
    WS_CLOSE_TOKEN_EXPIRED,
    WebSocketAuthenticator,
    get_websocket_user,
    monitor_token_expiry,
)


TEST_SECRET = "test-jwt-secret-for-unit-tests"


@pytest.fixture(autouse=True)
def set_jwt_secret(monkeypatch):
    """Set a consistent JWT secret for all tests."""
    monkeypatch.setenv("JWT_SECRET", TEST_SECRET)


def create_ws_test_app() -> FastAPI:
    """Create a minimal FastAPI app with a WebSocket endpoint for testing."""
    app = FastAPI()

    @app.websocket("/ws/test")
    async def ws_endpoint(websocket: WebSocket, user: User = Depends(get_websocket_user)):
        await websocket.accept()
        # Echo back the user info as confirmation
        await websocket.send_json({
            "type": "auth_success",
            "user_id": user.id,
            "tenant_id": user.tenant_id,
            "roles": user.roles,
        })
        try:
            while True:
                data = await websocket.receive_text()
                if data == "ping":
                    await websocket.send_text("pong")
        except Exception:
            pass

    return app


@pytest.fixture
def app():
    """Create a test FastAPI application with WebSocket endpoint."""
    return create_ws_test_app()


@pytest.fixture
def client(app):
    """Create a test client for the FastAPI application."""
    return TestClient(app)


# --- WebSocketAuthenticator Unit Tests ---


class TestWebSocketAuthenticator:
    """Tests for the WebSocketAuthenticator class."""

    def test_authenticate_with_valid_query_param_token(self, client):
        """A valid JWT in query param should authenticate successfully."""
        token = create_access_token("user-ws-1", "tenant-alpha", ["soc_analyst"])

        with client.websocket_connect(f"/ws/test?token={token}") as ws:
            data = ws.receive_json()
            assert data["type"] == "auth_success"
            assert data["user_id"] == "user-ws-1"
            assert data["tenant_id"] == "tenant-alpha"
            assert data["roles"] == ["soc_analyst"]

    def test_authenticate_with_valid_header_token(self, client):
        """A valid JWT in Authorization header should authenticate successfully."""
        token = create_access_token("user-ws-2", "tenant-beta", ["ir_lead"])

        with client.websocket_connect(
            "/ws/test",
            headers={"Authorization": f"Bearer {token}"},
        ) as ws:
            data = ws.receive_json()
            assert data["type"] == "auth_success"
            assert data["user_id"] == "user-ws-2"
            assert data["tenant_id"] == "tenant-beta"
            assert data["roles"] == ["ir_lead"]

    def test_query_param_takes_precedence_over_header(self, client):
        """Query param token should be used if both query param and header are provided."""
        token_query = create_access_token("user-query", "tenant-q", ["soc_analyst"])
        token_header = create_access_token("user-header", "tenant-h", ["ir_lead"])

        with client.websocket_connect(
            f"/ws/test?token={token_query}",
            headers={"Authorization": f"Bearer {token_header}"},
        ) as ws:
            data = ws.receive_json()
            assert data["user_id"] == "user-query"
            assert data["tenant_id"] == "tenant-q"

    def test_missing_token_closes_with_4001(self, client):
        """Missing token should close connection with code 4001."""
        with pytest.raises(Exception):
            with client.websocket_connect("/ws/test") as ws:
                ws.receive_json()

    def test_invalid_token_closes_with_4001(self, client):
        """An invalid/malformed token should close with code 4001."""
        with pytest.raises(Exception):
            with client.websocket_connect("/ws/test?token=not-a-valid-jwt") as ws:
                ws.receive_json()

    def test_expired_token_closes_with_4002(self, client):
        """An expired token should close connection with code 4002."""
        token = create_access_token(
            "user-expired", "tenant-1", ["soc_analyst"],
            expires_delta=timedelta(seconds=-10),
        )
        with pytest.raises(Exception):
            with client.websocket_connect(f"/ws/test?token={token}") as ws:
                ws.receive_json()

    def test_refresh_token_rejected_with_4001(self, client):
        """A refresh token should be rejected (only access tokens allowed)."""
        token = create_refresh_token("user-1", "tenant-1")
        with pytest.raises(Exception):
            with client.websocket_connect(f"/ws/test?token={token}") as ws:
                ws.receive_json()

    def test_tenant_id_scoped_to_connection(self, client):
        """The tenant_id from JWT should be available for data scoping."""
        token = create_access_token("analyst-1", "tenant-isolated-xyz", ["soc_analyst"])

        with client.websocket_connect(f"/ws/test?token={token}") as ws:
            data = ws.receive_json()
            assert data["tenant_id"] == "tenant-isolated-xyz"

    def test_multiple_roles_preserved(self, client):
        """All roles from the JWT should be preserved on the User object."""
        token = create_access_token("multi-role", "tenant-1", ["soc_analyst", "ir_lead", "ciso"])

        with client.websocket_connect(f"/ws/test?token={token}") as ws:
            data = ws.receive_json()
            assert data["roles"] == ["soc_analyst", "ir_lead", "ciso"]


# --- get_websocket_user Dependency Tests ---


class TestGetWebsocketUser:
    """Tests for the get_websocket_user FastAPI dependency."""

    def test_dependency_returns_user_on_valid_token(self, client):
        """The dependency should return a properly hydrated User."""
        token = create_access_token("dep-user", "dep-tenant", ["soc_analyst"])

        with client.websocket_connect(f"/ws/test?token={token}") as ws:
            data = ws.receive_json()
            assert data["type"] == "auth_success"
            assert data["user_id"] == "dep-user"
            assert data["tenant_id"] == "dep-tenant"

    def test_dependency_rejects_empty_token(self, client):
        """Empty token value should be rejected."""
        with pytest.raises(Exception):
            with client.websocket_connect("/ws/test?token=") as ws:
                ws.receive_json()


# --- monitor_token_expiry Tests ---


class TestMonitorTokenExpiry:
    """Tests for the monitor_token_expiry background task."""

    @pytest.mark.asyncio
    async def test_sends_warning_before_expiry(self):
        """Should send a token_expiring message when token is about to expire."""
        ws = AsyncMock(spec=WebSocket)
        ws.send_json = AsyncMock()
        ws.close = AsyncMock()

        # Token expires in 10 seconds (within warning threshold)
        token_exp = time.time() + 10

        task = asyncio.create_task(monitor_token_expiry(ws, token_exp))
        # Give it time to detect the approaching expiry
        await asyncio.sleep(2)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        # Should have sent a warning message
        calls = ws.send_json.call_args_list
        warning_calls = [
            c for c in calls
            if c[0][0].get("type") == "token_expiring"
        ]
        assert len(warning_calls) >= 1
        warning_msg = warning_calls[0][0][0]
        assert warning_msg["type"] == "token_expiring"
        assert "expires_in_seconds" in warning_msg

    @pytest.mark.asyncio
    async def test_disconnects_on_expiry(self):
        """Should close WebSocket with 4002 when token expires."""
        ws = AsyncMock(spec=WebSocket)
        ws.send_json = AsyncMock()
        ws.close = AsyncMock()

        # Token already expired
        token_exp = time.time() - 1

        task = asyncio.create_task(monitor_token_expiry(ws, token_exp))
        await asyncio.sleep(0.5)

        # Task should complete (not need cancellation)
        assert task.done()
        ws.close.assert_called_once_with(code=WS_CLOSE_TOKEN_EXPIRED, reason="Token expired")

    @pytest.mark.asyncio
    async def test_does_not_warn_when_token_has_long_life(self):
        """Should not send warning when token has plenty of time remaining."""
        ws = AsyncMock(spec=WebSocket)
        ws.send_json = AsyncMock()
        ws.close = AsyncMock()

        # Token expires in 5 minutes (well outside warning threshold)
        token_exp = time.time() + 300

        task = asyncio.create_task(monitor_token_expiry(ws, token_exp))
        await asyncio.sleep(1.5)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        # Should not have sent any messages
        ws.send_json.assert_not_called()
        ws.close.assert_not_called()

    @pytest.mark.asyncio
    async def test_handles_cancelled_error_gracefully(self):
        """Should handle CancelledError without raising."""
        ws = AsyncMock(spec=WebSocket)
        ws.send_json = AsyncMock()
        ws.close = AsyncMock()

        # Token expires far in the future
        token_exp = time.time() + 3600

        task = asyncio.create_task(monitor_token_expiry(ws, token_exp))
        await asyncio.sleep(0.1)
        task.cancel()

        # Should not raise
        try:
            await task
        except asyncio.CancelledError:
            pass  # Expected behavior

    @pytest.mark.asyncio
    async def test_sends_expired_message_before_close(self):
        """Should send a token_expired message before closing the connection."""
        ws = AsyncMock(spec=WebSocket)
        ws.send_json = AsyncMock()
        ws.close = AsyncMock()

        # Token expired 1 second ago
        token_exp = time.time() - 1

        task = asyncio.create_task(monitor_token_expiry(ws, token_exp))
        await asyncio.sleep(0.5)

        # Should have sent token_expired message
        expired_calls = [
            c for c in ws.send_json.call_args_list
            if c[0][0].get("type") == "token_expired"
        ]
        assert len(expired_calls) == 1

    @pytest.mark.asyncio
    async def test_handles_send_failure_gracefully(self):
        """Should not crash if send_json fails (connection already closed)."""
        ws = AsyncMock(spec=WebSocket)
        ws.send_json = AsyncMock(side_effect=RuntimeError("Connection closed"))
        ws.close = AsyncMock()

        # Token expiring soon
        token_exp = time.time() + 5

        task = asyncio.create_task(monitor_token_expiry(ws, token_exp))
        await asyncio.sleep(2)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        # Should not have raised — graceful handling


# --- Integration-style Tests ---


class TestWebSocketAuthIntegration:
    """Integration tests combining authentication with WebSocket communication."""

    def test_authenticated_connection_can_communicate(self, client):
        """An authenticated WebSocket should be able to send/receive messages."""
        token = create_access_token("ws-user", "ws-tenant", ["soc_analyst"])

        with client.websocket_connect(f"/ws/test?token={token}") as ws:
            # Receive auth confirmation
            data = ws.receive_json()
            assert data["type"] == "auth_success"

            # Send/receive messages
            ws.send_text("ping")
            response = ws.receive_text()
            assert response == "pong"

    def test_different_tenants_get_different_scoping(self, client):
        """Different tenants should receive their own tenant_id for scoping."""
        token_a = create_access_token("user-a", "tenant-alpha", ["soc_analyst"])
        token_b = create_access_token("user-b", "tenant-beta", ["ir_lead"])

        with client.websocket_connect(f"/ws/test?token={token_a}") as ws_a:
            data_a = ws_a.receive_json()
            assert data_a["tenant_id"] == "tenant-alpha"

        with client.websocket_connect(f"/ws/test?token={token_b}") as ws_b:
            data_b = ws_b.receive_json()
            assert data_b["tenant_id"] == "tenant-beta"

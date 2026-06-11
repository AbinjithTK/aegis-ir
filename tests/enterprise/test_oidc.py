"""Tests for OIDC discovery and token exchange endpoint.

Validates requirements:
    4.4 - SAML/OIDC integration maps external IdP groups to internal roles
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from sift_defender.enterprise.auth.oidc import (
    OIDCCallbackResponse,
    OIDCClient,
    OIDCDiscoveryDocument,
    OIDCDiscoveryError,
    OIDCError,
    OIDCTokenExchangeError,
    OIDCTokenResponse,
    _pending_states,
    configure_oidc,
    get_oidc_client,
    oidc_authorize,
    oidc_callback,
)


# --- Test Constants ---

DISCOVERY_URL = "https://idp.example.com/.well-known/openid-configuration"
CLIENT_ID = "aegis-ir-client-id"
CLIENT_SECRET = "aegis-ir-client-secret"
REDIRECT_URI = "https://aegis.example.com/api/auth/oidc/callback"

DISCOVERY_RESPONSE = {
    "issuer": "https://idp.example.com",
    "authorization_endpoint": "https://idp.example.com/authorize",
    "token_endpoint": "https://idp.example.com/oauth/token",
    "userinfo_endpoint": "https://idp.example.com/userinfo",
    "jwks_uri": "https://idp.example.com/.well-known/jwks.json",
}

TOKEN_RESPONSE = {
    "access_token": "idp-access-token-xyz",
    "id_token": "idp-id-token-jwt",
    "refresh_token": "idp-refresh-token",
    "token_type": "Bearer",
    "expires_in": 3600,
}

USERINFO_RESPONSE = {
    "sub": "ext-user-12345",
    "email": "analyst@corp.example.com",
    "name": "Jane Analyst",
    "groups": ["SOC-Team", "IR-Responders"],
}

TEST_SECRET = "test-jwt-secret-for-oidc-tests"


@pytest.fixture(autouse=True)
def set_jwt_secret(monkeypatch):
    """Set a consistent JWT secret for all tests."""
    monkeypatch.setenv("JWT_SECRET", TEST_SECRET)


@pytest.fixture
def oidc_client():
    """Create an OIDCClient instance for testing."""
    return OIDCClient(
        discovery_url=DISCOVERY_URL,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        redirect_uri=REDIRECT_URI,
    )


@pytest.fixture
def mock_http_client():
    """Create a mocked httpx.AsyncClient."""
    client = AsyncMock(spec=httpx.AsyncClient)
    client.is_closed = False
    return client


# --- OIDCClient Tests ---


class TestOIDCClientInit:
    """Tests for OIDCClient initialization."""

    def test_init_stores_parameters(self, oidc_client):
        """Client should store all initialization parameters."""
        assert oidc_client.discovery_url == DISCOVERY_URL
        assert oidc_client.client_id == CLIENT_ID
        assert oidc_client.client_secret == CLIENT_SECRET
        assert oidc_client.redirect_uri == REDIRECT_URI

    def test_init_no_discovery_cached(self, oidc_client):
        """Discovery document should not be cached initially."""
        assert oidc_client._discovery is None


class TestOIDCDiscovery:
    """Tests for OIDC discovery document fetching."""

    @pytest.mark.asyncio
    async def test_discover_success(self, oidc_client, mock_http_client):
        """Successful discovery should cache the document fields."""
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = DISCOVERY_RESPONSE
        response.raise_for_status = MagicMock()
        mock_http_client.get = AsyncMock(return_value=response)
        oidc_client._http_client = mock_http_client

        result = await oidc_client.discover()

        assert isinstance(result, OIDCDiscoveryDocument)
        assert result.authorization_endpoint == "https://idp.example.com/authorize"
        assert result.token_endpoint == "https://idp.example.com/oauth/token"
        assert result.userinfo_endpoint == "https://idp.example.com/userinfo"
        assert result.jwks_uri == "https://idp.example.com/.well-known/jwks.json"
        assert result.issuer == "https://idp.example.com"

    @pytest.mark.asyncio
    async def test_discover_caches_result(self, oidc_client, mock_http_client):
        """Second call to discover should return cached document without HTTP call."""
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = DISCOVERY_RESPONSE
        response.raise_for_status = MagicMock()
        mock_http_client.get = AsyncMock(return_value=response)
        oidc_client._http_client = mock_http_client

        await oidc_client.discover()
        await oidc_client.discover()

        # HTTP get should only be called once
        assert mock_http_client.get.call_count == 1

    @pytest.mark.asyncio
    async def test_discover_http_error_raises(self, oidc_client, mock_http_client):
        """HTTP errors during discovery should raise OIDCDiscoveryError."""
        mock_http_client.get = AsyncMock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        oidc_client._http_client = mock_http_client

        with pytest.raises(OIDCDiscoveryError, match="Failed to fetch"):
            await oidc_client.discover()

    @pytest.mark.asyncio
    async def test_discover_missing_field_raises(self, oidc_client, mock_http_client):
        """Missing required fields in discovery doc should raise OIDCDiscoveryError."""
        incomplete_doc = {"issuer": "https://idp.example.com"}  # Missing other fields
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = incomplete_doc
        response.raise_for_status = MagicMock()
        mock_http_client.get = AsyncMock(return_value=response)
        oidc_client._http_client = mock_http_client

        with pytest.raises(OIDCDiscoveryError, match="missing required field"):
            await oidc_client.discover()


class TestOIDCAuthorizationURL:
    """Tests for authorization URL generation."""

    def test_get_authorization_url_without_discovery_raises(self, oidc_client):
        """Calling get_authorization_url before discover should raise."""
        with pytest.raises(OIDCError, match="Discovery document not loaded"):
            oidc_client.get_authorization_url(state="abc", nonce="xyz")

    def test_get_authorization_url_includes_params(self, oidc_client):
        """Authorization URL should include all required OIDC parameters."""
        oidc_client._discovery = OIDCDiscoveryDocument(**DISCOVERY_RESPONSE)

        url = oidc_client.get_authorization_url(state="test-state", nonce="test-nonce")

        assert url.startswith("https://idp.example.com/authorize?")
        assert "response_type=code" in url
        assert f"client_id={CLIENT_ID}" in url
        assert "state=test-state" in url
        assert "nonce=test-nonce" in url
        assert "scope=openid" in url
        assert "redirect_uri=" in url

    def test_get_authorization_url_encodes_redirect_uri(self, oidc_client):
        """Redirect URI should be properly URL-encoded."""
        oidc_client._discovery = OIDCDiscoveryDocument(**DISCOVERY_RESPONSE)

        url = oidc_client.get_authorization_url(state="s", nonce="n")

        # The redirect_uri contains :// and / which should be encoded
        assert "redirect_uri=https%3A%2F%2Faegis.example.com" in url


class TestOIDCCodeExchange:
    """Tests for authorization code exchange."""

    @pytest.mark.asyncio
    async def test_exchange_code_success(self, oidc_client, mock_http_client):
        """Successful code exchange should return OIDCTokenResponse."""
        oidc_client._discovery = OIDCDiscoveryDocument(**DISCOVERY_RESPONSE)

        response = MagicMock()
        response.status_code = 200
        response.json.return_value = TOKEN_RESPONSE
        response.raise_for_status = MagicMock()
        mock_http_client.post = AsyncMock(return_value=response)
        oidc_client._http_client = mock_http_client

        result = await oidc_client.exchange_code("auth-code-123")

        assert isinstance(result, OIDCTokenResponse)
        assert result.access_token == "idp-access-token-xyz"
        assert result.id_token == "idp-id-token-jwt"
        assert result.refresh_token == "idp-refresh-token"
        assert result.token_type == "Bearer"
        assert result.expires_in == 3600

    @pytest.mark.asyncio
    async def test_exchange_code_sends_correct_data(self, oidc_client, mock_http_client):
        """Code exchange should POST correct form data to token endpoint."""
        oidc_client._discovery = OIDCDiscoveryDocument(**DISCOVERY_RESPONSE)

        response = MagicMock()
        response.status_code = 200
        response.json.return_value = TOKEN_RESPONSE
        response.raise_for_status = MagicMock()
        mock_http_client.post = AsyncMock(return_value=response)
        oidc_client._http_client = mock_http_client

        await oidc_client.exchange_code("my-code")

        call_kwargs = mock_http_client.post.call_args
        assert call_kwargs[0][0] == "https://idp.example.com/oauth/token"
        posted_data = call_kwargs[1]["data"]
        assert posted_data["grant_type"] == "authorization_code"
        assert posted_data["code"] == "my-code"
        assert posted_data["client_id"] == CLIENT_ID
        assert posted_data["client_secret"] == CLIENT_SECRET
        assert posted_data["redirect_uri"] == REDIRECT_URI

    @pytest.mark.asyncio
    async def test_exchange_code_without_discovery_raises(self, oidc_client):
        """Exchanging code before discovery should raise OIDCError."""
        with pytest.raises(OIDCError, match="Discovery document not loaded"):
            await oidc_client.exchange_code("code")

    @pytest.mark.asyncio
    async def test_exchange_code_http_error(self, oidc_client, mock_http_client):
        """HTTP error during exchange should raise OIDCTokenExchangeError."""
        oidc_client._discovery = OIDCDiscoveryDocument(**DISCOVERY_RESPONSE)
        mock_http_client.post = AsyncMock(
            side_effect=httpx.HTTPStatusError(
                "401", request=MagicMock(), response=MagicMock()
            )
        )
        oidc_client._http_client = mock_http_client

        with pytest.raises(OIDCTokenExchangeError, match="Token exchange failed"):
            await oidc_client.exchange_code("bad-code")

    @pytest.mark.asyncio
    async def test_exchange_code_missing_fields(self, oidc_client, mock_http_client):
        """Token response missing required fields should raise."""
        oidc_client._discovery = OIDCDiscoveryDocument(**DISCOVERY_RESPONSE)

        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {"token_type": "Bearer"}  # Missing access_token, id_token
        response.raise_for_status = MagicMock()
        mock_http_client.post = AsyncMock(return_value=response)
        oidc_client._http_client = mock_http_client

        with pytest.raises(OIDCTokenExchangeError, match="Invalid token response"):
            await oidc_client.exchange_code("code")


class TestOIDCUserinfo:
    """Tests for userinfo endpoint."""

    @pytest.mark.asyncio
    async def test_get_userinfo_success(self, oidc_client, mock_http_client):
        """Successful userinfo fetch should return user data dict."""
        oidc_client._discovery = OIDCDiscoveryDocument(**DISCOVERY_RESPONSE)

        response = MagicMock()
        response.status_code = 200
        response.json.return_value = USERINFO_RESPONSE
        response.raise_for_status = MagicMock()
        mock_http_client.get = AsyncMock(return_value=response)
        oidc_client._http_client = mock_http_client

        result = await oidc_client.get_userinfo("access-token-123")

        assert result["sub"] == "ext-user-12345"
        assert result["email"] == "analyst@corp.example.com"
        assert result["groups"] == ["SOC-Team", "IR-Responders"]

    @pytest.mark.asyncio
    async def test_get_userinfo_sends_bearer_token(self, oidc_client, mock_http_client):
        """Userinfo request should include Bearer token in Authorization header."""
        oidc_client._discovery = OIDCDiscoveryDocument(**DISCOVERY_RESPONSE)

        response = MagicMock()
        response.status_code = 200
        response.json.return_value = USERINFO_RESPONSE
        response.raise_for_status = MagicMock()
        mock_http_client.get = AsyncMock(return_value=response)
        oidc_client._http_client = mock_http_client

        await oidc_client.get_userinfo("my-token")

        call_kwargs = mock_http_client.get.call_args
        headers = call_kwargs[1]["headers"]
        assert headers["Authorization"] == "Bearer my-token"

    @pytest.mark.asyncio
    async def test_get_userinfo_without_discovery_raises(self, oidc_client):
        """Fetching userinfo before discovery should raise OIDCError."""
        with pytest.raises(OIDCError, match="Discovery document not loaded"):
            await oidc_client.get_userinfo("token")

    @pytest.mark.asyncio
    async def test_get_userinfo_http_error(self, oidc_client, mock_http_client):
        """HTTP error during userinfo fetch should raise OIDCError."""
        oidc_client._discovery = OIDCDiscoveryDocument(**DISCOVERY_RESPONSE)
        mock_http_client.get = AsyncMock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        oidc_client._http_client = mock_http_client

        with pytest.raises(OIDCError, match="Failed to fetch userinfo"):
            await oidc_client.get_userinfo("token")


# --- Module-level helpers tests ---


class TestConfigureOIDC:
    """Tests for module-level OIDC configuration."""

    def test_configure_oidc_returns_client(self):
        """configure_oidc should return a configured OIDCClient."""
        client = configure_oidc(
            discovery_url=DISCOVERY_URL,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            redirect_uri=REDIRECT_URI,
        )
        assert isinstance(client, OIDCClient)
        assert client.discovery_url == DISCOVERY_URL

    def test_get_oidc_client_after_configure(self):
        """get_oidc_client should return the configured client."""
        configure_oidc(
            discovery_url=DISCOVERY_URL,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            redirect_uri=REDIRECT_URI,
        )
        client = get_oidc_client()
        assert client.client_id == CLIENT_ID

    def test_get_oidc_client_unconfigured_raises(self):
        """get_oidc_client should raise if not configured."""
        import sift_defender.enterprise.auth.oidc as oidc_mod

        original = oidc_mod._oidc_client
        oidc_mod._oidc_client = None
        try:
            with pytest.raises(RuntimeError, match="not configured"):
                get_oidc_client()
        finally:
            oidc_mod._oidc_client = original


# --- Endpoint Tests ---


class TestOIDCAuthorizeEndpoint:
    """Tests for GET /api/auth/oidc/authorize endpoint."""

    @pytest.mark.asyncio
    async def test_authorize_redirects_to_idp(self):
        """Authorize endpoint should return a redirect to the IdP."""
        client = configure_oidc(
            discovery_url=DISCOVERY_URL,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            redirect_uri=REDIRECT_URI,
        )
        # Pre-load discovery
        client._discovery = OIDCDiscoveryDocument(**DISCOVERY_RESPONSE)

        response = await oidc_authorize()

        assert response.status_code == 307
        location = response.headers["location"]
        assert location.startswith("https://idp.example.com/authorize?")
        assert "response_type=code" in location
        assert f"client_id={CLIENT_ID}" in location

    @pytest.mark.asyncio
    async def test_authorize_stores_state(self):
        """Authorize should store the generated state for CSRF validation."""
        client = configure_oidc(
            discovery_url=DISCOVERY_URL,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            redirect_uri=REDIRECT_URI,
        )
        client._discovery = OIDCDiscoveryDocument(**DISCOVERY_RESPONSE)

        _pending_states.clear()
        await oidc_authorize()

        assert len(_pending_states) == 1
        state_key = list(_pending_states.keys())[0]
        assert "nonce" in _pending_states[state_key]

    @pytest.mark.asyncio
    async def test_authorize_unconfigured_returns_503(self):
        """Authorize without OIDC configured should return 503."""
        import sift_defender.enterprise.auth.oidc as oidc_mod

        original = oidc_mod._oidc_client
        oidc_mod._oidc_client = None
        try:
            from fastapi import HTTPException

            with pytest.raises(HTTPException) as exc_info:
                await oidc_authorize()
            assert exc_info.value.status_code == 503
        finally:
            oidc_mod._oidc_client = original

    @pytest.mark.asyncio
    async def test_authorize_discovery_failure_returns_503(self):
        """Authorize should return 503 if IdP discovery fails."""
        client = configure_oidc(
            discovery_url=DISCOVERY_URL,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            redirect_uri=REDIRECT_URI,
        )
        # Ensure discovery is not cached so it tries to fetch
        client._discovery = None

        mock_http = AsyncMock(spec=httpx.AsyncClient)
        mock_http.is_closed = False
        mock_http.get = AsyncMock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        client._http_client = mock_http

        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            await oidc_authorize()
        assert exc_info.value.status_code == 503


class TestOIDCCallbackEndpoint:
    """Tests for GET /api/auth/oidc/callback endpoint."""

    @pytest.fixture(autouse=True)
    def setup_oidc_client(self):
        """Configure OIDC client with discovery pre-loaded for callback tests."""
        client = configure_oidc(
            discovery_url=DISCOVERY_URL,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            redirect_uri=REDIRECT_URI,
        )
        client._discovery = OIDCDiscoveryDocument(**DISCOVERY_RESPONSE)
        _pending_states.clear()
        yield

    @pytest.mark.asyncio
    async def test_callback_invalid_state_returns_400(self):
        """Callback with unknown state parameter should return 400."""
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            await oidc_callback(code="auth-code", state="unknown-state")
        assert exc_info.value.status_code == 400
        assert "CSRF" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_callback_success_returns_tokens(self):
        """Successful callback should return AEGIS-IR JWT tokens."""
        # Register a valid state
        _pending_states["valid-state"] = {"nonce": "test-nonce"}

        tenant_id = str(uuid.uuid4())
        user_id = str(uuid.uuid4())
        role_id = str(uuid.uuid4())

        mock_conn = AsyncMock()
        # First fetchrow: check user by external_id
        # Second fetchrow: won't be called for existing user path
        mock_conn.fetchrow = AsyncMock(
            return_value={
                "id": user_id,
                "tenant_id": tenant_id,
                "is_active": True,
            }
        )
        # fetch for group mappings, then for role names
        mock_conn.fetch = AsyncMock(
            side_effect=[
                # idp_group_mappings query
                [
                    {"external_group": "SOC-Team", "role_id": role_id},
                ],
                # roles query for role names
                [{"name": "soc_analyst"}],
            ]
        )
        mock_conn.execute = AsyncMock()

        client = get_oidc_client()
        mock_http = AsyncMock(spec=httpx.AsyncClient)
        mock_http.is_closed = False

        # Mock token exchange
        token_resp = MagicMock()
        token_resp.status_code = 200
        token_resp.json.return_value = TOKEN_RESPONSE
        token_resp.raise_for_status = MagicMock()

        # Mock userinfo
        userinfo_resp = MagicMock()
        userinfo_resp.status_code = 200
        userinfo_resp.json.return_value = USERINFO_RESPONSE
        userinfo_resp.raise_for_status = MagicMock()

        mock_http.post = AsyncMock(return_value=token_resp)
        mock_http.get = AsyncMock(return_value=userinfo_resp)
        client._http_client = mock_http

        with patch(
            "sift_defender.enterprise.auth.oidc.get_connection"
        ) as mock_get_conn:
            mock_get_conn.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_get_conn.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await oidc_callback(code="auth-code-123", state="valid-state")

        assert isinstance(result, OIDCCallbackResponse)
        assert result.access_token
        assert result.refresh_token
        assert result.token_type == "bearer"

    @pytest.mark.asyncio
    async def test_callback_removes_used_state(self):
        """Callback should remove the state after use (prevent replay)."""
        _pending_states["one-time-state"] = {"nonce": "n"}

        tenant_id = str(uuid.uuid4())
        user_id = str(uuid.uuid4())

        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(
            return_value={
                "id": user_id,
                "tenant_id": tenant_id,
                "is_active": True,
            }
        )
        mock_conn.fetch = AsyncMock(
            side_effect=[
                [],  # No group mappings
                [],  # No roles (default will be assigned)
            ]
        )
        mock_conn.execute = AsyncMock()

        # Also mock the default role fetch for _map_groups_to_roles
        # When no mappings match, it fetches default soc_analyst role
        role_id = str(uuid.uuid4())
        original_fetchrow = mock_conn.fetchrow

        call_count = [0]

        async def fetchrow_side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                # First call: user lookup
                return {
                    "id": user_id,
                    "tenant_id": tenant_id,
                    "is_active": True,
                }
            else:
                # Second call: default role lookup
                return {"id": role_id}

        mock_conn.fetchrow = AsyncMock(side_effect=fetchrow_side_effect)
        # Update fetch to return role name for the default role
        mock_conn.fetch = AsyncMock(
            side_effect=[
                [],  # No group mappings
                [{"name": "soc_analyst"}],  # Role name
            ]
        )

        client = get_oidc_client()
        mock_http = AsyncMock(spec=httpx.AsyncClient)
        mock_http.is_closed = False

        token_resp = MagicMock()
        token_resp.status_code = 200
        token_resp.json.return_value = TOKEN_RESPONSE
        token_resp.raise_for_status = MagicMock()

        userinfo_resp = MagicMock()
        userinfo_resp.status_code = 200
        userinfo_resp.json.return_value = USERINFO_RESPONSE
        userinfo_resp.raise_for_status = MagicMock()

        mock_http.post = AsyncMock(return_value=token_resp)
        mock_http.get = AsyncMock(return_value=userinfo_resp)
        client._http_client = mock_http

        with patch(
            "sift_defender.enterprise.auth.oidc.get_connection"
        ) as mock_get_conn:
            mock_get_conn.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_get_conn.return_value.__aexit__ = AsyncMock(return_value=False)

            await oidc_callback(code="code", state="one-time-state")

        assert "one-time-state" not in _pending_states

    @pytest.mark.asyncio
    async def test_callback_token_exchange_failure_returns_502(self):
        """Failed token exchange should return 502."""
        _pending_states["state-for-502"] = {"nonce": "n"}

        client = get_oidc_client()
        mock_http = AsyncMock(spec=httpx.AsyncClient)
        mock_http.is_closed = False
        mock_http.post = AsyncMock(
            side_effect=httpx.HTTPStatusError(
                "401", request=MagicMock(), response=MagicMock()
            )
        )
        client._http_client = mock_http

        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            await oidc_callback(code="bad-code", state="state-for-502")
        assert exc_info.value.status_code == 502

    @pytest.mark.asyncio
    async def test_callback_userinfo_failure_returns_502(self):
        """Failed userinfo fetch should return 502."""
        _pending_states["state-userinfo-fail"] = {"nonce": "n"}

        client = get_oidc_client()
        mock_http = AsyncMock(spec=httpx.AsyncClient)
        mock_http.is_closed = False

        # Token exchange succeeds
        token_resp = MagicMock()
        token_resp.status_code = 200
        token_resp.json.return_value = TOKEN_RESPONSE
        token_resp.raise_for_status = MagicMock()
        mock_http.post = AsyncMock(return_value=token_resp)

        # Userinfo fails
        mock_http.get = AsyncMock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        client._http_client = mock_http

        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            await oidc_callback(code="code", state="state-userinfo-fail")
        assert exc_info.value.status_code == 502

    @pytest.mark.asyncio
    async def test_callback_missing_email_returns_400(self):
        """Callback should return 400 if IdP doesn't provide email."""
        _pending_states["state-no-email"] = {"nonce": "n"}

        client = get_oidc_client()
        mock_http = AsyncMock(spec=httpx.AsyncClient)
        mock_http.is_closed = False

        token_resp = MagicMock()
        token_resp.status_code = 200
        token_resp.json.return_value = TOKEN_RESPONSE
        token_resp.raise_for_status = MagicMock()
        mock_http.post = AsyncMock(return_value=token_resp)

        # Userinfo without email
        userinfo_resp = MagicMock()
        userinfo_resp.status_code = 200
        userinfo_resp.json.return_value = {"sub": "user-123"}  # No email
        userinfo_resp.raise_for_status = MagicMock()
        mock_http.get = AsyncMock(return_value=userinfo_resp)
        client._http_client = mock_http

        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            await oidc_callback(code="code", state="state-no-email")
        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_callback_inactive_user_returns_401(self):
        """Callback for an inactive user should return 401."""
        _pending_states["state-inactive"] = {"nonce": "n"}

        client = get_oidc_client()
        mock_http = AsyncMock(spec=httpx.AsyncClient)
        mock_http.is_closed = False

        token_resp = MagicMock()
        token_resp.status_code = 200
        token_resp.json.return_value = TOKEN_RESPONSE
        token_resp.raise_for_status = MagicMock()
        mock_http.post = AsyncMock(return_value=token_resp)

        userinfo_resp = MagicMock()
        userinfo_resp.status_code = 200
        userinfo_resp.json.return_value = USERINFO_RESPONSE
        userinfo_resp.raise_for_status = MagicMock()
        mock_http.get = AsyncMock(return_value=userinfo_resp)
        client._http_client = mock_http

        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(
            return_value={
                "id": str(uuid.uuid4()),
                "tenant_id": str(uuid.uuid4()),
                "is_active": False,
            }
        )

        with patch(
            "sift_defender.enterprise.auth.oidc.get_connection"
        ) as mock_get_conn:
            mock_get_conn.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_get_conn.return_value.__aexit__ = AsyncMock(return_value=False)

            from fastapi import HTTPException

            with pytest.raises(HTTPException) as exc_info:
                await oidc_callback(code="code", state="state-inactive")
            assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_callback_jit_provisions_new_user(self):
        """Callback for unknown user should create them (JIT provisioning)."""
        _pending_states["state-jit"] = {"nonce": "n"}

        tenant_id = str(uuid.uuid4())
        role_id = str(uuid.uuid4())

        client = get_oidc_client()
        mock_http = AsyncMock(spec=httpx.AsyncClient)
        mock_http.is_closed = False

        token_resp = MagicMock()
        token_resp.status_code = 200
        token_resp.json.return_value = TOKEN_RESPONSE
        token_resp.raise_for_status = MagicMock()
        mock_http.post = AsyncMock(return_value=token_resp)

        userinfo_resp = MagicMock()
        userinfo_resp.status_code = 200
        userinfo_resp.json.return_value = USERINFO_RESPONSE
        userinfo_resp.raise_for_status = MagicMock()
        mock_http.get = AsyncMock(return_value=userinfo_resp)
        client._http_client = mock_http

        mock_conn = AsyncMock()
        call_count = [0]

        async def fetchrow_side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                # User lookup by external_id: not found
                return None
            elif call_count[0] == 2:
                # Tenant lookup by domain
                return {"id": tenant_id}
            elif call_count[0] == 3:
                # Default role lookup (fallback if no mappings match)
                return {"id": role_id}
            return None

        mock_conn.fetchrow = AsyncMock(side_effect=fetchrow_side_effect)
        mock_conn.fetch = AsyncMock(
            side_effect=[
                # idp_group_mappings: no mappings configured
                [],
                # role names for the default role
                [{"name": "soc_analyst"}],
            ]
        )
        mock_conn.execute = AsyncMock()

        with patch(
            "sift_defender.enterprise.auth.oidc.get_connection"
        ) as mock_get_conn:
            mock_get_conn.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_get_conn.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await oidc_callback(code="code", state="state-jit")

        assert result.access_token
        assert result.refresh_token

        # Verify user was created (INSERT INTO users was called)
        insert_calls = [
            call
            for call in mock_conn.execute.call_args_list
            if "INSERT INTO users" in str(call)
        ]
        assert len(insert_calls) == 1

    @pytest.mark.asyncio
    async def test_callback_maps_idp_groups_to_roles(self):
        """Callback should map IdP groups to internal roles via tenant mappings."""
        _pending_states["state-groups"] = {"nonce": "n"}

        tenant_id = str(uuid.uuid4())
        user_id = str(uuid.uuid4())
        analyst_role_id = str(uuid.uuid4())
        lead_role_id = str(uuid.uuid4())

        client = get_oidc_client()
        mock_http = AsyncMock(spec=httpx.AsyncClient)
        mock_http.is_closed = False

        token_resp = MagicMock()
        token_resp.status_code = 200
        token_resp.json.return_value = TOKEN_RESPONSE
        token_resp.raise_for_status = MagicMock()
        mock_http.post = AsyncMock(return_value=token_resp)

        userinfo_resp = MagicMock()
        userinfo_resp.status_code = 200
        userinfo_resp.json.return_value = {
            "sub": "ext-user-789",
            "email": "lead@corp.example.com",
            "groups": ["SOC-Team", "IR-Responders"],
        }
        userinfo_resp.raise_for_status = MagicMock()
        mock_http.get = AsyncMock(return_value=userinfo_resp)
        client._http_client = mock_http

        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(
            return_value={
                "id": user_id,
                "tenant_id": tenant_id,
                "is_active": True,
            }
        )
        mock_conn.fetch = AsyncMock(
            side_effect=[
                # idp_group_mappings: both groups map to roles
                [
                    {"external_group": "SOC-Team", "role_id": analyst_role_id},
                    {"external_group": "IR-Responders", "role_id": lead_role_id},
                ],
                # role names
                [{"name": "soc_analyst"}, {"name": "ir_lead"}],
            ]
        )
        mock_conn.execute = AsyncMock()

        with patch(
            "sift_defender.enterprise.auth.oidc.get_connection"
        ) as mock_get_conn:
            mock_get_conn.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_get_conn.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await oidc_callback(code="code", state="state-groups")

        assert result.access_token
        # Verify roles were assigned (DELETE + INSERT INTO user_roles)
        delete_calls = [
            call
            for call in mock_conn.execute.call_args_list
            if "DELETE FROM user_roles" in str(call)
        ]
        assert len(delete_calls) == 1

        insert_role_calls = [
            call
            for call in mock_conn.execute.call_args_list
            if "INSERT INTO user_roles" in str(call)
        ]
        assert len(insert_role_calls) == 2  # Two roles assigned

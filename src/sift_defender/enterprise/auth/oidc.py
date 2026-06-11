"""OIDC (OpenID Connect) client and endpoints for external IdP integration.

Implements the Authorization Code Flow for integrating with external identity
providers (e.g., Okta, Azure AD, Auth0). Handles discovery document consumption,
authorization URL generation, code exchange, and user provisioning.

Requirements:
    4.4 - SAML/OIDC integration maps external IdP groups to internal roles
"""

from __future__ import annotations

import logging
import secrets
import uuid
from typing import Optional
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from sift_defender.enterprise.auth.jwt import create_access_token, create_refresh_token
from sift_defender.enterprise.db import get_connection

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth/oidc", tags=["auth", "oidc"])


# --- Models ---


class OIDCTokenResponse(BaseModel):
    """Token response from the OIDC provider's token endpoint.

    Attributes:
        access_token: The access token issued by the IdP.
        id_token: The OpenID Connect ID token (JWT with user claims).
        refresh_token: Optional refresh token from the IdP.
        token_type: Token type, typically "Bearer".
        expires_in: Token lifetime in seconds.
    """

    access_token: str
    id_token: str
    refresh_token: Optional[str] = None
    token_type: str = "Bearer"
    expires_in: int = 3600


class OIDCDiscoveryDocument(BaseModel):
    """Cached OIDC discovery document fields.

    Attributes:
        authorization_endpoint: URL for the authorization request.
        token_endpoint: URL for the token exchange.
        userinfo_endpoint: URL for fetching user info.
        jwks_uri: URL for JSON Web Key Set.
        issuer: The issuer identifier.
    """

    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str
    issuer: str


class OIDCCallbackResponse(BaseModel):
    """Response returned to the client after successful OIDC authentication.

    Attributes:
        access_token: AEGIS-IR access token (not the IdP token).
        refresh_token: AEGIS-IR refresh token.
        token_type: Always "bearer".
    """

    access_token: str
    refresh_token: str
    token_type: str = "bearer"


# --- OIDC Client ---


class OIDCError(Exception):
    """Base exception for OIDC-related errors."""

    pass


class OIDCDiscoveryError(OIDCError):
    """Raised when OIDC discovery fails."""

    pass


class OIDCTokenExchangeError(OIDCError):
    """Raised when the authorization code exchange fails."""

    pass


class OIDCClient:
    """OpenID Connect client implementing the Authorization Code Flow.

    Handles discovery document fetching, authorization URL construction,
    authorization code exchange, and user info retrieval.

    Args:
        discovery_url: The /.well-known/openid-configuration URL.
        client_id: The OIDC client ID registered with the IdP.
        client_secret: The OIDC client secret.
        redirect_uri: The callback URL registered with the IdP.
    """

    def __init__(
        self,
        discovery_url: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
    ):
        self.discovery_url = discovery_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self._discovery: Optional[OIDCDiscoveryDocument] = None
        self._http_client: Optional[httpx.AsyncClient] = None

    @property
    def http_client(self) -> httpx.AsyncClient:
        """Lazy-initialized HTTP client for making requests to the IdP."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(timeout=30.0)
        return self._http_client

    async def close(self) -> None:
        """Close the HTTP client, releasing connections."""
        if self._http_client is not None and not self._http_client.is_closed:
            await self._http_client.aclose()
            self._http_client = None

    async def discover(self) -> OIDCDiscoveryDocument:
        """Fetch and cache the OIDC discovery document.

        Retrieves the /.well-known/openid-configuration from the IdP
        and caches the authorization_endpoint, token_endpoint,
        userinfo_endpoint, and jwks_uri.

        Returns:
            The parsed discovery document.

        Raises:
            OIDCDiscoveryError: If the discovery endpoint is unreachable
                or returns invalid data.
        """
        if self._discovery is not None:
            return self._discovery

        try:
            response = await self.http_client.get(self.discovery_url)
            response.raise_for_status()
        except httpx.HTTPError as e:
            raise OIDCDiscoveryError(
                f"Failed to fetch OIDC discovery document from {self.discovery_url}: {e}"
            )

        try:
            data = response.json()
            self._discovery = OIDCDiscoveryDocument(
                authorization_endpoint=data["authorization_endpoint"],
                token_endpoint=data["token_endpoint"],
                userinfo_endpoint=data["userinfo_endpoint"],
                jwks_uri=data["jwks_uri"],
                issuer=data["issuer"],
            )
        except (KeyError, ValueError) as e:
            raise OIDCDiscoveryError(
                f"Invalid OIDC discovery document: missing required field: {e}"
            )

        return self._discovery

    def get_authorization_url(self, state: str, nonce: str) -> str:
        """Build the authorization URL to redirect the user to the IdP.

        Constructs the full authorization URL including required OIDC
        parameters: response_type, client_id, redirect_uri, scope, state,
        and nonce.

        Args:
            state: An opaque value used to maintain state between request
                and callback. Should be verified on callback to prevent CSRF.
            nonce: A unique value to associate the ID token with the session.

        Returns:
            The full authorization URL string.

        Raises:
            OIDCError: If the discovery document has not been fetched yet.
        """
        if self._discovery is None:
            raise OIDCError(
                "Discovery document not loaded. Call discover() first."
            )

        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": "openid email profile groups",
            "state": state,
            "nonce": nonce,
        }

        return f"{self._discovery.authorization_endpoint}?{urlencode(params)}"

    async def exchange_code(self, code: str) -> OIDCTokenResponse:
        """Exchange an authorization code for tokens from the IdP.

        Sends the authorization code to the token endpoint with
        client credentials to obtain access_token, id_token, and
        optionally a refresh_token.

        Args:
            code: The authorization code received from the IdP callback.

        Returns:
            An OIDCTokenResponse with the IdP-issued tokens.

        Raises:
            OIDCTokenExchangeError: If the token exchange fails.
            OIDCError: If the discovery document has not been fetched.
        """
        if self._discovery is None:
            raise OIDCError(
                "Discovery document not loaded. Call discover() first."
            )

        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        try:
            response = await self.http_client.post(
                self._discovery.token_endpoint,
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response.raise_for_status()
        except httpx.HTTPError as e:
            raise OIDCTokenExchangeError(
                f"Token exchange failed: {e}"
            )

        try:
            data = response.json()
            return OIDCTokenResponse(
                access_token=data["access_token"],
                id_token=data["id_token"],
                refresh_token=data.get("refresh_token"),
                token_type=data.get("token_type", "Bearer"),
                expires_in=data.get("expires_in", 3600),
            )
        except (KeyError, ValueError) as e:
            raise OIDCTokenExchangeError(
                f"Invalid token response from IdP: {e}"
            )

    async def get_userinfo(self, access_token: str) -> dict:
        """Fetch user information from the IdP's userinfo endpoint.

        Uses the IdP-issued access token to retrieve user profile
        information including email, name, and group memberships.

        Args:
            access_token: The access token from the IdP (not AEGIS-IR token).

        Returns:
            A dict with user profile fields (sub, email, name, groups, etc.).

        Raises:
            OIDCError: If the discovery document has not been fetched or
                the userinfo request fails.
        """
        if self._discovery is None:
            raise OIDCError(
                "Discovery document not loaded. Call discover() first."
            )

        try:
            response = await self.http_client.get(
                self._discovery.userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            response.raise_for_status()
        except httpx.HTTPError as e:
            raise OIDCError(f"Failed to fetch userinfo: {e}")

        return response.json()


# --- Module-level OIDC client (configured at startup) ---

_oidc_client: Optional[OIDCClient] = None


def get_oidc_client() -> OIDCClient:
    """Return the configured OIDC client instance.

    Raises:
        RuntimeError: If OIDC has not been configured.
    """
    if _oidc_client is None:
        raise RuntimeError(
            "OIDC client not configured. Configure OIDC settings before using SSO."
        )
    return _oidc_client


def configure_oidc(
    discovery_url: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
) -> OIDCClient:
    """Configure the module-level OIDC client.

    Should be called during application startup when OIDC settings are available.

    Args:
        discovery_url: The IdP's /.well-known/openid-configuration URL.
        client_id: The registered OIDC client ID.
        client_secret: The registered OIDC client secret.
        redirect_uri: The callback URL (must match IdP registration).

    Returns:
        The configured OIDCClient instance.
    """
    global _oidc_client
    _oidc_client = OIDCClient(
        discovery_url=discovery_url,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
    )
    return _oidc_client


# --- State management (in production, use Redis or a signed cookie) ---

# Simple in-memory state store for CSRF protection during auth flow.
# In production, replace with a session store or signed state parameter.
_pending_states: dict[str, dict] = {}


# --- FastAPI Endpoints ---


@router.get(
    "/authorize",
    status_code=status.HTTP_307_TEMPORARY_REDIRECT,
    responses={
        307: {"description": "Redirect to IdP authorization endpoint"},
        503: {"description": "OIDC not configured or IdP unreachable"},
    },
)
async def oidc_authorize() -> RedirectResponse:
    """Initiate OIDC authorization flow by redirecting to the IdP.

    Generates a state parameter for CSRF protection and a nonce for
    ID token validation, then redirects the user to the IdP's
    authorization endpoint.

    Returns:
        A redirect response to the IdP authorization URL.

    Raises:
        HTTPException: 503 if OIDC is not configured or discovery fails.
    """
    try:
        client = get_oidc_client()
    except RuntimeError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC authentication is not configured",
        )

    try:
        await client.discover()
    except OIDCDiscoveryError as e:
        logger.error("OIDC discovery failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Identity provider is unreachable",
        )

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    # Store state for validation on callback
    _pending_states[state] = {"nonce": nonce}

    authorization_url = client.get_authorization_url(state=state, nonce=nonce)

    return RedirectResponse(url=authorization_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@router.get(
    "/callback",
    response_model=OIDCCallbackResponse,
    responses={
        400: {"description": "Invalid state or missing code"},
        502: {"description": "Token exchange with IdP failed"},
    },
)
async def oidc_callback(
    code: str = Query(..., description="Authorization code from the IdP"),
    state: str = Query(..., description="State parameter for CSRF validation"),
) -> OIDCCallbackResponse:
    """Handle the OIDC callback from the IdP after user authorization.

    Validates the state parameter, exchanges the authorization code for
    tokens, fetches user info, creates/updates the user in the database,
    maps IdP groups to internal roles, and returns AEGIS-IR JWT tokens.

    Args:
        code: The authorization code from the IdP redirect.
        state: The state parameter that must match the one sent in /authorize.

    Returns:
        An OIDCCallbackResponse with AEGIS-IR access and refresh tokens.

    Raises:
        HTTPException: 400 if state is invalid or code is missing.
        HTTPException: 502 if token exchange or userinfo fetch fails.
    """
    # Validate state (CSRF protection)
    if state not in _pending_states:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid state parameter — possible CSRF attack",
        )

    # Remove used state to prevent replay
    state_data = _pending_states.pop(state)  # noqa: F841 (nonce available for ID token validation)

    client = get_oidc_client()

    # Exchange authorization code for tokens
    try:
        token_response = await client.exchange_code(code)
    except (OIDCTokenExchangeError, OIDCError) as e:
        logger.error("OIDC token exchange failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to exchange authorization code with identity provider",
        )

    # Fetch user information from IdP
    try:
        userinfo = await client.get_userinfo(token_response.access_token)
    except OIDCError as e:
        logger.error("OIDC userinfo fetch failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to fetch user information from identity provider",
        )

    # Extract user details
    external_id = userinfo.get("sub", "")
    email = userinfo.get("email", "")
    groups = userinfo.get("groups", [])

    if not external_id or not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Identity provider did not return required user information (sub, email)",
        )

    # Create or update user in the database (JIT provisioning)
    async with get_connection() as conn:
        # Check if user already exists by external_id
        user_row = await conn.fetchrow(
            """
            SELECT id, tenant_id, is_active
            FROM users
            WHERE external_id = $1
            LIMIT 1
            """,
            external_id,
        )

        if user_row is not None:
            if not user_row["is_active"]:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User account is inactive",
                )
            user_id = str(user_row["id"])
            tenant_id = str(user_row["tenant_id"])
        else:
            # JIT provisioning: find tenant by email domain or use default
            email_domain = email.split("@")[1] if "@" in email else ""
            tenant_row = await conn.fetchrow(
                """
                SELECT id FROM tenants
                WHERE domain = $1
                LIMIT 1
                """,
                email_domain,
            )

            if tenant_row is not None:
                tenant_id = str(tenant_row["id"])
            else:
                # Fall back to first available tenant (MVP behavior)
                tenant_row = await conn.fetchrow("SELECT id FROM tenants LIMIT 1")
                if tenant_row is None:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="No tenant configured for this organization",
                    )
                tenant_id = str(tenant_row["id"])

            # Create user
            user_id = str(uuid.uuid4())
            await conn.execute(
                """
                INSERT INTO users (id, tenant_id, email, external_id, is_active)
                VALUES ($1, $2, $3, $4, TRUE)
                """,
                user_id,
                tenant_id,
                email,
                external_id,
            )

        # Map IdP groups to internal roles
        roles = await _map_groups_to_roles(conn, groups, tenant_id, user_id)

    # Issue AEGIS-IR tokens
    access_token = create_access_token(user_id, tenant_id, roles)
    refresh_token = create_refresh_token(user_id, tenant_id)

    return OIDCCallbackResponse(
        access_token=access_token,
        refresh_token=refresh_token,
    )


async def _map_groups_to_roles(
    conn,
    groups: list[str],
    tenant_id: str,
    user_id: str,
) -> list[str]:
    """Map external IdP group names to internal AEGIS-IR roles.

    Looks up group-to-role mappings configured for the tenant, assigns
    matching roles to the user, and returns the list of role names.

    If no mappings match, assigns the default 'soc_analyst' role.

    Args:
        conn: Active database connection.
        groups: List of group names from the IdP userinfo.
        tenant_id: The tenant to scope role lookups to.
        user_id: The user ID to assign roles to.

    Returns:
        List of role name strings assigned to the user.
    """
    # Look up configured group-to-role mappings for this tenant
    mapping_rows = await conn.fetch(
        """
        SELECT external_group, role_id
        FROM idp_group_mappings
        WHERE tenant_id = $1
        """,
        tenant_id,
    )

    # Build mapping dict
    group_to_role_id: dict[str, str] = {
        row["external_group"]: str(row["role_id"]) for row in mapping_rows
    }

    # Find matching role IDs
    matched_role_ids: list[str] = []
    for group in groups:
        if group in group_to_role_id:
            matched_role_ids.append(group_to_role_id[group])

    # If no groups matched, assign default soc_analyst role
    if not matched_role_ids:
        default_role = await conn.fetchrow(
            """
            SELECT id FROM roles
            WHERE tenant_id = $1 AND name = 'soc_analyst' AND is_default = TRUE
            LIMIT 1
            """,
            tenant_id,
        )
        if default_role:
            matched_role_ids.append(str(default_role["id"]))

    # Clear existing roles and assign new ones
    await conn.execute(
        "DELETE FROM user_roles WHERE user_id = $1",
        user_id,
    )

    for role_id in matched_role_ids:
        await conn.execute(
            """
            INSERT INTO user_roles (user_id, role_id)
            VALUES ($1, $2)
            ON CONFLICT (user_id, role_id) DO NOTHING
            """,
            user_id,
            role_id,
        )

    # Fetch role names for token claims
    if matched_role_ids:
        role_rows = await conn.fetch(
            """
            SELECT name FROM roles
            WHERE id = ANY($1::uuid[])
            """,
            matched_role_ids,
        )
        return [row["name"] for row in role_rows]

    return []

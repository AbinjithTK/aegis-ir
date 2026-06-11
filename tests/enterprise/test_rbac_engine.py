"""Tests for the RBACEngine class.

Validates that:
- RBACEngine initializes without a DB session
- check_permission returns True when user has the permission via assigned roles
- check_permission returns False when user lacks the permission
- get_effective_permissions resolves permissions across multiple assigned roles (union)
- _resolve_roles queries the DB with correct SQL and parameters
- Unknown permission strings in DB are gracefully skipped
- A user with no roles gets an empty permission set

Requirements: 4.1, 4.2
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from contextlib import asynccontextmanager

import pytest

from sift_defender.enterprise.auth.rbac import (
    DEFAULT_ROLES,
    Permission,
    RBACEngine,
)


# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def engine():
    """Create a fresh RBACEngine instance."""
    return RBACEngine()


def _make_role_row(role_id: str, name: str, permissions: list[str]) -> dict:
    """Create a mock role record as returned by _resolve_roles."""
    return {"id": role_id, "name": name, "permissions": permissions}


def _mock_tenant_connection(rows: list):
    """Create a mock for get_tenant_connection that returns the given rows on fetch.

    Returns a tuple of (context_manager_factory, mock_connection).
    The context_manager_factory can be used to patch get_tenant_connection.
    """
    # Create mock Record objects that behave like asyncpg Records (dict-like)
    mock_records = []
    for r in rows:
        record = MagicMock()
        record.__getitem__ = MagicMock(side_effect=lambda key, _r=r: _r[key])
        record.keys = MagicMock(return_value=r.keys())
        # Support dict() conversion
        record.__iter__ = MagicMock(side_effect=lambda _r=r: iter(_r.keys()))
        record.items = MagicMock(return_value=r.items())
        # asyncpg Records also support .get()
        record.get = MagicMock(side_effect=lambda key, default=None, _r=r: _r.get(key, default))
        mock_records.append(record)

    mock_conn = AsyncMock()
    mock_conn.fetch = AsyncMock(return_value=mock_records)

    @asynccontextmanager
    async def _ctx(tenant_id):
        yield mock_conn

    return _ctx, mock_conn


# ─── RBACEngine Initialization ────────────────────────────────────────────────


class TestRBACEngineInit:
    """Test RBACEngine instantiation."""

    def test_init_requires_no_arguments(self):
        """RBACEngine should initialize with no DB session."""
        engine = RBACEngine()
        assert engine is not None

    def test_init_returns_rbac_engine_instance(self):
        engine = RBACEngine()
        assert isinstance(engine, RBACEngine)


# ─── _resolve_roles ──────────────────────────────────────────────────────────


class TestResolveRoles:
    """Test the _resolve_roles helper method."""

    @pytest.mark.asyncio
    async def test_resolve_roles_queries_database(self, engine):
        """_resolve_roles should query user_roles JOIN roles."""
        rows = [
            _make_role_row("role-1", "soc_analyst", ["investigation:start", "investigation:view"]),
        ]
        mock_ctx, mock_conn = _mock_tenant_connection(rows)

        with patch("sift_defender.enterprise.db.get_tenant_connection", mock_ctx):
            result = await engine._resolve_roles("user-123", "tenant-abc")

        mock_conn.fetch.assert_called_once()
        call_args = mock_conn.fetch.call_args
        # Verify the SQL includes the expected JOIN pattern
        sql = call_args[0][0]
        assert "user_roles" in sql
        assert "roles" in sql
        # Verify user_id and tenant_id are passed as parameters
        assert call_args[0][1] == "user-123"
        assert call_args[0][2] == "tenant-abc"

    @pytest.mark.asyncio
    async def test_resolve_roles_returns_list_of_dicts(self, engine):
        """_resolve_roles should return role records as dicts."""
        rows = [
            _make_role_row("role-1", "soc_analyst", ["investigation:start"]),
        ]
        mock_ctx, _ = _mock_tenant_connection(rows)

        with patch("sift_defender.enterprise.db.get_tenant_connection", mock_ctx):
            result = await engine._resolve_roles("user-123", "tenant-abc")

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["name"] == "soc_analyst"
        assert result[0]["permissions"] == ["investigation:start"]

    @pytest.mark.asyncio
    async def test_resolve_roles_returns_empty_for_no_roles(self, engine):
        """If user has no assigned roles, return empty list."""
        mock_ctx, _ = _mock_tenant_connection([])

        with patch("sift_defender.enterprise.db.get_tenant_connection", mock_ctx):
            result = await engine._resolve_roles("user-no-roles", "tenant-abc")

        assert result == []

    @pytest.mark.asyncio
    async def test_resolve_roles_returns_multiple_roles(self, engine):
        """A user can have multiple roles assigned."""
        rows = [
            _make_role_row("role-1", "soc_analyst", ["investigation:start", "investigation:view"]),
            _make_role_row("role-2", "ir_lead", ["case:manage", "case:assign"]),
        ]
        mock_ctx, _ = _mock_tenant_connection(rows)

        with patch("sift_defender.enterprise.db.get_tenant_connection", mock_ctx):
            result = await engine._resolve_roles("user-multi", "tenant-abc")

        assert len(result) == 2


# ─── get_effective_permissions ────────────────────────────────────────────────


class TestGetEffectivePermissions:
    """Test effective permission resolution across roles."""

    @pytest.mark.asyncio
    async def test_single_role_permissions(self, engine):
        """User with one role gets exactly that role's permissions."""
        soc_perms = [p.value for p in DEFAULT_ROLES["soc_analyst"]]
        rows = [_make_role_row("role-1", "soc_analyst", soc_perms)]
        mock_ctx, _ = _mock_tenant_connection(rows)

        with patch("sift_defender.enterprise.db.get_tenant_connection", mock_ctx):
            result = await engine.get_effective_permissions("user-1", "tenant-abc")

        assert result == set(DEFAULT_ROLES["soc_analyst"])

    @pytest.mark.asyncio
    async def test_multiple_roles_union_permissions(self, engine):
        """User with multiple roles gets the union of all permissions."""
        soc_perms = ["investigation:start", "investigation:view", "finding:approve"]
        ciso_perms = ["audit:view", "audit:export", "report:executive"]
        rows = [
            _make_role_row("role-1", "soc_analyst", soc_perms),
            _make_role_row("role-2", "ciso", ciso_perms),
        ]
        mock_ctx, _ = _mock_tenant_connection(rows)

        with patch("sift_defender.enterprise.db.get_tenant_connection", mock_ctx):
            result = await engine.get_effective_permissions("user-multi", "tenant-abc")

        expected = {
            Permission.INVESTIGATE_START,
            Permission.INVESTIGATE_VIEW,
            Permission.FINDING_APPROVE,
            Permission.AUDIT_VIEW,
            Permission.AUDIT_EXPORT,
            Permission.REPORT_EXECUTIVE,
        }
        assert result == expected

    @pytest.mark.asyncio
    async def test_overlapping_permissions_deduplicated(self, engine):
        """Overlapping permissions across roles are deduplicated (set union)."""
        # Both roles have INVESTIGATE_VIEW
        role1_perms = ["investigation:start", "investigation:view"]
        role2_perms = ["investigation:view", "audit:view"]
        rows = [
            _make_role_row("role-1", "soc_analyst", role1_perms),
            _make_role_row("role-2", "custom", role2_perms),
        ]
        mock_ctx, _ = _mock_tenant_connection(rows)

        with patch("sift_defender.enterprise.db.get_tenant_connection", mock_ctx):
            result = await engine.get_effective_permissions("user-overlap", "tenant-abc")

        assert result == {
            Permission.INVESTIGATE_START,
            Permission.INVESTIGATE_VIEW,
            Permission.AUDIT_VIEW,
        }

    @pytest.mark.asyncio
    async def test_no_roles_returns_empty_set(self, engine):
        """User with no roles gets an empty permission set."""
        mock_ctx, _ = _mock_tenant_connection([])

        with patch("sift_defender.enterprise.db.get_tenant_connection", mock_ctx):
            result = await engine.get_effective_permissions("user-noroles", "tenant-abc")

        assert result == set()

    @pytest.mark.asyncio
    async def test_unknown_permission_strings_skipped(self, engine):
        """Permission strings in DB not matching enum are gracefully skipped."""
        perms_with_unknown = [
            "investigation:start",
            "unknown:permission",
            "investigation:view",
        ]
        rows = [_make_role_row("role-1", "custom", perms_with_unknown)]
        mock_ctx, _ = _mock_tenant_connection(rows)

        with patch("sift_defender.enterprise.db.get_tenant_connection", mock_ctx):
            result = await engine.get_effective_permissions("user-1", "tenant-abc")

        # Only known permissions should be in the result
        assert result == {Permission.INVESTIGATE_START, Permission.INVESTIGATE_VIEW}

    @pytest.mark.asyncio
    async def test_returns_permission_enum_instances(self, engine):
        """All returned permissions must be Permission enum instances, not strings."""
        rows = [_make_role_row("role-1", "soc_analyst", ["investigation:start"])]
        mock_ctx, _ = _mock_tenant_connection(rows)

        with patch("sift_defender.enterprise.db.get_tenant_connection", mock_ctx):
            result = await engine.get_effective_permissions("user-1", "tenant-abc")

        for perm in result:
            assert isinstance(perm, Permission)


# ─── check_permission ─────────────────────────────────────────────────────────


class TestCheckPermission:
    """Test individual permission checks."""

    @pytest.mark.asyncio
    async def test_returns_true_when_user_has_permission(self, engine):
        """check_permission returns True if permission is in user's effective set."""
        rows = [_make_role_row("role-1", "soc_analyst", ["investigation:start", "finding:approve"])]
        mock_ctx, _ = _mock_tenant_connection(rows)

        with patch("sift_defender.enterprise.db.get_tenant_connection", mock_ctx):
            result = await engine.check_permission(
                "user-1", "tenant-abc", Permission.INVESTIGATE_START
            )

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_when_user_lacks_permission(self, engine):
        """check_permission returns False if permission is NOT in user's effective set."""
        rows = [_make_role_row("role-1", "soc_analyst", ["investigation:start"])]
        mock_ctx, _ = _mock_tenant_connection(rows)

        with patch("sift_defender.enterprise.db.get_tenant_connection", mock_ctx):
            result = await engine.check_permission(
                "user-1", "tenant-abc", Permission.USER_MANAGE
            )

        assert result is False

    @pytest.mark.asyncio
    async def test_returns_false_when_user_has_no_roles(self, engine):
        """User with no roles should be denied any permission."""
        mock_ctx, _ = _mock_tenant_connection([])

        with patch("sift_defender.enterprise.db.get_tenant_connection", mock_ctx):
            result = await engine.check_permission(
                "user-noroles", "tenant-abc", Permission.INVESTIGATE_VIEW
            )

        assert result is False

    @pytest.mark.asyncio
    async def test_permission_granted_via_multiple_roles(self, engine):
        """Permission can be granted through any one of multiple roles."""
        # AUDIT_VIEW is in role-2 but not role-1
        rows = [
            _make_role_row("role-1", "soc_analyst", ["investigation:start"]),
            _make_role_row("role-2", "ciso", ["audit:view", "audit:export"]),
        ]
        mock_ctx, _ = _mock_tenant_connection(rows)

        with patch("sift_defender.enterprise.db.get_tenant_connection", mock_ctx):
            result = await engine.check_permission(
                "user-multi", "tenant-abc", Permission.AUDIT_VIEW
            )

        assert result is True

    @pytest.mark.asyncio
    async def test_check_all_16_permissions_for_ir_lead(self, engine):
        """IR lead should have exactly the permissions defined in DEFAULT_ROLES."""
        ir_lead_perms = [p.value for p in DEFAULT_ROLES["ir_lead"]]
        rows = [_make_role_row("role-1", "ir_lead", ir_lead_perms)]
        mock_ctx, _ = _mock_tenant_connection(rows)

        with patch("sift_defender.enterprise.db.get_tenant_connection", mock_ctx):
            # Should have these
            for perm in DEFAULT_ROLES["ir_lead"]:
                result = await engine.check_permission("user-ir", "tenant-abc", perm)
                assert result is True, f"IR lead should have {perm}"

            # Should NOT have these
            denied_perms = set(Permission) - DEFAULT_ROLES["ir_lead"]
            for perm in denied_perms:
                result = await engine.check_permission("user-ir", "tenant-abc", perm)
                assert result is False, f"IR lead should NOT have {perm}"

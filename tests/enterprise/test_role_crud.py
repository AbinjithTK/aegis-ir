"""Tests for custom role CRUD operations (RoleService).

Validates:
- create_role creates a custom role with valid permissions
- create_role rejects invalid permissions
- create_role prevents duplicate role names within a tenant
- update_role updates name and/or permissions
- update_role rejects invalid permissions
- update_role prevents duplicate names
- update_role raises RoleNotFoundError for nonexistent role
- delete_role removes custom roles
- delete_role prevents deletion of default (built-in) roles
- delete_role raises RoleNotFoundError for nonexistent role
- list_roles returns all roles for a tenant
- Permission validation enforces valid enum values

Requirements: 4.3
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sift_defender.enterprise.auth.rbac import (
    DefaultRoleDeletionError,
    DuplicateRoleNameError,
    InvalidPermissionError,
    Permission,
    RoleNotFoundError,
    RoleService,
    _row_to_role_dict,
    _validate_permissions,
)


# ─── Helpers ─────────────────────────────────────────────────────────────────


def make_role_row(
    *,
    role_id: str | None = None,
    tenant_id: str | None = None,
    name: str = "test_role",
    permissions: list[str] | None = None,
    is_default: bool = False,
    created_at: datetime | None = None,
):
    """Create a mock database row (dict-like) for a role."""
    row = MagicMock()
    row_data = {
        "id": uuid.UUID(role_id) if role_id else uuid.uuid4(),
        "tenant_id": uuid.UUID(tenant_id) if tenant_id else uuid.uuid4(),
        "name": name,
        "permissions": permissions or ["investigation:start", "investigation:view"],
        "is_default": is_default,
        "created_at": created_at or datetime.now(timezone.utc),
    }
    row.__getitem__ = lambda self, key: row_data[key]
    row.get = lambda key, default=None: row_data.get(key, default)
    return row


TENANT_ID = str(uuid.uuid4())
ROLE_ID = str(uuid.uuid4())


# ─── _validate_permissions Tests ─────────────────────────────────────────────


class TestValidatePermissions:
    """Test the _validate_permissions helper function."""

    def test_valid_permissions_returns_enum_list(self):
        result = _validate_permissions(["investigation:start", "case:create"])
        assert result == [Permission.INVESTIGATE_START, Permission.CASE_CREATE]

    def test_empty_list_is_valid(self):
        result = _validate_permissions([])
        assert result == []

    def test_all_permissions_are_valid(self):
        all_perms = [p.value for p in Permission]
        result = _validate_permissions(all_perms)
        assert len(result) == 16

    def test_invalid_permission_raises_error(self):
        with pytest.raises(InvalidPermissionError, match="Invalid permission: 'not:real'"):
            _validate_permissions(["investigation:start", "not:real"])

    def test_partial_match_is_invalid(self):
        with pytest.raises(InvalidPermissionError):
            _validate_permissions(["investigation"])

    def test_empty_string_is_invalid(self):
        with pytest.raises(InvalidPermissionError):
            _validate_permissions([""])

    def test_case_sensitive(self):
        with pytest.raises(InvalidPermissionError):
            _validate_permissions(["Investigation:Start"])


# ─── _row_to_role_dict Tests ─────────────────────────────────────────────────


class TestRowToRoleDict:
    """Test the _row_to_role_dict helper function."""

    def test_converts_row_to_dict(self):
        role_id = str(uuid.uuid4())
        created = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        row = make_role_row(
            role_id=role_id,
            name="analyst",
            permissions=["investigation:start"],
            is_default=False,
            created_at=created,
        )
        result = _row_to_role_dict(row)

        assert result["id"] == role_id
        assert result["name"] == "analyst"
        assert result["permissions"] == ["investigation:start"]
        assert result["is_default"] is False
        assert result["created_at"] == created.isoformat()

    def test_handles_none_permissions(self):
        row = make_role_row(permissions=None)
        # Override the mock to return None for permissions
        row_data = {
            "id": uuid.uuid4(),
            "name": "empty",
            "permissions": None,
            "is_default": False,
            "created_at": datetime.now(timezone.utc),
        }
        row.__getitem__ = lambda self, key: row_data[key]
        result = _row_to_role_dict(row)
        assert result["permissions"] == []

    def test_handles_none_created_at(self):
        row_data = {
            "id": uuid.uuid4(),
            "name": "test",
            "permissions": [],
            "is_default": False,
            "created_at": None,
        }
        row = MagicMock()
        row.__getitem__ = lambda self, key: row_data[key]
        result = _row_to_role_dict(row)
        assert result["created_at"] is None


# ─── RoleService.create_role Tests ───────────────────────────────────────────


class TestCreateRole:
    """Test RoleService.create_role."""

    @pytest.fixture
    def service(self):
        return RoleService()

    @pytest.mark.asyncio
    async def test_creates_custom_role_successfully(self, service):
        """create_role inserts a new role with is_default=FALSE."""
        created_at = datetime.now(timezone.utc)
        mock_row = make_role_row(
            role_id=ROLE_ID,
            name="custom_analyst",
            permissions=["investigation:start", "investigation:view"],
            is_default=False,
            created_at=created_at,
        )

        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(side_effect=[None, mock_row])  # No duplicate, then INSERT

        with patch(
            "sift_defender.enterprise.auth.rbac.get_tenant_connection"
        ) as mock_get_conn:
            mock_get_conn.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_get_conn.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await service.create_role(
                tenant_id=TENANT_ID,
                name="custom_analyst",
                permissions=["investigation:start", "investigation:view"],
            )

        assert result["name"] == "custom_analyst"
        assert result["permissions"] == ["investigation:start", "investigation:view"]
        assert result["is_default"] is False
        assert result["created_at"] == created_at.isoformat()

    @pytest.mark.asyncio
    async def test_rejects_invalid_permissions(self, service):
        """create_role raises InvalidPermissionError for bad permissions."""
        with pytest.raises(InvalidPermissionError, match="Invalid permission"):
            await service.create_role(
                tenant_id=TENANT_ID,
                name="bad_role",
                permissions=["investigation:start", "invalid:perm"],
            )

    @pytest.mark.asyncio
    async def test_rejects_duplicate_name(self, service):
        """create_role raises DuplicateRoleNameError if name exists for tenant."""
        existing_row = MagicMock()
        existing_row.__getitem__ = lambda self, key: {"id": uuid.uuid4()}[key]

        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=existing_row)

        with patch(
            "sift_defender.enterprise.auth.rbac.get_tenant_connection"
        ) as mock_get_conn:
            mock_get_conn.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_get_conn.return_value.__aexit__ = AsyncMock(return_value=False)

            with pytest.raises(DuplicateRoleNameError, match="already exists"):
                await service.create_role(
                    tenant_id=TENANT_ID,
                    name="existing_role",
                    permissions=["investigation:start"],
                )

    @pytest.mark.asyncio
    async def test_validates_all_permissions_before_db_call(self, service):
        """Validation happens before any database interaction."""
        with pytest.raises(InvalidPermissionError):
            await service.create_role(
                tenant_id=TENANT_ID,
                name="test",
                permissions=["bogus:permission"],
            )


# ─── RoleService.update_role Tests ───────────────────────────────────────────


class TestUpdateRole:
    """Test RoleService.update_role."""

    @pytest.fixture
    def service(self):
        return RoleService()

    @pytest.mark.asyncio
    async def test_updates_name_successfully(self, service):
        """update_role changes the role name."""
        created_at = datetime.now(timezone.utc)
        existing_row = make_role_row(
            role_id=ROLE_ID,
            name="old_name",
            permissions=["investigation:start"],
            is_default=False,
            created_at=created_at,
        )
        updated_row = make_role_row(
            role_id=ROLE_ID,
            name="new_name",
            permissions=["investigation:start"],
            is_default=False,
            created_at=created_at,
        )

        mock_conn = AsyncMock()
        # First call: SELECT existing, second: duplicate check, third: UPDATE RETURNING
        mock_conn.fetchrow = AsyncMock(side_effect=[existing_row, None, updated_row])

        with patch(
            "sift_defender.enterprise.auth.rbac.get_tenant_connection"
        ) as mock_get_conn:
            mock_get_conn.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_get_conn.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await service.update_role(
                role_id=ROLE_ID,
                tenant_id=TENANT_ID,
                name="new_name",
            )

        assert result["name"] == "new_name"

    @pytest.mark.asyncio
    async def test_updates_permissions_successfully(self, service):
        """update_role changes the role permissions."""
        created_at = datetime.now(timezone.utc)
        existing_row = make_role_row(
            role_id=ROLE_ID,
            name="analyst",
            permissions=["investigation:start"],
            is_default=False,
            created_at=created_at,
        )
        updated_row = make_role_row(
            role_id=ROLE_ID,
            name="analyst",
            permissions=["investigation:start", "case:create"],
            is_default=False,
            created_at=created_at,
        )

        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(side_effect=[existing_row, updated_row])

        with patch(
            "sift_defender.enterprise.auth.rbac.get_tenant_connection"
        ) as mock_get_conn:
            mock_get_conn.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_get_conn.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await service.update_role(
                role_id=ROLE_ID,
                tenant_id=TENANT_ID,
                permissions=["investigation:start", "case:create"],
            )

        assert result["permissions"] == ["investigation:start", "case:create"]

    @pytest.mark.asyncio
    async def test_raises_not_found_for_nonexistent_role(self, service):
        """update_role raises RoleNotFoundError when role doesn't exist."""
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=None)

        with patch(
            "sift_defender.enterprise.auth.rbac.get_tenant_connection"
        ) as mock_get_conn:
            mock_get_conn.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_get_conn.return_value.__aexit__ = AsyncMock(return_value=False)

            with pytest.raises(RoleNotFoundError, match="not found"):
                await service.update_role(
                    role_id=ROLE_ID,
                    tenant_id=TENANT_ID,
                    name="new_name",
                )

    @pytest.mark.asyncio
    async def test_rejects_invalid_permissions(self, service):
        """update_role raises InvalidPermissionError for bad permissions."""
        with pytest.raises(InvalidPermissionError):
            await service.update_role(
                role_id=ROLE_ID,
                tenant_id=TENANT_ID,
                permissions=["fake:permission"],
            )

    @pytest.mark.asyncio
    async def test_rejects_duplicate_name(self, service):
        """update_role raises DuplicateRoleNameError if new name conflicts."""
        existing_row = make_role_row(
            role_id=ROLE_ID,
            name="old_name",
            is_default=False,
        )
        duplicate_row = MagicMock()
        duplicate_row.__getitem__ = lambda self, key: {"id": uuid.uuid4()}[key]

        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(side_effect=[existing_row, duplicate_row])

        with patch(
            "sift_defender.enterprise.auth.rbac.get_tenant_connection"
        ) as mock_get_conn:
            mock_get_conn.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_get_conn.return_value.__aexit__ = AsyncMock(return_value=False)

            with pytest.raises(DuplicateRoleNameError, match="already exists"):
                await service.update_role(
                    role_id=ROLE_ID,
                    tenant_id=TENANT_ID,
                    name="taken_name",
                )

    @pytest.mark.asyncio
    async def test_returns_current_state_when_nothing_to_update(self, service):
        """update_role with no name or permissions returns existing role."""
        existing_row = make_role_row(
            role_id=ROLE_ID,
            name="unchanged",
            permissions=["investigation:start"],
            is_default=False,
        )

        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=existing_row)

        with patch(
            "sift_defender.enterprise.auth.rbac.get_tenant_connection"
        ) as mock_get_conn:
            mock_get_conn.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_get_conn.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await service.update_role(
                role_id=ROLE_ID,
                tenant_id=TENANT_ID,
            )

        assert result["name"] == "unchanged"


# ─── RoleService.delete_role Tests ───────────────────────────────────────────


class TestDeleteRole:
    """Test RoleService.delete_role."""

    @pytest.fixture
    def service(self):
        return RoleService()

    @pytest.mark.asyncio
    async def test_deletes_custom_role_successfully(self, service):
        """delete_role removes a non-default role and returns True."""
        existing_row = make_role_row(
            role_id=ROLE_ID,
            name="custom_role",
            is_default=False,
        )

        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=existing_row)
        mock_conn.execute = AsyncMock(return_value="DELETE 1")

        with patch(
            "sift_defender.enterprise.auth.rbac.get_tenant_connection"
        ) as mock_get_conn:
            mock_get_conn.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_get_conn.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await service.delete_role(role_id=ROLE_ID, tenant_id=TENANT_ID)

        assert result is True
        mock_conn.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_prevents_deletion_of_default_role(self, service):
        """delete_role raises DefaultRoleDeletionError for built-in roles."""
        existing_row = make_role_row(
            role_id=ROLE_ID,
            name="soc_analyst",
            is_default=True,
        )

        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=existing_row)

        with patch(
            "sift_defender.enterprise.auth.rbac.get_tenant_connection"
        ) as mock_get_conn:
            mock_get_conn.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_get_conn.return_value.__aexit__ = AsyncMock(return_value=False)

            with pytest.raises(DefaultRoleDeletionError, match="Cannot delete default role"):
                await service.delete_role(role_id=ROLE_ID, tenant_id=TENANT_ID)

        # Verify DELETE was NOT called
        mock_conn.execute.assert_not_called()

    @pytest.mark.asyncio
    async def test_raises_not_found_for_nonexistent_role(self, service):
        """delete_role raises RoleNotFoundError when role doesn't exist."""
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=None)

        with patch(
            "sift_defender.enterprise.auth.rbac.get_tenant_connection"
        ) as mock_get_conn:
            mock_get_conn.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_get_conn.return_value.__aexit__ = AsyncMock(return_value=False)

            with pytest.raises(RoleNotFoundError, match="not found"):
                await service.delete_role(role_id=ROLE_ID, tenant_id=TENANT_ID)


# ─── RoleService.list_roles Tests ────────────────────────────────────────────


class TestListRoles:
    """Test RoleService.list_roles."""

    @pytest.fixture
    def service(self):
        return RoleService()

    @pytest.mark.asyncio
    async def test_lists_all_roles_for_tenant(self, service):
        """list_roles returns both default and custom roles."""
        rows = [
            make_role_row(name="soc_analyst", is_default=True),
            make_role_row(name="ir_lead", is_default=True),
            make_role_row(name="custom_role", is_default=False),
        ]

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=rows)

        with patch(
            "sift_defender.enterprise.auth.rbac.get_tenant_connection"
        ) as mock_get_conn:
            mock_get_conn.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_get_conn.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await service.list_roles(tenant_id=TENANT_ID)

        assert len(result) == 3
        assert result[0]["name"] == "soc_analyst"
        assert result[0]["is_default"] is True
        assert result[2]["name"] == "custom_role"
        assert result[2]["is_default"] is False

    @pytest.mark.asyncio
    async def test_returns_empty_list_for_tenant_with_no_roles(self, service):
        """list_roles returns empty list if no roles exist."""
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])

        with patch(
            "sift_defender.enterprise.auth.rbac.get_tenant_connection"
        ) as mock_get_conn:
            mock_get_conn.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_get_conn.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await service.list_roles(tenant_id=TENANT_ID)

        assert result == []

    @pytest.mark.asyncio
    async def test_role_dicts_have_correct_keys(self, service):
        """Each returned role dict has id, name, permissions, is_default, created_at."""
        rows = [make_role_row(name="test_role", is_default=False)]

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=rows)

        with patch(
            "sift_defender.enterprise.auth.rbac.get_tenant_connection"
        ) as mock_get_conn:
            mock_get_conn.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_get_conn.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await service.list_roles(tenant_id=TENANT_ID)

        role = result[0]
        expected_keys = {"id", "name", "permissions", "is_default", "created_at"}
        assert set(role.keys()) == expected_keys


# ─── Integration-Style Behavior Tests ────────────────────────────────────────


class TestGranularPermissionAssignment:
    """Test that permissions can be assigned at the resource level (granular)."""

    def test_single_permission_is_valid(self):
        """A role can have a single permission."""
        result = _validate_permissions(["evidence:access"])
        assert result == [Permission.EVIDENCE_ACCESS]

    def test_all_permissions_assigned_to_single_role(self):
        """A role can have all 16 permissions."""
        all_perms = [p.value for p in Permission]
        result = _validate_permissions(all_perms)
        assert len(result) == 16

    def test_resource_level_permissions_are_independent(self):
        """Permissions are granular — having case:create doesn't imply case:manage."""
        perms = _validate_permissions(["case:create"])
        assert Permission.CASE_CREATE in perms
        assert Permission.CASE_MANAGE not in perms

    def test_mixed_resource_permissions(self):
        """A custom role can mix permissions from different resources."""
        perms = _validate_permissions([
            "investigation:start",
            "case:create",
            "playbook:view",
            "audit:view",
        ])
        assert len(perms) == 4
        assert Permission.INVESTIGATE_START in perms
        assert Permission.CASE_CREATE in perms
        assert Permission.PLAYBOOK_VIEW in perms
        assert Permission.AUDIT_VIEW in perms

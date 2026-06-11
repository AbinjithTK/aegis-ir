"""RBAC Permission definitions, default role mappings, and custom role management.

This module defines the canonical Permission enum used throughout the AEGIS-IR
enterprise platform, the DEFAULT_ROLES mapping that associates each built-in
role with its permission set, and the RoleService for custom role CRUD operations.

The permission model uses a "resource:action" format (e.g., "investigation:start")
enabling granular access control at the resource level.

Requirements: 4.1 (RBAC default roles), 4.3 (granular permissions)
"""

from __future__ import annotations

import uuid
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from sift_defender.enterprise.db import get_tenant_connection

logger = logging.getLogger(__name__)


class Permission(str, Enum):
    """All platform permissions following 'resource:action' format.

    Each permission grants access to a specific action on a specific resource type.
    Permissions are composed into roles (default or custom) and resolved at
    request time by the RBAC engine.
    """

    # Investigation permissions
    INVESTIGATE_START = "investigation:start"
    INVESTIGATE_VIEW = "investigation:view"

    # Finding permissions
    FINDING_APPROVE = "finding:approve"
    FINDING_REJECT = "finding:reject"

    # Case management permissions
    CASE_CREATE = "case:create"
    CASE_MANAGE = "case:manage"
    CASE_ASSIGN = "case:assign"

    # Playbook permissions
    PLAYBOOK_EDIT = "playbook:edit"
    PLAYBOOK_VIEW = "playbook:view"

    # Settings permissions
    SETTINGS_VIEW = "settings:view"
    SETTINGS_EDIT = "settings:edit"

    # Evidence permissions
    EVIDENCE_ACCESS = "evidence:access"

    # Audit permissions
    AUDIT_VIEW = "audit:view"
    AUDIT_EXPORT = "audit:export"

    # Reporting permissions
    REPORT_EXECUTIVE = "report:executive"

    # User management permissions
    USER_MANAGE = "user:manage"


# Default role permission sets.
# ir_lead includes ALL soc_analyst permissions plus management capabilities.
# These sets are used for seeding new tenants and for resolving effective permissions.

_SOC_ANALYST_PERMISSIONS: frozenset[Permission] = frozenset(
    {
        Permission.INVESTIGATE_START,
        Permission.INVESTIGATE_VIEW,
        Permission.FINDING_APPROVE,
        Permission.FINDING_REJECT,
        Permission.CASE_CREATE,
        Permission.PLAYBOOK_VIEW,
        Permission.EVIDENCE_ACCESS,
    }
)

_IR_LEAD_PERMISSIONS: frozenset[Permission] = _SOC_ANALYST_PERMISSIONS | frozenset(
    {
        Permission.CASE_MANAGE,
        Permission.CASE_ASSIGN,
        Permission.PLAYBOOK_EDIT,
        Permission.SETTINGS_VIEW,
        Permission.SETTINGS_EDIT,
        Permission.AUDIT_VIEW,
        Permission.USER_MANAGE,
    }
)

_CISO_PERMISSIONS: frozenset[Permission] = frozenset(
    {
        Permission.INVESTIGATE_VIEW,
        Permission.AUDIT_VIEW,
        Permission.AUDIT_EXPORT,
        Permission.REPORT_EXECUTIVE,
    }
)

DEFAULT_ROLES: dict[str, frozenset[Permission]] = {
    "soc_analyst": _SOC_ANALYST_PERMISSIONS,
    "ir_lead": _IR_LEAD_PERMISSIONS,
    "ciso": _CISO_PERMISSIONS,
}


class RBACEngine:
    """Role-Based Access Control engine with tenant isolation.

    Resolves effective permissions for a user by querying their assigned roles
    from the database and computing the union of all role permission sets.

    The engine is stateless at initialization — database connections are acquired
    per-operation using the tenant-scoped connection manager.

    Requirements: 4.1 (RBAC default roles), 4.2 (permission enforcement)
    """

    def __init__(self) -> None:
        """Initialize the RBAC engine.

        No database session is required at init time. Connections are acquired
        on demand via get_tenant_connection for each permission check.
        """

    async def _resolve_roles(
        self, user_id: str, tenant_id: str
    ) -> list[dict[str, object]]:
        """Resolve all role records assigned to a user within a tenant.

        Queries the user_roles JOIN roles tables to retrieve the full role
        definitions (id, name, permissions array) for the given user.

        Args:
            user_id: UUID string identifying the user.
            tenant_id: UUID string identifying the tenant scope.

        Returns:
            A list of role record dicts, each containing at minimum:
                - id: UUID of the role
                - name: role name string
                - permissions: list of permission strings
        """
        from sift_defender.enterprise.db import get_tenant_connection

        async with get_tenant_connection(tenant_id) as conn:
            rows = await conn.fetch(
                """
                SELECT r.id, r.name, r.permissions
                FROM user_roles ur
                JOIN roles r ON ur.role_id = r.id
                WHERE ur.user_id = $1 AND ur.tenant_id = $2
                """,
                user_id,
                tenant_id,
            )

        return [dict(row) for row in rows]

    async def get_effective_permissions(
        self, user_id: str, tenant_id: str
    ) -> set[Permission]:
        """Resolve all permissions from a user's assigned roles.

        Fetches all roles assigned to the user, collects their permission
        arrays, and returns the union as a set of Permission enum instances.
        Multiple roles are supported — permissions are merged (union).

        Args:
            user_id: UUID string identifying the user.
            tenant_id: UUID string identifying the tenant scope.

        Returns:
            A set of Permission enum instances representing all permissions
            the user holds across all their assigned roles.
        """
        roles = await self._resolve_roles(user_id, tenant_id)

        effective: set[Permission] = set()
        for role in roles:
            permissions_list = role["permissions"]
            for perm_str in permissions_list:
                try:
                    effective.add(Permission(perm_str))
                except ValueError:
                    # Skip unknown permission strings that don't match the enum.
                    # This handles forward-compatibility if DB has permissions
                    # not yet defined in code.
                    continue

        return effective

    async def check_permission(
        self, user_id: str, tenant_id: str, permission: Permission
    ) -> bool:
        """Check if a user has a specific permission via their assigned roles.

        Resolves the user's effective permission set and checks membership.

        Args:
            user_id: UUID string identifying the user.
            tenant_id: UUID string identifying the tenant scope.
            permission: The Permission enum value to check.

        Returns:
            True if the user has the permission, False otherwise.
        """
        effective = await self.get_effective_permissions(user_id, tenant_id)
        return permission in effective


# ─── Exceptions ──────────────────────────────────────────────────────────────


class RoleNotFoundError(Exception):
    """Raised when a role cannot be found."""

    pass


class DuplicateRoleNameError(Exception):
    """Raised when creating/updating a role with a name that already exists for the tenant."""

    pass


class DefaultRoleDeletionError(Exception):
    """Raised when attempting to delete a default (built-in) role."""

    pass


class InvalidPermissionError(Exception):
    """Raised when an invalid permission string is provided."""

    pass


# ─── RoleService ─────────────────────────────────────────────────────────────


def _validate_permissions(permissions: list[str]) -> list[Permission]:
    """Validate that all permission strings are valid Permission enum values.

    Args:
        permissions: List of permission strings to validate.

    Returns:
        List of validated Permission enum members.

    Raises:
        InvalidPermissionError: If any permission string is not a valid Permission value.
    """
    valid_values = {p.value for p in Permission}
    validated: list[Permission] = []

    for perm_str in permissions:
        if perm_str not in valid_values:
            raise InvalidPermissionError(
                f"Invalid permission: '{perm_str}'. "
                f"Valid permissions: {sorted(valid_values)}"
            )
        validated.append(Permission(perm_str))

    return validated


def _row_to_role_dict(row) -> dict:
    """Convert a database row (asyncpg Record) to a role dictionary.

    Returns:
        Dict with keys: id, name, permissions, is_default, created_at
    """
    return {
        "id": str(row["id"]),
        "name": row["name"],
        "permissions": list(row["permissions"]) if row["permissions"] else [],
        "is_default": row["is_default"],
        "created_at": row["created_at"].isoformat() if row["created_at"] else None,
    }


class RoleService:
    """Service for managing custom roles with granular permissions.

    Provides CRUD operations for roles within a tenant, enforcing:
    - Valid Permission enum values for all permission assignments
    - Unique role names within a tenant
    - Protection of default (built-in) roles from deletion

    Requirements: 4.3 (custom role creation with granular permissions)
    """

    async def create_role(
        self,
        tenant_id: str,
        name: str,
        permissions: list[str],
    ) -> dict:
        """Create a custom role with granular permission assignment.

        Args:
            tenant_id: The tenant ID to scope the role to.
            name: The display name for the role. Must be unique within the tenant.
            permissions: List of permission strings (e.g., ["investigation:start"]).

        Returns:
            Dict with keys: id, name, permissions, is_default, created_at

        Raises:
            InvalidPermissionError: If any permission is not a valid Permission value.
            DuplicateRoleNameError: If a role with the same name already exists for this tenant.
        """
        # Validate permissions
        _validate_permissions(permissions)

        role_id = str(uuid.uuid4())

        async with get_tenant_connection(tenant_id) as conn:
            # Check for duplicate name within tenant
            existing = await conn.fetchrow(
                "SELECT id FROM roles WHERE tenant_id = $1 AND name = $2",
                uuid.UUID(tenant_id),
                name,
            )
            if existing:
                raise DuplicateRoleNameError(
                    f"A role named '{name}' already exists for this tenant."
                )

            row = await conn.fetchrow(
                """
                INSERT INTO roles (id, tenant_id, name, permissions, is_default, created_at, updated_at)
                VALUES ($1, $2, $3, $4, FALSE, NOW(), NOW())
                RETURNING id, tenant_id, name, permissions, is_default, created_at
                """,
                uuid.UUID(role_id),
                uuid.UUID(tenant_id),
                name,
                permissions,
            )

        logger.info(
            "Created custom role '%s' (id=%s) for tenant %s with %d permissions",
            name,
            role_id,
            tenant_id,
            len(permissions),
        )
        return _row_to_role_dict(row)

    async def update_role(
        self,
        role_id: str,
        tenant_id: str,
        name: Optional[str] = None,
        permissions: Optional[list[str]] = None,
    ) -> dict:
        """Update a custom role's name and/or permissions.

        Args:
            role_id: The UUID of the role to update.
            tenant_id: The tenant ID for scoping.
            name: New name for the role (optional).
            permissions: New permission list (optional).

        Returns:
            Dict with updated role data: id, name, permissions, is_default, created_at

        Raises:
            RoleNotFoundError: If the role does not exist for this tenant.
            InvalidPermissionError: If any permission is not a valid Permission value.
            DuplicateRoleNameError: If the new name conflicts with an existing role.
        """
        if permissions is not None:
            _validate_permissions(permissions)

        async with get_tenant_connection(tenant_id) as conn:
            # Fetch existing role
            existing = await conn.fetchrow(
                "SELECT id, name, permissions, is_default, created_at FROM roles "
                "WHERE id = $1 AND tenant_id = $2",
                uuid.UUID(role_id),
                uuid.UUID(tenant_id),
            )
            if not existing:
                raise RoleNotFoundError(
                    f"Role '{role_id}' not found for tenant '{tenant_id}'."
                )

            # Check for duplicate name if name is being changed
            if name is not None and name != existing["name"]:
                duplicate = await conn.fetchrow(
                    "SELECT id FROM roles WHERE tenant_id = $1 AND name = $2 AND id != $3",
                    uuid.UUID(tenant_id),
                    name,
                    uuid.UUID(role_id),
                )
                if duplicate:
                    raise DuplicateRoleNameError(
                        f"A role named '{name}' already exists for this tenant."
                    )

            # Build update query dynamically based on provided fields
            updates = []
            params = []
            param_idx = 1

            if name is not None:
                updates.append(f"name = ${param_idx}")
                params.append(name)
                param_idx += 1

            if permissions is not None:
                updates.append(f"permissions = ${param_idx}")
                params.append(permissions)
                param_idx += 1

            if not updates:
                # Nothing to update, return current state
                return _row_to_role_dict(existing)

            updates.append(f"updated_at = ${param_idx}")
            params.append(datetime.now(timezone.utc))
            param_idx += 1

            # Add WHERE clause params
            params.append(uuid.UUID(role_id))
            params.append(uuid.UUID(tenant_id))

            query = (
                f"UPDATE roles SET {', '.join(updates)} "
                f"WHERE id = ${param_idx} AND tenant_id = ${param_idx + 1} "
                f"RETURNING id, tenant_id, name, permissions, is_default, created_at"
            )

            row = await conn.fetchrow(query, *params)

        logger.info("Updated role '%s' for tenant %s", role_id, tenant_id)
        return _row_to_role_dict(row)

    async def delete_role(self, role_id: str, tenant_id: str) -> bool:
        """Delete a custom role.

        Default (built-in) roles cannot be deleted.

        Args:
            role_id: The UUID of the role to delete.
            tenant_id: The tenant ID for scoping.

        Returns:
            True if the role was successfully deleted.

        Raises:
            RoleNotFoundError: If the role does not exist for this tenant.
            DefaultRoleDeletionError: If the role is a default (built-in) role.
        """
        async with get_tenant_connection(tenant_id) as conn:
            # Fetch the role to check if it exists and whether it's a default
            existing = await conn.fetchrow(
                "SELECT id, name, is_default FROM roles WHERE id = $1 AND tenant_id = $2",
                uuid.UUID(role_id),
                uuid.UUID(tenant_id),
            )
            if not existing:
                raise RoleNotFoundError(
                    f"Role '{role_id}' not found for tenant '{tenant_id}'."
                )

            if existing["is_default"]:
                raise DefaultRoleDeletionError(
                    f"Cannot delete default role '{existing['name']}'. "
                    "Default roles are system-defined and cannot be removed."
                )

            await conn.execute(
                "DELETE FROM roles WHERE id = $1 AND tenant_id = $2",
                uuid.UUID(role_id),
                uuid.UUID(tenant_id),
            )

        logger.info(
            "Deleted role '%s' (name='%s') for tenant %s",
            role_id,
            existing["name"],
            tenant_id,
        )
        return True

    async def list_roles(self, tenant_id: str) -> list[dict]:
        """List all roles (default and custom) for a tenant.

        Args:
            tenant_id: The tenant ID to list roles for.

        Returns:
            List of role dicts with keys: id, name, permissions, is_default, created_at
        """
        async with get_tenant_connection(tenant_id) as conn:
            rows = await conn.fetch(
                "SELECT id, name, permissions, is_default, created_at "
                "FROM roles WHERE tenant_id = $1 ORDER BY is_default DESC, name ASC",
                uuid.UUID(tenant_id),
            )

        return [_row_to_role_dict(row) for row in rows]

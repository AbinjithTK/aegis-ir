"""002 - Seed Default Roles: soc_analyst, ir_lead, ciso with permission sets.

Provides a reusable seed function that inserts the three default RBAC roles
for a given tenant. The upgrade migration demonstrates usage by creating a
'system' tenant placeholder and seeding its roles.

The seed_default_roles() function is designed to be called during tenant
provisioning to bootstrap new tenants with the standard role set.

Requirements: 4.1 (RBAC default roles)
"""

from __future__ import annotations

import textwrap
from typing import Any

# Alembic revision identifiers
revision = "002_seed_default_roles"
down_revision = "001_initial_schema"
branch_labels = None
depends_on = None

# Default roles and their permission sets as defined in the design document.
# Each role maps to a list of permission strings following the format:
#   "resource:action"
DEFAULT_ROLES: dict[str, list[str]] = {
    "soc_analyst": [
        "investigation:start",
        "investigation:view",
        "finding:approve",
        "finding:reject",
        "case:create",
        "playbook:view",
        "evidence:access",
    ],
    "ir_lead": [
        # All SOC_Analyst permissions plus management capabilities
        "investigation:start",
        "investigation:view",
        "finding:approve",
        "finding:reject",
        "case:create",
        "case:manage",
        "case:assign",
        "playbook:view",
        "playbook:edit",
        "settings:view",
        "settings:edit",
        "audit:view",
        "evidence:access",
        "user:manage",
    ],
    "ciso": [
        "investigation:view",
        "audit:view",
        "audit:export",
        "report:executive",
    ],
}


def seed_default_roles(conn: Any, tenant_id: str) -> list[str]:
    """Insert the three default roles for a given tenant.

    This function is idempotent — it uses INSERT ... ON CONFLICT DO NOTHING
    so that re-running it for an existing tenant will not duplicate roles.

    Args:
        conn: A database connection object supporting execute() (asyncpg or
              Alembic migration connection).
        tenant_id: The UUID string of the tenant to seed roles for.

    Returns:
        A list of role names that were inserted (or already existed).
    """
    inserted_roles: list[str] = []

    for role_name, permissions in DEFAULT_ROLES.items():
        # Format permissions as a PostgreSQL TEXT[] literal
        permissions_array = _format_pg_array(permissions)

        stmt = textwrap.dedent(f"""\
            INSERT INTO roles (id, tenant_id, name, permissions, is_default)
            VALUES (
                uuid_generate_v4(),
                '{tenant_id}'::uuid,
                '{role_name}',
                '{permissions_array}',
                TRUE
            )
            ON CONFLICT (tenant_id, name) DO NOTHING;
        """).strip()

        conn.execute(stmt)
        inserted_roles.append(role_name)

    return inserted_roles


def _format_pg_array(items: list[str]) -> str:
    """Format a Python list of strings as a PostgreSQL TEXT[] literal.

    Example:
        ["a", "b"] -> '{a,b}'
        ["investigation:start", "case:create"] -> '{investigation:start,case:create}'
    """
    inner = ",".join(items)
    return "{" + inner + "}"


def upgrade(conn: Any) -> None:
    """Apply migration: seed default roles for all existing tenants.

    If no tenants exist yet, this migration is a no-op for data but still
    exposes the seed_default_roles function for use during tenant provisioning.

    For any existing tenants, this inserts the three default roles.
    """
    # Seed default roles for all existing tenants
    # This handles the case where tenants were created before this migration
    for role_name, permissions in DEFAULT_ROLES.items():
        permissions_array = _format_pg_array(permissions)

        stmt = textwrap.dedent(f"""\
            INSERT INTO roles (id, tenant_id, name, permissions, is_default)
            SELECT
                uuid_generate_v4(),
                t.id,
                '{role_name}',
                '{permissions_array}',
                TRUE
            FROM tenants t
            WHERE NOT EXISTS (
                SELECT 1 FROM roles r
                WHERE r.tenant_id = t.id AND r.name = '{role_name}'
            );
        """).strip()

        conn.execute(stmt)


def downgrade(conn: Any) -> None:
    """Revert migration: remove all default roles across all tenants."""
    conn.execute(
        "DELETE FROM roles WHERE is_default = TRUE AND name IN ('soc_analyst', 'ir_lead', 'ciso');"
    )

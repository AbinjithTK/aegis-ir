"""005 - IdP Group Mappings: table for mapping external IdP groups to internal roles.

Creates the idp_group_mappings table with:
- UUID primary key
- Foreign key to tenants(id)
- IdP group name (TEXT) and role name (TEXT)
- UNIQUE constraint on (tenant_id, idp_group, role_name) to prevent duplicates
- Index on tenant_id for efficient tenant-scoped lookups
- Timestamp for audit trail

Requirements: 4.4 (SAML/OIDC group-to-role mapping)
"""

from __future__ import annotations

import textwrap

# Alembic revision identifiers
revision = "005_idp_group_mappings"
down_revision = "004_audit_log"
branch_labels = None
depends_on = None


def upgrade(conn) -> None:
    """Apply migration: create idp_group_mappings table."""
    statements = [
        # ------------------------------------------------------------------
        # IdP Group Mappings table — maps external identity provider groups
        # (from SAML assertions or OIDC claims) to internal role names per tenant
        # ------------------------------------------------------------------
        """
        CREATE TABLE IF NOT EXISTS idp_group_mappings (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            idp_group TEXT NOT NULL,
            role_name TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CONSTRAINT uq_idp_group_mappings_tenant_group_role
                UNIQUE (tenant_id, idp_group, role_name)
        );
        """,
        # ------------------------------------------------------------------
        # Index on tenant_id for efficient tenant-scoped queries
        # ------------------------------------------------------------------
        """
        CREATE INDEX IF NOT EXISTS idx_idp_group_mappings_tenant_id
            ON idp_group_mappings(tenant_id);
        """,
        # ------------------------------------------------------------------
        # Index on (tenant_id, idp_group) for fast group resolution lookups
        # ------------------------------------------------------------------
        """
        CREATE INDEX IF NOT EXISTS idx_idp_group_mappings_tenant_group
            ON idp_group_mappings(tenant_id, idp_group);
        """,
    ]

    for stmt in statements:
        conn.execute(textwrap.dedent(stmt).strip())


def downgrade(conn) -> None:
    """Revert migration: drop idp_group_mappings table."""
    statements = [
        "DROP TABLE IF EXISTS idp_group_mappings CASCADE;",
    ]

    for stmt in statements:
        conn.execute(stmt)

"""001 - Initial Schema: tenants, users, roles, user_roles tables.

Creates the foundational multi-tenant RBAC schema for AEGIS-IR Enterprise Platform.

Requirements: 4.1 (RBAC default roles), 4.3 (custom roles), 8.1 (tenant isolation)
"""

from __future__ import annotations

import textwrap

# Alembic revision identifiers
revision = "001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade(conn) -> None:
    """Apply migration: create tenants, users, roles, and user_roles tables."""
    statements = [
        # ------------------------------------------------------------------
        # Enable UUID generation extension (idempotent)
        # ------------------------------------------------------------------
        """
        CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
        """,
        # ------------------------------------------------------------------
        # Tenants table — top-level organizational unit for multi-tenant isolation
        # ------------------------------------------------------------------
        """
        CREATE TABLE IF NOT EXISTS tenants (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            name TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        """,
        # ------------------------------------------------------------------
        # Users table — platform users with tenant scoping
        # Includes password_hash for local auth and external_id for IdP mapping
        # ------------------------------------------------------------------
        """
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            email TEXT NOT NULL,
            password_hash TEXT,
            external_id TEXT,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CONSTRAINT uq_users_tenant_email UNIQUE (tenant_id, email)
        );
        """,
        # ------------------------------------------------------------------
        # Roles table — RBAC roles per tenant (default + custom)
        # permissions is a TEXT[] array of permission strings
        # ------------------------------------------------------------------
        """
        CREATE TABLE IF NOT EXISTS roles (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            permissions TEXT[] NOT NULL DEFAULT '{}',
            is_default BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CONSTRAINT uq_roles_tenant_name UNIQUE (tenant_id, name)
        );
        """,
        # ------------------------------------------------------------------
        # User-Role junction table — many-to-many assignment
        # ------------------------------------------------------------------
        """
        CREATE TABLE IF NOT EXISTS user_roles (
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
            assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (user_id, role_id)
        );
        """,
        # ------------------------------------------------------------------
        # Indexes for performance on tenant-scoped queries
        # ------------------------------------------------------------------
        """
        CREATE INDEX IF NOT EXISTS idx_users_tenant_id
            ON users(tenant_id);
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_users_external_id
            ON users(external_id)
            WHERE external_id IS NOT NULL;
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_roles_tenant_id
            ON roles(tenant_id);
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_roles_tenant_default
            ON roles(tenant_id, is_default)
            WHERE is_default = TRUE;
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_user_roles_role_id
            ON user_roles(role_id);
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_user_roles_user_id
            ON user_roles(user_id);
        """,
    ]

    for stmt in statements:
        conn.execute(textwrap.dedent(stmt).strip())


def downgrade(conn) -> None:
    """Revert migration: drop tables in reverse dependency order."""
    statements = [
        "DROP TABLE IF EXISTS user_roles CASCADE;",
        "DROP TABLE IF EXISTS roles CASCADE;",
        "DROP TABLE IF EXISTS users CASCADE;",
        "DROP TABLE IF EXISTS tenants CASCADE;",
    ]

    for stmt in statements:
        conn.execute(stmt)

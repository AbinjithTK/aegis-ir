"""003 - Row-Level Security: Enable RLS on all tenant-scoped tables.

Adds Row-Level Security policies to enforce tenant isolation at the database
level. Creates an `app_user` role with limited privileges so that RLS is always
enforced (FORCE ROW LEVEL SECURITY prevents even table owners from bypassing
policies when connected as app_user).

For user_roles, a `tenant_id` column is added (denormalization) so that the
RLS policy can filter directly without a sub-select join to users.

Requirements: 8.1 (tenant isolation), 8.2 (session-based tenant scoping)
"""

from __future__ import annotations

import textwrap

# Alembic revision identifiers
revision = "003_row_level_security"
down_revision = "001_initial_schema"
branch_labels = None
depends_on = None


def upgrade(conn) -> None:
    """Apply migration: enable RLS and create tenant isolation policies."""
    statements = [
        # ------------------------------------------------------------------
        # Create app_user role (IF NOT EXISTS) for application connections.
        # RLS is enforced for this role on all tenant-scoped tables.
        # ------------------------------------------------------------------
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_user') THEN
                CREATE ROLE app_user NOLOGIN;
            END IF;
        END
        $$;
        """,
        # ------------------------------------------------------------------
        # Grant DML privileges to app_user on tenant-scoped tables
        # ------------------------------------------------------------------
        """
        GRANT SELECT, INSERT, UPDATE, DELETE ON users TO app_user;
        """,
        """
        GRANT SELECT, INSERT, UPDATE, DELETE ON roles TO app_user;
        """,
        """
        GRANT SELECT, INSERT, UPDATE, DELETE ON user_roles TO app_user;
        """,
        # ------------------------------------------------------------------
        # Add tenant_id to user_roles for direct RLS filtering
        # (denormalization avoids sub-select in policy)
        # ------------------------------------------------------------------
        """
        ALTER TABLE user_roles
            ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE;
        """,
        # ------------------------------------------------------------------
        # Backfill tenant_id on user_roles from the users table
        # ------------------------------------------------------------------
        """
        UPDATE user_roles
        SET tenant_id = users.tenant_id
        FROM users
        WHERE user_roles.user_id = users.id
          AND user_roles.tenant_id IS NULL;
        """,
        # ------------------------------------------------------------------
        # Make tenant_id NOT NULL after backfill
        # ------------------------------------------------------------------
        """
        ALTER TABLE user_roles
            ALTER COLUMN tenant_id SET NOT NULL;
        """,
        # ------------------------------------------------------------------
        # Create index on user_roles.tenant_id for RLS performance
        # ------------------------------------------------------------------
        """
        CREATE INDEX IF NOT EXISTS idx_user_roles_tenant_id
            ON user_roles(tenant_id);
        """,
        # ------------------------------------------------------------------
        # Enable RLS on users table
        # ------------------------------------------------------------------
        """
        ALTER TABLE users ENABLE ROW LEVEL SECURITY;
        """,
        """
        ALTER TABLE users FORCE ROW LEVEL SECURITY;
        """,
        """
        CREATE POLICY tenant_isolation_users ON users
            USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
        """,
        # ------------------------------------------------------------------
        # Enable RLS on roles table
        # ------------------------------------------------------------------
        """
        ALTER TABLE roles ENABLE ROW LEVEL SECURITY;
        """,
        """
        ALTER TABLE roles FORCE ROW LEVEL SECURITY;
        """,
        """
        CREATE POLICY tenant_isolation_roles ON roles
            USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
        """,
        # ------------------------------------------------------------------
        # Enable RLS on user_roles table
        # ------------------------------------------------------------------
        """
        ALTER TABLE user_roles ENABLE ROW LEVEL SECURITY;
        """,
        """
        ALTER TABLE user_roles FORCE ROW LEVEL SECURITY;
        """,
        """
        CREATE POLICY tenant_isolation_user_roles ON user_roles
            USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
        """,
    ]

    for stmt in statements:
        conn.execute(textwrap.dedent(stmt).strip())


def downgrade(conn) -> None:
    """Revert migration: drop RLS policies, disable RLS, drop app_user grants."""
    statements = [
        # Drop policies
        "DROP POLICY IF EXISTS tenant_isolation_user_roles ON user_roles;",
        "DROP POLICY IF EXISTS tenant_isolation_roles ON roles;",
        "DROP POLICY IF EXISTS tenant_isolation_users ON users;",
        # Disable RLS
        "ALTER TABLE user_roles DISABLE ROW LEVEL SECURITY;",
        "ALTER TABLE roles DISABLE ROW LEVEL SECURITY;",
        "ALTER TABLE users DISABLE ROW LEVEL SECURITY;",
        # Remove tenant_id from user_roles
        "DROP INDEX IF EXISTS idx_user_roles_tenant_id;",
        "ALTER TABLE user_roles DROP COLUMN IF EXISTS tenant_id;",
        # Revoke grants
        "REVOKE SELECT, INSERT, UPDATE, DELETE ON users FROM app_user;",
        "REVOKE SELECT, INSERT, UPDATE, DELETE ON roles FROM app_user;",
        "REVOKE SELECT, INSERT, UPDATE, DELETE ON user_roles FROM app_user;",
        # Drop role
        "DROP ROLE IF EXISTS app_user;",
    ]

    for stmt in statements:
        conn.execute(stmt)

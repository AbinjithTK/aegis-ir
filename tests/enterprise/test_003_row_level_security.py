"""Tests for 003_row_level_security migration.

Validates that the migration produces correct SQL for:
- Creating app_user role with DML grants on tenant-scoped tables
- Adding tenant_id column to user_roles (denormalization for RLS)
- Enabling and forcing RLS on users, roles, user_roles
- Creating tenant_isolation policies using current_setting('app.current_tenant')
- Downgrade drops policies, disables RLS, and reverts schema changes

Requirements: 8.1, 8.2
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

# Load migration module via importlib (same pattern as test_001)
_migration_path = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "sift_defender"
    / "enterprise"
    / "migrations"
    / "versions"
    / "003_row_level_security.py"
)
_spec = importlib.util.spec_from_file_location("migration_003", _migration_path)
_migration = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_migration)

upgrade = _migration.upgrade
downgrade = _migration.downgrade
revision = _migration.revision


class FakeConnection:
    """Records executed SQL statements for assertion."""

    def __init__(self):
        self.statements: list[str] = []

    def execute(self, sql: str) -> None:
        self.statements.append(sql)


class TestMigrationMetadata:
    """Test migration revision metadata."""

    def test_revision_id(self):
        assert revision == "003_row_level_security"

    def test_down_revision(self):
        assert _migration.down_revision == "001_initial_schema"

    def test_module_has_upgrade_and_downgrade(self):
        assert callable(upgrade)
        assert callable(downgrade)


class TestUpgradeAppUserRole:
    """Test that upgrade creates app_user role and grants."""

    @pytest.fixture
    def conn(self):
        fake = FakeConnection()
        upgrade(fake)
        return fake

    @pytest.fixture
    def all_sql(self, conn):
        return "\n".join(conn.statements)

    def test_creates_app_user_role(self, all_sql):
        assert "CREATE ROLE app_user" in all_sql

    def test_app_user_creation_is_idempotent(self, all_sql):
        # Uses IF NOT EXISTS check via DO block
        assert "IF NOT EXISTS" in all_sql
        assert "pg_roles" in all_sql

    def test_grants_dml_on_users(self, all_sql):
        assert "GRANT SELECT, INSERT, UPDATE, DELETE ON users TO app_user" in all_sql

    def test_grants_dml_on_roles(self, all_sql):
        assert "GRANT SELECT, INSERT, UPDATE, DELETE ON roles TO app_user" in all_sql

    def test_grants_dml_on_user_roles(self, all_sql):
        assert "GRANT SELECT, INSERT, UPDATE, DELETE ON user_roles TO app_user" in all_sql


class TestUpgradeUserRolesTenantId:
    """Test that upgrade adds tenant_id to user_roles for RLS."""

    @pytest.fixture
    def conn(self):
        fake = FakeConnection()
        upgrade(fake)
        return fake

    @pytest.fixture
    def all_sql(self, conn):
        return "\n".join(conn.statements)

    def test_adds_tenant_id_column_to_user_roles(self, all_sql):
        assert "ALTER TABLE user_roles" in all_sql
        assert "ADD COLUMN" in all_sql
        assert "tenant_id UUID" in all_sql

    def test_tenant_id_references_tenants(self, all_sql):
        # The ADD COLUMN statement should reference tenants(id)
        assert "REFERENCES tenants(id)" in all_sql

    def test_backfills_tenant_id_from_users(self, all_sql):
        assert "UPDATE user_roles" in all_sql
        assert "SET tenant_id = users.tenant_id" in all_sql
        assert "FROM users" in all_sql
        assert "user_roles.user_id = users.id" in all_sql

    def test_sets_tenant_id_not_null(self, all_sql):
        assert "ALTER COLUMN tenant_id SET NOT NULL" in all_sql

    def test_creates_tenant_id_index_on_user_roles(self, all_sql):
        assert "idx_user_roles_tenant_id" in all_sql
        assert "ON user_roles(tenant_id)" in all_sql


class TestUpgradeRLSUsers:
    """Test RLS is enabled and policy created on users table."""

    @pytest.fixture
    def conn(self):
        fake = FakeConnection()
        upgrade(fake)
        return fake

    @pytest.fixture
    def all_sql(self, conn):
        return "\n".join(conn.statements)

    def test_enables_rls_on_users(self, all_sql):
        assert "ALTER TABLE users ENABLE ROW LEVEL SECURITY" in all_sql

    def test_forces_rls_on_users(self, all_sql):
        assert "ALTER TABLE users FORCE ROW LEVEL SECURITY" in all_sql

    def test_creates_tenant_isolation_policy_on_users(self, all_sql):
        assert "CREATE POLICY tenant_isolation_users ON users" in all_sql

    def test_users_policy_uses_current_setting(self, all_sql):
        # Policy should reference app.current_tenant
        assert "current_setting('app.current_tenant', true)::uuid" in all_sql


class TestUpgradeRLSRoles:
    """Test RLS is enabled and policy created on roles table."""

    @pytest.fixture
    def conn(self):
        fake = FakeConnection()
        upgrade(fake)
        return fake

    @pytest.fixture
    def all_sql(self, conn):
        return "\n".join(conn.statements)

    def test_enables_rls_on_roles(self, all_sql):
        assert "ALTER TABLE roles ENABLE ROW LEVEL SECURITY" in all_sql

    def test_forces_rls_on_roles(self, all_sql):
        assert "ALTER TABLE roles FORCE ROW LEVEL SECURITY" in all_sql

    def test_creates_tenant_isolation_policy_on_roles(self, all_sql):
        assert "CREATE POLICY tenant_isolation_roles ON roles" in all_sql


class TestUpgradeRLSUserRoles:
    """Test RLS is enabled and policy created on user_roles table."""

    @pytest.fixture
    def conn(self):
        fake = FakeConnection()
        upgrade(fake)
        return fake

    @pytest.fixture
    def all_sql(self, conn):
        return "\n".join(conn.statements)

    def test_enables_rls_on_user_roles(self, all_sql):
        assert "ALTER TABLE user_roles ENABLE ROW LEVEL SECURITY" in all_sql

    def test_forces_rls_on_user_roles(self, all_sql):
        assert "ALTER TABLE user_roles FORCE ROW LEVEL SECURITY" in all_sql

    def test_creates_tenant_isolation_policy_on_user_roles(self, all_sql):
        assert "CREATE POLICY tenant_isolation_user_roles ON user_roles" in all_sql


class TestUpgradeAllTablesHaveRLS:
    """Verify all tenant-scoped tables get RLS (not tenants itself)."""

    @pytest.fixture
    def conn(self):
        fake = FakeConnection()
        upgrade(fake)
        return fake

    @pytest.fixture
    def all_sql(self, conn):
        return "\n".join(conn.statements)

    def test_rls_not_on_tenants_table(self, all_sql):
        # tenants is the root table — RLS should NOT be on it
        assert "ENABLE ROW LEVEL SECURITY" in all_sql
        # Ensure no policy references the tenants table directly
        assert "tenant_isolation_tenants" not in all_sql

    def test_all_policies_use_same_setting(self, all_sql):
        # All three policies use the same current_setting expression
        count = all_sql.count("current_setting('app.current_tenant', true)::uuid")
        assert count == 3, f"Expected 3 policy USING clauses, found {count}"

    def test_all_tables_force_rls(self, all_sql):
        # Should have FORCE on all three tables
        force_count = all_sql.count("FORCE ROW LEVEL SECURITY")
        assert force_count == 3, f"Expected 3 FORCE statements, found {force_count}"

    def test_all_tables_enable_rls(self, all_sql):
        enable_count = all_sql.count("ENABLE ROW LEVEL SECURITY")
        assert enable_count == 3, f"Expected 3 ENABLE statements, found {enable_count}"


class TestDowngradeMigration:
    """Test downgrade() reverts all RLS changes."""

    @pytest.fixture
    def conn(self):
        fake = FakeConnection()
        downgrade(fake)
        return fake

    @pytest.fixture
    def all_sql(self, conn):
        return "\n".join(conn.statements)

    def test_drops_all_policies(self, all_sql):
        assert "DROP POLICY IF EXISTS tenant_isolation_user_roles ON user_roles" in all_sql
        assert "DROP POLICY IF EXISTS tenant_isolation_roles ON roles" in all_sql
        assert "DROP POLICY IF EXISTS tenant_isolation_users ON users" in all_sql

    def test_disables_rls_on_all_tables(self, all_sql):
        assert "ALTER TABLE user_roles DISABLE ROW LEVEL SECURITY" in all_sql
        assert "ALTER TABLE roles DISABLE ROW LEVEL SECURITY" in all_sql
        assert "ALTER TABLE users DISABLE ROW LEVEL SECURITY" in all_sql

    def test_drops_tenant_id_from_user_roles(self, all_sql):
        assert "ALTER TABLE user_roles DROP COLUMN IF EXISTS tenant_id" in all_sql

    def test_drops_tenant_id_index(self, all_sql):
        assert "DROP INDEX IF EXISTS idx_user_roles_tenant_id" in all_sql

    def test_revokes_grants(self, all_sql):
        assert "REVOKE SELECT, INSERT, UPDATE, DELETE ON users FROM app_user" in all_sql
        assert "REVOKE SELECT, INSERT, UPDATE, DELETE ON roles FROM app_user" in all_sql
        assert "REVOKE SELECT, INSERT, UPDATE, DELETE ON user_roles FROM app_user" in all_sql

    def test_drops_app_user_role(self, all_sql):
        assert "DROP ROLE IF EXISTS app_user" in all_sql

    def test_downgrade_statement_count(self, conn):
        # 3 drop policies + 3 disable RLS + 1 drop index + 1 drop column
        # + 3 revoke grants + 1 drop role = 12
        assert len(conn.statements) == 12

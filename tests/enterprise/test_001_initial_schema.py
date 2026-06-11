"""Tests for 001_initial_schema migration.

Validates that the migration produces correct SQL DDL for:
- tenants, users, roles, user_roles tables
- UUID primary keys and foreign key constraints
- Unique constraints: (tenant_id, email) on users, (tenant_id, name) on roles
- Indexes on tenant_id columns and other lookup fields
- Upgrade and downgrade are callable without error

Requirements: 4.1, 4.3, 8.1
"""

from __future__ import annotations

import importlib
import importlib.util
import re
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Load migration module with numeric prefix via importlib
_migration_path = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "sift_defender"
    / "enterprise"
    / "migrations"
    / "versions"
    / "001_initial_schema.py"
)
_spec = importlib.util.spec_from_file_location("migration_001", _migration_path)
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
        assert revision == "001_initial_schema"

    def test_module_has_upgrade_and_downgrade(self):
        assert callable(upgrade)
        assert callable(downgrade)


class TestUpgradeMigration:
    """Test upgrade() produces correct schema DDL."""

    @pytest.fixture
    def conn(self):
        fake = FakeConnection()
        upgrade(fake)
        return fake

    @pytest.fixture
    def all_sql(self, conn):
        return "\n".join(conn.statements)

    def test_creates_uuid_extension(self, all_sql):
        assert 'CREATE EXTENSION IF NOT EXISTS "uuid-ossp"' in all_sql

    def test_creates_tenants_table(self, all_sql):
        assert "CREATE TABLE IF NOT EXISTS tenants" in all_sql
        assert "id UUID PRIMARY KEY" in all_sql
        assert "name TEXT NOT NULL" in all_sql
        assert "created_at TIMESTAMPTZ" in all_sql

    def test_creates_users_table(self, all_sql):
        assert "CREATE TABLE IF NOT EXISTS users" in all_sql
        assert "tenant_id UUID NOT NULL REFERENCES tenants(id)" in all_sql
        assert "email TEXT NOT NULL" in all_sql
        assert "password_hash TEXT" in all_sql
        assert "external_id TEXT" in all_sql

    def test_users_unique_tenant_email(self, all_sql):
        assert "UNIQUE (tenant_id, email)" in all_sql

    def test_creates_roles_table(self, all_sql):
        assert "CREATE TABLE IF NOT EXISTS roles" in all_sql
        assert "tenant_id UUID NOT NULL REFERENCES tenants(id)" in all_sql
        assert "permissions TEXT[] NOT NULL" in all_sql
        assert "is_default BOOLEAN" in all_sql

    def test_roles_unique_tenant_name(self, all_sql):
        assert "UNIQUE (tenant_id, name)" in all_sql

    def test_creates_user_roles_table(self, all_sql):
        assert "CREATE TABLE IF NOT EXISTS user_roles" in all_sql
        assert "user_id UUID NOT NULL REFERENCES users(id)" in all_sql
        assert "role_id UUID NOT NULL REFERENCES roles(id)" in all_sql
        assert "PRIMARY KEY (user_id, role_id)" in all_sql

    def test_creates_tenant_id_indexes(self, all_sql):
        assert "idx_users_tenant_id" in all_sql
        assert "idx_roles_tenant_id" in all_sql

    def test_creates_external_id_index(self, all_sql):
        assert "idx_users_external_id" in all_sql

    def test_creates_user_roles_indexes(self, all_sql):
        assert "idx_user_roles_role_id" in all_sql
        assert "idx_user_roles_user_id" in all_sql

    def test_creates_default_roles_index(self, all_sql):
        assert "idx_roles_tenant_default" in all_sql

    def test_cascade_delete_on_users(self, all_sql):
        # Users reference tenants with ON DELETE CASCADE
        users_section = [s for s in all_sql.split("CREATE TABLE") if "users" in s and "user_roles" not in s]
        assert len(users_section) > 0
        assert "ON DELETE CASCADE" in users_section[0]

    def test_cascade_delete_on_user_roles(self, all_sql):
        user_roles_section = [s for s in all_sql.split("CREATE TABLE") if "user_roles" in s]
        assert len(user_roles_section) > 0
        assert "ON DELETE CASCADE" in user_roles_section[0]

    def test_statement_count(self, conn):
        # Extension + 4 tables + 6 indexes = 11 statements
        assert len(conn.statements) == 11


class TestDowngradeMigration:
    """Test downgrade() drops tables in correct order."""

    @pytest.fixture
    def conn(self):
        fake = FakeConnection()
        downgrade(fake)
        return fake

    def test_drops_tables_in_reverse_order(self, conn):
        assert len(conn.statements) == 4
        # user_roles first (depends on users and roles)
        assert "user_roles" in conn.statements[0]
        # roles next (depends on tenants)
        assert "roles" in conn.statements[1]
        # users next (depends on tenants)
        assert "users" in conn.statements[2]
        # tenants last (no dependencies)
        assert "tenants" in conn.statements[3]

    def test_uses_cascade(self, conn):
        for stmt in conn.statements:
            assert "CASCADE" in stmt

    def test_uses_if_exists(self, conn):
        for stmt in conn.statements:
            assert "IF EXISTS" in stmt

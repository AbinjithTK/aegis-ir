"""Tests for 002_seed_default_roles migration.

Validates that the migration:
- Defines the correct DEFAULT_ROLES mapping with proper permission sets
- seed_default_roles() inserts 3 roles with is_default=TRUE for a given tenant
- seed_default_roles() is idempotent (ON CONFLICT DO NOTHING)
- upgrade() seeds roles for all existing tenants
- downgrade() removes only default roles (soc_analyst, ir_lead, ciso)
- Permission arrays are correctly formatted as PostgreSQL TEXT[] literals
- Revision metadata links correctly to 001_initial_schema

Requirements: 4.1
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

# Load migration module via importlib (handles numeric prefix)
_migration_path = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "sift_defender"
    / "enterprise"
    / "migrations"
    / "versions"
    / "002_seed_default_roles.py"
)
_spec = importlib.util.spec_from_file_location("migration_002", _migration_path)
_migration = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_migration)

upgrade = _migration.upgrade
downgrade = _migration.downgrade
seed_default_roles = _migration.seed_default_roles
DEFAULT_ROLES = _migration.DEFAULT_ROLES
revision = _migration.revision
down_revision = _migration.down_revision
_format_pg_array = _migration._format_pg_array


class FakeConnection:
    """Records executed SQL statements for assertion."""

    def __init__(self):
        self.statements: list[str] = []

    def execute(self, sql: str) -> None:
        self.statements.append(sql)


# ─── Migration Metadata ─────────────────────────────────────────────────────


class TestMigrationMetadata:
    """Test migration revision chain and module structure."""

    def test_revision_id(self):
        assert revision == "002_seed_default_roles"

    def test_down_revision_links_to_001(self):
        assert down_revision == "001_initial_schema"

    def test_module_has_upgrade_and_downgrade(self):
        assert callable(upgrade)
        assert callable(downgrade)

    def test_module_exposes_seed_function(self):
        assert callable(seed_default_roles)

    def test_module_exposes_default_roles(self):
        assert isinstance(DEFAULT_ROLES, dict)


# ─── DEFAULT_ROLES Definition ────────────────────────────────────────────────


class TestDefaultRolesDefinition:
    """Test the DEFAULT_ROLES mapping matches design specification."""

    def test_contains_three_roles(self):
        assert len(DEFAULT_ROLES) == 3

    def test_role_names(self):
        assert set(DEFAULT_ROLES.keys()) == {"soc_analyst", "ir_lead", "ciso"}

    def test_soc_analyst_permissions(self):
        expected = [
            "investigation:start",
            "investigation:view",
            "finding:approve",
            "finding:reject",
            "case:create",
            "playbook:view",
            "evidence:access",
        ]
        assert DEFAULT_ROLES["soc_analyst"] == expected

    def test_ir_lead_permissions(self):
        perms = DEFAULT_ROLES["ir_lead"]
        # ir_lead has all SOC analyst permissions plus management ones
        assert "investigation:start" in perms
        assert "investigation:view" in perms
        assert "finding:approve" in perms
        assert "finding:reject" in perms
        assert "case:create" in perms
        assert "case:manage" in perms
        assert "case:assign" in perms
        assert "playbook:view" in perms
        assert "playbook:edit" in perms
        assert "settings:view" in perms
        assert "settings:edit" in perms
        assert "audit:view" in perms
        assert "evidence:access" in perms
        assert "user:manage" in perms

    def test_ir_lead_has_14_permissions(self):
        assert len(DEFAULT_ROLES["ir_lead"]) == 14

    def test_ciso_permissions(self):
        expected = [
            "investigation:view",
            "audit:view",
            "audit:export",
            "report:executive",
        ]
        assert DEFAULT_ROLES["ciso"] == expected

    def test_soc_analyst_permissions_are_subset_of_ir_lead(self):
        soc_perms = set(DEFAULT_ROLES["soc_analyst"])
        ir_lead_perms = set(DEFAULT_ROLES["ir_lead"])
        assert soc_perms.issubset(ir_lead_perms)

    def test_all_permissions_follow_resource_action_format(self):
        for role_name, perms in DEFAULT_ROLES.items():
            for perm in perms:
                parts = perm.split(":")
                assert len(parts) == 2, (
                    f"Permission '{perm}' in role '{role_name}' "
                    f"does not follow 'resource:action' format"
                )
                assert len(parts[0]) > 0
                assert len(parts[1]) > 0


# ─── PostgreSQL Array Formatting ─────────────────────────────────────────────


class TestPgArrayFormatting:
    """Test _format_pg_array helper."""

    def test_empty_list(self):
        assert _format_pg_array([]) == "{}"

    def test_single_item(self):
        assert _format_pg_array(["investigation:start"]) == "{investigation:start}"

    def test_multiple_items(self):
        result = _format_pg_array(["a:b", "c:d", "e:f"])
        assert result == "{a:b,c:d,e:f}"

    def test_soc_analyst_permissions_format(self):
        result = _format_pg_array(DEFAULT_ROLES["soc_analyst"])
        assert result.startswith("{")
        assert result.endswith("}")
        assert "investigation:start" in result
        assert "evidence:access" in result


# ─── seed_default_roles Function ─────────────────────────────────────────────


class TestSeedDefaultRoles:
    """Test the reusable seed_default_roles() function."""

    @pytest.fixture
    def conn(self):
        return FakeConnection()

    @pytest.fixture
    def tenant_id(self):
        return "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

    def test_inserts_three_roles(self, conn, tenant_id):
        result = seed_default_roles(conn, tenant_id)
        assert len(conn.statements) == 3
        assert len(result) == 3

    def test_returns_role_names(self, conn, tenant_id):
        result = seed_default_roles(conn, tenant_id)
        assert result == ["soc_analyst", "ir_lead", "ciso"]

    def test_uses_correct_tenant_id(self, conn, tenant_id):
        seed_default_roles(conn, tenant_id)
        for stmt in conn.statements:
            assert tenant_id in stmt

    def test_sets_is_default_true(self, conn, tenant_id):
        seed_default_roles(conn, tenant_id)
        for stmt in conn.statements:
            assert "TRUE" in stmt

    def test_uses_on_conflict_do_nothing(self, conn, tenant_id):
        seed_default_roles(conn, tenant_id)
        for stmt in conn.statements:
            assert "ON CONFLICT" in stmt
            assert "DO NOTHING" in stmt

    def test_inserts_into_roles_table(self, conn, tenant_id):
        seed_default_roles(conn, tenant_id)
        for stmt in conn.statements:
            assert "INSERT INTO roles" in stmt

    def test_uses_uuid_generate_v4(self, conn, tenant_id):
        seed_default_roles(conn, tenant_id)
        for stmt in conn.statements:
            assert "uuid_generate_v4()" in stmt

    def test_soc_analyst_statement_has_correct_permissions(self, conn, tenant_id):
        seed_default_roles(conn, tenant_id)
        soc_stmt = conn.statements[0]
        assert "'soc_analyst'" in soc_stmt
        assert "investigation:start" in soc_stmt
        assert "evidence:access" in soc_stmt

    def test_ir_lead_statement_has_management_permissions(self, conn, tenant_id):
        seed_default_roles(conn, tenant_id)
        ir_stmt = conn.statements[1]
        assert "'ir_lead'" in ir_stmt
        assert "case:manage" in ir_stmt
        assert "user:manage" in ir_stmt
        assert "playbook:edit" in ir_stmt

    def test_ciso_statement_has_executive_permissions(self, conn, tenant_id):
        seed_default_roles(conn, tenant_id)
        ciso_stmt = conn.statements[2]
        assert "'ciso'" in ciso_stmt
        assert "report:executive" in ciso_stmt
        assert "audit:export" in ciso_stmt

    def test_idempotent_on_conflict_clause(self, conn, tenant_id):
        """Calling seed twice should produce ON CONFLICT DO NOTHING statements."""
        seed_default_roles(conn, tenant_id)
        seed_default_roles(conn, tenant_id)
        # All 6 statements should have ON CONFLICT
        assert len(conn.statements) == 6
        for stmt in conn.statements:
            assert "ON CONFLICT (tenant_id, name) DO NOTHING" in stmt


# ─── upgrade() Function ──────────────────────────────────────────────────────


class TestUpgradeMigration:
    """Test upgrade() seeds roles for all existing tenants."""

    @pytest.fixture
    def conn(self):
        fake = FakeConnection()
        upgrade(fake)
        return fake

    def test_executes_three_statements(self, conn):
        """One INSERT per role (uses subquery from tenants)."""
        assert len(conn.statements) == 3

    def test_uses_select_from_tenants(self, conn):
        """upgrade() seeds for ALL existing tenants via subquery."""
        for stmt in conn.statements:
            assert "FROM tenants t" in stmt

    def test_uses_not_exists_guard(self, conn):
        """Prevents duplicate insertion for existing roles."""
        for stmt in conn.statements:
            assert "NOT EXISTS" in stmt

    def test_inserts_soc_analyst(self, conn):
        soc_stmts = [s for s in conn.statements if "'soc_analyst'" in s]
        assert len(soc_stmts) == 1

    def test_inserts_ir_lead(self, conn):
        ir_stmts = [s for s in conn.statements if "'ir_lead'" in s]
        assert len(ir_stmts) == 1

    def test_inserts_ciso(self, conn):
        ciso_stmts = [s for s in conn.statements if "'ciso'" in s]
        assert len(ciso_stmts) == 1

    def test_sets_is_default_true(self, conn):
        for stmt in conn.statements:
            assert "TRUE" in stmt


# ─── downgrade() Function ────────────────────────────────────────────────────


class TestDowngradeMigration:
    """Test downgrade() removes only the seeded default roles."""

    @pytest.fixture
    def conn(self):
        fake = FakeConnection()
        downgrade(fake)
        return fake

    def test_executes_single_delete(self, conn):
        assert len(conn.statements) == 1

    def test_deletes_from_roles(self, conn):
        assert "DELETE FROM roles" in conn.statements[0]

    def test_filters_by_is_default(self, conn):
        assert "is_default = TRUE" in conn.statements[0]

    def test_filters_by_role_names(self, conn):
        stmt = conn.statements[0]
        assert "'soc_analyst'" in stmt
        assert "'ir_lead'" in stmt
        assert "'ciso'" in stmt

    def test_does_not_delete_custom_roles(self, conn):
        """The WHERE clause ensures only default roles are removed."""
        stmt = conn.statements[0]
        # Must require BOTH is_default AND name IN (...)
        assert "is_default = TRUE" in stmt
        assert "IN (" in stmt

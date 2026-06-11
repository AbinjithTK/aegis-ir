"""Tests for 004_audit_log migration.

Validates that the migration produces correct SQL DDL for:
- Partitioned audit_log table with PARTITION BY RANGE (created_at)
- chain_hash column for SHA-256 tamper detection
- Monthly partition creation (current + next 3 months)
- Auto-partition creation function
- Partition name helper function
- Indexes on (tenant_id, created_at), event_type, user_id, (resource_type, resource_id)
- REVOKE UPDATE, DELETE on audit_log from app_user
- Correct downgrade (drops functions and table)

Requirements: 7.3
"""

from __future__ import annotations

import importlib.util
import re
from datetime import date
from pathlib import Path

import pytest

# Load migration module via importlib
_migration_path = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "sift_defender"
    / "enterprise"
    / "migrations"
    / "versions"
    / "004_audit_log.py"
)
_spec = importlib.util.spec_from_file_location("migration_004", _migration_path)
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
        assert revision == "004_audit_log"

    def test_down_revision(self):
        assert _migration.down_revision == "001_initial_schema"

    def test_module_has_upgrade_and_downgrade(self):
        assert callable(upgrade)
        assert callable(downgrade)


class TestUpgradePartitionedTable:
    """Test upgrade() creates the partitioned audit_log table."""

    @pytest.fixture
    def conn(self):
        fake = FakeConnection()
        upgrade(fake)
        return fake

    @pytest.fixture
    def all_sql(self, conn):
        return "\n".join(conn.statements)

    def test_creates_audit_log_table(self, all_sql):
        assert "CREATE TABLE IF NOT EXISTS audit_log" in all_sql

    def test_table_is_partitioned_by_range(self, all_sql):
        assert "PARTITION BY RANGE (created_at)" in all_sql

    def test_has_id_column_uuid(self, all_sql):
        assert "id UUID NOT NULL" in all_sql

    def test_has_tenant_id_column(self, all_sql):
        assert "tenant_id UUID NOT NULL" in all_sql

    def test_has_event_type_column(self, all_sql):
        assert "event_type TEXT NOT NULL" in all_sql

    def test_has_user_id_column(self, all_sql):
        assert "user_id UUID" in all_sql

    def test_has_resource_type_column(self, all_sql):
        assert "resource_type TEXT" in all_sql

    def test_has_resource_id_column(self, all_sql):
        assert "resource_id TEXT" in all_sql

    def test_has_details_jsonb_column(self, all_sql):
        assert "details JSONB" in all_sql

    def test_has_trace_span_id_column(self, all_sql):
        assert "trace_span_id TEXT" in all_sql

    def test_has_chain_hash_column(self, all_sql):
        """chain_hash column for SHA-256 tamper detection linking."""
        assert "chain_hash TEXT" in all_sql

    def test_has_created_at_column(self, all_sql):
        assert "created_at TIMESTAMPTZ" in all_sql
        assert "DEFAULT NOW()" in all_sql

    def test_composite_primary_key(self, all_sql):
        """Partitioned tables require partition key in PK."""
        assert "PRIMARY KEY (id, created_at)" in all_sql


class TestUpgradePartitions:
    """Test that initial monthly partitions are created."""

    @pytest.fixture
    def conn(self):
        fake = FakeConnection()
        upgrade(fake)
        return fake

    @pytest.fixture
    def all_sql(self, conn):
        return "\n".join(conn.statements)

    def test_creates_partitions(self, all_sql):
        """Should create 4 monthly partitions."""
        partition_matches = re.findall(
            r"CREATE TABLE IF NOT EXISTS audit_log_\d{4}_\d{2} PARTITION OF audit_log",
            all_sql,
        )
        assert len(partition_matches) == 4

    def test_partition_names_follow_convention(self, all_sql):
        """Partition names follow audit_log_YYYY_MM format."""
        today = date.today()
        first_partition = f"audit_log_{today.year}_{today.month:02d}"
        assert first_partition in all_sql

    def test_partitions_use_for_values_from_to(self, all_sql):
        """Each partition specifies date range bounds."""
        assert "FOR VALUES FROM" in all_sql
        assert "TO" in all_sql


class TestUpgradeAutoPartitionFunction:
    """Test auto-partition creation function."""

    @pytest.fixture
    def conn(self):
        fake = FakeConnection()
        upgrade(fake)
        return fake

    @pytest.fixture
    def all_sql(self, conn):
        return "\n".join(conn.statements)

    def test_creates_auto_partition_function(self, all_sql):
        assert "CREATE OR REPLACE FUNCTION create_audit_log_partition()" in all_sql

    def test_auto_partition_function_returns_void(self, all_sql):
        assert "RETURNS void" in all_sql

    def test_auto_partition_uses_plpgsql(self, all_sql):
        assert "LANGUAGE plpgsql" in all_sql

    def test_auto_partition_checks_existence(self, all_sql):
        """Function checks if partition already exists before creating."""
        assert "pg_class" in all_sql
        assert "NOT EXISTS" in all_sql


class TestUpgradePartitionNameHelper:
    """Test partition name helper function."""

    @pytest.fixture
    def conn(self):
        fake = FakeConnection()
        upgrade(fake)
        return fake

    @pytest.fixture
    def all_sql(self, conn):
        return "\n".join(conn.statements)

    def test_creates_partition_name_function(self, all_sql):
        assert "CREATE OR REPLACE FUNCTION audit_log_partition_name" in all_sql

    def test_function_accepts_timestamptz(self, all_sql):
        assert "audit_log_partition_name(ts TIMESTAMPTZ)" in all_sql

    def test_function_returns_text(self, all_sql):
        assert "RETURNS TEXT" in all_sql

    def test_function_is_immutable(self, all_sql):
        """Immutable for index usage and query optimization."""
        assert "IMMUTABLE" in all_sql


class TestUpgradeIndexes:
    """Test performance indexes are created."""

    @pytest.fixture
    def conn(self):
        fake = FakeConnection()
        upgrade(fake)
        return fake

    @pytest.fixture
    def all_sql(self, conn):
        return "\n".join(conn.statements)

    def test_creates_tenant_created_at_index(self, all_sql):
        assert "idx_audit_log_tenant_created" in all_sql
        assert "tenant_id, created_at" in all_sql

    def test_creates_event_type_index(self, all_sql):
        assert "idx_audit_log_event_type" in all_sql
        assert "event_type" in all_sql

    def test_creates_user_id_index(self, all_sql):
        assert "idx_audit_log_user_id" in all_sql
        # Partial index on non-null user_id
        assert "WHERE user_id IS NOT NULL" in all_sql

    def test_creates_resource_index(self, all_sql):
        assert "idx_audit_log_resource" in all_sql
        assert "resource_type, resource_id" in all_sql
        # Partial index on non-null resource_type
        assert "WHERE resource_type IS NOT NULL" in all_sql


class TestUpgradeRevoke:
    """Test REVOKE UPDATE/DELETE enforcement."""

    @pytest.fixture
    def conn(self):
        fake = FakeConnection()
        upgrade(fake)
        return fake

    @pytest.fixture
    def all_sql(self, conn):
        return "\n".join(conn.statements)

    def test_revokes_update_on_audit_log(self, all_sql):
        assert "REVOKE UPDATE" in all_sql

    def test_revokes_delete_on_audit_log(self, all_sql):
        assert "REVOKE" in all_sql and "DELETE" in all_sql

    def test_revoke_targets_app_user_role(self, all_sql):
        assert "app_user" in all_sql

    def test_revoke_handles_missing_role(self, all_sql):
        """Uses DO block to handle case where app_user role doesn't exist."""
        assert "pg_roles" in all_sql
        assert "rolname = 'app_user'" in all_sql


class TestDowngradeMigration:
    """Test downgrade() drops audit_log and associated functions."""

    @pytest.fixture
    def conn(self):
        fake = FakeConnection()
        downgrade(fake)
        return fake

    def test_drops_partition_name_function(self, conn):
        assert any("audit_log_partition_name" in s for s in conn.statements)
        assert any("DROP FUNCTION" in s for s in conn.statements)

    def test_drops_auto_partition_function(self, conn):
        assert any("create_audit_log_partition" in s for s in conn.statements)

    def test_drops_audit_log_table(self, conn):
        assert any("DROP TABLE" in s and "audit_log" in s for s in conn.statements)

    def test_uses_cascade(self, conn):
        for stmt in conn.statements:
            assert "CASCADE" in stmt

    def test_uses_if_exists(self, conn):
        for stmt in conn.statements:
            assert "IF EXISTS" in stmt

    def test_drop_order_functions_before_table(self, conn):
        """Functions should be dropped before the table."""
        func_idx = None
        table_idx = None
        for i, stmt in enumerate(conn.statements):
            if "DROP FUNCTION" in stmt and func_idx is None:
                func_idx = i
            if "DROP TABLE" in stmt:
                table_idx = i
        assert func_idx is not None
        assert table_idx is not None
        assert func_idx < table_idx


class TestPartitionBoundsHelper:
    """Test the _partition_bounds helper function."""

    def test_returns_correct_count(self):
        bounds = _migration._partition_bounds(4)
        assert len(bounds) == 4

    def test_first_partition_is_current_month(self):
        bounds = _migration._partition_bounds(4)
        today = date.today()
        expected_start = today.replace(day=1).isoformat()
        assert bounds[0][1] == expected_start

    def test_partitions_are_contiguous(self):
        """Each partition's end date is the next partition's start date."""
        bounds = _migration._partition_bounds(4)
        for i in range(len(bounds) - 1):
            assert bounds[i][2] == bounds[i + 1][1]

    def test_partition_names_follow_format(self):
        bounds = _migration._partition_bounds(4)
        for name, start, end in bounds:
            assert re.match(r"audit_log_\d{4}_\d{2}", name)

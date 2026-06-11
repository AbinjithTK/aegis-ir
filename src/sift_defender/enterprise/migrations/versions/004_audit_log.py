"""004 - Audit Log: append-only, partitioned, tamper-resistant audit table.

Creates the audit_log partitioned table with:
- Monthly range partitioning on created_at
- Initial partitions (current month + next 3 months)
- Auto-partition creation function
- chain_hash column for SHA-256 tamper detection linking
- REVOKE UPDATE/DELETE on the table from app_user
- Performance indexes on tenant_id, event_type, user_id, and resource lookups

Requirements: 7.3
"""

from __future__ import annotations

import textwrap
from datetime import date, timedelta

# Alembic revision identifiers
revision = "004_audit_log"
down_revision = "001_initial_schema"
branch_labels = None
depends_on = None


def _partition_bounds(months_ahead: int = 4) -> list[tuple[str, str, str]]:
    """Generate (partition_name, start_date, end_date) for current + N months.

    Returns a list of tuples like:
        ("audit_log_2025_01", "2025-01-01", "2025-02-01")
    """
    today = date.today()
    first_of_month = today.replace(day=1)
    partitions = []
    for i in range(months_ahead):
        # Calculate start of this partition month
        month = first_of_month.month + i
        year = first_of_month.year
        while month > 12:
            month -= 12
            year += 1
        start = date(year, month, 1)

        # Calculate start of next month (partition upper bound)
        next_month = month + 1
        next_year = year
        if next_month > 12:
            next_month = 1
            next_year += 1
        end = date(next_year, next_month, 1)

        name = f"audit_log_{start.year}_{start.month:02d}"
        partitions.append((name, start.isoformat(), end.isoformat()))
    return partitions


def upgrade(conn) -> None:
    """Apply migration: create partitioned audit_log table with security constraints."""
    statements = [
        # ------------------------------------------------------------------
        # Partitioned parent table — audit_log
        # Append-only, tamper-resistant via chain_hash linking entries
        # ------------------------------------------------------------------
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id UUID NOT NULL,
            tenant_id UUID NOT NULL,
            event_type TEXT NOT NULL,
            user_id UUID,
            resource_type TEXT,
            resource_id TEXT,
            details JSONB,
            trace_span_id TEXT,
            chain_hash TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (id, created_at)
        ) PARTITION BY RANGE (created_at);
        """,
    ]

    # ------------------------------------------------------------------
    # Create initial monthly partitions (current month + next 3 months)
    # ------------------------------------------------------------------
    for name, start, end in _partition_bounds(4):
        statements.append(
            f"""
            CREATE TABLE IF NOT EXISTS {name} PARTITION OF audit_log
                FOR VALUES FROM ('{start}') TO ('{end}');
            """
        )

    # ------------------------------------------------------------------
    # Function to auto-create monthly partitions
    # Called by a scheduled job or trigger to ensure future partitions exist
    # ------------------------------------------------------------------
    statements.append(
        """
        CREATE OR REPLACE FUNCTION create_audit_log_partition()
        RETURNS void AS $$
        DECLARE
            partition_name TEXT;
            start_date DATE;
            end_date DATE;
        BEGIN
            -- Create partition for next month if it doesn't exist
            start_date := date_trunc('month', NOW() + INTERVAL '1 month')::DATE;
            end_date := (start_date + INTERVAL '1 month')::DATE;
            partition_name := 'audit_log_' || to_char(start_date, 'YYYY_MM');

            IF NOT EXISTS (
                SELECT 1 FROM pg_class WHERE relname = partition_name
            ) THEN
                EXECUTE format(
                    'CREATE TABLE %I PARTITION OF audit_log FOR VALUES FROM (%L) TO (%L)',
                    partition_name, start_date, end_date
                );
            END IF;
        END;
        $$ LANGUAGE plpgsql;
        """
    )

    # ------------------------------------------------------------------
    # Helper function to generate partition name from a timestamp
    # ------------------------------------------------------------------
    statements.append(
        """
        CREATE OR REPLACE FUNCTION audit_log_partition_name(ts TIMESTAMPTZ)
        RETURNS TEXT AS $$
        BEGIN
            RETURN 'audit_log_' || to_char(ts, 'YYYY_MM');
        END;
        $$ LANGUAGE plpgsql IMMUTABLE;
        """
    )

    # ------------------------------------------------------------------
    # Performance indexes
    # ------------------------------------------------------------------
    statements.append(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_created
            ON audit_log (tenant_id, created_at);
        """
    )
    statements.append(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_log_event_type
            ON audit_log (event_type);
        """
    )
    statements.append(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_log_user_id
            ON audit_log (user_id)
            WHERE user_id IS NOT NULL;
        """
    )
    statements.append(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_log_resource
            ON audit_log (resource_type, resource_id)
            WHERE resource_type IS NOT NULL;
        """
    )

    # ------------------------------------------------------------------
    # REVOKE UPDATE and DELETE — enforce append-only at the DB level
    # Uses DO block to handle case where role doesn't exist yet
    # ------------------------------------------------------------------
    statements.append(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_user') THEN
                REVOKE UPDATE, DELETE ON audit_log FROM app_user;
            END IF;
        END $$;
        """
    )

    for stmt in statements:
        conn.execute(textwrap.dedent(stmt).strip())


def downgrade(conn) -> None:
    """Revert migration: drop audit_log table, partitions, and helper functions."""
    statements = [
        "DROP FUNCTION IF EXISTS audit_log_partition_name(TIMESTAMPTZ) CASCADE;",
        "DROP FUNCTION IF EXISTS create_audit_log_partition() CASCADE;",
        "DROP TABLE IF EXISTS audit_log CASCADE;",
    ]

    for stmt in statements:
        conn.execute(stmt)

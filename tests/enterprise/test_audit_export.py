"""Tests for AuditLogService.export() — CSV and JSON export with SHA-256 integrity hash.

Validates:
- ExportResult model structure and fields
- export() serializes records as JSON array
- export() serializes records as CSV with correct headers
- export() computes SHA-256 hash of output content
- export() caps records at 10,000 for safety
- export() validates format parameter (only "csv" and "json")
- export() raises ValueError on empty tenant_id
- export() applies filters correctly
- Integrity hash changes when content changes

Requirements: 7.4, 7.5
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from sift_defender.enterprise.audit.service import (
    AuditEventType,
    AuditFilters,
    AuditLogService,
    ExportResult,
)


class TestExportResult:
    """Test ExportResult Pydantic model."""

    def test_model_fields(self):
        """ExportResult has all required fields."""
        now = datetime.now(timezone.utc)
        result = ExportResult(
            content='[{"id": "abc"}]',
            format="json",
            integrity_hash="a" * 64,
            record_count=1,
            exported_at=now,
        )
        assert result.content == '[{"id": "abc"}]'
        assert result.format == "json"
        assert result.integrity_hash == "a" * 64
        assert result.record_count == 1
        assert result.exported_at == now

    def test_csv_format(self):
        """ExportResult accepts csv format."""
        now = datetime.now(timezone.utc)
        result = ExportResult(
            content="id,event_type\nabc,user.login\n",
            format="csv",
            integrity_hash="b" * 64,
            record_count=1,
            exported_at=now,
        )
        assert result.format == "csv"


class TestAuditLogServiceExport:
    """Test AuditLogService.export() method."""

    TENANT_ID = "550e8400-e29b-41d4-a716-446655440000"
    USER_ID = "660e8400-e29b-41d4-a716-446655440001"

    CSV_COLUMNS = [
        "id", "tenant_id", "event_type", "user_id", "resource_type",
        "resource_id", "details", "trace_span_id", "chain_hash", "created_at",
    ]

    @pytest.fixture
    def service(self):
        return AuditLogService()

    @pytest.fixture
    def sample_rows(self):
        """Sample DB rows simulating asyncpg fetch results."""
        now = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        return [
            {
                "id": uuid.UUID("11111111-1111-1111-1111-111111111111"),
                "tenant_id": uuid.UUID(self.TENANT_ID),
                "event_type": "user.login",
                "user_id": uuid.UUID(self.USER_ID),
                "resource_type": "session",
                "resource_id": "sess-001",
                "details": '{"ip": "10.0.0.1"}',
                "trace_span_id": "span-123",
                "chain_hash": "a" * 64,
                "created_at": now,
            },
            {
                "id": uuid.UUID("22222222-2222-2222-2222-222222222222"),
                "tenant_id": uuid.UUID(self.TENANT_ID),
                "event_type": "user.logout",
                "user_id": None,
                "resource_type": None,
                "resource_id": None,
                "details": "{}",
                "trace_span_id": None,
                "chain_hash": "b" * 64,
                "created_at": now,
            },
        ]

    @pytest.fixture
    def mock_conn_empty(self):
        """Mock connection returning no rows."""
        conn = AsyncMock()
        conn.fetch = AsyncMock(return_value=[])
        return conn

    @pytest.fixture
    def mock_conn_with_rows(self, sample_rows):
        """Mock connection returning sample rows."""
        conn = AsyncMock()
        conn.fetch = AsyncMock(return_value=sample_rows)
        return conn

    def _patch_tenant_conn(self, mock_conn):
        """Helper to patch get_tenant_connection with a mock conn."""
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        return patch(
            "sift_defender.enterprise.audit.service.get_tenant_connection",
            return_value=mock_ctx,
        )

    # --- Validation Tests ---

    @pytest.mark.asyncio
    async def test_export_raises_on_empty_tenant_id(self, service):
        """export() raises ValueError if tenant_id is empty."""
        with pytest.raises(ValueError, match="tenant_id must be a non-empty string"):
            await service.export("", AuditFilters(), format="json")

    @pytest.mark.asyncio
    async def test_export_raises_on_invalid_format(self, service, mock_conn_empty):
        """export() raises ValueError for unsupported format."""
        with self._patch_tenant_conn(mock_conn_empty):
            with pytest.raises(ValueError, match="Unsupported export format"):
                await service.export(self.TENANT_ID, AuditFilters(), format="xml")

    @pytest.mark.asyncio
    async def test_export_raises_on_uppercase_format(self, service, mock_conn_empty):
        """export() rejects 'JSON' (must be lowercase)."""
        with self._patch_tenant_conn(mock_conn_empty):
            with pytest.raises(ValueError, match="Unsupported export format"):
                await service.export(self.TENANT_ID, AuditFilters(), format="JSON")

    # --- JSON Export Tests ---

    @pytest.mark.asyncio
    async def test_export_json_returns_export_result(self, service, mock_conn_with_rows):
        """export() returns an ExportResult instance for JSON format."""
        with self._patch_tenant_conn(mock_conn_with_rows):
            result = await service.export(self.TENANT_ID, AuditFilters(), format="json")

        assert isinstance(result, ExportResult)
        assert result.format == "json"

    @pytest.mark.asyncio
    async def test_export_json_content_is_valid_json_array(self, service, mock_conn_with_rows):
        """JSON export content is parseable as a JSON array."""
        with self._patch_tenant_conn(mock_conn_with_rows):
            result = await service.export(self.TENANT_ID, AuditFilters(), format="json")

        parsed = json.loads(result.content)
        assert isinstance(parsed, list)
        assert len(parsed) == 2

    @pytest.mark.asyncio
    async def test_export_json_record_structure(self, service, mock_conn_with_rows):
        """Each JSON record has all expected fields."""
        with self._patch_tenant_conn(mock_conn_with_rows):
            result = await service.export(self.TENANT_ID, AuditFilters(), format="json")

        parsed = json.loads(result.content)
        record = parsed[0]
        assert record["id"] == "11111111-1111-1111-1111-111111111111"
        assert record["tenant_id"] == self.TENANT_ID
        assert record["event_type"] == "user.login"
        assert record["user_id"] == self.USER_ID
        assert record["resource_type"] == "session"
        assert record["resource_id"] == "sess-001"
        assert record["details"] == {"ip": "10.0.0.1"}
        assert record["trace_span_id"] == "span-123"
        assert record["chain_hash"] == "a" * 64
        assert record["created_at"] is not None

    @pytest.mark.asyncio
    async def test_export_json_handles_null_fields(self, service, mock_conn_with_rows):
        """JSON export handles None values correctly."""
        with self._patch_tenant_conn(mock_conn_with_rows):
            result = await service.export(self.TENANT_ID, AuditFilters(), format="json")

        parsed = json.loads(result.content)
        record = parsed[1]  # Second row has many null fields
        assert record["user_id"] is None
        assert record["resource_type"] is None
        assert record["resource_id"] is None
        assert record["trace_span_id"] is None

    @pytest.mark.asyncio
    async def test_export_json_empty_result(self, service, mock_conn_empty):
        """JSON export with no matching records returns empty array."""
        with self._patch_tenant_conn(mock_conn_empty):
            result = await service.export(self.TENANT_ID, AuditFilters(), format="json")

        parsed = json.loads(result.content)
        assert parsed == []
        assert result.record_count == 0

    # --- CSV Export Tests ---

    @pytest.mark.asyncio
    async def test_export_csv_returns_export_result(self, service, mock_conn_with_rows):
        """export() returns an ExportResult instance for CSV format."""
        with self._patch_tenant_conn(mock_conn_with_rows):
            result = await service.export(self.TENANT_ID, AuditFilters(), format="csv")

        assert isinstance(result, ExportResult)
        assert result.format == "csv"

    @pytest.mark.asyncio
    async def test_export_csv_has_correct_headers(self, service, mock_conn_with_rows):
        """CSV export includes the expected column headers."""
        with self._patch_tenant_conn(mock_conn_with_rows):
            result = await service.export(self.TENANT_ID, AuditFilters(), format="csv")

        reader = csv.reader(io.StringIO(result.content))
        headers = next(reader)
        assert headers == self.CSV_COLUMNS

    @pytest.mark.asyncio
    async def test_export_csv_row_count(self, service, mock_conn_with_rows):
        """CSV export has header + data rows."""
        with self._patch_tenant_conn(mock_conn_with_rows):
            result = await service.export(self.TENANT_ID, AuditFilters(), format="csv")

        reader = csv.reader(io.StringIO(result.content))
        rows = list(reader)
        # 1 header + 2 data rows
        assert len(rows) == 3

    @pytest.mark.asyncio
    async def test_export_csv_data_values(self, service, mock_conn_with_rows):
        """CSV export serializes field values correctly."""
        with self._patch_tenant_conn(mock_conn_with_rows):
            result = await service.export(self.TENANT_ID, AuditFilters(), format="csv")

        reader = csv.DictReader(io.StringIO(result.content))
        rows = list(reader)
        first_row = rows[0]
        assert first_row["id"] == "11111111-1111-1111-1111-111111111111"
        assert first_row["event_type"] == "user.login"
        assert first_row["user_id"] == self.USER_ID
        # details should be JSON string in CSV
        assert json.loads(first_row["details"]) == {"ip": "10.0.0.1"}

    @pytest.mark.asyncio
    async def test_export_csv_empty_result(self, service, mock_conn_empty):
        """CSV export with no matching records returns only header."""
        with self._patch_tenant_conn(mock_conn_empty):
            result = await service.export(self.TENANT_ID, AuditFilters(), format="csv")

        reader = csv.reader(io.StringIO(result.content))
        rows = list(reader)
        # Only header row
        assert len(rows) == 1
        assert rows[0] == self.CSV_COLUMNS
        assert result.record_count == 0

    # --- Integrity Hash Tests ---

    @pytest.mark.asyncio
    async def test_export_integrity_hash_is_sha256(self, service, mock_conn_with_rows):
        """Integrity hash is a valid 64-character SHA-256 hex digest."""
        with self._patch_tenant_conn(mock_conn_with_rows):
            result = await service.export(self.TENANT_ID, AuditFilters(), format="json")

        assert len(result.integrity_hash) == 64
        # Should be all hex characters
        int(result.integrity_hash, 16)

    @pytest.mark.asyncio
    async def test_export_integrity_hash_matches_content(self, service, mock_conn_with_rows):
        """Integrity hash is SHA-256 of the actual content string."""
        with self._patch_tenant_conn(mock_conn_with_rows):
            result = await service.export(self.TENANT_ID, AuditFilters(), format="json")

        expected_hash = hashlib.sha256(result.content.encode("utf-8")).hexdigest()
        assert result.integrity_hash == expected_hash

    @pytest.mark.asyncio
    async def test_export_csv_integrity_hash_matches_content(self, service, mock_conn_with_rows):
        """CSV integrity hash is SHA-256 of the CSV content string."""
        with self._patch_tenant_conn(mock_conn_with_rows):
            result = await service.export(self.TENANT_ID, AuditFilters(), format="csv")

        expected_hash = hashlib.sha256(result.content.encode("utf-8")).hexdigest()
        assert result.integrity_hash == expected_hash

    @pytest.mark.asyncio
    async def test_export_different_content_different_hash(self, service):
        """Different export content produces different integrity hashes."""
        now = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

        # Two different row sets
        rows_a = [{
            "id": uuid.UUID("11111111-1111-1111-1111-111111111111"),
            "tenant_id": uuid.UUID(self.TENANT_ID),
            "event_type": "user.login",
            "user_id": None,
            "resource_type": None,
            "resource_id": None,
            "details": "{}",
            "trace_span_id": None,
            "chain_hash": "a" * 64,
            "created_at": now,
        }]
        rows_b = [{
            "id": uuid.UUID("22222222-2222-2222-2222-222222222222"),
            "tenant_id": uuid.UUID(self.TENANT_ID),
            "event_type": "user.logout",
            "user_id": None,
            "resource_type": None,
            "resource_id": None,
            "details": "{}",
            "trace_span_id": None,
            "chain_hash": "b" * 64,
            "created_at": now,
        }]

        conn_a = AsyncMock()
        conn_a.fetch = AsyncMock(return_value=rows_a)
        conn_b = AsyncMock()
        conn_b.fetch = AsyncMock(return_value=rows_b)

        with self._patch_tenant_conn(conn_a):
            result_a = await service.export(self.TENANT_ID, AuditFilters(), format="json")

        with self._patch_tenant_conn(conn_b):
            result_b = await service.export(self.TENANT_ID, AuditFilters(), format="json")

        assert result_a.integrity_hash != result_b.integrity_hash

    # --- Record Count and Metadata Tests ---

    @pytest.mark.asyncio
    async def test_export_record_count(self, service, mock_conn_with_rows):
        """export() reports correct record_count."""
        with self._patch_tenant_conn(mock_conn_with_rows):
            result = await service.export(self.TENANT_ID, AuditFilters(), format="json")

        assert result.record_count == 2

    @pytest.mark.asyncio
    async def test_export_exported_at_is_utc(self, service, mock_conn_with_rows):
        """exported_at is a UTC timestamp."""
        with self._patch_tenant_conn(mock_conn_with_rows):
            result = await service.export(self.TENANT_ID, AuditFilters(), format="json")

        assert result.exported_at.tzinfo == timezone.utc

    @pytest.mark.asyncio
    async def test_export_default_format_is_json(self, service, mock_conn_with_rows):
        """Default export format is JSON when not specified."""
        with self._patch_tenant_conn(mock_conn_with_rows):
            result = await service.export(self.TENANT_ID, AuditFilters())

        assert result.format == "json"

    # --- Filter Application Tests ---

    @pytest.mark.asyncio
    async def test_export_applies_filters(self, service, mock_conn_empty):
        """export() applies filters to the query."""
        filters = AuditFilters(
            event_type=AuditEventType.USER_LOGIN,
            user_id=self.USER_ID,
        )

        with self._patch_tenant_conn(mock_conn_empty):
            await service.export(self.TENANT_ID, filters, format="json")

        fetch_sql = mock_conn_empty.fetch.call_args[0][0]
        assert "tenant_id = $1" in fetch_sql
        assert "event_type" in fetch_sql
        assert "user_id" in fetch_sql

    @pytest.mark.asyncio
    async def test_export_scopes_to_tenant(self, service, mock_conn_empty):
        """export() always scopes query to tenant_id."""
        with self._patch_tenant_conn(mock_conn_empty) as mock_get_conn:
            await service.export(self.TENANT_ID, AuditFilters(), format="json")

        mock_get_conn.assert_called_once_with(self.TENANT_ID)

    # --- Safety Cap Tests ---

    @pytest.mark.asyncio
    async def test_export_applies_limit_cap(self, service, mock_conn_empty):
        """export() applies a LIMIT of 10,000 for safety."""
        with self._patch_tenant_conn(mock_conn_empty):
            await service.export(self.TENANT_ID, AuditFilters(), format="json")

        fetch_call = mock_conn_empty.fetch.call_args[0]
        fetch_sql = fetch_call[0]
        assert "LIMIT" in fetch_sql
        # The 10,000 cap should be passed as a parameter
        all_args = fetch_call[1:]
        assert 10_000 in all_args

    @pytest.mark.asyncio
    async def test_export_no_pagination_offset(self, service, mock_conn_empty):
        """export() does NOT use OFFSET (exports all matching records)."""
        with self._patch_tenant_conn(mock_conn_empty):
            await service.export(self.TENANT_ID, AuditFilters(), format="json")

        fetch_sql = mock_conn_empty.fetch.call_args[0][0]
        assert "OFFSET" not in fetch_sql

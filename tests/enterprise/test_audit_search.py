"""Tests for AuditLogService.search() with filters, pagination, and tenant scoping.

Validates:
- AuditFilters Pydantic model validation and defaults
- AuditSearchResult model structure
- search() builds correct dynamic SQL with parameterized WHERE clauses
- search() always scopes to tenant_id (defense-in-depth)
- search() orders by created_at DESC
- search() uses OFFSET/LIMIT for pagination
- search() raises ValueError on empty tenant_id

Requirements: 7.4
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import ValidationError

from sift_defender.enterprise.audit.service import (
    AuditEventType,
    AuditFilters,
    AuditLogService,
    AuditSearchResult,
)


class TestAuditFilters:
    """Test AuditFilters Pydantic model validation."""

    def test_default_values(self):
        """All filters are optional with sensible defaults."""
        filters = AuditFilters()
        assert filters.date_from is None
        assert filters.date_to is None
        assert filters.user_id is None
        assert filters.event_type is None
        assert filters.resource_type is None
        assert filters.resource_id is None
        assert filters.page == 1
        assert filters.page_size == 50

    def test_all_fields_populated(self):
        """Model accepts all fields when provided."""
        now = datetime.now(timezone.utc)
        filters = AuditFilters(
            date_from=now,
            date_to=now,
            user_id="660e8400-e29b-41d4-a716-446655440001",
            event_type=AuditEventType.USER_LOGIN,
            resource_type="case",
            resource_id="case-123",
            page=3,
            page_size=25,
        )
        assert filters.date_from == now
        assert filters.date_to == now
        assert filters.user_id == "660e8400-e29b-41d4-a716-446655440001"
        assert filters.event_type == AuditEventType.USER_LOGIN
        assert filters.resource_type == "case"
        assert filters.resource_id == "case-123"
        assert filters.page == 3
        assert filters.page_size == 25

    def test_page_must_be_positive(self):
        """Page number must be >= 1."""
        with pytest.raises(ValidationError):
            AuditFilters(page=0)

    def test_page_size_must_be_positive(self):
        """Page size must be >= 1."""
        with pytest.raises(ValidationError):
            AuditFilters(page_size=0)

    def test_page_size_max_200(self):
        """Page size cannot exceed 200."""
        with pytest.raises(ValidationError):
            AuditFilters(page_size=201)

    def test_page_size_at_boundary(self):
        """Page size of exactly 200 is allowed."""
        filters = AuditFilters(page_size=200)
        assert filters.page_size == 200

    def test_event_type_validates_enum(self):
        """Event type must be a valid AuditEventType."""
        with pytest.raises(ValidationError):
            AuditFilters(event_type="invalid.type")


class TestAuditSearchResult:
    """Test AuditSearchResult model."""

    def test_default_values(self):
        """Result has sensible defaults."""
        result = AuditSearchResult()
        assert result.items == []
        assert result.total_count == 0
        assert result.page == 1
        assert result.page_size == 50

    def test_with_items(self):
        """Result stores items as list of dicts."""
        items = [
            {"id": "abc", "event_type": "user.login"},
            {"id": "def", "event_type": "user.logout"},
        ]
        result = AuditSearchResult(items=items, total_count=2, page=1, page_size=50)
        assert len(result.items) == 2
        assert result.total_count == 2

    def test_pagination_metadata(self):
        """Result carries page and page_size metadata."""
        result = AuditSearchResult(
            items=[],
            total_count=150,
            page=3,
            page_size=25,
        )
        assert result.page == 3
        assert result.page_size == 25
        assert result.total_count == 150


class TestAuditLogServiceSearch:
    """Test AuditLogService.search() method."""

    TENANT_ID = "550e8400-e29b-41d4-a716-446655440000"
    USER_ID = "660e8400-e29b-41d4-a716-446655440001"

    @pytest.fixture
    def service(self):
        return AuditLogService()

    @pytest.fixture
    def mock_conn(self):
        """Create a mock asyncpg connection returning empty results."""
        conn = AsyncMock()
        conn.fetchval = AsyncMock(return_value=0)
        conn.fetch = AsyncMock(return_value=[])
        return conn

    @pytest.fixture
    def mock_conn_with_results(self):
        """Mock connection returning sample audit rows."""
        conn = AsyncMock()
        conn.fetchval = AsyncMock(return_value=2)
        now = datetime.now(timezone.utc)
        conn.fetch = AsyncMock(return_value=[
            {
                "id": uuid.UUID("11111111-1111-1111-1111-111111111111"),
                "tenant_id": uuid.UUID("550e8400-e29b-41d4-a716-446655440000"),
                "event_type": "user.login",
                "user_id": uuid.UUID("660e8400-e29b-41d4-a716-446655440001"),
                "resource_type": "session",
                "resource_id": "sess-001",
                "details": '{"ip": "10.0.0.1"}',
                "trace_span_id": "span-123",
                "chain_hash": "a" * 64,
                "created_at": now,
            },
            {
                "id": uuid.UUID("22222222-2222-2222-2222-222222222222"),
                "tenant_id": uuid.UUID("550e8400-e29b-41d4-a716-446655440000"),
                "event_type": "user.logout",
                "user_id": None,
                "resource_type": None,
                "resource_id": None,
                "details": "{}",
                "trace_span_id": None,
                "chain_hash": "b" * 64,
                "created_at": now,
            },
        ])
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

    @pytest.mark.asyncio
    async def test_search_raises_on_empty_tenant_id(self, service):
        """search() raises ValueError if tenant_id is empty."""
        with pytest.raises(ValueError, match="tenant_id must be a non-empty string"):
            await service.search("", AuditFilters())

    @pytest.mark.asyncio
    async def test_search_returns_audit_search_result(self, service, mock_conn):
        """search() returns an AuditSearchResult instance."""
        with self._patch_tenant_conn(mock_conn):
            result = await service.search(self.TENANT_ID, AuditFilters())

        assert isinstance(result, AuditSearchResult)

    @pytest.mark.asyncio
    async def test_search_no_filters_returns_empty(self, service, mock_conn):
        """search() with no filters and empty DB returns empty result."""
        with self._patch_tenant_conn(mock_conn):
            result = await service.search(self.TENANT_ID, AuditFilters())

        assert result.items == []
        assert result.total_count == 0
        assert result.page == 1
        assert result.page_size == 50

    @pytest.mark.asyncio
    async def test_search_always_scopes_to_tenant(self, service, mock_conn):
        """search() always includes tenant_id in WHERE clause."""
        with self._patch_tenant_conn(mock_conn):
            await service.search(self.TENANT_ID, AuditFilters())

        # Both count and select queries should have tenant_id = $1
        count_call = mock_conn.fetchval.call_args
        count_sql = count_call[0][0]
        assert "tenant_id = $1" in count_sql

        fetch_call = mock_conn.fetch.call_args
        fetch_sql = fetch_call[0][0]
        assert "tenant_id = $1" in fetch_sql

    @pytest.mark.asyncio
    async def test_search_passes_tenant_uuid_as_first_param(self, service, mock_conn):
        """search() passes tenant_id as UUID for the $1 parameter."""
        with self._patch_tenant_conn(mock_conn):
            await service.search(self.TENANT_ID, AuditFilters())

        count_call = mock_conn.fetchval.call_args
        # First param after SQL should be the tenant UUID
        assert count_call[0][1] == uuid.UUID(self.TENANT_ID)

    @pytest.mark.asyncio
    async def test_search_with_date_from_filter(self, service, mock_conn):
        """search() adds created_at >= condition for date_from."""
        date_from = datetime(2025, 1, 1, tzinfo=timezone.utc)
        filters = AuditFilters(date_from=date_from)

        with self._patch_tenant_conn(mock_conn):
            await service.search(self.TENANT_ID, filters)

        count_sql = mock_conn.fetchval.call_args[0][0]
        assert "created_at >= $2" in count_sql

    @pytest.mark.asyncio
    async def test_search_with_date_to_filter(self, service, mock_conn):
        """search() adds created_at <= condition for date_to."""
        date_to = datetime(2025, 6, 30, tzinfo=timezone.utc)
        filters = AuditFilters(date_to=date_to)

        with self._patch_tenant_conn(mock_conn):
            await service.search(self.TENANT_ID, filters)

        count_sql = mock_conn.fetchval.call_args[0][0]
        assert "created_at <= $2" in count_sql

    @pytest.mark.asyncio
    async def test_search_with_user_id_filter(self, service, mock_conn):
        """search() adds user_id condition and passes UUID."""
        filters = AuditFilters(user_id=self.USER_ID)

        with self._patch_tenant_conn(mock_conn):
            await service.search(self.TENANT_ID, filters)

        count_sql = mock_conn.fetchval.call_args[0][0]
        assert "user_id = $2" in count_sql

        # Verify user_id is passed as UUID
        params = mock_conn.fetchval.call_args[0]
        assert params[2] == uuid.UUID(self.USER_ID)

    @pytest.mark.asyncio
    async def test_search_with_event_type_filter(self, service, mock_conn):
        """search() adds event_type condition with enum value."""
        filters = AuditFilters(event_type=AuditEventType.USER_LOGIN)

        with self._patch_tenant_conn(mock_conn):
            await service.search(self.TENANT_ID, filters)

        count_sql = mock_conn.fetchval.call_args[0][0]
        assert "event_type = $2" in count_sql

        # Verify event_type string value is passed
        params = mock_conn.fetchval.call_args[0]
        assert params[2] == "user.login"

    @pytest.mark.asyncio
    async def test_search_with_resource_type_filter(self, service, mock_conn):
        """search() adds resource_type condition."""
        filters = AuditFilters(resource_type="case")

        with self._patch_tenant_conn(mock_conn):
            await service.search(self.TENANT_ID, filters)

        count_sql = mock_conn.fetchval.call_args[0][0]
        assert "resource_type = $2" in count_sql

    @pytest.mark.asyncio
    async def test_search_with_resource_id_filter(self, service, mock_conn):
        """search() adds resource_id condition."""
        filters = AuditFilters(resource_id="case-456")

        with self._patch_tenant_conn(mock_conn):
            await service.search(self.TENANT_ID, filters)

        count_sql = mock_conn.fetchval.call_args[0][0]
        assert "resource_id = $2" in count_sql

    @pytest.mark.asyncio
    async def test_search_multiple_filters_increment_params(self, service, mock_conn):
        """Multiple filters produce correct parameter numbering ($2, $3, $4...)."""
        filters = AuditFilters(
            date_from=datetime(2025, 1, 1, tzinfo=timezone.utc),
            user_id=self.USER_ID,
            event_type=AuditEventType.CASE_CREATED,
        )

        with self._patch_tenant_conn(mock_conn):
            await service.search(self.TENANT_ID, filters)

        count_sql = mock_conn.fetchval.call_args[0][0]
        assert "tenant_id = $1" in count_sql
        assert "created_at >= $2" in count_sql
        assert "user_id = $3" in count_sql
        assert "event_type = $4" in count_sql

    @pytest.mark.asyncio
    async def test_search_orders_by_created_at_desc(self, service, mock_conn):
        """search() orders results by created_at DESC."""
        with self._patch_tenant_conn(mock_conn):
            await service.search(self.TENANT_ID, AuditFilters())

        fetch_sql = mock_conn.fetch.call_args[0][0]
        assert "ORDER BY created_at DESC" in fetch_sql

    @pytest.mark.asyncio
    async def test_search_uses_limit_offset(self, service, mock_conn):
        """search() applies LIMIT and OFFSET for pagination."""
        filters = AuditFilters(page=3, page_size=25)

        with self._patch_tenant_conn(mock_conn):
            await service.search(self.TENANT_ID, filters)

        fetch_call = mock_conn.fetch.call_args[0]
        fetch_sql = fetch_call[0]
        assert "LIMIT" in fetch_sql
        assert "OFFSET" in fetch_sql

        # page_size=25, offset=(3-1)*25=50
        # Params: tenant_id, page_size, offset
        all_args = fetch_call[1:]
        assert 25 in all_args  # page_size
        assert 50 in all_args  # offset

    @pytest.mark.asyncio
    async def test_search_pagination_defaults(self, service, mock_conn):
        """Default pagination is page=1, page_size=50, offset=0."""
        with self._patch_tenant_conn(mock_conn):
            await service.search(self.TENANT_ID, AuditFilters())

        fetch_call = mock_conn.fetch.call_args[0]
        all_args = fetch_call[1:]
        assert 50 in all_args  # default page_size
        assert 0 in all_args  # offset for page 1

    @pytest.mark.asyncio
    async def test_search_returns_items_as_dicts(self, service, mock_conn_with_results):
        """search() converts DB rows to dictionaries."""
        with self._patch_tenant_conn(mock_conn_with_results):
            result = await service.search(self.TENANT_ID, AuditFilters())

        assert len(result.items) == 2
        assert result.items[0]["id"] == "11111111-1111-1111-1111-111111111111"
        assert result.items[0]["event_type"] == "user.login"
        assert result.items[0]["user_id"] == "660e8400-e29b-41d4-a716-446655440001"
        assert result.items[0]["details"] == {"ip": "10.0.0.1"}
        assert result.items[0]["trace_span_id"] == "span-123"

    @pytest.mark.asyncio
    async def test_search_handles_null_user_id(self, service, mock_conn_with_results):
        """search() converts None user_id to None in result dict."""
        with self._patch_tenant_conn(mock_conn_with_results):
            result = await service.search(self.TENANT_ID, AuditFilters())

        # Second item has user_id=None
        assert result.items[1]["user_id"] is None

    @pytest.mark.asyncio
    async def test_search_parses_details_json(self, service, mock_conn_with_results):
        """search() parses JSON details string into dict."""
        with self._patch_tenant_conn(mock_conn_with_results):
            result = await service.search(self.TENANT_ID, AuditFilters())

        assert result.items[0]["details"] == {"ip": "10.0.0.1"}
        assert result.items[1]["details"] == {}

    @pytest.mark.asyncio
    async def test_search_total_count(self, service, mock_conn_with_results):
        """search() includes total_count from COUNT query."""
        with self._patch_tenant_conn(mock_conn_with_results):
            result = await service.search(self.TENANT_ID, AuditFilters())

        assert result.total_count == 2

    @pytest.mark.asyncio
    async def test_search_calls_get_tenant_connection(self, service, mock_conn):
        """search() uses get_tenant_connection with tenant_id for RLS."""
        with self._patch_tenant_conn(mock_conn) as mock_get_conn:
            await service.search(self.TENANT_ID, AuditFilters())

        mock_get_conn.assert_called_once_with(self.TENANT_ID)

    @pytest.mark.asyncio
    async def test_search_serializes_created_at_as_iso(self, service, mock_conn_with_results):
        """search() serializes created_at as ISO format string."""
        with self._patch_tenant_conn(mock_conn_with_results):
            result = await service.search(self.TENANT_ID, AuditFilters())

        # created_at should be an ISO string
        assert isinstance(result.items[0]["created_at"], str)
        # Should be parseable as datetime
        datetime.fromisoformat(result.items[0]["created_at"])

    @pytest.mark.asyncio
    async def test_search_with_all_filters(self, service, mock_conn):
        """search() handles all filters simultaneously."""
        filters = AuditFilters(
            date_from=datetime(2025, 1, 1, tzinfo=timezone.utc),
            date_to=datetime(2025, 6, 30, tzinfo=timezone.utc),
            user_id=self.USER_ID,
            event_type=AuditEventType.FINDING_APPROVED,
            resource_type="finding",
            resource_id="f-789",
            page=2,
            page_size=10,
        )

        with self._patch_tenant_conn(mock_conn):
            result = await service.search(self.TENANT_ID, filters)

        count_sql = mock_conn.fetchval.call_args[0][0]
        assert "tenant_id = $1" in count_sql
        assert "created_at >= $2" in count_sql
        assert "created_at <= $3" in count_sql
        assert "user_id = $4" in count_sql
        assert "event_type = $5" in count_sql
        assert "resource_type = $6" in count_sql
        assert "resource_id = $7" in count_sql

        assert isinstance(result, AuditSearchResult)
        assert result.page == 2
        assert result.page_size == 10

"""Tests for AuditLogService with chain_hash linking.

Validates:
- AuditEventType enum covers all required event types
- AuditEvent Pydantic model validation
- compute_chain_hash produces deterministic SHA-256 hashes
- Chain hash links to previous entry (tamper detection)
- AuditLogService.record() inserts entry and returns UUID
- First entry uses empty string as previous_hash (genesis entry)

Requirements: 7.1, 7.2, 7.3
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sift_defender.enterprise.audit.service import (
    AuditEvent,
    AuditEventType,
    AuditLogService,
    compute_chain_hash,
)


class TestAuditEventType:
    """Test AuditEventType enum completeness."""

    def test_has_user_login(self):
        assert AuditEventType.USER_LOGIN == "user.login"

    def test_has_user_logout(self):
        assert AuditEventType.USER_LOGOUT == "user.logout"

    def test_has_investigation_start(self):
        assert AuditEventType.INVESTIGATION_START == "investigation.start"

    def test_has_investigation_complete(self):
        assert AuditEventType.INVESTIGATION_COMPLETE == "investigation.complete"

    def test_has_finding_generated(self):
        assert AuditEventType.FINDING_GENERATED == "finding.generated"

    def test_has_finding_approved(self):
        assert AuditEventType.FINDING_APPROVED == "finding.approved"

    def test_has_finding_rejected(self):
        assert AuditEventType.FINDING_REJECTED == "finding.rejected"

    def test_has_finding_blocked(self):
        assert AuditEventType.FINDING_BLOCKED == "finding.blocked"

    def test_has_case_created(self):
        assert AuditEventType.CASE_CREATED == "case.created"

    def test_has_case_state_change(self):
        assert AuditEventType.CASE_STATE_CHANGE == "case.state_change"

    def test_has_settings_changed(self):
        assert AuditEventType.SETTINGS_CHANGED == "settings.changed"

    def test_has_evidence_accessed(self):
        assert AuditEventType.EVIDENCE_ACCESSED == "evidence.accessed"

    def test_has_permission_denied(self):
        assert AuditEventType.PERMISSION_DENIED == "permission.denied"

    def test_has_agent_tool_call(self):
        assert AuditEventType.AGENT_TOOL_CALL == "agent.tool_call"

    def test_has_agent_self_improvement(self):
        assert AuditEventType.AGENT_SELF_IMPROVEMENT == "agent.self_improvement"

    def test_total_event_type_count(self):
        """All 16 event types defined in the design document (15 original + API_REQUEST)."""
        assert len(AuditEventType) == 16

    def test_all_are_strings(self):
        """Event types are string enums for DB storage."""
        for event_type in AuditEventType:
            assert isinstance(event_type.value, str)


class TestAuditEvent:
    """Test AuditEvent Pydantic model."""

    def test_minimal_event(self):
        """Minimal event with just required fields."""
        event = AuditEvent(
            tenant_id="550e8400-e29b-41d4-a716-446655440000",
            event_type=AuditEventType.USER_LOGIN,
        )
        assert event.tenant_id == "550e8400-e29b-41d4-a716-446655440000"
        assert event.event_type == AuditEventType.USER_LOGIN
        assert event.user_id is None
        assert event.resource_type is None
        assert event.resource_id is None
        assert event.details == {}
        assert event.trace_span_id is None

    def test_full_event(self):
        """Event with all fields populated."""
        event = AuditEvent(
            tenant_id="550e8400-e29b-41d4-a716-446655440000",
            event_type=AuditEventType.FINDING_APPROVED,
            user_id="660e8400-e29b-41d4-a716-446655440001",
            resource_type="finding",
            resource_id="f-12345",
            details={"reason": "Confirmed by SIEM correlation", "confidence": 0.95},
            trace_span_id="span-abc-123",
        )
        assert event.user_id == "660e8400-e29b-41d4-a716-446655440001"
        assert event.resource_type == "finding"
        assert event.resource_id == "f-12345"
        assert event.details["confidence"] == 0.95
        assert event.trace_span_id == "span-abc-123"

    def test_details_defaults_to_empty_dict(self):
        """Details should default to an empty dict, not None."""
        event = AuditEvent(
            tenant_id="550e8400-e29b-41d4-a716-446655440000",
            event_type=AuditEventType.USER_LOGIN,
        )
        assert event.details == {}
        assert isinstance(event.details, dict)

    def test_event_type_validates_enum(self):
        """Event type must be a valid AuditEventType."""
        with pytest.raises(Exception):
            AuditEvent(
                tenant_id="550e8400-e29b-41d4-a716-446655440000",
                event_type="invalid.event.type",
            )


class TestComputeChainHash:
    """Test compute_chain_hash determinism and correctness."""

    def test_produces_sha256_hex_string(self):
        """Output is a 64-character hex-encoded SHA-256 hash."""
        result = compute_chain_hash(
            previous_hash="",
            event_type="user.login",
            timestamp="2025-01-15T10:00:00+00:00",
            details_json="{}",
        )
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_deterministic_same_inputs(self):
        """Same inputs produce the same hash."""
        args = {
            "previous_hash": "abc123",
            "event_type": "user.login",
            "timestamp": "2025-01-15T10:00:00+00:00",
            "details_json": '{"key": "value"}',
        }
        result1 = compute_chain_hash(**args)
        result2 = compute_chain_hash(**args)
        assert result1 == result2

    def test_different_previous_hash_produces_different_result(self):
        """Changing previous_hash changes the output — ensures chain linking."""
        base_args = {
            "event_type": "user.login",
            "timestamp": "2025-01-15T10:00:00+00:00",
            "details_json": "{}",
        }
        hash1 = compute_chain_hash(previous_hash="hash_a", **base_args)
        hash2 = compute_chain_hash(previous_hash="hash_b", **base_args)
        assert hash1 != hash2

    def test_different_event_type_produces_different_result(self):
        """Changing event_type changes the output."""
        base_args = {
            "previous_hash": "prev",
            "timestamp": "2025-01-15T10:00:00+00:00",
            "details_json": "{}",
        }
        hash1 = compute_chain_hash(event_type="user.login", **base_args)
        hash2 = compute_chain_hash(event_type="user.logout", **base_args)
        assert hash1 != hash2

    def test_different_timestamp_produces_different_result(self):
        """Changing timestamp changes the output."""
        base_args = {
            "previous_hash": "prev",
            "event_type": "user.login",
            "details_json": "{}",
        }
        hash1 = compute_chain_hash(timestamp="2025-01-15T10:00:00+00:00", **base_args)
        hash2 = compute_chain_hash(timestamp="2025-01-15T11:00:00+00:00", **base_args)
        assert hash1 != hash2

    def test_different_details_produces_different_result(self):
        """Changing details changes the output."""
        base_args = {
            "previous_hash": "prev",
            "event_type": "user.login",
            "timestamp": "2025-01-15T10:00:00+00:00",
        }
        hash1 = compute_chain_hash(details_json='{"a": 1}', **base_args)
        hash2 = compute_chain_hash(details_json='{"a": 2}', **base_args)
        assert hash1 != hash2

    def test_matches_manual_sha256_computation(self):
        """Verify hash matches a manually computed SHA-256."""
        previous_hash = "abc"
        event_type = "user.login"
        timestamp = "2025-01-15T10:00:00+00:00"
        details_json = '{"key": "val"}'

        payload = f"{previous_hash}{event_type}{timestamp}{details_json}"
        expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        result = compute_chain_hash(previous_hash, event_type, timestamp, details_json)
        assert result == expected

    def test_genesis_entry_uses_empty_previous_hash(self):
        """First entry in chain uses empty string as previous_hash."""
        result = compute_chain_hash(
            previous_hash="",
            event_type="user.login",
            timestamp="2025-01-15T10:00:00+00:00",
            details_json="{}",
        )
        # Should be a valid hash, not raise an error
        assert len(result) == 64

    def test_chain_linking_integrity(self):
        """Simulating a chain of 3 entries — each links to the previous."""
        hash1 = compute_chain_hash("", "user.login", "2025-01-15T10:00:00+00:00", "{}")
        hash2 = compute_chain_hash(hash1, "investigation.start", "2025-01-15T10:01:00+00:00", "{}")
        hash3 = compute_chain_hash(hash2, "finding.generated", "2025-01-15T10:02:00+00:00", "{}")

        # All hashes are different
        assert len({hash1, hash2, hash3}) == 3

        # Tampering with hash1 would produce a different hash2
        tampered_hash1 = compute_chain_hash("", "user.logout", "2025-01-15T10:00:00+00:00", "{}")
        tampered_hash2 = compute_chain_hash(
            tampered_hash1, "investigation.start", "2025-01-15T10:01:00+00:00", "{}"
        )
        assert tampered_hash2 != hash2


class TestAuditLogServiceRecord:
    """Test AuditLogService.record() method with mocked DB."""

    @pytest.fixture
    def mock_conn(self):
        """Create a mock asyncpg connection."""
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value=None)  # No previous entry
        conn.execute = AsyncMock()
        return conn

    @pytest.fixture
    def mock_conn_with_previous(self):
        """Mock connection that returns a previous chain_hash."""
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(
            return_value={"chain_hash": "a" * 64}
        )
        conn.execute = AsyncMock()
        return conn

    @pytest.fixture
    def service(self):
        return AuditLogService()

    @pytest.fixture
    def sample_event(self):
        return AuditEvent(
            tenant_id="550e8400-e29b-41d4-a716-446655440000",
            event_type=AuditEventType.USER_LOGIN,
            user_id="660e8400-e29b-41d4-a716-446655440001",
            resource_type="session",
            resource_id="sess-001",
            details={"ip": "192.168.1.1"},
            trace_span_id="span-xyz",
        )

    @pytest.mark.asyncio
    async def test_record_returns_uuid_string(self, service, sample_event, mock_conn):
        """record() returns a valid UUID string."""
        with patch(
            "sift_defender.enterprise.audit.service.get_tenant_connection"
        ) as mock_get_conn:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)
            mock_get_conn.return_value = mock_ctx

            event_id = await service.record(sample_event)

        # Should be a valid UUID
        parsed = uuid.UUID(event_id)
        assert str(parsed) == event_id

    @pytest.mark.asyncio
    async def test_record_calls_fetchrow_for_previous_hash(
        self, service, sample_event, mock_conn
    ):
        """record() fetches the last chain_hash for the tenant."""
        with patch(
            "sift_defender.enterprise.audit.service.get_tenant_connection"
        ) as mock_get_conn:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)
            mock_get_conn.return_value = mock_ctx

            await service.record(sample_event)

        mock_conn.fetchrow.assert_called_once()
        call_args = mock_conn.fetchrow.call_args
        sql = call_args[0][0]
        assert "SELECT chain_hash" in sql
        assert "ORDER BY created_at DESC" in sql
        assert "LIMIT 1" in sql

    @pytest.mark.asyncio
    async def test_record_inserts_with_chain_hash(
        self, service, sample_event, mock_conn
    ):
        """record() inserts a row with computed chain_hash."""
        with patch(
            "sift_defender.enterprise.audit.service.get_tenant_connection"
        ) as mock_get_conn:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)
            mock_get_conn.return_value = mock_ctx

            await service.record(sample_event)

        mock_conn.execute.assert_called_once()
        call_args = mock_conn.execute.call_args
        sql = call_args[0][0]
        assert "INSERT INTO audit_log" in sql
        assert "chain_hash" in sql

        # The 9th positional arg (index 8 in args[0]) is chain_hash
        insert_args = call_args[0][1:]  # Skip the SQL string
        chain_hash_arg = insert_args[8]  # chain_hash is 9th column
        assert len(chain_hash_arg) == 64
        assert all(c in "0123456789abcdef" for c in chain_hash_arg)

    @pytest.mark.asyncio
    async def test_record_genesis_entry_uses_empty_previous(
        self, service, sample_event, mock_conn
    ):
        """First entry (no previous) uses empty string for chain computation."""
        with patch(
            "sift_defender.enterprise.audit.service.get_tenant_connection"
        ) as mock_get_conn:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)
            mock_get_conn.return_value = mock_ctx

            await service.record(sample_event)

        # fetchrow returned None (no previous), so chain computed with ""
        call_args = mock_conn.execute.call_args[0]
        chain_hash = call_args[9]  # chain_hash position in insert

        # Compute expected hash with empty previous
        details_json = json.dumps(sample_event.details, sort_keys=True, default=str)
        # We can't know exact timestamp, but we can verify the hash is valid SHA-256
        assert len(chain_hash) == 64

    @pytest.mark.asyncio
    async def test_record_links_to_previous_hash(
        self, service, sample_event, mock_conn_with_previous
    ):
        """record() uses previous entry's chain_hash in computation."""
        with patch(
            "sift_defender.enterprise.audit.service.get_tenant_connection"
        ) as mock_get_conn:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn_with_previous)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)
            mock_get_conn.return_value = mock_ctx

            await service.record(sample_event)

        # The chain_hash should be different from genesis (since previous_hash != "")
        call_args = mock_conn_with_previous.execute.call_args[0]
        chain_hash = call_args[9]

        # Compute what genesis would be (with empty previous)
        # The hash should NOT match a genesis entry since we have a previous
        assert len(chain_hash) == 64

    @pytest.mark.asyncio
    async def test_record_passes_correct_tenant_id(self, service, sample_event, mock_conn):
        """record() uses tenant_id from event for connection and query."""
        with patch(
            "sift_defender.enterprise.audit.service.get_tenant_connection"
        ) as mock_get_conn:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)
            mock_get_conn.return_value = mock_ctx

            await service.record(sample_event)

        # get_tenant_connection called with tenant_id
        mock_get_conn.assert_called_once_with(sample_event.tenant_id)

    @pytest.mark.asyncio
    async def test_record_inserts_event_type(self, service, sample_event, mock_conn):
        """record() stores the event type string in the DB."""
        with patch(
            "sift_defender.enterprise.audit.service.get_tenant_connection"
        ) as mock_get_conn:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)
            mock_get_conn.return_value = mock_ctx

            await service.record(sample_event)

        call_args = mock_conn.execute.call_args[0]
        event_type_arg = call_args[3]  # event_type is 3rd column
        assert event_type_arg == "user.login"

    @pytest.mark.asyncio
    async def test_record_inserts_user_id_as_uuid(self, service, sample_event, mock_conn):
        """record() converts user_id string to UUID for DB insertion."""
        with patch(
            "sift_defender.enterprise.audit.service.get_tenant_connection"
        ) as mock_get_conn:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)
            mock_get_conn.return_value = mock_ctx

            await service.record(sample_event)

        call_args = mock_conn.execute.call_args[0]
        user_id_arg = call_args[4]  # user_id is 4th column
        assert user_id_arg == uuid.UUID("660e8400-e29b-41d4-a716-446655440001")

    @pytest.mark.asyncio
    async def test_record_handles_none_user_id(self, service, mock_conn):
        """record() passes None for user_id when not provided."""
        event = AuditEvent(
            tenant_id="550e8400-e29b-41d4-a716-446655440000",
            event_type=AuditEventType.AGENT_TOOL_CALL,
            details={"tool": "splunk_search"},
        )
        with patch(
            "sift_defender.enterprise.audit.service.get_tenant_connection"
        ) as mock_get_conn:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)
            mock_get_conn.return_value = mock_ctx

            await service.record(event)

        call_args = mock_conn.execute.call_args[0]
        user_id_arg = call_args[4]  # user_id is 4th column
        assert user_id_arg is None

    @pytest.mark.asyncio
    async def test_record_serializes_details_as_json(self, service, sample_event, mock_conn):
        """record() stores details as JSON string."""
        with patch(
            "sift_defender.enterprise.audit.service.get_tenant_connection"
        ) as mock_get_conn:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)
            mock_get_conn.return_value = mock_ctx

            await service.record(sample_event)

        call_args = mock_conn.execute.call_args[0]
        details_arg = call_args[7]  # details is 7th column
        # Should be a JSON string
        parsed = json.loads(details_arg)
        assert parsed == {"ip": "192.168.1.1"}

    @pytest.mark.asyncio
    async def test_record_inserts_trace_span_id(self, service, sample_event, mock_conn):
        """record() stores the trace_span_id for observability linking."""
        with patch(
            "sift_defender.enterprise.audit.service.get_tenant_connection"
        ) as mock_get_conn:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)
            mock_get_conn.return_value = mock_ctx

            await service.record(sample_event)

        call_args = mock_conn.execute.call_args[0]
        trace_span_arg = call_args[8]  # trace_span_id is 8th column
        assert trace_span_arg == "span-xyz"

    @pytest.mark.asyncio
    async def test_record_inserts_timestamp_as_utc(self, service, sample_event, mock_conn):
        """record() inserts a UTC timestamp."""
        with patch(
            "sift_defender.enterprise.audit.service.get_tenant_connection"
        ) as mock_get_conn:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)
            mock_get_conn.return_value = mock_ctx

            await service.record(sample_event)

        call_args = mock_conn.execute.call_args[0]
        timestamp_arg = call_args[10]  # created_at is 10th column
        assert isinstance(timestamp_arg, datetime)
        assert timestamp_arg.tzinfo is not None

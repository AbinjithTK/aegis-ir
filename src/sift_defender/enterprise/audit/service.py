"""Audit Log Service — append-only, tamper-resistant event recording.

Implements chain hashing (SHA-256) where each entry's hash links to the previous
entry's hash, forming a tamper-evident chain. If any record is modified, all
subsequent chain hashes become invalid.

Requirements:
    7.1 - Record every user action and agent decision with full context
    7.2 - Record every agent decision with associated trace span ID
    7.3 - Append-only, tamper-resistant log with chain hash linking
    7.4 - Audit log search and export filtered by date range, user, action type, case ID
    7.5 - Export with SHA-256 hash of contents for integrity verification
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

from sift_defender.enterprise.db import get_tenant_connection

logger = logging.getLogger(__name__)


class AuditEventType(str, Enum):
    """All auditable event types in the AEGIS-IR platform."""

    USER_LOGIN = "user.login"
    USER_LOGOUT = "user.logout"
    INVESTIGATION_START = "investigation.start"
    INVESTIGATION_COMPLETE = "investigation.complete"
    FINDING_GENERATED = "finding.generated"
    FINDING_APPROVED = "finding.approved"
    FINDING_REJECTED = "finding.rejected"
    FINDING_BLOCKED = "finding.blocked"
    CASE_CREATED = "case.created"
    CASE_STATE_CHANGE = "case.state_change"
    SETTINGS_CHANGED = "settings.changed"
    EVIDENCE_ACCESSED = "evidence.accessed"
    PERMISSION_DENIED = "permission.denied"
    AGENT_TOOL_CALL = "agent.tool_call"
    AGENT_SELF_IMPROVEMENT = "agent.self_improvement"
    API_REQUEST = "api.request"


class AuditEvent(BaseModel):
    """Data model for an audit event to be recorded.

    Attributes:
        tenant_id: The tenant this event belongs to.
        event_type: Categorized event type from AuditEventType enum.
        user_id: The user who triggered the event (None for system/agent events).
        resource_type: The type of resource affected (e.g., "case", "investigation").
        resource_id: The identifier of the affected resource.
        details: Additional structured context about the event.
        trace_span_id: Phoenix trace span ID linking to observability data.
    """

    tenant_id: str
    event_type: AuditEventType
    user_id: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    details: dict[str, Any] = Field(default_factory=dict)
    trace_span_id: Optional[str] = None


class AuditFilters(BaseModel):
    """Filters for searching the audit log.

    All fields are optional — only provided filters narrow the result set.
    Pagination defaults to page 1 with 50 items per page (max 200).

    Attributes:
        date_from: Only return events created at or after this timestamp.
        date_to: Only return events created at or before this timestamp.
        user_id: Filter by the user who triggered the event.
        event_type: Filter by a specific event type.
        resource_type: Filter by the type of affected resource.
        resource_id: Filter by the specific resource identifier.
        page: Page number for pagination (1-indexed).
        page_size: Number of items per page (1–200, default 50).
    """

    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    user_id: Optional[str] = None
    event_type: Optional[AuditEventType] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=200)

    @field_validator("page_size")
    @classmethod
    def cap_page_size(cls, v: int) -> int:
        """Ensure page_size does not exceed 200."""
        if v > 200:
            return 200
        return v


class AuditSearchResult(BaseModel):
    """Paginated result from an audit log search.

    Attributes:
        items: List of audit event dictionaries for the current page.
        total_count: Total number of events matching the filters.
        page: Current page number.
        page_size: Number of items per page.
    """

    items: list[dict[str, Any]] = Field(default_factory=list)
    total_count: int = 0
    page: int = 1
    page_size: int = 50


class ExportResult(BaseModel):
    """Result of an audit log export operation.

    Contains the serialized content (CSV or JSON), format indicator,
    a SHA-256 integrity hash of the content, record count, and timestamp.

    Attributes:
        content: The serialized audit log data (CSV or JSON string).
        format: The export format used ("csv" or "json").
        integrity_hash: SHA-256 hex digest of the content for verification.
        record_count: Number of records included in the export.
        exported_at: UTC timestamp when the export was generated.
    """

    content: str
    format: str
    integrity_hash: str
    record_count: int
    exported_at: datetime


def compute_chain_hash(
    previous_hash: str,
    event_type: str,
    timestamp: str,
    details_json: str,
) -> str:
    """Compute SHA-256 chain hash linking to the previous entry.

    The chain hash is computed as:
        SHA-256(previous_hash + event_type + timestamp + details_json)

    This creates a tamper-evident chain — if any earlier record is modified,
    all subsequent chain hashes become invalid.

    Args:
        previous_hash: The chain_hash of the most recent prior entry for the
            tenant. Use empty string for the genesis entry.
        event_type: The event type string (e.g., "user.login").
        timestamp: ISO-8601 timestamp string of the event.
        details_json: JSON-serialized details dict (canonical form).

    Returns:
        Hex-encoded SHA-256 hash string.
    """
    payload = f"{previous_hash}{event_type}{timestamp}{details_json}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditLogService:
    """Append-only audit log service with integrity verification via chain hashing.

    Each recorded event includes a chain_hash computed from the previous entry's
    hash, the event type, timestamp, and details. This forms a tamper-evident
    chain per tenant.

    Usage:
        service = AuditLogService()
        event_id = await service.record(event)
    """

    async def record(self, event: AuditEvent) -> str:
        """Append an audit event to the log with chain hash linking.

        Steps:
            1. Generate a new UUID for the event.
            2. Generate the event timestamp (UTC).
            3. Fetch the most recent chain_hash for the tenant from the DB.
            4. Compute the new chain_hash = SHA-256(prev_hash + event_type + timestamp + details_json).
            5. Insert the record into the audit_log table.

        Args:
            event: The audit event to record.

        Returns:
            The UUID string of the newly created audit log entry.

        Raises:
            RuntimeError: If the database pool is not initialized.
        """
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc)
        timestamp_iso = timestamp.isoformat()

        # Canonical JSON serialization of details for deterministic hashing
        details_json = json.dumps(event.details, sort_keys=True, default=str)

        async with get_tenant_connection(event.tenant_id) as conn:
            # Fetch the last chain_hash for this tenant
            row = await conn.fetchrow(
                """
                SELECT chain_hash
                FROM audit_log
                WHERE tenant_id = $1
                ORDER BY created_at DESC
                LIMIT 1
                """,
                uuid.UUID(event.tenant_id),
            )
            previous_hash = row["chain_hash"] if row and row["chain_hash"] else ""

            # Compute the new chain hash
            chain_hash = compute_chain_hash(
                previous_hash=previous_hash,
                event_type=event.event_type.value,
                timestamp=timestamp_iso,
                details_json=details_json,
            )

            # Insert the audit log entry
            await conn.execute(
                """
                INSERT INTO audit_log (
                    id, tenant_id, event_type, user_id, resource_type,
                    resource_id, details, trace_span_id, chain_hash, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                """,
                uuid.UUID(event_id),
                uuid.UUID(event.tenant_id),
                event.event_type.value,
                uuid.UUID(event.user_id) if event.user_id else None,
                event.resource_type,
                event.resource_id,
                details_json,
                event.trace_span_id,
                chain_hash,
                timestamp,
            )

        logger.info(
            "Audit event recorded",
            extra={
                "event_id": event_id,
                "event_type": event.event_type.value,
                "tenant_id": event.tenant_id,
                "chain_hash": chain_hash[:16] + "...",
            },
        )

        return event_id

    async def search(self, tenant_id: str, filters: AuditFilters) -> AuditSearchResult:
        """Search audit log entries with filters and tenant scoping.

        Builds a dynamic SQL query based on provided filters. Always scopes
        results to the specified tenant_id for defense-in-depth (on top of RLS).
        Results are ordered by created_at DESC and paginated.

        Args:
            tenant_id: The tenant to scope results to.
            filters: Optional search filters (date range, user, event type, etc.).

        Returns:
            AuditSearchResult with matching items, total count, and pagination info.

        Raises:
            RuntimeError: If the database pool is not initialized.
            ValueError: If tenant_id is empty.
        """
        if not tenant_id:
            raise ValueError("tenant_id must be a non-empty string.")

        # Build dynamic WHERE clause
        conditions = ["tenant_id = $1"]
        params: list[Any] = [uuid.UUID(tenant_id)]
        param_idx = 2  # Next parameter index ($2, $3, ...)

        if filters.date_from is not None:
            conditions.append(f"created_at >= ${param_idx}")
            params.append(filters.date_from)
            param_idx += 1

        if filters.date_to is not None:
            conditions.append(f"created_at <= ${param_idx}")
            params.append(filters.date_to)
            param_idx += 1

        if filters.user_id is not None:
            conditions.append(f"user_id = ${param_idx}")
            params.append(uuid.UUID(filters.user_id))
            param_idx += 1

        if filters.event_type is not None:
            conditions.append(f"event_type = ${param_idx}")
            params.append(filters.event_type.value)
            param_idx += 1

        if filters.resource_type is not None:
            conditions.append(f"resource_type = ${param_idx}")
            params.append(filters.resource_type)
            param_idx += 1

        if filters.resource_id is not None:
            conditions.append(f"resource_id = ${param_idx}")
            params.append(filters.resource_id)
            param_idx += 1

        where_clause = " AND ".join(conditions)

        # Calculate pagination offset
        offset = (filters.page - 1) * filters.page_size

        async with get_tenant_connection(tenant_id) as conn:
            # Get total count for pagination metadata
            count_sql = f"SELECT COUNT(*) FROM audit_log WHERE {where_clause}"
            total_count = await conn.fetchval(count_sql, *params)

            # Fetch paginated results ordered by created_at DESC
            query_sql = (
                f"SELECT id, tenant_id, event_type, user_id, resource_type, "
                f"resource_id, details, trace_span_id, chain_hash, created_at "
                f"FROM audit_log WHERE {where_clause} "
                f"ORDER BY created_at DESC "
                f"LIMIT ${param_idx} OFFSET ${param_idx + 1}"
            )
            rows = await conn.fetch(query_sql, *params, filters.page_size, offset)

        # Convert rows to dictionaries
        items = []
        for row in rows:
            item = {
                "id": str(row["id"]),
                "tenant_id": str(row["tenant_id"]),
                "event_type": row["event_type"],
                "user_id": str(row["user_id"]) if row["user_id"] else None,
                "resource_type": row["resource_type"],
                "resource_id": row["resource_id"],
                "details": json.loads(row["details"]) if row["details"] else {},
                "trace_span_id": row["trace_span_id"],
                "chain_hash": row["chain_hash"],
                "created_at": row["created_at"].isoformat()
                if row["created_at"]
                else None,
            }
            items.append(item)

        logger.info(
            "Audit search completed",
            extra={
                "tenant_id": tenant_id,
                "total_count": total_count,
                "page": filters.page,
                "page_size": filters.page_size,
                "results_returned": len(items),
            },
        )

        return AuditSearchResult(
            items=items,
            total_count=total_count or 0,
            page=filters.page,
            page_size=filters.page_size,
        )

    async def export(
        self, tenant_id: str, filters: AuditFilters, format: str = "json"
    ) -> ExportResult:
        """Export audit log entries in CSV or JSON format with integrity hash.

        Fetches ALL matching records (up to a safety cap of 10,000) without
        pagination and serializes them in the requested format. A SHA-256 hash
        of the serialized content is computed for integrity verification.

        Args:
            tenant_id: The tenant to scope results to.
            filters: Search filters (date range, user, event type, etc.).
            format: Export format — "csv" or "json". Defaults to "json".

        Returns:
            ExportResult containing the serialized content, format, integrity
            hash, record count, and export timestamp.

        Raises:
            ValueError: If tenant_id is empty or format is not "csv"/"json".
            RuntimeError: If the database pool is not initialized.
        """
        if not tenant_id:
            raise ValueError("tenant_id must be a non-empty string.")

        if format not in ("csv", "json"):
            raise ValueError(f"Unsupported export format: '{format}'. Must be 'csv' or 'json'.")

        # Safety cap — export at most 10,000 records
        max_export_records = 10_000

        # Build dynamic WHERE clause (same logic as search)
        conditions = ["tenant_id = $1"]
        params: list[Any] = [uuid.UUID(tenant_id)]
        param_idx = 2

        if filters.date_from is not None:
            conditions.append(f"created_at >= ${param_idx}")
            params.append(filters.date_from)
            param_idx += 1

        if filters.date_to is not None:
            conditions.append(f"created_at <= ${param_idx}")
            params.append(filters.date_to)
            param_idx += 1

        if filters.user_id is not None:
            conditions.append(f"user_id = ${param_idx}")
            params.append(uuid.UUID(filters.user_id))
            param_idx += 1

        if filters.event_type is not None:
            conditions.append(f"event_type = ${param_idx}")
            params.append(filters.event_type.value)
            param_idx += 1

        if filters.resource_type is not None:
            conditions.append(f"resource_type = ${param_idx}")
            params.append(filters.resource_type)
            param_idx += 1

        if filters.resource_id is not None:
            conditions.append(f"resource_id = ${param_idx}")
            params.append(filters.resource_id)
            param_idx += 1

        where_clause = " AND ".join(conditions)

        async with get_tenant_connection(tenant_id) as conn:
            query_sql = (
                f"SELECT id, tenant_id, event_type, user_id, resource_type, "
                f"resource_id, details, trace_span_id, chain_hash, created_at "
                f"FROM audit_log WHERE {where_clause} "
                f"ORDER BY created_at DESC "
                f"LIMIT ${param_idx}"
            )
            rows = await conn.fetch(query_sql, *params, max_export_records)

        # Convert rows to dictionaries
        records: list[dict[str, Any]] = []
        for row in rows:
            record = {
                "id": str(row["id"]),
                "tenant_id": str(row["tenant_id"]),
                "event_type": row["event_type"],
                "user_id": str(row["user_id"]) if row["user_id"] else None,
                "resource_type": row["resource_type"],
                "resource_id": row["resource_id"],
                "details": json.loads(row["details"]) if row["details"] else {},
                "trace_span_id": row["trace_span_id"],
                "chain_hash": row["chain_hash"],
                "created_at": row["created_at"].isoformat()
                if row["created_at"]
                else None,
            }
            records.append(record)

        # Serialize to the requested format
        if format == "json":
            content = json.dumps(records, indent=2, default=str)
        else:
            # CSV format with fixed column order
            csv_columns = [
                "id", "tenant_id", "event_type", "user_id", "resource_type",
                "resource_id", "details", "trace_span_id", "chain_hash", "created_at",
            ]
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=csv_columns)
            writer.writeheader()
            for record in records:
                # Serialize details dict to JSON string for CSV
                csv_row = {**record, "details": json.dumps(record["details"], default=str)}
                writer.writerow(csv_row)
            content = output.getvalue()

        # Compute SHA-256 integrity hash of the content
        integrity_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

        exported_at = datetime.now(timezone.utc)

        logger.info(
            "Audit export completed",
            extra={
                "tenant_id": tenant_id,
                "format": format,
                "record_count": len(records),
                "integrity_hash": integrity_hash[:16] + "...",
            },
        )

        return ExportResult(
            content=content,
            format=format,
            integrity_hash=integrity_hash,
            record_count=len(records),
            exported_at=exported_at,
        )

"""Observability API routes for AEGIS-IR Enterprise Platform.

Provides endpoints for embedded observability panels:
- Trace viewer (live spans for active investigations)
- Accuracy trend (30-day rolling metrics)
- Evaluation summary (per-investigation guardrail results)
- Tool effectiveness (tool → outcome correlations)

All endpoints require appropriate RBAC permissions and are tenant-scoped.

Requirements: 1.1, 2.1, 3.1, 3.2, 15.4
"""

from __future__ import annotations

import logging
from dataclasses import asdict
from datetime import date, datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from sift_defender.enterprise.auth.dependencies import User, require_permission
from sift_defender.enterprise.auth.rbac import Permission

# Use relative import to avoid circular import through __init__.py
from .aggregator import ObservabilityAggregator, SpanSummary

logger = logging.getLogger(__name__)

observability_router = APIRouter(
    prefix="/api/observability",
    tags=["observability"],
)

# Alias for package-level import compatibility
router = observability_router


def _get_aggregator(user: User) -> ObservabilityAggregator:
    """Create an ObservabilityAggregator scoped to the user's tenant.

    Uses None as the phoenix_client for now — in production this would
    be resolved from a connection pool or service registry.
    """
    # In production, resolve phoenix_client from app state or DI container.
    # For now we pass a placeholder that the aggregator handles gracefully.
    try:
        from sift_defender.phoenix.tracer import PhoenixTracer

        phoenix = PhoenixTracer.get_instance()
        client = phoenix.client if hasattr(phoenix, "client") else None
    except Exception:
        client = None

    return ObservabilityAggregator(
        phoenix_client=client if client is not None else "http://localhost:6006",
        tenant_id=user.tenant_id,
    )


# --- Response Models ---


class DayAccuracyResponse(BaseModel):
    """Single day's accuracy metrics."""

    date: date
    approved_count: int
    flagged_count: int
    blocked_count: int
    total: int
    pass_rate: float
    flag_rate: float
    block_rate: float


class AccuracyTrendResponse(BaseModel):
    """Accuracy trend over a multi-day window."""

    days: list[DayAccuracyResponse]
    rolling_average: float
    total_evaluated: int = 0


class SpanSummaryResponse(BaseModel):
    """Pydantic response model for a single trace span summary."""

    span_id: str
    name: str
    duration_ms: float
    status: str
    start_time: datetime
    end_time: datetime
    attributes: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_dataclass(cls, span: SpanSummary) -> "SpanSummaryResponse":
        """Convert a SpanSummary dataclass to a response model."""
        return cls(
            span_id=span.span_id,
            name=span.name,
            duration_ms=span.duration_ms,
            status=span.status,
            start_time=span.start_time,
            end_time=span.end_time,
            attributes=span.attributes,
        )


# --- Endpoints ---


@observability_router.get("/accuracy-trend", response_model=AccuracyTrendResponse)
async def get_accuracy_trend(
    days: int = Query(default=30, ge=1, le=90, description="Number of days to look back (1-90)"),
    user: User = Depends(require_permission(Permission.AUDIT_VIEW)),
) -> AccuracyTrendResponse:
    """Get accuracy trend data for the guardrail pipeline.

    Returns daily pass/flag/block rates and a 7-day rolling average.
    Requires AUDIT_VIEW permission (available to IR_Lead and CISO roles).

    Requirements: 2.1
    """
    aggregator = _get_aggregator(user)
    trend = await aggregator.get_accuracy_trend(days=days)

    day_responses = [
        DayAccuracyResponse(
            date=d.date,
            approved_count=d.approved_count,
            flagged_count=d.flagged_count,
            blocked_count=d.blocked_count,
            total=d.total,
            pass_rate=d.pass_rate,
            flag_rate=d.flag_rate,
            block_rate=d.block_rate,
        )
        for d in trend.days
    ]

    return AccuracyTrendResponse(
        days=day_responses,
        rolling_average=trend.rolling_average,
        total_evaluated=trend.total_evaluated,
    )


@observability_router.get(
    "/traces/{case_id}",
    response_model=list[SpanSummaryResponse],
    summary="Get live spans for an active investigation",
    description=(
        "Returns real-time trace spans for a specific case/investigation. "
        "Requires INVESTIGATE_VIEW permission."
    ),
)
async def get_traces(
    case_id: str,
    since: Optional[datetime] = Query(
        default=None,
        description="ISO datetime to query spans from. Defaults to 5 minutes ago.",
    ),
    user: User = Depends(require_permission(Permission.INVESTIGATE_VIEW)),
) -> list[SpanSummaryResponse]:
    """Get live spans for an active investigation.

    Creates an ObservabilityAggregator scoped to the user's tenant and queries
    Phoenix for spans associated with the given case_id since the specified time.

    Args:
        case_id: The case/investigation identifier to filter spans.
        since: ISO datetime cutoff. Defaults to 5 minutes ago if not provided.
        user: Authenticated user with INVESTIGATE_VIEW permission.

    Returns:
        List of SpanSummary objects as JSON.

    Requirements: 1.1, 1.4
    """
    if since is None:
        since = datetime.now(timezone.utc) - timedelta(minutes=5)

    aggregator = _get_aggregator(user)
    spans = await aggregator.get_live_spans(case_id=case_id, since=since)

    return [SpanSummaryResponse.from_dataclass(span) for span in spans]


@observability_router.get("/investigation/{investigation_id}/evals")
async def get_investigation_evals(
    investigation_id: str,
    user: User = Depends(require_permission(Permission.INVESTIGATE_VIEW)),
) -> dict[str, Any]:
    """Get evaluation summary for a specific investigation.

    Returns per-finding evaluation details including score, label, action,
    and any issues identified by the guardrail pipeline.

    Args:
        investigation_id: The investigation/case identifier.
        user: Authenticated user with INVESTIGATE_VIEW permission.

    Returns:
        JSON response with total/approved/flagged/blocked counts and
        a list of per-finding evaluation details.

    Requirements: 3.1, 3.2
    """
    aggregator = _get_aggregator(user)
    eval_summary = await aggregator.get_investigation_eval_summary(investigation_id)

    return {
        "investigation_id": investigation_id,
        "total": eval_summary.total,
        "approved": eval_summary.approved,
        "flagged": eval_summary.flagged,
        "blocked": eval_summary.blocked,
        "findings": [
            {
                "finding_id": finding.finding_id,
                "score": finding.score,
                "label": finding.label,
                "action": finding.action,
                "issues": finding.issues,
            }
            for finding in eval_summary.findings
        ],
    }

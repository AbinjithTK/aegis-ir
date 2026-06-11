"""Observability Aggregator for AEGIS-IR Enterprise Platform.

Bridges Phoenix Client SDK to the dashboard, providing pre-aggregated
observability data without requiring users to query Phoenix directly.

Each tenant is isolated via a dedicated Phoenix project namespace
(aegis-ir-{tenant_id}), preventing observability data leakage between tenants.

Requirements: 1.4, 2.1, 3.4, 8.3, 15.4
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)


# --- Data Models ---


@dataclass
class SpanSummary:
    """Summary of a single trace span from Phoenix."""

    span_id: str
    name: str
    duration_ms: float
    status: str
    start_time: datetime
    end_time: datetime
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class DayAccuracy:
    """Accuracy metrics for a single day."""

    date: date
    approved_count: int
    flagged_count: int
    blocked_count: int
    total: int
    pass_rate: float
    flag_rate: float
    block_rate: float


@dataclass
class AccuracyTrend:
    """Accuracy trend over a multi-day window."""

    days: list[DayAccuracy]
    rolling_average: float
    total_evaluated: int = 0


@dataclass
class EvalDetail:
    """Evaluation detail for a single finding."""

    finding_id: str
    score: float
    label: str
    action: str
    issues: list[str] = field(default_factory=list)


@dataclass
class EvalSummary:
    """Aggregated evaluation results for an investigation."""

    total: int
    approved: int
    flagged: int
    blocked: int
    findings: list[EvalDetail] = field(default_factory=list)


@dataclass
class ToolStats:
    """Effectiveness statistics for a single agent tool."""

    tool_name: str
    confirmed_count: int
    blocked_count: int
    flagged_count: int
    total_count: int
    effectiveness_ratio: float


@dataclass
class _CacheEntry:
    """Internal cache entry storing a result with its insertion timestamp."""

    timestamp: float
    result: Any


# --- ObservabilityAggregator ---


class ObservabilityAggregator:
    """Aggregates Phoenix trace data for dashboard consumption.

    Requirements: 1.4, 8.3, 15.4
    """

    def __init__(self, phoenix_client: Any, tenant_id: str) -> None:
        """Initialize with tenant-specific project namespace."""
        if not tenant_id:
            raise ValueError("tenant_id must be a non-empty string")

        if isinstance(phoenix_client, str):
            self.client = None
            self.endpoint_url: str | None = phoenix_client
        else:
            self.client = phoenix_client
            self.endpoint_url = None

        self.tenant_id = tenant_id
        self.project_name = f"aegis-ir-{tenant_id}"

        # In-memory cache for accuracy trend results. Keyed by (tenant_id, days).
        # Each entry stores a _CacheEntry with timestamp and result.
        # TTL: 60 seconds. Requirements: 2.1
        self._accuracy_cache: dict[tuple[str, int], _CacheEntry] = {}
        self._cache_ttl: float = 60.0  # seconds
        self._cache_lock: asyncio.Lock = asyncio.Lock()

    async def get_live_spans(
        self, case_id: str, since: datetime
    ) -> list[SpanSummary]:
        """Query Phoenix for spans since timestamp, filtered by project/case.
        Returns SpanSummary objects sorted chronologically. Requirements: 1.1
        """
        try:
            if self.client is None:
                return []
            df = self.client.query_spans(
                project_name=self.project_name,
                start_time=since,
            )
            if df is None or (hasattr(df, 'empty') and df.empty):
                return []
            filtered_df = self._filter_spans_by_case_live(df, case_id)
            if hasattr(filtered_df, 'empty') and filtered_df.empty:
                return []
            spans = []
            for _, row in filtered_df.iterrows():
                try:
                    span = self._row_to_span_summary_live(row)
                    spans.append(span)
                except (KeyError, ValueError, TypeError):
                    continue
            spans.sort(key=lambda s: s.start_time)
            return spans
        except Exception as exc:
            logger.warning('Failed to query Phoenix for live spans: %s', exc)
            return []

    def _filter_spans_by_case_live(self, df, case_id: str):
        """Filter spans DataFrame to those matching a case_id."""
        for col_name in ('metadata.case_id', 'attributes.case_id', 'case_id'):
            if col_name in df.columns:
                return df[df[col_name] == case_id]
        if 'attributes' in df.columns:
            mask = df['attributes'].apply(
                lambda attrs: isinstance(attrs, dict) and attrs.get('case_id') == case_id
            )
            return df[mask]
        return pd.DataFrame()

    def _row_to_span_summary_live(self, row) -> "SpanSummary":
        """Convert a single DataFrame row to a SpanSummary."""
        span_id = None
        for col in ('context.span_id', 'span_id', 'id'):
            if col in row.index and pd.notna(row[col]):
                span_id = str(row[col])
                break
        if span_id is None:
            raise KeyError('No span_id')
        name = str(row.get('name', 'unknown'))
        raw_start = raw_end = None
        for col in ('start_time', 'startTime'):
            if col in row.index and pd.notna(row[col]):
                raw_start = pd.Timestamp(row[col]).to_pydatetime()
                break
        for col in ('end_time', 'endTime'):
            if col in row.index and pd.notna(row[col]):
                raw_end = pd.Timestamp(row[col]).to_pydatetime()
                break
        if raw_start is None or raw_end is None:
            raise KeyError('Missing timestamps')
        duration_ms = (raw_end - raw_start).total_seconds() * 1000
        raw_status = str(row.get('status', 'UNSET')).upper().strip()
        if raw_status in ('OK', 'STATUS_CODE_OK', '1'):
            status = 'OK'
        elif raw_status in ('ERROR', 'STATUS_CODE_ERROR', '2'):
            status = 'ERROR'
        else:
            status = 'UNSET'
        attributes = {}
        if 'attributes' in row.index and isinstance(row['attributes'], dict):
            attributes = row['attributes']
        else:
            for col in row.index:
                if col.startswith(('attributes.', 'metadata.')) and pd.notna(row[col]):
                    key = col.split('.', 1)[1]
                    attributes[key] = row[col]
        return SpanSummary(
            span_id=span_id, name=name, duration_ms=duration_ms,
            status=status, start_time=raw_start, end_time=raw_end,
            attributes=attributes,
        )

    async def get_accuracy_trend(self, days: int = 30) -> AccuracyTrend:
        """Calculate pass/block/flag rates over time window.

        Queries Phoenix for guardrail evaluation spans within the specified
        number of days, groups them by date, and calculates daily metrics
        and a 7-day rolling average pass rate.

        Results are cached in-memory for 60 seconds keyed by (tenant_id, days)
        to reduce Phoenix API load. Concurrent callers are serialized via an
        asyncio lock to prevent redundant queries.

        Args:
            days: Number of days to look back. Defaults to 30.

        Returns:
            AccuracyTrend with daily breakdowns and rolling average.

        Requirements: 2.1, 2.3
        """
        cache_key = (self.tenant_id, days)

        async with self._cache_lock:
            # Check cache hit
            entry = self._accuracy_cache.get(cache_key)
            if entry is not None:
                age = time.monotonic() - entry.timestamp
                if age < self._cache_ttl:
                    return entry.result

            # Cache miss or expired - query Phoenix
            result = await self._fetch_accuracy_trend(days)

            # Store in cache
            self._accuracy_cache[cache_key] = _CacheEntry(
                timestamp=time.monotonic(),
                result=result,
            )

        return result

    def clear_cache(self) -> None:
        """Clear the accuracy trend cache.

        Useful for testing and manual cache invalidation.
        """
        self._accuracy_cache.clear()

    async def _fetch_accuracy_trend(self, days: int) -> AccuracyTrend:
        """Fetch accuracy trend from Phoenix (uncached).

        This is the actual Phoenix query logic, extracted to separate
        caching concerns from data retrieval.
        """
        try:
            if self.client is None:
                return AccuracyTrend(days=[], rolling_average=0.0, total_evaluated=0)

            since_dt = datetime.now(timezone.utc) - timedelta(days=days)

            df = self.client.query_spans(
                project_name=self.project_name,
                start_time=since_dt,
            )

            if df is None or (hasattr(df, "empty") and df.empty):
                return AccuracyTrend(days=[], rolling_average=0.0, total_evaluated=0)

            guardrail_df = self._filter_guardrail_spans(df)

            if guardrail_df.empty:
                return AccuracyTrend(days=[], rolling_average=0.0, total_evaluated=0)

            daily_data = self._group_by_day(guardrail_df)
            daily_data.sort(key=lambda d: d.date)
            rolling_avg = self._calculate_rolling_average(daily_data, window=7)
            total_evaluated = sum(d.total for d in daily_data)

            return AccuracyTrend(
                days=daily_data,
                rolling_average=rolling_avg,
                total_evaluated=total_evaluated,
            )
        except Exception as exc:
            logger.warning(
                "Failed to query Phoenix for accuracy trend: %s (project=%s)",
                exc,
                self.project_name,
            )
            return AccuracyTrend(days=[], rolling_average=0.0, total_evaluated=0)

    async def get_investigation_eval_summary(self, case_id: str) -> EvalSummary:
        """Aggregate evaluation results for a single investigation.

        Queries Phoenix for guardrail evaluation spans filtered by the specified
        case/investigation. Aggregates counts of approved, flagged, and blocked
        evaluations, and collects per-finding evaluation details.

        Args:
            case_id: The case/investigation identifier to filter evaluation spans.

        Returns:
            EvalSummary with total/approved/flagged/blocked counts and
            per-finding EvalDetail entries.

        Requirements: 3.4
        """
        eval_spans = await self._query_investigation_eval_spans(case_id)

        approved = 0
        flagged = 0
        blocked = 0
        findings: list[EvalDetail] = []

        for span in eval_spans:
            action = span.get("guardrail_action", "")

            if action == "APPROVE":
                approved += 1
            elif action == "FLAG_FOR_REVIEW":
                flagged += 1
            elif action == "BLOCK":
                blocked += 1

            detail = EvalDetail(
                finding_id=span.get("finding_id", ""),
                score=float(span.get("evaluator_score", 0.0)),
                label=span.get("label", ""),
                action=action,
                issues=span.get("issues", []),
            )
            findings.append(detail)

        total = approved + flagged + blocked

        return EvalSummary(
            total=total,
            approved=approved,
            flagged=flagged,
            blocked=blocked,
            findings=findings,
        )

    async def _query_investigation_eval_spans(
        self, case_id: str
    ) -> list[dict[str, Any]]:
        """Query Phoenix for guardrail evaluation spans for a specific investigation."""
        try:
            if self.client is None:
                return []

            spans_df = self.client.get_spans_dataframe(
                project_name=self.project_name,
                filter_condition="name == 'guardrail_evaluation'",
            )

            if spans_df is None or (hasattr(spans_df, "empty") and spans_df.empty):
                return []

            filtered = self._filter_eval_spans_by_case(spans_df, case_id)

            if hasattr(filtered, "empty") and filtered.empty:
                return []

            eval_spans: list[dict[str, Any]] = []
            for _, row in filtered.iterrows():
                span_data = self._extract_eval_data(row)
                if span_data:
                    eval_spans.append(span_data)

            return eval_spans

        except Exception as exc:
            logger.warning("Failed to query Phoenix for eval spans: %s", exc)
            return []

    def _filter_eval_spans_by_case(self, df: pd.DataFrame, case_id: str) -> pd.DataFrame:
        """Filter evaluation spans DataFrame to those matching a case_id."""
        for col_name in ("attributes.case_id", "metadata.case_id", "case_id", "attributes.investigation_id"):
            if col_name in df.columns:
                return df[df[col_name] == case_id]
        if "attributes" in df.columns:
            mask = df["attributes"].apply(
                lambda attrs: isinstance(attrs, dict) and (attrs.get("case_id") == case_id or attrs.get("investigation_id") == case_id)
            )
            return df[mask]
        return pd.DataFrame()

    def _extract_eval_data(self, row: pd.Series) -> dict[str, Any] | None:
        """Extract evaluation data from a single span row."""
        try:
            finding_id = self._safe_get_field(row, ["attributes.finding_id", "metadata.finding_id", "finding_id"], "")
            evaluator_score = float(self._safe_get_field(row, ["attributes.evaluator_score", "attributes.guardrail.score", "evaluator_score"], 0.0))
            label = str(self._safe_get_field(row, ["attributes.label", "attributes.guardrail.label", "label"], ""))
            guardrail_action = str(self._safe_get_field(row, ["attributes.guardrail_action", "attributes.guardrail.action", "guardrail_action"], ""))
            issues_raw = self._safe_get_field(row, ["attributes.issues", "attributes.guardrail.issues", "issues"], [])
            if isinstance(issues_raw, str):
                import json
                try:
                    issues = json.loads(issues_raw)
                except (json.JSONDecodeError, TypeError):
                    issues = [issues_raw] if issues_raw else []
            elif isinstance(issues_raw, list):
                issues = issues_raw
            else:
                issues = []
            return {
                "finding_id": str(finding_id),
                "evaluator_score": evaluator_score,
                "label": label,
                "guardrail_action": guardrail_action,
                "issues": issues,
            }
        except Exception as exc:
            logger.debug("Failed to extract eval data: %s", exc)
            return None

    @staticmethod
    def _safe_get_field(row: pd.Series, candidates: list[str], default: Any = None) -> Any:
        """Get a field value from a span row, trying multiple column names."""
        for name in candidates:
            if name in row.index:
                val = row[name]
                if isinstance(val, float) and pd.isna(val):
                    continue
                if isinstance(val, (list, dict)):
                    return val
                try:
                    if pd.notna(val):
                        return val
                except (ValueError, TypeError):
                    return val
        return default

    async def get_tool_effectiveness(self) -> dict[str, ToolStats]:
        """Correlate tool spans with guardrail outcomes. Requirements: 15.4"""
        try:
            if self.client is None:
                return {}
            tool_df = self.client.get_spans_dataframe(
                project_name=self.project_name,
                filter_condition="span_kind == 'TOOL'",
            )
            if tool_df is None or (hasattr(tool_df, 'empty') and tool_df.empty):
                return {}
            guardrail_df = self.client.get_spans_dataframe(
                project_name=self.project_name,
                filter_condition="name == 'guardrail_pipeline'",
            )
            if guardrail_df is None or (hasattr(guardrail_df, 'empty') and guardrail_df.empty):
                return {}
            return self._correlate_tools(tool_df, guardrail_df)
        except Exception as exc:
            logger.warning('Failed to query tool effectiveness: %s', exc)
            return {}

    def _correlate_tools(self, tool_df, guardrail_df) -> "dict[str, ToolStats]":
        """Correlate tool usage with guardrail outcomes via trace_id."""
        from collections import defaultdict as _dd
        trace_actions = _dd(list)
        for _, row in guardrail_df.iterrows():
            trace_id = None
            for col in ('context.trace_id', 'trace_id'):
                if col in row.index and pd.notna(row[col]):
                    trace_id = str(row[col])
                    break
            if not trace_id:
                continue
            action = None
            for col in ('attributes.guardrail.action', 'attributes.guardrail_action'):
                if col in row.index and pd.notna(row[col]):
                    action = self._normalize_action(str(row[col]))
                    break
            if action:
                trace_actions[trace_id].append(action)
        tool_counts = _dd(lambda: {'confirmed': 0, 'flagged': 0, 'blocked': 0, 'total': 0})
        for _, row in tool_df.iterrows():
            tool_name = None
            for col in ('attributes.tool.name', 'name'):
                if col in row.index and pd.notna(row[col]):
                    tool_name = str(row[col])
                    break
            if not tool_name:
                continue
            trace_id = None
            for col in ('context.trace_id', 'trace_id'):
                if col in row.index and pd.notna(row[col]):
                    trace_id = str(row[col])
                    break
            if not trace_id or trace_id not in trace_actions:
                continue
            for action in trace_actions[trace_id]:
                tool_counts[tool_name]['total'] += 1
                if action == 'APPROVE':
                    tool_counts[tool_name]['confirmed'] += 1
                elif action == 'FLAG_FOR_REVIEW':
                    tool_counts[tool_name]['flagged'] += 1
                elif action == 'BLOCK':
                    tool_counts[tool_name]['blocked'] += 1
        result = {}
        for tn, counts in tool_counts.items():
            total = counts['total']
            ratio = counts['confirmed'] / total if total > 0 else 0.0
            result[tn] = ToolStats(
                tool_name=tn, confirmed_count=counts['confirmed'],
                blocked_count=counts['blocked'], flagged_count=counts['flagged'],
                total_count=total, effectiveness_ratio=ratio,
            )
        return dict(sorted(result.items(), key=lambda x: x[1].effectiveness_ratio, reverse=True))

    # --- Private helpers for accuracy trend ---

    @staticmethod
    def _filter_guardrail_spans(df: pd.DataFrame) -> pd.DataFrame:
        """Filter DataFrame to only guardrail evaluation spans."""
        mask = pd.Series([False] * len(df), index=df.index)

        if "name" in df.columns:
            mask = mask | df["name"].str.contains(
                "guardrail", case=False, na=False
            )

        for col in ("attributes.guardrail_action", "attributes.guardrail.action"):
            if col in df.columns:
                mask = mask | df[col].notna()

        if "attributes" in df.columns:
            attr_mask = df["attributes"].apply(
                lambda attrs: (
                    isinstance(attrs, dict)
                    and (
                        "guardrail_action" in attrs
                        or "guardrail.action" in attrs
                    )
                )
            )
            mask = mask | attr_mask

        return df[mask]

    @staticmethod
    def _extract_guardrail_action(row: pd.Series) -> str | None:
        """Extract the guardrail action from a span row."""
        action = None

        for col in ("attributes.guardrail_action", "attributes.guardrail.action"):
            if col in row.index and pd.notna(row[col]):
                action = str(row[col]).upper().strip()
                break

        if action is None and "attributes" in row.index:
            attrs = row["attributes"]
            if isinstance(attrs, dict):
                raw = attrs.get("guardrail_action") or attrs.get("guardrail.action")
                if raw:
                    action = str(raw).upper().strip()

        if action:
            action = ObservabilityAggregator._normalize_action(action)

        return action

    @staticmethod
    def _normalize_action(action: str) -> str:
        """Normalize guardrail action string to canonical form."""
        action = action.upper().strip()
        if action in {"APPROVE", "APPROVED", "PASS", "PASSED"}:
            return "APPROVE"
        if action in {"FLAG_FOR_REVIEW", "FLAG", "FLAGGED", "REVIEW"}:
            return "FLAG_FOR_REVIEW"
        if action in {"BLOCK", "BLOCKED", "DENY", "DENIED", "REJECT", "REJECTED"}:
            return "BLOCK"
        return action

    @staticmethod
    def _extract_span_date(row: pd.Series) -> date | None:
        """Extract the date from a span row start_time."""
        for col in ("start_time", "startTime", "end_time", "endTime"):
            if col in row.index and pd.notna(row[col]):
                try:
                    ts = pd.Timestamp(row[col])
                    return ts.date()
                except (ValueError, TypeError):
                    continue
        return None

    @staticmethod
    def _group_by_day(df: pd.DataFrame) -> list[DayAccuracy]:
        """Group guardrail spans by day and calculate daily metrics."""
        day_counts: dict[date, dict[str, int]] = defaultdict(
            lambda: {"approved": 0, "flagged": 0, "blocked": 0}
        )

        for _, row in df.iterrows():
            span_date = ObservabilityAggregator._extract_span_date(row)
            if span_date is None:
                continue
            action = ObservabilityAggregator._extract_guardrail_action(row)
            if action is None:
                continue
            if action == "APPROVE":
                day_counts[span_date]["approved"] += 1
            elif action == "FLAG_FOR_REVIEW":
                day_counts[span_date]["flagged"] += 1
            elif action == "BLOCK":
                day_counts[span_date]["blocked"] += 1

        result: list[DayAccuracy] = []
        for day, counts in day_counts.items():
            approved = counts["approved"]
            flagged = counts["flagged"]
            blocked = counts["blocked"]
            total = approved + flagged + blocked
            if total == 0:
                continue
            result.append(
                DayAccuracy(
                    date=day,
                    approved_count=approved,
                    flagged_count=flagged,
                    blocked_count=blocked,
                    total=total,
                    pass_rate=approved / total,
                    flag_rate=flagged / total,
                    block_rate=blocked / total,
                )
            )
        return result

    @staticmethod
    def _calculate_rolling_average(
        daily_data: list[DayAccuracy], window: int = 7
    ) -> float:
        """Calculate rolling average pass_rate over the most recent N days."""
        if not daily_data:
            return 0.0
        recent_days = daily_data[-window:]
        total_approved = sum(d.approved_count for d in recent_days)
        total_all = sum(d.total for d in recent_days)
        if total_all == 0:
            return 0.0
        return total_approved / total_all

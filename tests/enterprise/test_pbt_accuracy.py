"""Property-based tests for Accuracy Trend Aggregation Invariant.

**Validates: Requirements 2.1, 3.4**

Property 1: Accuracy Trend Aggregation Invariant
For any set of guardrail decisions D, the sum of
(approved_count + flagged_count + blocked_count) SHALL equal len(D).
The pass_rate + flag_rate + block_rate SHALL equal 1.0 (±0.001 for floating point).
Additionally, for any AccuracyTrend, rolling_average is between 0.0 and 1.0.

Strategy:
- Generate arbitrary lists of guardrail decisions (each being "APPROVE",
  "FLAG_FOR_REVIEW", or "BLOCK").
- Feed them through _group_by_day() via a constructed DataFrame.
- Assert: sum(approved + flagged + blocked) across all days = total decisions.
- Assert: for each day, pass_rate + flag_rate + block_rate ≈ 1.0.
- Assert: rolling_average is always in [0.0, 1.0].
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

import pandas as pd
import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from sift_defender.enterprise.observability.aggregator import (
    AccuracyTrend,
    DayAccuracy,
    ObservabilityAggregator,
)


# ─── Strategies ───────────────────────────────────────────────────────────────

# Canonical guardrail decision values
GUARDRAIL_ACTIONS = ["APPROVE", "FLAG_FOR_REVIEW", "BLOCK"]

# Strategy: generate a list of guardrail decisions (1 to 200 decisions)
guardrail_decisions = st.lists(
    st.sampled_from(GUARDRAIL_ACTIONS),
    min_size=1,
    max_size=200,
)

# Strategy: generate decisions spread across multiple days (1 to 14 days)
multi_day_decisions = st.lists(
    st.tuples(
        st.integers(min_value=0, max_value=13),  # day offset
        st.sampled_from(GUARDRAIL_ACTIONS),
    ),
    min_size=1,
    max_size=200,
)


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _build_guardrail_dataframe(
    decisions: list[str], base_date: date | None = None
) -> pd.DataFrame:
    """Build a DataFrame of guardrail spans from a list of action strings.

    All decisions are assigned to the same day (base_date or today).
    """
    if base_date is None:
        base_date = date.today()

    rows = []
    for i, action in enumerate(decisions):
        start = datetime.combine(base_date, datetime.min.time(), tzinfo=timezone.utc) + timedelta(
            seconds=i
        )
        rows.append(
            {
                "name": "guardrail_evaluation",
                "start_time": start,
                "end_time": start + timedelta(seconds=1),
                "attributes.guardrail_action": action,
            }
        )
    return pd.DataFrame(rows)


def _build_multi_day_dataframe(
    day_decisions: list[tuple[int, str]],
) -> pd.DataFrame:
    """Build a DataFrame with decisions spread across multiple days.

    Each tuple is (day_offset_from_today, action).
    """
    today = date.today()
    rows = []
    for i, (day_offset, action) in enumerate(day_decisions):
        span_date = today - timedelta(days=day_offset)
        start = datetime.combine(span_date, datetime.min.time(), tzinfo=timezone.utc) + timedelta(
            seconds=i
        )
        rows.append(
            {
                "name": "guardrail_evaluation",
                "start_time": start,
                "end_time": start + timedelta(seconds=1),
                "attributes.guardrail_action": action,
            }
        )
    return pd.DataFrame(rows)


# ─── Property Tests ───────────────────────────────────────────────────────────


class TestAccuracyTrendAggregationInvariant:
    """Property 1: Accuracy Trend Aggregation Invariant.

    **Validates: Requirements 2.1, 3.4**
    """

    @settings(max_examples=200, deadline=None)
    @given(decisions=guardrail_decisions)
    def test_count_invariant_single_day(self, decisions: list[str]):
        """For any set of guardrail decisions D, the sum of
        (approved_count + flagged_count + blocked_count) SHALL equal len(D).

        Tests on a single day: all decisions map to one DayAccuracy,
        and counts must sum to the total number of decisions.
        """
        df = _build_guardrail_dataframe(decisions)
        result = ObservabilityAggregator._group_by_day(df)

        # All decisions on the same day → exactly one DayAccuracy
        assert len(result) == 1
        day = result[0]

        # Count invariant: approved + flagged + blocked = total = len(decisions)
        assert day.approved_count + day.flagged_count + day.blocked_count == day.total
        assert day.total == len(decisions)

    @settings(max_examples=200, deadline=None)
    @given(decisions=guardrail_decisions)
    def test_rate_sum_invariant_single_day(self, decisions: list[str]):
        """For any set of guardrail decisions, pass_rate + flag_rate + block_rate
        SHALL equal 1.0 (±0.001 for floating point).
        """
        df = _build_guardrail_dataframe(decisions)
        result = ObservabilityAggregator._group_by_day(df)

        assert len(result) == 1
        day = result[0]

        rate_sum = day.pass_rate + day.flag_rate + day.block_rate
        assert abs(rate_sum - 1.0) < 0.001, (
            f"Rate sum invariant violated: {day.pass_rate} + {day.flag_rate} + "
            f"{day.block_rate} = {rate_sum}, expected ≈ 1.0"
        )

    @settings(max_examples=200, deadline=None)
    @given(day_decisions=multi_day_decisions)
    def test_count_invariant_multi_day(self, day_decisions: list[tuple[int, str]]):
        """Across multiple days, the sum of all days' totals SHALL equal
        the total number of decisions provided.
        """
        df = _build_multi_day_dataframe(day_decisions)
        result = ObservabilityAggregator._group_by_day(df)

        total_counted = sum(d.total for d in result)
        assert total_counted == len(day_decisions)

        # Also verify per-day count invariant
        for day in result:
            assert day.approved_count + day.flagged_count + day.blocked_count == day.total

    @settings(max_examples=200, deadline=None)
    @given(day_decisions=multi_day_decisions)
    def test_rate_sum_invariant_multi_day(self, day_decisions: list[tuple[int, str]]):
        """For every DayAccuracy across multiple days,
        pass_rate + flag_rate + block_rate SHALL equal 1.0 (±0.001).
        """
        df = _build_multi_day_dataframe(day_decisions)
        result = ObservabilityAggregator._group_by_day(df)

        for day in result:
            rate_sum = day.pass_rate + day.flag_rate + day.block_rate
            assert abs(rate_sum - 1.0) < 0.001, (
                f"Rate sum invariant violated on {day.date}: "
                f"{day.pass_rate} + {day.flag_rate} + {day.block_rate} = {rate_sum}"
            )

    @settings(max_examples=200, deadline=None)
    @given(day_decisions=multi_day_decisions)
    def test_rolling_average_bounded(self, day_decisions: list[tuple[int, str]]):
        """For any AccuracyTrend, rolling_average is between 0.0 and 1.0.

        The rolling average represents the fraction of APPROVE decisions
        in the most recent 7-day window, so it must always be in [0, 1].
        """
        df = _build_multi_day_dataframe(day_decisions)
        daily_data = ObservabilityAggregator._group_by_day(df)
        daily_data.sort(key=lambda d: d.date)

        rolling_avg = ObservabilityAggregator._calculate_rolling_average(
            daily_data, window=7
        )

        assert 0.0 <= rolling_avg <= 1.0, (
            f"Rolling average out of bounds: {rolling_avg}. "
            f"Expected 0.0 <= rolling_average <= 1.0"
        )

    @settings(max_examples=200, deadline=None)
    @given(decisions=guardrail_decisions)
    def test_individual_rates_bounded(self, decisions: list[str]):
        """Each individual rate (pass_rate, flag_rate, block_rate) must be
        in [0.0, 1.0] for any set of decisions.
        """
        df = _build_guardrail_dataframe(decisions)
        result = ObservabilityAggregator._group_by_day(df)

        for day in result:
            assert 0.0 <= day.pass_rate <= 1.0, (
                f"pass_rate out of bounds: {day.pass_rate}"
            )
            assert 0.0 <= day.flag_rate <= 1.0, (
                f"flag_rate out of bounds: {day.flag_rate}"
            )
            assert 0.0 <= day.block_rate <= 1.0, (
                f"block_rate out of bounds: {day.block_rate}"
            )

    @settings(max_examples=200, deadline=None)
    @given(decisions=guardrail_decisions)
    def test_rates_match_counts(self, decisions: list[str]):
        """Each rate SHALL equal its corresponding count divided by total.

        pass_rate = approved_count / total
        flag_rate = flagged_count / total
        block_rate = blocked_count / total
        """
        df = _build_guardrail_dataframe(decisions)
        result = ObservabilityAggregator._group_by_day(df)

        for day in result:
            assert day.total > 0
            expected_pass = day.approved_count / day.total
            expected_flag = day.flagged_count / day.total
            expected_block = day.blocked_count / day.total

            assert abs(day.pass_rate - expected_pass) < 0.001, (
                f"pass_rate mismatch: {day.pass_rate} != {expected_pass}"
            )
            assert abs(day.flag_rate - expected_flag) < 0.001, (
                f"flag_rate mismatch: {day.flag_rate} != {expected_flag}"
            )
            assert abs(day.block_rate - expected_block) < 0.001, (
                f"block_rate mismatch: {day.block_rate} != {expected_block}"
            )

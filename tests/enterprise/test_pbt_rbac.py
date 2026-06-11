"""Property-based tests for RBAC Enforcement Completeness.

**Validates: Requirements 4.1, 4.2**

Property 2: RBAC Enforcement Completeness
For any (user, permission) pair where the user's resolved roles do NOT include
the permission, the RBAC_Engine SHALL deny access. For any (user, permission) pair
where the user's resolved roles DO include the permission, access SHALL be granted.
No false positives or false negatives.

Strategy:
- Generate an arbitrary subset of Permission enum values representing a user's
  effective permission set (what the DB would return via their assigned roles).
- Generate a target Permission to check.
- Mock the DB layer to return the generated permission set as the user's roles.
- Assert: check_permission returns True iff the target permission is in the set.
- Assert: get_effective_permissions returns exactly the generated permission set.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from sift_defender.enterprise.auth.rbac import Permission, RBACEngine


# ─── Strategies ───────────────────────────────────────────────────────────────

# Strategy: generate any subset of Permission values (including empty set)
permission_subsets = st.frozensets(st.sampled_from(list(Permission)))

# Strategy: generate a single target permission to check
target_permissions = st.sampled_from(list(Permission))


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _mock_db_for_permissions(permission_set: frozenset[Permission]):
    """Create a mock get_tenant_connection that returns a single role
    containing exactly the given permission set.

    This simulates a user whose resolved roles grant exactly `permission_set`.
    """
    # Build a single mock role row that contains all permissions in the set
    perm_strings = [p.value for p in permission_set]

    # Create a mock asyncpg Record
    row_data = {
        "id": "test-role-id",
        "name": "generated_role",
        "permissions": perm_strings,
    }
    mock_record = MagicMock()
    mock_record.__getitem__ = MagicMock(side_effect=lambda key: row_data[key])
    mock_record.keys = MagicMock(return_value=row_data.keys())
    mock_record.__iter__ = MagicMock(side_effect=lambda: iter(row_data.keys()))
    mock_record.items = MagicMock(return_value=row_data.items())
    mock_record.get = MagicMock(
        side_effect=lambda key, default=None: row_data.get(key, default)
    )

    # If the permission set is empty, return no roles (empty list)
    # This correctly models a user with no permissions
    rows = [mock_record] if permission_set else []

    mock_conn = AsyncMock()
    mock_conn.fetch = AsyncMock(return_value=rows)

    @asynccontextmanager
    async def _ctx(tenant_id):
        yield mock_conn

    return _ctx


# ─── Property Tests ───────────────────────────────────────────────────────────


class TestRBACEnforcementCompleteness:
    """Property 2: RBAC Enforcement Completeness.

    **Validates: Requirements 4.1, 4.2**
    """

    @pytest.mark.asyncio
    @settings(max_examples=200, deadline=None)
    @given(
        perm_set=permission_subsets,
        target=target_permissions,
    )
    async def test_no_false_positives_or_negatives(
        self,
        perm_set: frozenset[Permission],
        target: Permission,
    ):
        """For any (user, permission) pair, check_permission returns True iff
        the permission is in the user's resolved role set.

        No false positives: if permission NOT in set → access denied.
        No false negatives: if permission IN set → access granted.
        """
        engine = RBACEngine()
        mock_ctx = _mock_db_for_permissions(perm_set)

        with patch(
            "sift_defender.enterprise.db.get_tenant_connection", mock_ctx
        ):
            result = await engine.check_permission("user-pbt", "tenant-pbt", target)

        expected = target in perm_set
        assert result == expected, (
            f"RBAC violation: check_permission returned {result} "
            f"but expected {expected}. "
            f"Target={target.value}, "
            f"PermSet={[p.value for p in perm_set]}"
        )

    @pytest.mark.asyncio
    @settings(max_examples=200, deadline=None)
    @given(perm_set=permission_subsets)
    async def test_get_effective_permissions_returns_exact_set(
        self,
        perm_set: frozenset[Permission],
    ):
        """get_effective_permissions returns exactly the union of role permissions.

        For any generated permission set, the effective permissions resolved by
        the engine must equal that set — no extra permissions (false positives)
        and no missing permissions (false negatives).
        """
        engine = RBACEngine()
        mock_ctx = _mock_db_for_permissions(perm_set)

        with patch(
            "sift_defender.enterprise.db.get_tenant_connection", mock_ctx
        ):
            result = await engine.get_effective_permissions("user-pbt", "tenant-pbt")

        assert result == set(perm_set), (
            f"Effective permissions mismatch. "
            f"Expected: {sorted(p.value for p in perm_set)}, "
            f"Got: {sorted(p.value for p in result)}"
        )

    @pytest.mark.asyncio
    @settings(max_examples=200, deadline=None)
    @given(perm_set=permission_subsets)
    async def test_all_permissions_in_set_are_granted(
        self,
        perm_set: frozenset[Permission],
    ):
        """Every permission in the user's resolved set SHALL be granted.

        This tests the no-false-negatives invariant exhaustively: for every
        permission that IS in the set, check_permission must return True.
        """
        assume(len(perm_set) > 0)
        engine = RBACEngine()
        mock_ctx = _mock_db_for_permissions(perm_set)

        with patch(
            "sift_defender.enterprise.db.get_tenant_connection", mock_ctx
        ):
            for perm in perm_set:
                result = await engine.check_permission(
                    "user-pbt", "tenant-pbt", perm
                )
                assert result is True, (
                    f"False negative: permission {perm.value} is in the user's "
                    f"role set but check_permission returned False."
                )

    @pytest.mark.asyncio
    @settings(max_examples=200, deadline=None)
    @given(perm_set=permission_subsets)
    async def test_all_permissions_outside_set_are_denied(
        self,
        perm_set: frozenset[Permission],
    ):
        """Every permission NOT in the user's resolved set SHALL be denied.

        This tests the no-false-positives invariant exhaustively: for every
        permission that is NOT in the set, check_permission must return False.
        """
        all_perms = set(Permission)
        denied_perms = all_perms - perm_set
        assume(len(denied_perms) > 0)

        engine = RBACEngine()
        mock_ctx = _mock_db_for_permissions(perm_set)

        with patch(
            "sift_defender.enterprise.db.get_tenant_connection", mock_ctx
        ):
            for perm in denied_perms:
                result = await engine.check_permission(
                    "user-pbt", "tenant-pbt", perm
                )
                assert result is False, (
                    f"False positive: permission {perm.value} is NOT in the "
                    f"user's role set but check_permission returned True."
                )

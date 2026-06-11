"""Tests for IdP Group-to-Role Mapping (IdPGroupMapper).

Validates that:
- IdPGroupMapper initializes statelessly
- get_mappings retrieves all mappings for a tenant
- create_mapping creates a new mapping and returns GroupMapping
- create_mapping raises ValueError for empty inputs
- create_mapping raises DuplicateMappingError for duplicate mappings
- delete_mapping returns True when mapping exists, False otherwise
- resolve_roles maps IdP groups to internal role names
- resolve_roles returns empty list for empty input
- resolve_roles deduplicates role names
- resolve_roles handles groups with no matching mappings

Requirements: 4.4
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sift_defender.enterprise.auth.idp_mapping import (
    DuplicateMappingError,
    GroupMapping,
    IdPGroupMapper,
)


# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def mapper():
    """Create a fresh IdPGroupMapper instance."""
    return IdPGroupMapper()


def _make_mapping_row(
    mapping_id: str,
    tenant_id: str,
    idp_group: str,
    role_name: str,
    created_at: datetime | None = None,
) -> MagicMock:
    """Create a mock asyncpg Record for an idp_group_mappings row."""
    if created_at is None:
        created_at = datetime.now(timezone.utc)

    data = {
        "id": uuid.UUID(mapping_id),
        "tenant_id": uuid.UUID(tenant_id),
        "idp_group": idp_group,
        "role_name": role_name,
        "created_at": created_at,
    }
    record = MagicMock()
    record.__getitem__ = MagicMock(side_effect=lambda key: data[key])
    record.keys = MagicMock(return_value=data.keys())
    record.__iter__ = MagicMock(side_effect=lambda: iter(data.keys()))
    record.items = MagicMock(return_value=data.items())
    record.get = MagicMock(side_effect=lambda key, default=None: data.get(key, default))
    return record


def _mock_tenant_connection(
    fetch_return=None,
    fetchrow_return=None,
    execute_return="DELETE 0",
):
    """Create a mock for get_tenant_connection.

    Args:
        fetch_return: Return value for conn.fetch() calls.
        fetchrow_return: Return value for conn.fetchrow() calls.
        execute_return: Return value for conn.execute() calls.
    """
    mock_conn = AsyncMock()
    mock_conn.fetch = AsyncMock(return_value=fetch_return or [])
    mock_conn.fetchrow = AsyncMock(return_value=fetchrow_return)
    mock_conn.execute = AsyncMock(return_value=execute_return)

    @asynccontextmanager
    async def _ctx(tenant_id):
        yield mock_conn

    return _ctx, mock_conn


# ─── Constants for tests ──────────────────────────────────────────────────────

TENANT_ID = "11111111-1111-1111-1111-111111111111"
MAPPING_ID = "22222222-2222-2222-2222-222222222222"


# ─── IdPGroupMapper Initialization ───────────────────────────────────────────


class TestIdPGroupMapperInit:
    """Test IdPGroupMapper instantiation."""

    def test_init_requires_no_arguments(self):
        """IdPGroupMapper should initialize with no arguments."""
        mapper = IdPGroupMapper()
        assert mapper is not None

    def test_init_returns_instance(self):
        mapper = IdPGroupMapper()
        assert isinstance(mapper, IdPGroupMapper)


# ─── get_mappings ─────────────────────────────────────────────────────────────


class TestGetMappings:
    """Test retrieving IdP group-to-role mappings for a tenant."""

    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_mappings(self, mapper):
        """get_mappings returns empty list when no mappings configured."""
        mock_ctx, _ = _mock_tenant_connection(fetch_return=[])

        with patch(
            "sift_defender.enterprise.auth.idp_mapping.get_tenant_connection",
            mock_ctx,
        ):
            result = await mapper.get_mappings(TENANT_ID)

        assert result == []

    @pytest.mark.asyncio
    async def test_returns_list_of_group_mappings(self, mapper):
        """get_mappings returns GroupMapping objects for all tenant mappings."""
        now = datetime.now(timezone.utc)
        rows = [
            _make_mapping_row(MAPPING_ID, TENANT_ID, "security-team", "soc_analyst", now),
            _make_mapping_row(
                "33333333-3333-3333-3333-333333333333",
                TENANT_ID,
                "ir-leads",
                "ir_lead",
                now,
            ),
        ]
        mock_ctx, mock_conn = _mock_tenant_connection(fetch_return=rows)

        with patch(
            "sift_defender.enterprise.auth.idp_mapping.get_tenant_connection",
            mock_ctx,
        ):
            result = await mapper.get_mappings(TENANT_ID)

        assert len(result) == 2
        assert all(isinstance(m, GroupMapping) for m in result)
        assert result[0].idp_group == "security-team"
        assert result[0].role_name == "soc_analyst"
        assert result[1].idp_group == "ir-leads"
        assert result[1].role_name == "ir_lead"

    @pytest.mark.asyncio
    async def test_queries_with_correct_tenant_id(self, mapper):
        """get_mappings queries the database with the correct tenant_id."""
        mock_ctx, mock_conn = _mock_tenant_connection(fetch_return=[])

        with patch(
            "sift_defender.enterprise.auth.idp_mapping.get_tenant_connection",
            mock_ctx,
        ):
            await mapper.get_mappings(TENANT_ID)

        mock_conn.fetch.assert_called_once()
        call_args = mock_conn.fetch.call_args
        sql = call_args[0][0]
        assert "idp_group_mappings" in sql
        assert call_args[0][1] == uuid.UUID(TENANT_ID)


# ─── create_mapping ───────────────────────────────────────────────────────────


class TestCreateMapping:
    """Test creating IdP group-to-role mappings."""

    @pytest.mark.asyncio
    async def test_creates_mapping_successfully(self, mapper):
        """create_mapping creates and returns a GroupMapping object."""
        now = datetime.now(timezone.utc)
        returned_row = _make_mapping_row(
            MAPPING_ID, TENANT_ID, "security-ops", "soc_analyst", now
        )
        # First fetchrow (duplicate check) returns None, second (INSERT RETURNING) returns the row
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(side_effect=[None, returned_row])

        @asynccontextmanager
        async def _ctx(tenant_id):
            yield mock_conn

        with patch(
            "sift_defender.enterprise.auth.idp_mapping.get_tenant_connection",
            _ctx,
        ):
            result = await mapper.create_mapping(TENANT_ID, "security-ops", "soc_analyst")

        assert isinstance(result, GroupMapping)
        assert result.idp_group == "security-ops"
        assert result.role_name == "soc_analyst"
        assert result.tenant_id == TENANT_ID

    @pytest.mark.asyncio
    async def test_raises_value_error_for_empty_idp_group(self, mapper):
        """create_mapping raises ValueError if idp_group is empty."""
        with pytest.raises(ValueError, match="idp_group must be a non-empty string"):
            await mapper.create_mapping(TENANT_ID, "", "soc_analyst")

    @pytest.mark.asyncio
    async def test_raises_value_error_for_whitespace_idp_group(self, mapper):
        """create_mapping raises ValueError if idp_group is only whitespace."""
        with pytest.raises(ValueError, match="idp_group must be a non-empty string"):
            await mapper.create_mapping(TENANT_ID, "   ", "soc_analyst")

    @pytest.mark.asyncio
    async def test_raises_value_error_for_empty_role_name(self, mapper):
        """create_mapping raises ValueError if role_name is empty."""
        with pytest.raises(ValueError, match="role_name must be a non-empty string"):
            await mapper.create_mapping(TENANT_ID, "admins", "")

    @pytest.mark.asyncio
    async def test_raises_duplicate_mapping_error(self, mapper):
        """create_mapping raises DuplicateMappingError if mapping already exists."""
        existing_row = MagicMock()
        existing_row.__getitem__ = MagicMock(side_effect=lambda key: uuid.UUID(MAPPING_ID))

        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=existing_row)

        @asynccontextmanager
        async def _ctx(tenant_id):
            yield mock_conn

        with patch(
            "sift_defender.enterprise.auth.idp_mapping.get_tenant_connection",
            _ctx,
        ):
            with pytest.raises(DuplicateMappingError):
                await mapper.create_mapping(TENANT_ID, "admins", "ir_lead")

    @pytest.mark.asyncio
    async def test_strips_whitespace_from_inputs(self, mapper):
        """create_mapping strips leading/trailing whitespace from idp_group and role_name."""
        now = datetime.now(timezone.utc)
        returned_row = _make_mapping_row(
            MAPPING_ID, TENANT_ID, "admins", "ir_lead", now
        )
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(side_effect=[None, returned_row])

        @asynccontextmanager
        async def _ctx(tenant_id):
            yield mock_conn

        with patch(
            "sift_defender.enterprise.auth.idp_mapping.get_tenant_connection",
            _ctx,
        ):
            result = await mapper.create_mapping(TENANT_ID, "  admins  ", "  ir_lead  ")

        # Verify the INSERT was called with stripped values
        # call_args_list[0] = duplicate check, call_args_list[1] = INSERT
        insert_call = mock_conn.fetchrow.call_args_list[1]
        # Positional args: SQL, mapping_id UUID, tenant_id UUID, idp_group, role_name, created_at
        assert insert_call[0][3] == "admins"  # idp_group param (stripped)
        assert insert_call[0][4] == "ir_lead"  # role_name param (stripped)


# ─── delete_mapping ───────────────────────────────────────────────────────────


class TestDeleteMapping:
    """Test deleting IdP group-to-role mappings."""

    @pytest.mark.asyncio
    async def test_returns_true_when_mapping_deleted(self, mapper):
        """delete_mapping returns True when a mapping is found and deleted."""
        mock_ctx, _ = _mock_tenant_connection(execute_return="DELETE 1")

        with patch(
            "sift_defender.enterprise.auth.idp_mapping.get_tenant_connection",
            mock_ctx,
        ):
            result = await mapper.delete_mapping(TENANT_ID, MAPPING_ID)

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_when_mapping_not_found(self, mapper):
        """delete_mapping returns False when no matching mapping exists."""
        mock_ctx, _ = _mock_tenant_connection(execute_return="DELETE 0")

        with patch(
            "sift_defender.enterprise.auth.idp_mapping.get_tenant_connection",
            mock_ctx,
        ):
            result = await mapper.delete_mapping(TENANT_ID, MAPPING_ID)

        assert result is False

    @pytest.mark.asyncio
    async def test_delete_queries_with_correct_params(self, mapper):
        """delete_mapping uses both mapping_id and tenant_id for scoped deletion."""
        mock_ctx, mock_conn = _mock_tenant_connection(execute_return="DELETE 1")

        with patch(
            "sift_defender.enterprise.auth.idp_mapping.get_tenant_connection",
            mock_ctx,
        ):
            await mapper.delete_mapping(TENANT_ID, MAPPING_ID)

        mock_conn.execute.assert_called_once()
        call_args = mock_conn.execute.call_args
        sql = call_args[0][0]
        assert "DELETE" in sql
        assert "idp_group_mappings" in sql
        assert call_args[0][1] == uuid.UUID(MAPPING_ID)
        assert call_args[0][2] == uuid.UUID(TENANT_ID)


# ─── resolve_roles ────────────────────────────────────────────────────────────


class TestResolveRoles:
    """Test resolving IdP groups to internal role names."""

    @pytest.mark.asyncio
    async def test_returns_empty_list_for_empty_groups(self, mapper):
        """resolve_roles returns empty list when no groups provided."""
        result = await mapper.resolve_roles(TENANT_ID, [])
        assert result == []

    @pytest.mark.asyncio
    async def test_resolves_single_group_to_single_role(self, mapper):
        """resolve_roles maps a single IdP group to its corresponding role."""
        role_row = MagicMock()
        role_row.__getitem__ = MagicMock(side_effect=lambda key: "soc_analyst")
        mock_ctx, _ = _mock_tenant_connection(fetch_return=[role_row])

        with patch(
            "sift_defender.enterprise.auth.idp_mapping.get_tenant_connection",
            mock_ctx,
        ):
            result = await mapper.resolve_roles(TENANT_ID, ["security-ops"])

        assert result == ["soc_analyst"]

    @pytest.mark.asyncio
    async def test_resolves_multiple_groups_to_multiple_roles(self, mapper):
        """resolve_roles maps multiple IdP groups to their corresponding roles."""
        role_row_1 = MagicMock()
        role_row_1.__getitem__ = MagicMock(side_effect=lambda key: "ir_lead")
        role_row_2 = MagicMock()
        role_row_2.__getitem__ = MagicMock(side_effect=lambda key: "soc_analyst")
        mock_ctx, _ = _mock_tenant_connection(fetch_return=[role_row_1, role_row_2])

        with patch(
            "sift_defender.enterprise.auth.idp_mapping.get_tenant_connection",
            mock_ctx,
        ):
            result = await mapper.resolve_roles(
                TENANT_ID, ["ir-team", "security-ops"]
            )

        assert "ir_lead" in result
        assert "soc_analyst" in result

    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_mappings_match(self, mapper):
        """resolve_roles returns empty list if none of the groups have mappings."""
        mock_ctx, _ = _mock_tenant_connection(fetch_return=[])

        with patch(
            "sift_defender.enterprise.auth.idp_mapping.get_tenant_connection",
            mock_ctx,
        ):
            result = await mapper.resolve_roles(TENANT_ID, ["unknown-group"])

        assert result == []

    @pytest.mark.asyncio
    async def test_deduplicates_role_names(self, mapper):
        """resolve_roles returns deduplicated roles (DISTINCT in query)."""
        # SQL uses DISTINCT, so even if multiple groups map to same role,
        # only one instance is returned
        role_row = MagicMock()
        role_row.__getitem__ = MagicMock(side_effect=lambda key: "soc_analyst")
        mock_ctx, _ = _mock_tenant_connection(fetch_return=[role_row])

        with patch(
            "sift_defender.enterprise.auth.idp_mapping.get_tenant_connection",
            mock_ctx,
        ):
            result = await mapper.resolve_roles(
                TENANT_ID, ["team-a", "team-b"]
            )

        # Only one soc_analyst should appear (DISTINCT handles this in SQL)
        assert result == ["soc_analyst"]

    @pytest.mark.asyncio
    async def test_passes_groups_as_array_parameter(self, mapper):
        """resolve_roles passes idp_groups as a PostgreSQL array parameter."""
        mock_ctx, mock_conn = _mock_tenant_connection(fetch_return=[])

        with patch(
            "sift_defender.enterprise.auth.idp_mapping.get_tenant_connection",
            mock_ctx,
        ):
            await mapper.resolve_roles(TENANT_ID, ["group-a", "group-b"])

        mock_conn.fetch.assert_called_once()
        call_args = mock_conn.fetch.call_args
        sql = call_args[0][0]
        assert "ANY" in sql
        assert call_args[0][1] == uuid.UUID(TENANT_ID)
        assert call_args[0][2] == ["group-a", "group-b"]


# ─── GroupMapping Model ───────────────────────────────────────────────────────


class TestGroupMappingModel:
    """Test the GroupMapping Pydantic model."""

    def test_creates_valid_group_mapping(self):
        """GroupMapping can be constructed with valid fields."""
        now = datetime.now(timezone.utc)
        mapping = GroupMapping(
            id=MAPPING_ID,
            tenant_id=TENANT_ID,
            idp_group="security-team",
            role_name="soc_analyst",
            created_at=now,
        )
        assert mapping.id == MAPPING_ID
        assert mapping.tenant_id == TENANT_ID
        assert mapping.idp_group == "security-team"
        assert mapping.role_name == "soc_analyst"
        assert mapping.created_at == now

    def test_group_mapping_is_pydantic_model(self):
        """GroupMapping should be a Pydantic BaseModel."""
        now = datetime.now(timezone.utc)
        mapping = GroupMapping(
            id=MAPPING_ID,
            tenant_id=TENANT_ID,
            idp_group="admins",
            role_name="ir_lead",
            created_at=now,
        )
        # Pydantic models have model_dump
        data = mapping.model_dump()
        assert data["id"] == MAPPING_ID
        assert data["idp_group"] == "admins"
        assert data["role_name"] == "ir_lead"

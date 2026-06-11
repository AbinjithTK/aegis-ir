"""IdP Group-to-Role Mapping for SAML/OIDC claims.

Maps external identity provider group names to internal role names on a
per-tenant basis. When a user authenticates via SAML or OIDC, the groups
claim from the identity provider is resolved to internal AEGIS-IR roles
using the mappings configured for that tenant.

Requirements: 4.4 (SAML/OIDC group-to-role mapping)
"""

from __future__ import annotations

import uuid
import logging
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field

from sift_defender.enterprise.db import get_tenant_connection

logger = logging.getLogger(__name__)


class GroupMapping(BaseModel):
    """Represents a mapping from an external IdP group to an internal role.

    Attributes:
        id: Unique identifier for this mapping (UUID).
        tenant_id: The tenant this mapping belongs to.
        idp_group: The external group name from the identity provider.
        role_name: The internal AEGIS-IR role name to map to.
        created_at: Timestamp when this mapping was created.
    """

    id: str = Field(description="UUID of the mapping")
    tenant_id: str = Field(description="Tenant this mapping belongs to")
    idp_group: str = Field(description="External IdP group name")
    role_name: str = Field(description="Internal role name")
    created_at: datetime = Field(description="When this mapping was created")


class IdPGroupMapper:
    """Maps external identity provider groups to internal roles per tenant.

    Provides CRUD operations for group-to-role mappings and a resolve method
    that translates a list of IdP group names (from SAML/OIDC claims) into
    the corresponding internal role names for a given tenant.

    The mapper is stateless — database connections are acquired per-operation
    using the tenant-scoped connection manager.

    Requirements: 4.4
    """

    def __init__(self) -> None:
        """Initialize the IdP group mapper (stateless)."""

    async def get_mappings(self, tenant_id: str) -> list[GroupMapping]:
        """Retrieve all group-to-role mappings for a tenant.

        Args:
            tenant_id: UUID string identifying the tenant.

        Returns:
            List of GroupMapping objects for the tenant, ordered by creation time.
        """
        async with get_tenant_connection(tenant_id) as conn:
            rows = await conn.fetch(
                """
                SELECT id, tenant_id, idp_group, role_name, created_at
                FROM idp_group_mappings
                WHERE tenant_id = $1
                ORDER BY created_at ASC
                """,
                uuid.UUID(tenant_id),
            )

        return [
            GroupMapping(
                id=str(row["id"]),
                tenant_id=str(row["tenant_id"]),
                idp_group=row["idp_group"],
                role_name=row["role_name"],
                created_at=row["created_at"],
            )
            for row in rows
        ]

    async def create_mapping(
        self, tenant_id: str, idp_group: str, role_name: str
    ) -> GroupMapping:
        """Create a new IdP group-to-role mapping for a tenant.

        Args:
            tenant_id: UUID string identifying the tenant.
            idp_group: The external group name from the identity provider.
            role_name: The internal role name to map to.

        Returns:
            The created GroupMapping object.

        Raises:
            ValueError: If idp_group or role_name is empty.
            DuplicateMappingError: If this exact mapping already exists.
        """
        if not idp_group or not idp_group.strip():
            raise ValueError("idp_group must be a non-empty string.")
        if not role_name or not role_name.strip():
            raise ValueError("role_name must be a non-empty string.")

        mapping_id = str(uuid.uuid4())

        async with get_tenant_connection(tenant_id) as conn:
            # Check for duplicate mapping
            existing = await conn.fetchrow(
                """
                SELECT id FROM idp_group_mappings
                WHERE tenant_id = $1 AND idp_group = $2 AND role_name = $3
                """,
                uuid.UUID(tenant_id),
                idp_group.strip(),
                role_name.strip(),
            )
            if existing:
                raise DuplicateMappingError(
                    f"Mapping from '{idp_group}' to '{role_name}' already exists "
                    f"for tenant '{tenant_id}'."
                )

            row = await conn.fetchrow(
                """
                INSERT INTO idp_group_mappings (id, tenant_id, idp_group, role_name, created_at)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING id, tenant_id, idp_group, role_name, created_at
                """,
                uuid.UUID(mapping_id),
                uuid.UUID(tenant_id),
                idp_group.strip(),
                role_name.strip(),
                datetime.now(timezone.utc),
            )

        logger.info(
            "Created IdP group mapping: '%s' -> '%s' for tenant %s",
            idp_group,
            role_name,
            tenant_id,
        )

        return GroupMapping(
            id=str(row["id"]),
            tenant_id=str(row["tenant_id"]),
            idp_group=row["idp_group"],
            role_name=row["role_name"],
            created_at=row["created_at"],
        )

    async def delete_mapping(self, tenant_id: str, mapping_id: str) -> bool:
        """Delete an IdP group-to-role mapping.

        Args:
            tenant_id: UUID string identifying the tenant.
            mapping_id: UUID string identifying the mapping to delete.

        Returns:
            True if the mapping was found and deleted, False if not found.
        """
        async with get_tenant_connection(tenant_id) as conn:
            result = await conn.execute(
                """
                DELETE FROM idp_group_mappings
                WHERE id = $1 AND tenant_id = $2
                """,
                uuid.UUID(mapping_id),
                uuid.UUID(tenant_id),
            )

        # asyncpg returns "DELETE N" where N is the number of rows deleted
        deleted = result == "DELETE 1"

        if deleted:
            logger.info(
                "Deleted IdP group mapping %s for tenant %s",
                mapping_id,
                tenant_id,
            )
        else:
            logger.warning(
                "IdP group mapping %s not found for tenant %s",
                mapping_id,
                tenant_id,
            )

        return deleted

    async def resolve_roles(
        self, tenant_id: str, idp_groups: list[str]
    ) -> list[str]:
        """Resolve IdP groups from SAML/OIDC claims to internal role names.

        Given a list of external group names from an identity provider's claims,
        looks up which internal role names correspond to those groups for the
        specified tenant.

        Args:
            tenant_id: UUID string identifying the tenant.
            idp_groups: List of external group names from SAML/OIDC claims.

        Returns:
            Deduplicated list of internal role names that the IdP groups map to.
            Returns an empty list if no mappings match.
        """
        if not idp_groups:
            return []

        async with get_tenant_connection(tenant_id) as conn:
            rows = await conn.fetch(
                """
                SELECT DISTINCT role_name
                FROM idp_group_mappings
                WHERE tenant_id = $1 AND idp_group = ANY($2)
                ORDER BY role_name
                """,
                uuid.UUID(tenant_id),
                idp_groups,
            )

        role_names = [row["role_name"] for row in rows]

        logger.debug(
            "Resolved IdP groups %s to roles %s for tenant %s",
            idp_groups,
            role_names,
            tenant_id,
        )

        return role_names


class DuplicateMappingError(Exception):
    """Raised when attempting to create a mapping that already exists."""

    pass

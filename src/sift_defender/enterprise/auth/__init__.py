"""AEGIS-IR Enterprise Authentication and Authorization.

This package provides RBAC (Role-Based Access Control), JWT authentication,
password hashing, and identity provider integration for the enterprise platform.
"""

from sift_defender.enterprise.auth.dependencies import (
    User,
    get_current_active_user,
    get_current_user,
    oauth2_scheme,
)
from sift_defender.enterprise.auth.idp_mapping import (
    DuplicateMappingError,
    GroupMapping,
    IdPGroupMapper,
)
from sift_defender.enterprise.auth.passwords import hash_password, verify_password
from sift_defender.enterprise.auth.rbac import (
    DEFAULT_ROLES,
    DefaultRoleDeletionError,
    DuplicateRoleNameError,
    InvalidPermissionError,
    Permission,
    RBACEngine,
    RoleNotFoundError,
    RoleService,
)

__all__ = [
    "DEFAULT_ROLES",
    "DefaultRoleDeletionError",
    "DuplicateMappingError",
    "DuplicateRoleNameError",
    "GroupMapping",
    "IdPGroupMapper",
    "InvalidPermissionError",
    "Permission",
    "RBACEngine",
    "RoleNotFoundError",
    "RoleService",
    "User",
    "get_current_active_user",
    "get_current_user",
    "hash_password",
    "oauth2_scheme",
    "verify_password",
]

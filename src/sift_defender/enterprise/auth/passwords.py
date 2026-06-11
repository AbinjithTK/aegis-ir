"""Password hashing utilities using bcrypt via passlib.

Provides secure password hashing and verification for local credential
authentication in the AEGIS-IR enterprise platform.

Requirements:
    4.1 - RBAC default roles (user authentication supports role enforcement)
    14.1 - SOC Analyst investigation workflow (login prerequisite)
"""

from __future__ import annotations

import bcrypt


def hash_password(plain: str) -> str:
    """Hash a plaintext password using bcrypt.

    Args:
        plain: The plaintext password to hash.

    Returns:
        A bcrypt hash string suitable for storage in the database.

    Raises:
        ValueError: If the password is empty.
    """
    if not plain:
        raise ValueError("Password must not be empty.")

    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(plain.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash.

    Args:
        plain: The plaintext password to verify.
        hashed: The bcrypt hash string from the database.

    Returns:
        True if the password matches the hash, False otherwise.
    """
    if not plain or not hashed:
        return False

    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False

"""Database connection module using asyncpg with connection pooling.

Provides connection pool management, health checks, tenant-scoped session
configuration via Row-Level Security, and graceful shutdown support.

Requirements:
    8.1 - Multi-tenant data isolation via tenant_id session variable
    13.1 - Configurable database connection managed at runtime
"""

from __future__ import annotations

import os
import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

import asyncpg

logger = logging.getLogger(__name__)

# Module-level pool reference
_pool: asyncpg.Pool | None = None


def get_database_url() -> str:
    """Retrieve the database URL from environment variables.

    Returns DATABASE_URL env var, defaulting to a local PostgreSQL instance
    for development convenience.
    """
    return os.environ.get(
        "DATABASE_URL",
        "postgresql://aegis:aegis@localhost:5432/aegis_ir",
    )


async def init_pool(
    dsn: str | None = None,
    *,
    min_size: int = 5,
    max_size: int = 20,
    command_timeout: float = 60,
    max_inactive_connection_lifetime: float = 300,
) -> asyncpg.Pool:
    """Initialize the asyncpg connection pool.

    Args:
        dsn: PostgreSQL connection string. Defaults to DATABASE_URL env var.
        min_size: Minimum number of connections maintained in the pool.
        max_size: Maximum number of connections allowed in the pool.
        command_timeout: Default timeout (seconds) for a single SQL command.
        max_inactive_connection_lifetime: Seconds before an idle connection
            is closed and removed from the pool.

    Returns:
        The initialized asyncpg connection pool.

    Raises:
        asyncpg.PostgresError: If connection to the database fails.
    """
    global _pool

    if _pool is not None:
        logger.warning("Connection pool already initialized; returning existing pool.")
        return _pool

    if dsn is None:
        dsn = get_database_url()

    logger.info("Initializing asyncpg connection pool (min=%d, max=%d)", min_size, max_size)

    _pool = await asyncpg.create_pool(
        dsn,
        min_size=min_size,
        max_size=max_size,
        command_timeout=command_timeout,
        max_inactive_connection_lifetime=max_inactive_connection_lifetime,
    )

    logger.info("Connection pool initialized successfully.")
    return _pool


def get_pool() -> asyncpg.Pool:
    """Return the current connection pool.

    Raises:
        RuntimeError: If the pool has not been initialized via init_pool().
    """
    if _pool is None:
        raise RuntimeError(
            "Database pool is not initialized. Call init_pool() during application startup."
        )
    return _pool


@asynccontextmanager
async def get_connection() -> AsyncIterator[asyncpg.Connection]:
    """Acquire a connection from the pool as an async context manager.

    Usage:
        async with get_connection() as conn:
            row = await conn.fetchrow("SELECT 1")

    Yields:
        An asyncpg Connection that is automatically released back to the pool.

    Raises:
        RuntimeError: If the pool has not been initialized.
    """
    pool = get_pool()
    async with pool.acquire() as connection:
        yield connection


@asynccontextmanager
async def get_tenant_connection(tenant_id: str) -> AsyncIterator[asyncpg.Connection]:
    """Acquire a connection with the tenant_id session variable set for RLS.

    Sets the PostgreSQL session variable `app.current_tenant` so that
    Row-Level Security policies can enforce tenant isolation automatically.

    Args:
        tenant_id: The UUID string identifying the current tenant.

    Usage:
        async with get_tenant_connection(tenant_id) as conn:
            rows = await conn.fetch("SELECT * FROM cases")
            # RLS ensures only tenant's rows are returned

    Yields:
        An asyncpg Connection configured for the specified tenant.

    Raises:
        RuntimeError: If the pool has not been initialized.
        ValueError: If tenant_id is empty or None.
    """
    if not tenant_id:
        raise ValueError("tenant_id must be a non-empty string.")

    async with get_connection() as connection:
        await set_tenant(connection, tenant_id)
        yield connection


async def set_tenant(connection: asyncpg.Connection, tenant_id: str) -> None:
    """Set the tenant_id session variable for Row-Level Security.

    Configures the PostgreSQL session so RLS policies referencing
    `current_setting('app.current_tenant')` will filter data to the
    specified tenant.

    Args:
        connection: An active asyncpg connection.
        tenant_id: The UUID string identifying the current tenant.

    Raises:
        ValueError: If tenant_id is empty or None.
    """
    if not tenant_id:
        raise ValueError("tenant_id must be a non-empty string.")

    # Use a parameterized SET via format to avoid SQL injection.
    # asyncpg doesn't support $1 params in SET, so we use set_config() which
    # accepts a text parameter safely.
    await connection.execute(
        "SELECT set_config('app.current_tenant', $1, false)",
        tenant_id,
    )


async def health_check() -> dict:
    """Perform a health check on the database connection pool.

    Tests connectivity by executing a simple query and reports pool statistics.

    Returns:
        A dict with keys:
            - healthy (bool): Whether the database is reachable.
            - pool_size (int): Current number of connections in the pool.
            - pool_free_size (int): Number of idle connections available.
            - pool_min_size (int): Configured minimum pool size.
            - pool_max_size (int): Configured maximum pool size.
            - error (str | None): Error message if unhealthy.
    """
    result: dict = {
        "healthy": False,
        "pool_size": 0,
        "pool_free_size": 0,
        "pool_min_size": 0,
        "pool_max_size": 0,
        "error": None,
    }

    if _pool is None:
        result["error"] = "Connection pool not initialized."
        return result

    try:
        async with _pool.acquire() as conn:
            row = await conn.fetchval("SELECT 1")
            if row == 1:
                result["healthy"] = True
    except Exception as exc:
        result["error"] = str(exc)
        logger.error("Database health check failed: %s", exc)

    result["pool_size"] = _pool.get_size()
    result["pool_free_size"] = _pool.get_idle_size()
    result["pool_min_size"] = _pool.get_min_size()
    result["pool_max_size"] = _pool.get_max_size()

    return result


async def close_pool() -> None:
    """Close the connection pool gracefully.

    Should be called during application shutdown to release all database
    connections cleanly.
    """
    global _pool

    if _pool is None:
        logger.debug("No connection pool to close.")
        return

    logger.info("Closing database connection pool...")
    await _pool.close()
    _pool = None
    logger.info("Database connection pool closed.")

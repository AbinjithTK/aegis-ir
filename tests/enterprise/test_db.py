"""Tests for the database connection module.

Validates connection pool initialization, health checks, tenant-scoped
connections, and graceful shutdown.

Requirements: 8.1, 13.1
"""

from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sift_defender.enterprise import db


@pytest.fixture(autouse=True)
def reset_pool():
    """Reset the module-level pool before and after each test."""
    db._pool = None
    yield
    db._pool = None


def _make_pool_acm(mock_conn):
    """Create a proper async context manager mock for pool.acquire()."""

    @asynccontextmanager
    async def _acquire():
        yield mock_conn

    return _acquire


class TestGetDatabaseUrl:
    """Test database URL retrieval from environment."""

    def test_returns_env_var_when_set(self):
        with patch.dict(os.environ, {"DATABASE_URL": "postgresql://test:test@db:5432/test"}):
            assert db.get_database_url() == "postgresql://test:test@db:5432/test"

    def test_returns_default_when_env_not_set(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DATABASE_URL", None)
            url = db.get_database_url()
            assert url == "postgresql://aegis:aegis@localhost:5432/aegis_ir"


class TestGetPool:
    """Test get_pool() accessor."""

    def test_raises_when_pool_not_initialized(self):
        with pytest.raises(RuntimeError, match="not initialized"):
            db.get_pool()

    def test_returns_pool_when_initialized(self):
        fake_pool = MagicMock()
        db._pool = fake_pool
        assert db.get_pool() is fake_pool


class TestInitPool:
    """Test pool initialization."""

    @pytest.mark.asyncio
    async def test_creates_pool_with_specified_params(self):
        mock_pool = MagicMock()

        async def fake_create_pool(*args, **kwargs):
            return mock_pool

        with patch("sift_defender.enterprise.db.asyncpg.create_pool", side_effect=fake_create_pool) as mock_create:
            pool = await db.init_pool(
                dsn="postgresql://test:test@localhost:5432/test_db",
                min_size=3,
                max_size=10,
                command_timeout=30,
                max_inactive_connection_lifetime=120,
            )

            mock_create.assert_called_once_with(
                "postgresql://test:test@localhost:5432/test_db",
                min_size=3,
                max_size=10,
                command_timeout=30,
                max_inactive_connection_lifetime=120,
            )
            assert pool is mock_pool
            assert db._pool is mock_pool

    @pytest.mark.asyncio
    async def test_uses_env_dsn_when_none_provided(self):
        mock_pool = MagicMock()

        async def fake_create_pool(*args, **kwargs):
            return mock_pool

        with patch("sift_defender.enterprise.db.asyncpg.create_pool", side_effect=fake_create_pool) as mock_create:
            with patch.dict(os.environ, {"DATABASE_URL": "postgresql://env:env@host:5432/envdb"}):
                await db.init_pool()

            mock_create.assert_called_once()
            call_args = mock_create.call_args
            assert call_args[0][0] == "postgresql://env:env@host:5432/envdb"

    @pytest.mark.asyncio
    async def test_returns_existing_pool_if_already_initialized(self):
        existing_pool = MagicMock()
        db._pool = existing_pool

        async def fake_create_pool(*args, **kwargs):
            return MagicMock()

        with patch("sift_defender.enterprise.db.asyncpg.create_pool", side_effect=fake_create_pool) as mock_create:
            result = await db.init_pool(dsn="postgresql://x:x@x:5432/x")
            mock_create.assert_not_called()
            assert result is existing_pool

    @pytest.mark.asyncio
    async def test_default_pool_parameters(self):
        mock_pool = MagicMock()

        async def fake_create_pool(*args, **kwargs):
            return mock_pool

        with patch("sift_defender.enterprise.db.asyncpg.create_pool", side_effect=fake_create_pool) as mock_create:
            await db.init_pool(dsn="postgresql://x:x@x:5432/x")

            call_kwargs = mock_create.call_args[1]
            assert call_kwargs["min_size"] == 5
            assert call_kwargs["max_size"] == 20
            assert call_kwargs["command_timeout"] == 60
            assert call_kwargs["max_inactive_connection_lifetime"] == 300


class TestGetConnection:
    """Test get_connection context manager."""

    @pytest.mark.asyncio
    async def test_raises_if_pool_not_initialized(self):
        with pytest.raises(RuntimeError, match="not initialized"):
            async with db.get_connection():
                pass

    @pytest.mark.asyncio
    async def test_acquires_and_releases_connection(self):
        mock_conn = AsyncMock()
        mock_pool = MagicMock()
        mock_pool.acquire = _make_pool_acm(mock_conn)

        db._pool = mock_pool

        async with db.get_connection() as conn:
            assert conn is mock_conn


class TestGetTenantConnection:
    """Test get_tenant_connection sets the RLS session variable."""

    @pytest.mark.asyncio
    async def test_raises_on_empty_tenant_id(self):
        mock_pool = MagicMock()
        mock_pool.acquire = _make_pool_acm(AsyncMock())
        db._pool = mock_pool

        with pytest.raises(ValueError, match="non-empty"):
            async with db.get_tenant_connection(""):
                pass

    @pytest.mark.asyncio
    async def test_raises_on_none_tenant_id(self):
        mock_pool = MagicMock()
        mock_pool.acquire = _make_pool_acm(AsyncMock())
        db._pool = mock_pool

        with pytest.raises(ValueError, match="non-empty"):
            async with db.get_tenant_connection(None):
                pass

    @pytest.mark.asyncio
    async def test_sets_tenant_session_variable(self):
        mock_conn = AsyncMock()
        mock_pool = MagicMock()
        mock_pool.acquire = _make_pool_acm(mock_conn)

        db._pool = mock_pool

        tenant_id = "550e8400-e29b-41d4-a716-446655440000"

        async with db.get_tenant_connection(tenant_id) as conn:
            assert conn is mock_conn

        # Verify set_config was called with the tenant_id
        mock_conn.execute.assert_called_once_with(
            "SELECT set_config('app.current_tenant', $1, false)",
            tenant_id,
        )


class TestSetTenant:
    """Test set_tenant helper."""

    @pytest.mark.asyncio
    async def test_executes_set_config(self):
        mock_conn = AsyncMock()
        tenant_id = "abc-123"

        await db.set_tenant(mock_conn, tenant_id)

        mock_conn.execute.assert_called_once_with(
            "SELECT set_config('app.current_tenant', $1, false)",
            tenant_id,
        )

    @pytest.mark.asyncio
    async def test_raises_on_empty_string(self):
        mock_conn = AsyncMock()
        with pytest.raises(ValueError, match="non-empty"):
            await db.set_tenant(mock_conn, "")

    @pytest.mark.asyncio
    async def test_raises_on_none(self):
        mock_conn = AsyncMock()
        with pytest.raises(ValueError, match="non-empty"):
            await db.set_tenant(mock_conn, None)


class TestHealthCheck:
    """Test health check functionality."""

    @pytest.mark.asyncio
    async def test_unhealthy_when_pool_not_initialized(self):
        result = await db.health_check()
        assert result["healthy"] is False
        assert "not initialized" in result["error"]

    @pytest.mark.asyncio
    async def test_healthy_when_query_succeeds(self):
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=1)

        mock_pool = MagicMock()
        mock_pool.acquire = _make_pool_acm(mock_conn)
        mock_pool.get_size.return_value = 5
        mock_pool.get_idle_size.return_value = 3
        mock_pool.get_min_size.return_value = 5
        mock_pool.get_max_size.return_value = 20

        db._pool = mock_pool

        result = await db.health_check()
        assert result["healthy"] is True
        assert result["error"] is None
        assert result["pool_size"] == 5
        assert result["pool_free_size"] == 3
        assert result["pool_min_size"] == 5
        assert result["pool_max_size"] == 20

    @pytest.mark.asyncio
    async def test_unhealthy_when_query_fails(self):
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(side_effect=Exception("Connection refused"))

        mock_pool = MagicMock()
        mock_pool.acquire = _make_pool_acm(mock_conn)
        mock_pool.get_size.return_value = 0
        mock_pool.get_idle_size.return_value = 0
        mock_pool.get_min_size.return_value = 5
        mock_pool.get_max_size.return_value = 20

        db._pool = mock_pool

        result = await db.health_check()
        assert result["healthy"] is False
        assert "Connection refused" in result["error"]


class TestClosePool:
    """Test pool shutdown."""

    @pytest.mark.asyncio
    async def test_closes_pool_and_clears_reference(self):
        mock_pool = AsyncMock()
        db._pool = mock_pool

        await db.close_pool()

        mock_pool.close.assert_called_once()
        assert db._pool is None

    @pytest.mark.asyncio
    async def test_noop_when_pool_is_none(self):
        # Should not raise
        await db.close_pool()
        assert db._pool is None

"""Tests for the /health endpoint and service health checks."""

from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_endpoint_returns_json_structure(async_client: AsyncClient) -> None:
    """Verify that /health returns all required fields in its JSON payload."""
    response = await async_client.get("/health")
    assert response.status_code in (200, 503)

    data = response.json()
    assert "status" in data
    assert "postgres" in data
    assert "redis" in data
    assert "version" in data
    assert "timestamp" in data
    assert data["status"] in ("healthy", "degraded", "unhealthy")


@pytest.mark.asyncio
async def test_health_healthy_when_both_services_up(async_client: AsyncClient) -> None:
    """Verify that /health returns HTTP 200 and 'healthy' when PostgreSQL and Redis are both UP."""
    with (
        patch("app.api.v1.health.check_db_health", new_callable=AsyncMock) as mock_db,
        patch("app.api.v1.health.check_redis_health", new_callable=AsyncMock) as mock_redis,
    ):
        mock_db.return_value = True
        mock_redis.return_value = True

        response = await async_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["postgres"] == "connected"
        assert data["redis"] == "connected"


@pytest.mark.asyncio
async def test_health_degraded_when_one_service_down(async_client: AsyncClient) -> None:
    """Verify that /health returns HTTP 200 and 'degraded' when one service is DOWN."""
    with (
        patch("app.api.v1.health.check_db_health", new_callable=AsyncMock) as mock_db,
        patch("app.api.v1.health.check_redis_health", new_callable=AsyncMock) as mock_redis,
    ):
        mock_db.return_value = True
        mock_redis.return_value = False

        response = await async_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "degraded"
        assert data["postgres"] == "connected"
        assert data["redis"] == "disconnected"


@pytest.mark.asyncio
async def test_health_unhealthy_when_both_services_down(async_client: AsyncClient) -> None:
    """Verify that /health returns HTTP 503 and 'unhealthy' when both services are DOWN."""
    with (
        patch("app.api.v1.health.check_db_health", new_callable=AsyncMock) as mock_db,
        patch("app.api.v1.health.check_redis_health", new_callable=AsyncMock) as mock_redis,
    ):
        mock_db.return_value = False
        mock_redis.return_value = False

        response = await async_client.get("/health")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "unhealthy"
        assert data["postgres"] == "disconnected"
        assert data["redis"] == "disconnected"


@pytest.mark.asyncio
async def test_api_v1_health_matches_root_health(async_client: AsyncClient) -> None:
    """Verify that /api/v1/health is also reachable and returns valid structure."""
    response = await async_client.get("/api/v1/health")
    assert response.status_code in (200, 503)
    data = response.json()
    assert "status" in data
    assert "postgres" in data
    assert "redis" in data

"""Integration tests for Stage 11: Admin and Management Endpoints."""

import pytest
from httpx import AsyncClient
from redis.asyncio import Redis

from app.schemas.indicator import IndicatorType
from app.schemas.threat_cache import generate_cache_key


@pytest.mark.asyncio
class TestBlacklistEndpoints:
    """Test Blacklist CRUD management endpoints."""

    async def test_add_and_list_and_delete_blacklist(
        self, async_client: AsyncClient, redis_test_client: Redis
    ) -> None:
        ip = "192.0.2.100"

        # 1. Add IP to blacklist
        add_resp = await async_client.post("/api/blacklist", json={"indicator": ip})
        assert add_resp.status_code == 201
        data = add_resp.json()
        assert data["indicator"] == ip
        assert data["indicator_type"] == "ip"
        assert data["blacklisted"] is True

        # 2. Check blacklist listing
        list_resp = await async_client.get("/api/blacklist", params={"indicator_type": "ip"})
        assert list_resp.status_code == 200
        list_data = list_resp.json()
        assert list_data["total"] >= 1
        assert ip in list_data["items"]

        # 3. Lookup on this IP should now immediately hit blacklist
        check_resp = await async_client.post("/api/check", json={"indicator": ip})
        assert check_resp.status_code == 200
        check_data = check_resp.json()
        assert check_data["malicious"] is True
        assert check_data["threat_score"] == 100
        assert check_data["source"] == "redis_blacklist"

        # 4. Remove IP from blacklist
        del_resp = await async_client.delete(f"/api/blacklist/{ip}")
        assert del_resp.status_code == 200
        del_data = del_resp.json()
        assert del_data["blacklisted"] is False
        assert "removed" in del_data["message"]

        # 5. Verify it is no longer listed
        list_resp2 = await async_client.get("/api/blacklist", params={"indicator_type": "ip"})
        assert ip not in list_resp2.json()["items"]

    async def test_blacklist_url_path_handling(
        self, async_client: AsyncClient
    ) -> None:
        url = "http://phishing-site.test/login.php?user=admin"

        add_resp = await async_client.post("/api/blacklist", json={"indicator": url})
        assert add_resp.status_code == 201

        # Delete with URL in path
        del_resp = await async_client.delete(f"/api/blacklist/{url}")
        assert del_resp.status_code == 200
        assert del_resp.json()["blacklisted"] is False

    async def test_blacklist_invalid_indicator_returns_422(
        self, async_client: AsyncClient
    ) -> None:
        resp = await async_client.post("/api/blacklist", json={"indicator": "invalid@@domain"})
        assert resp.status_code == 422


@pytest.mark.asyncio
class TestRefreshEndpoint:
    """Test POST /api/refresh/{indicator} cache bypass and Redis repopulation."""

    async def test_refresh_indicator_bypasses_cache_and_updates_redis(
        self, async_client: AsyncClient, redis_test_client: Redis
    ) -> None:
        indicator = "198.51.100.25"
        key = generate_cache_key(IndicatorType.IP, indicator)

        # 1. First populate the cache
        resp1 = await async_client.post("/api/check", json={"indicator": indicator})
        assert resp1.status_code == 200
        assert resp1.json()["cached"] is False

        # Verify it is in Redis
        assert await redis_test_client.exists(key) == 1

        # 2. Call refresh endpoint
        ref_resp = await async_client.post(f"/api/refresh/{indicator}")
        assert ref_resp.status_code == 200
        ref_data = ref_resp.json()

        # Must report fresh provider query (cached=False)
        assert ref_data["cached"] is False
        assert ref_data["malicious"] is True
        assert ref_data["threat_score"] == 95
        assert ref_data["ttl_seconds"] is not None
        assert ref_data["ttl_seconds"] > 0

        # Redis key must still exist with fresh TTL
        ttl = await redis_test_client.ttl(key)
        assert ttl > 0

    async def test_refresh_invalid_indicator_returns_422(
        self, async_client: AsyncClient
    ) -> None:
        resp = await async_client.post("/api/refresh/invalid@@domain")
        assert resp.status_code == 422


@pytest.mark.asyncio
class TestHealthAndStatsEndpoints:
    """Test operational health and statistics endpoints."""

    async def test_health_check_returns_healthy(
        self, async_client: AsyncClient
    ) -> None:
        resp = await async_client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] in ("healthy", "degraded")
        assert "postgres" in data
        assert "redis" in data

    async def test_stats_endpoint_returns_metrics(
        self, async_client: AsyncClient
    ) -> None:
        # Perform at least one lookup to generate metrics
        await async_client.post("/api/check", json={"indicator": "198.51.100.25"})

        resp = await async_client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_lookups"] >= 1
        assert "cache_hit_rate" in data
        assert "latency_stats" in data
        assert "avg_ms" in data["latency_stats"]

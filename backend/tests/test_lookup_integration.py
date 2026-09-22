"""Integration tests for the cache-first threat lookup pipeline (PostgreSQL <-> Redis)."""

import asyncio

import pytest
from httpx import AsyncClient
from redis.asyncio import Redis

from app.schemas.indicator import IndicatorType
from app.schemas.threat_cache import generate_cache_key


@pytest.mark.asyncio
async def test_first_lookup_queries_postgres_and_populates_redis(
    async_client: AsyncClient, redis_test_client: Redis
) -> None:
    """1. First lookup: cache miss -> queries PostgreSQL -> populates Redis -> returns cached=False."""
    indicator = "198.51.100.25"
    key = generate_cache_key(IndicatorType.IP, indicator)

    # Ensure Redis cache is cold for this indicator
    await redis_test_client.delete(key)

    response = await async_client.post("/api/check", json={"indicator": indicator})
    assert response.status_code == 200

    data = response.json()
    assert data["original_indicator"] == indicator
    assert data["normalized_indicator"] == indicator
    assert data["indicator_type"] == "ip"
    assert data["cached"] is False
    assert data["malicious"] is True
    assert data["threat_score"] == 95
    assert data["confidence"] == 0.95
    assert "c2" in data["categories"]
    assert "local_cti" in data["source"]
    assert data["ttl_seconds"] is not None
    assert data["ttl_seconds"] > 0

    # Verify that Redis Hash is populated
    redis_data = await redis_test_client.hgetall(key)
    assert redis_data != {}
    assert redis_data["indicator"] == indicator
    assert redis_data["malicious"] == "true"
    assert redis_data["threat_score"] == "95"


@pytest.mark.asyncio
async def test_second_lookup_hits_redis_only(
    async_client: AsyncClient, redis_test_client: Redis
) -> None:
    """2. Second lookup: cache hit -> served from Redis only -> returns cached=True."""
    indicator = "198.51.100.25"
    key = generate_cache_key(IndicatorType.IP, indicator)

    # Initial lookup to populate cache
    resp1 = await async_client.post("/api/check", json={"indicator": indicator})
    assert resp1.status_code == 200
    assert resp1.json()["cached"] is False

    # Pre-condition: key exists in Redis
    assert await redis_test_client.exists(key) == 1

    response = await async_client.post("/api/check", json={"indicator": indicator})
    assert response.status_code == 200

    data = response.json()
    assert data["original_indicator"] == indicator
    assert data["normalized_indicator"] == indicator
    assert data["cached"] is True
    assert data["malicious"] is True
    assert data["threat_score"] == 95
    assert data["ttl_seconds"] is not None
    assert data["ttl_seconds"] > 0


@pytest.mark.asyncio
async def test_expired_redis_entry_queries_postgres_again(
    async_client: AsyncClient, redis_test_client: Redis
) -> None:
    """3. Expired Redis entry: cache miss -> queries PostgreSQL again -> repopulates Redis."""
    indicator = "203.0.113.50"
    key = generate_cache_key(IndicatorType.IP, indicator)

    # First lookup to establish baseline
    await redis_test_client.delete(key)
    resp1 = await async_client.post("/api/check", json={"indicator": indicator})
    assert resp1.status_code == 200
    assert resp1.json()["cached"] is False

    # Simulate key expiration by setting 1s TTL and waiting
    await redis_test_client.expire(key, 1)
    await asyncio.sleep(1.2)
    assert await redis_test_client.ttl(key) == -2

    # Query again: must query PostgreSQL, return cached=False, and repopulate Redis
    resp2 = await async_client.post("/api/check", json={"indicator": indicator})
    assert resp2.status_code == 200

    data = resp2.json()
    assert data["cached"] is False
    assert data["malicious"] is True
    assert data["threat_score"] == 85
    assert "local_cti" in data["source"]

    # Redis must be repopulated
    assert await redis_test_client.ttl(key) > 0


@pytest.mark.asyncio
async def test_malformed_indicator_returns_validation_error(
    async_client: AsyncClient,
) -> None:
    """4. Malformed indicator returns HTTP 422 with structured validation error."""
    response = await async_client.post(
        "/api/check", json={"indicator": "invalid_domain@@##!!"}
    )
    assert response.status_code == 422
    data = response.json()
    assert "detail" in data
    assert "Validation error" in data["detail"]

    # Test empty indicator
    empty_resp = await async_client.post("/api/check", json={"indicator": "   "})
    assert empty_resp.status_code == 422


@pytest.mark.asyncio
async def test_trusted_domain_lookup_recognizes_whitelist(
    async_client: AsyncClient, redis_test_client: Redis
) -> None:
    """Trusted root domains (and subdomains) are recognized and marked benign."""
    trusted_url = "https://accounts.google.com/signin"
    key = generate_cache_key(IndicatorType.URL, "https://accounts.google.com/signin")
    await redis_test_client.delete(key)

    response = await async_client.post("/api/check", json={"indicator": trusted_url})
    assert response.status_code == 200

    data = response.json()
    assert data["malicious"] is False
    assert data["threat_score"] == 0
    assert data["confidence"] == 1.0
    assert "trusted" in data["source"]

    # Subsequent lookup should hit Redis
    cached_resp = await async_client.post("/api/check", json={"indicator": trusted_url})
    assert cached_resp.status_code == 200
    assert cached_resp.json()["cached"] is True

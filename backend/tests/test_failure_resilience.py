"""Tests for Stage 10: Failure Handling, Resilience, and Graceful Degradation."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest
from httpx import AsyncClient
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from app.api.deps import get_provider
from app.core.exceptions import (
    DatabaseUnavailableError,
    ProviderError,
    ProviderRateLimitError,
    ProviderTimeoutError,
    ProviderUnavailableError,
)
from app.main import app
from app.schemas.indicator import IndicatorType
from app.schemas.threat_cache import CachedThreatRecord
from app.services.lookup import LookupService
from app.services.providers.base import ThreatIntelligenceProvider
from app.services.threat_cache import ThreatCacheService


class FailingProvider(ThreatIntelligenceProvider):
    """Mock provider that simulates specific failure modes."""

    def __init__(self, failure_type: str = "timeout") -> None:
        self.failure_type = failure_type

    async def lookup(
        self, indicator: str, indicator_type: IndicatorType
    ) -> CachedThreatRecord | None:
        if self.failure_type == "timeout":
            raise ProviderTimeoutError(f"Provider timed out for indicator {indicator}")
        elif self.failure_type == "rate_limit":
            raise ProviderRateLimitError(f"Rate limit exceeded (429) for indicator {indicator}")
        elif self.failure_type == "unavailable":
            raise ProviderUnavailableError(f"Provider service unavailable (503) for indicator {indicator}")
        elif self.failure_type == "malformed":
            raise ProviderError(f"Malformed JSON response from upstream provider for {indicator}")
        elif self.failure_type == "database_error":
            raise DatabaseUnavailableError("PostgreSQL connection pool exhausted")
        return None

    async def is_trusted_domain(self, domain: str) -> bool:
        return False

    async def get_matched_trusted_domain(self, domain: str) -> str | None:
        return None


@pytest.mark.asyncio
class TestProviderFailureModes:
    """Test API behavior under external provider failures without fabricating verdicts."""

    async def test_provider_timeout_returns_504(
        self, async_client: AsyncClient
    ) -> None:
        provider = FailingProvider(failure_type="timeout")
        app.dependency_overrides[get_provider] = lambda: provider

        try:
            resp = await async_client.post("/api/check", json={"indicator": "198.51.100.99"})
            assert resp.status_code == 504
            data = resp.json()
            assert data["error_type"] == "provider_timeout"
            assert "timed out" in data["detail"]
        finally:
            app.dependency_overrides.pop(get_provider, None)

    async def test_provider_rate_limit_returns_429(
        self, async_client: AsyncClient
    ) -> None:
        provider = FailingProvider(failure_type="rate_limit")
        app.dependency_overrides[get_provider] = lambda: provider

        try:
            resp = await async_client.post("/api/check", json={"indicator": "198.51.100.99"})
            assert resp.status_code == 429
            data = resp.json()
            assert data["error_type"] == "provider_rate_limit"
            assert "Rate limit" in data["detail"]
        finally:
            app.dependency_overrides.pop(get_provider, None)

    async def test_provider_unavailable_returns_503(
        self, async_client: AsyncClient
    ) -> None:
        provider = FailingProvider(failure_type="unavailable")
        app.dependency_overrides[get_provider] = lambda: provider

        try:
            resp = await async_client.post("/api/check", json={"indicator": "198.51.100.99"})
            assert resp.status_code == 503
            data = resp.json()
            assert data["error_type"] == "provider_unavailable"
            assert "unavailable" in data["detail"]
        finally:
            app.dependency_overrides.pop(get_provider, None)

    async def test_provider_malformed_response_returns_502(
        self, async_client: AsyncClient
    ) -> None:
        provider = FailingProvider(failure_type="malformed")
        app.dependency_overrides[get_provider] = lambda: provider

        try:
            resp = await async_client.post("/api/check", json={"indicator": "198.51.100.99"})
            assert resp.status_code == 502
            data = resp.json()
            assert data["error_type"] == "provider_error"
            assert "Malformed JSON" in data["detail"]
        finally:
            app.dependency_overrides.pop(get_provider, None)

    async def test_database_unavailable_returns_503(
        self, async_client: AsyncClient
    ) -> None:
        provider = FailingProvider(failure_type="database_error")
        app.dependency_overrides[get_provider] = lambda: provider

        try:
            resp = await async_client.post("/api/check", json={"indicator": "198.51.100.99"})
            assert resp.status_code == 503
            data = resp.json()
            assert data["error_type"] == "database_unavailable"
            assert "Database service unavailable" in data["detail"]
        finally:
            app.dependency_overrides.pop(get_provider, None)


@pytest.mark.asyncio
class TestCacheFallbackOnProviderFailure:
    """If a valid cached result is present and provider fails, return cached result with clear fallback source."""

    async def test_cached_fallback_returned_when_provider_fails_during_lookup(
        self, redis_test_client: Redis
    ) -> None:
        cache_service = ThreatCacheService(redis_test_client)
        provider = FailingProvider(failure_type="timeout")
        lookup_service = LookupService(cache_service=cache_service, provider=provider)

        # Populate cache with a verified threat
        indicator = "203.0.113.10"
        record = CachedThreatRecord(
            indicator=indicator,
            indicator_type=IndicatorType.IP,
            malicious=True,
            threat_score=88,
            confidence=0.9,
            categories=["ransomware"],
            source="virustotal",
            checked_at=datetime.now(UTC),
        )
        await cache_service.set(record, ttl_seconds=300)

        # Run lookup with force_refresh=True (which attempts provider query)
        result = await lookup_service.lookup(indicator, force_refresh=True)

        # Must NOT crash or return safe; must return the cached fallback with clear source tag
        assert result.original_indicator == indicator
        assert result.malicious is True
        assert result.threat_score == 88
        assert "cache_fallback:virustotal" in result.source
        assert result.cached is True


@pytest.mark.asyncio
class TestRedisFailureGracefulDegradation:
    """When Redis is unavailable, the service degrades gracefully to direct provider query."""

    async def test_redis_connection_error_does_not_crash_lookup(
        self, db_session
    ) -> None:
        from app.services.providers.local_cti import LocalCTIProvider

        # Mock Redis cache that throws ConnectionError on get and set
        mock_cache = AsyncMock(spec=ThreatCacheService)
        mock_cache.get.side_effect = RedisConnectionError("Redis connection refused")
        mock_cache.set.side_effect = RedisConnectionError("Redis connection refused")
        mock_cache.determine_ttl.return_value = 300

        provider = LocalCTIProvider(db_session)
        lookup_service = LookupService(
            cache_service=mock_cache,
            provider=provider,
            blacklist_service=None,  # skip or test separately
            metrics_service=None,
        )

        # Known indicator in DB: 198.51.100.25 (seeded in conftest or seed data)
        # Should gracefully execute local CTI lookup and return malicious=True, cached=False
        result = await lookup_service.lookup("198.51.100.25")
        assert result.normalized_indicator == "198.51.100.25"
        assert result.malicious is True
        assert result.threat_score == 95
        assert result.cached is False

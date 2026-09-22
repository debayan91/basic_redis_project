"""Tests for Stage 12: Benchmarking Module."""

import pytest
from redis.asyncio import Redis

from app.services.benchmark import BenchmarkEngine
from app.services.lookup import LookupService
from app.services.providers.mock_external import MockExternalCTIProvider
from app.services.threat_cache import ThreatCacheService


@pytest.mark.asyncio
class TestBenchmarkEngine:
    """Test standalone benchmarking generation, execution, and outputs."""

    async def test_workload_generation_is_reproducible(self) -> None:
        workload1 = BenchmarkEngine.generate_workload(num_unique=10, total_requests=50, seed=123)
        workload2 = BenchmarkEngine.generate_workload(num_unique=10, total_requests=50, seed=123)
        assert workload1 == workload2
        assert len(workload1) == 50

    async def test_compare_produces_json_and_csv(self, redis_test_client: Redis) -> None:
        cache_service = ThreatCacheService(redis_test_client)
        provider = MockExternalCTIProvider(simulated_latency=0.001)
        lookup_service = LookupService(cache_service=cache_service, provider=provider)

        engine = BenchmarkEngine(
            lookup_service=lookup_service,
            provider=provider,
            cache_service=cache_service,
        )

        results = await engine.compare(
            num_unique=5,
            total_requests=20,
            repetition_frequency=0.8,
            seed=42,
        )

        assert "direct_mode" in results
        assert "redis_mode" in results
        assert results["redis_mode"]["cache_hit_rate"] > 0
        assert results["redis_mode"]["provider_requests_avoided"] > 0

        # Verify CSV conversion
        csv_output = BenchmarkEngine.to_csv(results)
        assert "Direct (No Cache)" in csv_output
        assert "Redis Cache-First" in csv_output

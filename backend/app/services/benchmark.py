"""Standalone benchmarking engine for Threat Intelligence Lookup performance.

Compares:
- Mode A (Direct): Direct queries to threat intelligence provider (no operational cache)
- Mode B (Redis): Cache-first Redis pipeline with dynamic TTL
"""

import csv
import io
import random
import statistics
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from app.services.indicator import IndicatorService
from app.services.lookup import LookupService
from app.services.providers.base import ThreatIntelligenceProvider
from app.services.threat_cache import ThreatCacheService


@dataclass
class BenchmarkMetrics:
    """Performance and operational metrics recorded during a benchmark run."""

    mode: str
    total_requests: int
    execution_time_seconds: float
    avg_latency_ms: float
    p50_latency_ms: float
    p95_latency_ms: float
    min_latency_ms: float
    max_latency_ms: float
    cache_hits: int
    cache_misses: int
    cache_hit_rate: float
    cache_miss_rate: float
    provider_requests: int
    provider_requests_avoided: int
    malicious_detections: int
    errors: int


class BenchmarkEngine:
    """Executes controlled, reproducible benchmark workloads comparing Direct vs Redis pipelines."""

    def __init__(
        self,
        lookup_service: LookupService,
        provider: ThreatIntelligenceProvider,
        cache_service: ThreatCacheService,
    ) -> None:
        self.lookup_service = lookup_service
        self.provider = provider
        self.cache = cache_service

    @staticmethod
    def generate_workload(
        num_unique: int = 20,
        total_requests: int = 100,
        repetition_frequency: float = 0.7,
        seed: int = 42,
    ) -> list[str]:
        """Generate a reproducible workload with controlled repetition frequency."""
        rng = random.Random(seed)

        # Generate unique synthetic indicators
        unique_ips = [f"198.51.100.{i}" for i in range(1, num_unique + 1)]
        popular_subset_size = max(1, int(num_unique * 0.2))
        popular_pool = unique_ips[:popular_subset_size]

        workload: list[str] = []
        for _ in range(total_requests):
            if rng.random() < repetition_frequency and popular_pool:
                workload.append(rng.choice(popular_pool))
            else:
                workload.append(rng.choice(unique_ips))

        return workload

    async def run_direct_mode(self, workload: list[str]) -> BenchmarkMetrics:
        """Mode A — DIRECT: Every request bypasses operational cache directly to the provider."""
        latencies: list[float] = []
        provider_requests = 0
        malicious_count = 0
        errors = 0

        start_time = time.perf_counter()

        for indicator in workload:
            t0 = time.perf_counter()
            try:
                parsed = IndicatorService.parse_and_normalize(indicator)
                res = await self.provider.lookup(parsed.normalized, parsed.indicator_type)
                provider_requests += 1
                if res and res.malicious:
                    malicious_count += 1
            except Exception:
                errors += 1
            t1 = time.perf_counter()
            latencies.append((t1 - t0) * 1000)

        total_time = time.perf_counter() - start_time
        total_reqs = len(workload)
        sorted_lat = sorted(latencies) if latencies else [0.0]

        return BenchmarkMetrics(
            mode="Direct (No Cache)",
            total_requests=total_reqs,
            execution_time_seconds=round(total_time, 4),
            avg_latency_ms=round(statistics.mean(latencies) if latencies else 0.0, 2),
            p50_latency_ms=round(sorted_lat[int(len(sorted_lat) * 0.50)], 2),
            p95_latency_ms=round(sorted_lat[min(int(len(sorted_lat) * 0.95), len(sorted_lat) - 1)], 2),
            min_latency_ms=round(min(latencies) if latencies else 0.0, 2),
            max_latency_ms=round(max(latencies) if latencies else 0.0, 2),
            cache_hits=0,
            cache_misses=total_reqs,
            cache_hit_rate=0.0,
            cache_miss_rate=1.0,
            provider_requests=provider_requests,
            provider_requests_avoided=0,
            malicious_detections=malicious_count,
            errors=errors,
        )

    async def run_redis_mode(self, workload: list[str]) -> BenchmarkMetrics:
        """Mode B — REDIS: Requests pass through the Redis cache-first pipeline."""
        latencies: list[float] = []
        cache_hits = 0
        cache_misses = 0
        provider_requests = 0
        malicious_count = 0
        errors = 0

        start_time = time.perf_counter()

        for indicator in workload:
            t0 = time.perf_counter()
            try:
                res = await self.lookup_service.lookup(indicator)
                if res.cached:
                    cache_hits += 1
                else:
                    cache_misses += 1
                    provider_requests += 1
                if res.malicious:
                    malicious_count += 1
            except Exception:
                errors += 1
            t1 = time.perf_counter()
            latencies.append((t1 - t0) * 1000)

        total_time = time.perf_counter() - start_time
        total_reqs = len(workload)
        hit_rate = round(cache_hits / total_reqs, 4) if total_reqs else 0.0
        miss_rate = round(cache_misses / total_reqs, 4) if total_reqs else 0.0
        avoided = cache_hits
        sorted_lat = sorted(latencies) if latencies else [0.0]

        return BenchmarkMetrics(
            mode="Redis Cache-First",
            total_requests=total_reqs,
            execution_time_seconds=round(total_time, 4),
            avg_latency_ms=round(statistics.mean(latencies) if latencies else 0.0, 2),
            p50_latency_ms=round(sorted_lat[int(len(sorted_lat) * 0.50)], 2),
            p95_latency_ms=round(sorted_lat[min(int(len(sorted_lat) * 0.95), len(sorted_lat) - 1)], 2),
            min_latency_ms=round(min(latencies) if latencies else 0.0, 2),
            max_latency_ms=round(max(latencies) if latencies else 0.0, 2),
            cache_hits=cache_hits,
            cache_misses=cache_misses,
            cache_hit_rate=hit_rate,
            cache_miss_rate=miss_rate,
            provider_requests=provider_requests,
            provider_requests_avoided=avoided,
            malicious_detections=malicious_count,
            errors=errors,
        )

    async def compare(
        self,
        num_unique: int = 25,
        total_requests: int = 150,
        repetition_frequency: float = 0.75,
        seed: int = 42,
    ) -> dict[str, Any]:
        """Execute identical workload on both Mode A (Direct) and Mode B (Redis)."""
        workload = self.generate_workload(
            num_unique=num_unique,
            total_requests=total_requests,
            repetition_frequency=repetition_frequency,
            seed=seed,
        )

        direct_metrics = await self.run_direct_mode(workload)
        redis_metrics = await self.run_redis_mode(workload)

        speedup = (
            round(direct_metrics.avg_latency_ms / redis_metrics.avg_latency_ms, 2)
            if redis_metrics.avg_latency_ms > 0
            else 1.0
        )

        return {
            "experiment": "Direct vs Redis Benchmark",
            "timestamp": datetime.now(UTC).isoformat(),
            "config": {
                "num_unique_indicators": num_unique,
                "total_requests": total_requests,
                "repetition_frequency": repetition_frequency,
                "seed": seed,
            },
            "speedup_factor": speedup,
            "direct_mode": asdict(direct_metrics),
            "redis_mode": asdict(redis_metrics),
        }

    @staticmethod
    def to_csv(comparison_data: dict[str, Any]) -> str:
        """Convert benchmark comparison results to standard CSV format."""
        output = io.StringIO()
        writer = csv.writer(output)

        headers = [
            "mode",
            "total_requests",
            "execution_time_seconds",
            "avg_latency_ms",
            "p50_latency_ms",
            "p95_latency_ms",
            "cache_hit_rate",
            "cache_miss_rate",
            "provider_requests",
            "provider_requests_avoided",
            "malicious_detections",
            "errors",
        ]
        writer.writerow(headers)

        for mode_key in ("direct_mode", "redis_mode"):
            m = comparison_data[mode_key]
            writer.writerow([
                m["mode"],
                m["total_requests"],
                m["execution_time_seconds"],
                m["avg_latency_ms"],
                m["p50_latency_ms"],
                m["p95_latency_ms"],
                m["cache_hit_rate"],
                m["cache_miss_rate"],
                m["provider_requests"],
                m["provider_requests_avoided"],
                m["malicious_detections"],
                m["errors"],
            ])

        return output.getvalue()

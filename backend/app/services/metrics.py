"""Metrics Service managing atomic operational counters and latency statistics in Redis."""

import logging
import math
from typing import Any

from redis.asyncio import Redis

logger = logging.getLogger(__name__)


class MetricsService:
    """Tracks operational security metrics using atomic Redis counters and latency buffers."""

    KEY_TOTAL = "stats:lookups:total"
    KEY_HITS = "stats:cache:hits"
    KEY_MISSES = "stats:cache:misses"
    KEY_PROVIDER = "stats:provider:lookups"
    KEY_MALICIOUS = "stats:malicious:detections"
    KEY_ERRORS = "stats:errors"
    KEY_LATENCY_SAMPLES = "stats:latency:samples"
    MAX_LATENCY_SAMPLES = 1000

    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    async def record_lookup(
        self,
        cached: bool,
        malicious: bool,
        latency_ms: float,
        provider_queried: bool = False,
    ) -> None:
        """Atomically record lookup outcome, counters, and execution latency."""
        pipe = self.redis.pipeline(transaction=True)
        pipe.incr(self.KEY_TOTAL)

        if cached:
            pipe.incr(self.KEY_HITS)
        else:
            pipe.incr(self.KEY_MISSES)

        if provider_queried:
            pipe.incr(self.KEY_PROVIDER)

        if malicious:
            pipe.incr(self.KEY_MALICIOUS)

        # Buffer latency sample (push left and trim right to keep bounded buffer)
        pipe.lpush(self.KEY_LATENCY_SAMPLES, str(round(latency_ms, 3)))
        pipe.ltrim(self.KEY_LATENCY_SAMPLES, 0, self.MAX_LATENCY_SAMPLES - 1)

        await pipe.execute()

    async def record_error(self) -> None:
        """Atomically increment operational error counter."""
        await self.redis.incr(self.KEY_ERRORS)

    async def get_stats(self) -> dict[str, Any]:
        """Retrieve aggregated operational metrics and compute latency percentiles."""
        pipe = self.redis.pipeline(transaction=False)
        pipe.get(self.KEY_TOTAL)
        pipe.get(self.KEY_HITS)
        pipe.get(self.KEY_MISSES)
        pipe.get(self.KEY_PROVIDER)
        pipe.get(self.KEY_MALICIOUS)
        pipe.get(self.KEY_ERRORS)
        pipe.lrange(self.KEY_LATENCY_SAMPLES, 0, -1)

        results = await pipe.execute()

        total = int(results[0] or 0)
        hits = int(results[1] or 0)
        misses = int(results[2] or 0)
        provider_lookups = int(results[3] or 0)
        malicious = int(results[4] or 0)
        errors = int(results[5] or 0)
        raw_samples = results[6] or []

        # Calculate cache hit rate percentage
        hit_rate = round((hits / total) * 100, 2) if total > 0 else 0.0

        # Calculate latency statistics
        latency_floats = []
        for s in raw_samples:
            try:
                latency_floats.append(float(s))
            except (ValueError, TypeError):
                continue

        if latency_floats:
            sorted_latencies = sorted(latency_floats)
            n = len(sorted_latencies)
            avg_lat = round(sum(sorted_latencies) / n, 2)
            min_lat = round(sorted_latencies[0], 2)
            max_lat = round(sorted_latencies[-1], 2)
            p50_lat = round(sorted_latencies[int(math.floor(0.50 * (n - 1)))], 2)
            p95_lat = round(sorted_latencies[int(math.floor(0.95 * (n - 1)))], 2)
        else:
            avg_lat = min_lat = max_lat = p50_lat = p95_lat = 0.0

        return {
            "total_lookups": total,
            "cache_hits": hits,
            "cache_misses": misses,
            "cache_hit_rate": hit_rate,
            "provider_lookups": provider_lookups,
            "malicious_detections": malicious,
            "error_count": errors,
            "latency_stats": {
                "avg_ms": avg_lat,
                "p50_ms": p50_lat,
                "p95_ms": p95_lat,
                "min_ms": min_lat,
                "max_ms": max_lat,
                "sample_count": len(latency_floats),
            },
        }

    async def reset(self) -> None:
        """Reset all counters and latency buffers (primarily for tests)."""
        await self.redis.delete(
            self.KEY_TOTAL,
            self.KEY_HITS,
            self.KEY_MISSES,
            self.KEY_PROVIDER,
            self.KEY_MALICIOUS,
            self.KEY_ERRORS,
            self.KEY_LATENCY_SAMPLES,
        )

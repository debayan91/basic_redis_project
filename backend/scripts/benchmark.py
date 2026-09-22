"""Standalone CLI script for running Threat Intelligence Cache benchmarks."""

import argparse
import asyncio
import json
import sys
from pathlib import Path

# Add backend directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redis.asyncio import Redis

from app.core.config import get_settings
from app.services.benchmark import BenchmarkEngine
from app.services.lookup import LookupService
from app.services.providers.mock_external import MockExternalCTIProvider
from app.services.threat_cache import ThreatCacheService


async def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark Direct vs Redis Threat Cache pipelines")
    parser.add_argument("--requests", type=int, default=100, help="Total requests in workload")
    parser.add_argument("--unique", type=int, default=20, help="Number of unique indicators")
    parser.add_argument("--repetition", type=float, default=0.75, help="Repetition frequency (0.0 to 1.0)")
    parser.add_argument("--format", choices=["json", "csv"], default="json", help="Output format")
    parser.add_argument("--output-file", type=str, default=None, help="Optional output filepath")

    args = parser.parse_args()
    settings = get_settings()

    redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
    cache_service = ThreatCacheService(redis_client, settings=settings)

    # Use simulated provider with realistic CTI latency (15ms)
    provider = MockExternalCTIProvider(simulated_latency=0.015)
    lookup_service = LookupService(
        cache_service=cache_service,
        provider=provider,
        settings=settings,
    )

    try:
        # Flush redis to ensure cold baseline
        await redis_client.flushdb()

        engine = BenchmarkEngine(
            lookup_service=lookup_service,
            provider=provider,
            cache_service=cache_service,
        )

        results = await engine.compare(
            num_unique=args.unique,
            total_requests=args.requests,
            repetition_frequency=args.repetition,
        )

        if args.format == "csv":
            formatted_output = BenchmarkEngine.to_csv(results)
        else:
            formatted_output = json.dumps(results, indent=2)

        if args.output_file:
            with open(args.output_file, "w") as f:
                f.write(formatted_output)
            print(f"Results written to {args.output_file}")
        else:
            print(formatted_output)

    finally:
        await redis_client.aclose()


if __name__ == "__main__":
    asyncio.run(main())

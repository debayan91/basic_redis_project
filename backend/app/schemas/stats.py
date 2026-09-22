"""Schemas for system and lookup operational metrics."""

from pydantic import BaseModel, Field


class LatencyStats(BaseModel):
    """Detailed latency distribution statistics in milliseconds."""
    avg_ms: float = Field(..., description="Average lookup latency")
    p50_ms: float = Field(..., description="50th percentile (median) latency")
    p95_ms: float = Field(..., description="95th percentile latency")
    min_ms: float = Field(..., description="Minimum recorded latency")
    max_ms: float = Field(..., description="Maximum recorded latency")
    sample_count: int = Field(..., description="Number of latency samples in rolling window")


class SystemStatsResponse(BaseModel):
    """Operational metrics returned by GET /api/stats."""
    total_lookups: int = Field(..., description="Total number of indicator lookups processed")
    cache_hits: int = Field(..., description="Number of lookups served directly from Redis cache")
    cache_misses: int = Field(..., description="Number of lookups requiring provider queries")
    cache_hit_rate: float = Field(..., description="Percentage of requests served from cache (0.0 to 100.0)")
    provider_lookups: int = Field(..., description="Total calls dispatched to threat intelligence providers")
    malicious_detections: int = Field(..., description="Total confirmed malicious indicators detected")
    error_count: int = Field(..., description="Total operational or lookup errors recorded")
    latency_stats: LatencyStats = Field(..., description="Lookup latency percentiles and distribution")

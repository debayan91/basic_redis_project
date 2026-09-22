"""Operational stats endpoint."""

from fastapi import APIRouter, Depends

from app.api.deps import get_metrics_service
from app.schemas.stats import SystemStatsResponse
from app.services.metrics import MetricsService

router = APIRouter(tags=["Metrics & Statistics"])


@router.get(
    "/stats",
    response_model=SystemStatsResponse,
    summary="Get operational lookup and cache metrics",
    description="Retrieve system-wide lookups, cache hits, cache misses, hit rate, and latency statistics.",
)
async def get_system_stats(
    metrics_service: MetricsService = Depends(get_metrics_service),
) -> SystemStatsResponse:
    """Retrieve operational lookup and performance metrics."""
    stats = await metrics_service.get_stats()
    return SystemStatsResponse(**stats)

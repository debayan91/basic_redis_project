"""FastAPI route dependencies."""

from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.db.session import get_db
from app.services.alerts import AlertService
from app.services.blacklist import BlacklistService
from app.services.lookup import LookupService
from app.services.metrics import MetricsService
from app.services.providers.base import ThreatIntelligenceProvider
from app.services.providers.factory import get_configured_provider
from app.services.ranking import RankingService
from app.services.redis import get_redis
from app.services.threat_cache import ThreatCacheService


def get_blacklist_service(redis: Redis = Depends(get_redis)) -> BlacklistService:
    """Dependency supplying a BlacklistService instance."""
    return BlacklistService(redis)


def get_metrics_service(redis: Redis = Depends(get_redis)) -> MetricsService:
    """Dependency supplying a MetricsService instance."""
    return MetricsService(redis)


def get_ranking_service(redis: Redis = Depends(get_redis)) -> RankingService:
    """Dependency supplying a RankingService instance."""
    return RankingService(redis)


def get_alert_service(
    redis: Redis = Depends(get_redis),
    settings: Settings = Depends(get_settings),
) -> AlertService:
    """Dependency supplying an AlertService instance."""
    return AlertService(redis, settings=settings)


def get_provider(
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ThreatIntelligenceProvider:
    """Dependency supplying the configured threat intelligence provider."""
    return get_configured_provider(db, settings=settings)


def get_lookup_service(
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
    provider: ThreatIntelligenceProvider = Depends(get_provider),
    settings: Settings = Depends(get_settings),
) -> LookupService:
    """Dependency supplying a configured LookupService instance."""
    cache_service = ThreatCacheService(redis, settings=settings)
    blacklist = BlacklistService(redis)
    metrics = MetricsService(redis)
    ranking = RankingService(redis)
    alerts = AlertService(redis, settings=settings)

    return LookupService(
        cache_service=cache_service,
        provider=provider,
        blacklist_service=blacklist,
        metrics_service=metrics,
        ranking_service=ranking,
        alert_service=alerts,
        settings=settings,
    )


__all__ = [
    "get_alert_service",
    "get_blacklist_service",
    "get_db",
    "get_lookup_service",
    "get_metrics_service",
    "get_provider",
    "get_ranking_service",
    "get_redis",
    "get_settings",
]

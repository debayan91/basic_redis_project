"""Dedicated Redis Threat Intelligence Cache Service using Redis Hashes."""

import logging

from redis.asyncio import Redis

from app.core.config import Settings, get_settings
from app.schemas.threat_cache import CachedThreatRecord, generate_cache_key
from app.services.indicator import IndicatorType

logger = logging.getLogger(__name__)


class ThreatCacheService:
    """Service providing high-speed threat record caching in Redis using Hashes with dynamic TTLs."""

    def __init__(self, redis: Redis, settings: Settings | None = None) -> None:
        self.redis = redis
        self.settings = settings or get_settings()

    def determine_ttl(self, record: CachedThreatRecord) -> int:
        """Calculate the appropriate TTL based on record threat characteristics."""
        if record.malicious:
            return self.settings.CACHE_TTL_MALICIOUS
        elif record.threat_score == 0:
            return self.settings.CACHE_TTL_BENIGN
        elif record.threat_score >= 60:
            return self.settings.CACHE_TTL_SUSPICIOUS
        else:
            return self.settings.CACHE_DEFAULT_TTL

    async def get(
        self, indicator_type: IndicatorType | str, normalized_indicator: str
    ) -> CachedThreatRecord | None:
        """Retrieve a cached threat record by type and normalized value.
        
        Returns CachedThreatRecord on cache hit, or None on cache miss / expiration.
        """
        key = generate_cache_key(indicator_type, normalized_indicator)

        pipe = self.redis.pipeline(transaction=False)
        pipe.hgetall(key)
        pipe.ttl(key)
        raw_data, remaining_ttl = await pipe.execute()

        # Cache miss: hash is empty or key does not exist / has expired (ttl == -2)
        if not raw_data or remaining_ttl == -2:
            return None

        ttl = max(0, remaining_ttl) if remaining_ttl > 0 else None
        return CachedThreatRecord.from_hash_dict(raw_data, ttl_seconds=ttl)

    async def set(
        self, record: CachedThreatRecord, ttl_seconds: int | None = None
    ) -> None:
        """Store a threat record in Redis as a Hash with a configurable TTL."""
        key = generate_cache_key(record.indicator_type, record.indicator)
        ttl = ttl_seconds if ttl_seconds is not None else self.determine_ttl(record)

        pipe = self.redis.pipeline(transaction=True)
        pipe.hset(key, mapping=record.to_hash_dict())
        if ttl > 0:
            pipe.expire(key, ttl)

        await pipe.execute()
        logger.debug(f"Cached threat record for key '{key}' with TTL={ttl}s")

    async def delete(
        self, indicator_type: IndicatorType | str, normalized_indicator: str
    ) -> bool:
        """Delete a cached threat record. Returns True if deleted, False if not found."""
        key = generate_cache_key(indicator_type, normalized_indicator)
        deleted = await self.redis.delete(key)
        return bool(deleted > 0)

    async def get_ttl(
        self, indicator_type: IndicatorType | str, normalized_indicator: str
    ) -> int:
        """Get the remaining TTL in seconds for a cached threat record.
        
        Returns:
            >= 0: Remaining seconds before expiration.
            -1: Key exists without expiration.
            -2: Key does not exist or has expired.
        """
        key = generate_cache_key(indicator_type, normalized_indicator)
        return await self.redis.ttl(key)

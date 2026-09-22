"""Redis Blacklist Service managing fast-lookup security Sets."""

import logging

from redis.asyncio import Redis

from app.schemas.indicator import IndicatorType

logger = logging.getLogger(__name__)


class BlacklistService:
    """Manages Redis-native blacklist Sets for O(1) membership verification."""

    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    @staticmethod
    def _get_key(indicator_type: IndicatorType | str) -> str:
        """Format the Redis set key for the given indicator type."""
        type_str = (
            indicator_type.value
            if isinstance(indicator_type, IndicatorType)
            else str(indicator_type).lower().strip()
        )
        return f"blacklist:{type_str}"

    async def add(self, indicator_type: IndicatorType | str, indicator: str) -> bool:
        """Add an indicator to its type-specific blacklist set.
        
        Returns True if newly added, False if already present.
        """
        key = self._get_key(indicator_type)
        val = indicator.strip()
        added_count = await self.redis.sadd(key, val)
        return added_count > 0

    async def remove(self, indicator_type: IndicatorType | str, indicator: str) -> bool:
        """Remove an indicator from its blacklist set.
        
        Returns True if removed, False if not present.
        """
        key = self._get_key(indicator_type)
        val = indicator.strip()
        removed_count = await self.redis.srem(key, val)
        return removed_count > 0

    async def is_blacklisted(self, indicator_type: IndicatorType | str, indicator: str) -> bool:
        """Perform O(1) membership check against the blacklist set."""
        key = self._get_key(indicator_type)
        val = indicator.strip()
        return bool(await self.redis.sismember(key, val))

    async def count(self, indicator_type: IndicatorType | str | None = None) -> int:
        """Return count of blacklisted entries. If None, sums across all types."""
        if indicator_type is not None:
            key = self._get_key(indicator_type)
            return await self.redis.scard(key)

        # Aggregate across ip, domain, url
        pipe = self.redis.pipeline(transaction=False)
        for t in IndicatorType:
            pipe.scard(self._get_key(t))
        counts = await pipe.execute()
        return sum(counts)

    async def list_all(
        self,
        indicator_type: IndicatorType | str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[str]:
        """List blacklisted entries with pagination."""
        if indicator_type is not None:
            key = self._get_key(indicator_type)
            members = await self.redis.smembers(key)
            sorted_items = sorted(members)
            return sorted_items[offset : offset + limit]

        # Combine all sets
        all_items: list[str] = []
        for t in IndicatorType:
            key = self._get_key(t)
            members = await self.redis.smembers(key)
            all_items.extend(members)

        all_items.sort()
        return all_items[offset : offset + limit]

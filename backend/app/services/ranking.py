"""Ranking Service managing threat severity rankings using Redis Sorted Sets."""

import logging
from typing import Any

from redis.asyncio import Redis

logger = logging.getLogger(__name__)


class RankingService:
    """Tracks and retrieves threat rankings using Redis Sorted Sets (rank:threats)."""

    KEY_RANK_THREATS = "rank:threats"

    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    async def increment_threat(self, indicator: str, score_delta: float = 1.0) -> float:
        """Increment threat score for an indicator in the sorted set.
        
        Returns the updated total score.
        """
        val = indicator.strip()
        new_score = await self.redis.zincrby(self.KEY_RANK_THREATS, score_delta, val)
        return float(new_score)

    async def get_top_threats(self, limit: int = 10) -> list[dict[str, Any]]:
        """Retrieve top N threat indicators sorted by cumulative score descending."""
        if limit <= 0:
            return []

        # zrevrange returns list of (member, score) tuples when withscores=True
        raw_items = await self.redis.zrevrange(
            self.KEY_RANK_THREATS, 0, limit - 1, withscores=True
        )

        ranked: list[dict[str, Any]] = []
        for rank_idx, (indicator, score) in enumerate(raw_items, start=1):
            ranked.append({
                "rank": rank_idx,
                "indicator": indicator,
                "score": float(score),
            })
        return ranked

    async def get_indicator_score(self, indicator: str) -> float | None:
        """Get current threat score for an indicator."""
        score = await self.redis.zscore(self.KEY_RANK_THREATS, indicator.strip())
        return float(score) if score is not None else None

    async def get_indicator_rank(self, indicator: str) -> int | None:
        """Get current rank position (1-indexed) for an indicator, or None if unranked."""
        zero_rank = await self.redis.zrevrank(self.KEY_RANK_THREATS, indicator.strip())
        return (zero_rank + 1) if zero_rank is not None else None

    async def remove(self, indicator: str) -> bool:
        """Remove an indicator from the ranking set."""
        count = await self.redis.zrem(self.KEY_RANK_THREATS, indicator.strip())
        return count > 0

    async def reset(self) -> None:
        """Clear all threat rankings."""
        await self.redis.delete(self.KEY_RANK_THREATS)

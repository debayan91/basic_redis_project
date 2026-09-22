"""Alert Service managing Redis Pub/Sub channels for high-risk threat detections."""

import json
import logging
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from typing import Any

from redis.asyncio import Redis

from app.core.config import Settings, get_settings
from app.schemas.indicator import IndicatorType

logger = logging.getLogger(__name__)


class AlertService:
    """Manages publishing and subscribing to real-time security alerts via Redis Pub/Sub."""

    def __init__(self, redis: Redis, settings: Settings | None = None) -> None:
        self.redis = redis
        self.settings = settings or get_settings()
        self.channel = self.settings.REDIS_PUBSUB_CHANNEL

    async def publish_alert(
        self,
        indicator: str,
        indicator_type: IndicatorType | str,
        threat_score: int,
        confidence: float,
        source: str,
        categories: list[str] | None = None,
    ) -> int:
        """Publish a high-risk threat detection event to the Redis Pub/Sub channel.
        
        Returns the number of subscribers that received the message.
        """
        payload = {
            "indicator": indicator,
            "indicator_type": (
                indicator_type.value
                if isinstance(indicator_type, IndicatorType)
                else str(indicator_type)
            ),
            "threat_score": threat_score,
            "confidence": confidence,
            "source": source,
            "categories": categories or [],
            "timestamp": datetime.now(UTC).isoformat(),
        }
        message = json.dumps(payload)
        logger.info(f"Publishing threat alert to '{self.channel}': {indicator} (score: {threat_score})")
        subscribers = await self.redis.publish(self.channel, message)
        return int(subscribers)

    async def subscribe_alerts(self) -> AsyncGenerator[dict[str, Any], None]:
        """Subscribe to the threat alerts channel and yield incoming alert dictionaries."""
        pubsub = self.redis.pubsub()
        await pubsub.subscribe(self.channel)
        try:
            async for raw_msg in pubsub.listen():
                if raw_msg.get("type") == "message":
                    data = raw_msg.get("data")
                    if isinstance(data, bytes):
                        data = data.decode("utf-8")
                    if isinstance(data, str):
                        try:
                            parsed = json.loads(data)
                            yield parsed
                        except json.JSONDecodeError:
                            logger.error(f"Malformed alert JSON on channel '{self.channel}': {data}")
        finally:
            if hasattr(pubsub, "aclose"):
                await pubsub.aclose()
            else:
                await pubsub.close()

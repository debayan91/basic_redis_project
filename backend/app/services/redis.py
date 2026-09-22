"""Async Redis connection pool and client management using redis.asyncio."""

import logging

from redis.asyncio import ConnectionPool, Redis

from app.core.config import get_settings

logger = logging.getLogger(__name__)

redis_pool: ConnectionPool | None = None
redis_client: Redis | None = None


def init_redis_pool() -> Redis:
    """Initialize the asynchronous Redis connection pool and client."""
    global redis_pool, redis_client
    settings = get_settings()

    if redis_pool is None:
        redis_pool = ConnectionPool.from_url(
            settings.redis_url,
            max_connections=settings.REDIS_MAX_CONNECTIONS,
            socket_timeout=settings.REDIS_SOCKET_TIMEOUT,
            decode_responses=True,
        )
        redis_client = Redis(connection_pool=redis_pool)
        logger.info("Initialized Redis async connection pool.")
    return redis_client


async def close_redis_pool() -> None:
    """Close the asynchronous Redis connection pool."""
    global redis_pool, redis_client
    if redis_client is not None:
        await redis_client.aclose()
        redis_client = None
    if redis_pool is not None:
        await redis_pool.disconnect()
        redis_pool = None
        logger.info("Closed Redis async connection pool.")


def get_redis_client() -> Redis:
    """Retrieve or initialize the singleton Redis client instance."""
    if redis_client is None:
        init_redis_pool()
    assert redis_client is not None
    return redis_client


async def get_redis() -> Redis:
    """FastAPI dependency for accessing the Redis client."""
    return get_redis_client()



async def check_redis_health() -> bool:
    """Send a PING to Redis and verify PONG response."""
    if redis_client is None:
        init_redis_pool()
    assert redis_client is not None

    try:
        response = await redis_client.ping()
        return bool(response)
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"Redis healthcheck failed: {exc}")
        return False

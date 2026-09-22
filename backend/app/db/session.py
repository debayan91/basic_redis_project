"""Async PostgreSQL session and connection pool management."""

import logging
from collections.abc import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import get_settings

logger = logging.getLogger(__name__)

async_engine: AsyncEngine | None = None
async_session_factory: async_sessionmaker[AsyncSession] | None = None


def init_db_pool() -> AsyncEngine:
    """Initialize the asynchronous SQLAlchemy engine and sessionmaker."""
    global async_engine, async_session_factory
    settings = get_settings()

    if async_engine is None:
        async_engine = create_async_engine(
            settings.async_database_url,
            pool_size=settings.POSTGRES_POOL_SIZE,
            max_overflow=settings.POSTGRES_MAX_OVERFLOW,
            echo=settings.DEBUG and settings.ENVIRONMENT == "development",
            future=True,
        )
        async_session_factory = async_sessionmaker(
            bind=async_engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )
        logger.info("Initialized PostgreSQL async connection pool.")
    return async_engine


async def close_db_pool() -> None:
    """Dispose of the asynchronous SQLAlchemy connection pool."""
    global async_engine, async_session_factory
    if async_engine is not None:
        await async_engine.dispose()
        async_engine = None
        async_session_factory = None
        logger.info("Closed PostgreSQL async connection pool.")


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for providing a transactional async database session."""
    if async_session_factory is None:
        init_db_pool()
    assert async_session_factory is not None

    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def check_db_health() -> bool:
    """Execute a simple query to verify PostgreSQL connectivity."""
    if async_engine is None:
        init_db_pool()
    assert async_engine is not None

    try:
        async with async_engine.connect() as conn:
            result = await conn.execute(text("SELECT 1"))
            return result.scalar() == 1
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"PostgreSQL healthcheck failed: {exc}")
        return False

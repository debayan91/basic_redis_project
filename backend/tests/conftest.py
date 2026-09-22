"""Pytest fixtures for backend tests."""

from collections.abc import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import Settings, get_settings
from app.db.session import get_db
from app.main import app
from app.services.redis import get_redis


@pytest.fixture(scope="session")
def settings() -> Settings:
    """Return application settings fixture."""
    return get_settings()


@pytest.fixture
async def db_session(settings: Settings) -> AsyncGenerator[AsyncSession, None]:
    """Provide an isolated, transactional database session for test execution."""
    engine = create_async_engine(
        settings.async_database_url,
        poolclass=NullPool,
    )
    session_factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with session_factory() as session:
        yield session
        await session.rollback()

    await engine.dispose()


@pytest.fixture
async def redis_test_client(settings: Settings) -> AsyncGenerator[Redis, None]:
    """Provide a dedicated Redis client for integration testing."""
    client = Redis.from_url(
        settings.redis_url,
        decode_responses=True,
    )
    await client.flushdb()
    yield client
    await client.flushdb()
    await client.aclose()


@pytest.fixture
async def async_client(
    db_session: AsyncSession, redis_test_client: Redis
) -> AsyncGenerator[AsyncClient, None]:
    """Provide an asynchronous HTTP client bound to FastAPI with test session overrides."""
    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    async def override_get_redis() -> Redis:
        return redis_test_client

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_redis] = override_get_redis

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client

    app.dependency_overrides.clear()

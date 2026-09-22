"""FastAPI application factory and entry point."""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import api_v1_router
from app.api.v1.health import router as root_health_router
from app.core.config import get_settings
from app.core.exceptions import (
    DatabaseUnavailableError,
    InvalidIndicatorError,
    ProviderError,
    ProviderRateLimitError,
    ProviderTimeoutError,
    ProviderUnavailableError,
    RedisUnavailableError,
)
from app.db.session import check_db_health, close_db_pool, init_db_pool
from app.services.redis import check_redis_health, close_redis_pool, init_redis_pool

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application startup and shutdown lifecycle."""
    settings = get_settings()
    logger.info(f"Starting {settings.PROJECT_NAME} [{settings.ENVIRONMENT}]...")

    # Startup: initialize database and Redis pools
    init_db_pool()
    init_redis_pool()

    db_ok = await check_db_health()
    redis_ok = await check_redis_health()
    logger.info(f"Startup connectivity - PostgreSQL: {'OK' if db_ok else 'FAILED'}, Redis: {'OK' if redis_ok else 'FAILED'}")

    yield

    # Shutdown: gracefully close connections
    logger.info("Initiating graceful shutdown...")
    await close_redis_pool()
    await close_db_pool()
    logger.info("Shutdown complete.")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    application = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        docs_url="/docs" if settings.DEBUG else None,
        redoc_url="/redoc" if settings.DEBUG else None,
        lifespan=lifespan,
    )

    # CORS Middleware
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Global Exception Handlers for Failure Modes and Resilience
    @application.exception_handler(InvalidIndicatorError)
    async def invalid_indicator_handler(request: Request, exc: InvalidIndicatorError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content={"detail": f"Validation error: {exc.message}", "error_type": "invalid_indicator"},
        )

    @application.exception_handler(ProviderTimeoutError)
    async def provider_timeout_handler(request: Request, exc: ProviderTimeoutError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            content={"detail": f"Provider timeout: {exc.message}", "error_type": "provider_timeout"},
        )

    @application.exception_handler(ProviderRateLimitError)
    async def provider_rate_limit_handler(request: Request, exc: ProviderRateLimitError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": f"Provider rate limit exceeded: {exc.message}", "error_type": "provider_rate_limit"},
        )

    @application.exception_handler(ProviderUnavailableError)
    async def provider_unavailable_handler(request: Request, exc: ProviderUnavailableError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"detail": f"Provider unavailable: {exc.message}", "error_type": "provider_unavailable"},
        )

    @application.exception_handler(DatabaseUnavailableError)
    async def database_unavailable_handler(request: Request, exc: DatabaseUnavailableError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"detail": f"Database service unavailable: {exc.message}", "error_type": "database_unavailable"},
        )

    @application.exception_handler(RedisUnavailableError)
    async def redis_unavailable_handler(request: Request, exc: RedisUnavailableError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"detail": f"Redis operational layer unavailable: {exc.message}", "error_type": "redis_unavailable"},
        )

    @application.exception_handler(ProviderError)
    async def provider_error_handler(request: Request, exc: ProviderError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content={"detail": f"Provider error: {exc.message}", "error_type": "provider_error"},
        )

    # Include root health router (/health)
    application.include_router(root_health_router)

    # Include all API routers at /api (e.g. /api/check, /api/stats, /api/blacklist, /api/refresh, /api/ws/alerts)
    application.include_router(api_v1_router, prefix="/api")

    # Also include versioned API routers (/api/v1/...)
    application.include_router(api_v1_router, prefix=settings.API_PREFIX)

    return application


app = create_app()

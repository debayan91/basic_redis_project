"""Healthcheck endpoint router."""

from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

from app.core.config import get_settings
from app.db.session import check_db_health
from app.schemas.health import HealthResponse
from app.services.redis import check_redis_health

router = APIRouter(tags=["Health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Check PostgreSQL and Redis connectivity and return service status.",
)
async def health_check() -> JSONResponse:
    """Evaluate PostgreSQL and Redis connectivity and return status."""
    settings = get_settings()

    db_healthy = await check_db_health()
    redis_healthy = await check_redis_health()

    postgres_status = "connected" if db_healthy else "disconnected"
    redis_status = "connected" if redis_healthy else "disconnected"

    if db_healthy and redis_healthy:
        overall_status = "healthy"
        http_status = status.HTTP_200_OK
    elif db_healthy or redis_healthy:
        overall_status = "degraded"
        http_status = status.HTTP_200_OK
    else:
        overall_status = "unhealthy"
        http_status = status.HTTP_503_SERVICE_UNAVAILABLE

    payload = HealthResponse(
        status=overall_status,
        postgres=postgres_status,
        redis=redis_status,
        version=settings.VERSION,
    )
    return JSONResponse(status_code=http_status, content=payload.model_dump(mode="json"))

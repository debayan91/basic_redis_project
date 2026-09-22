"""Indicator cache refresh endpoint."""

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.deps import get_lookup_service
from app.core.exceptions import (
    DatabaseUnavailableError,
    InvalidIndicatorError,
    ProviderRateLimitError,
    ProviderTimeoutError,
    ProviderUnavailableError,
)
from app.schemas.check import ThreatCheckResponse
from app.services.lookup import LookupService

router = APIRouter(tags=["Threat Intelligence Management"])


@router.post(
    "/refresh/{indicator:path}",
    response_model=ThreatCheckResponse,
    summary="Force refresh cached intelligence for an indicator",
    description="Bypasses the Redis cache, queries the configured CTI provider, updates Redis with fresh TTL, and returns the result.",
)
async def refresh_indicator(
    indicator: str,
    lookup_service: LookupService = Depends(get_lookup_service),
) -> ThreatCheckResponse:
    """Force refresh threat intelligence from authoritative provider."""
    try:
        return await lookup_service.lookup(indicator, force_refresh=True)
    except InvalidIndicatorError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Validation error: {exc.message}",
        ) from exc
    except ProviderRateLimitError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Provider rate limit exceeded: {exc.message}",
        ) from exc
    except ProviderTimeoutError as exc:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=f"Provider request timed out: {exc.message}",
        ) from exc
    except (ProviderUnavailableError, DatabaseUnavailableError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"CTI source unavailable: {exc.message}",
        ) from exc

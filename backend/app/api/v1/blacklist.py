"""Blacklist management endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.deps import get_blacklist_service
from app.core.exceptions import InvalidIndicatorError
from app.schemas.blacklist import (
    BlacklistEntryRequest,
    BlacklistEntryResponse,
    BlacklistListResponse,
)
from app.schemas.indicator import IndicatorType
from app.services.blacklist import BlacklistService
from app.services.indicator import IndicatorService

router = APIRouter(tags=["Blacklist Management"])


@router.get(
    "/blacklist",
    response_model=BlacklistListResponse,
    summary="List blacklisted indicators",
    description="Retrieve paginated list of currently blacklisted IPs, Domains, and URLs.",
)
async def list_blacklist(
    indicator_type: IndicatorType | None = Query(default=None, description="Filter by indicator type"),
    limit: int = Query(default=100, ge=1, le=1000, description="Items per page"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    blacklist_service: BlacklistService = Depends(get_blacklist_service),
) -> BlacklistListResponse:
    """List blacklisted indicators with optional type filter and pagination."""
    items = await blacklist_service.list_all(
        indicator_type=indicator_type, limit=limit, offset=offset
    )
    total = await blacklist_service.count(indicator_type=indicator_type)
    return BlacklistListResponse(total=total, indicator_type=indicator_type, items=items)


@router.post(
    "/blacklist",
    response_model=BlacklistEntryResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add indicator to blacklist",
    description="Explicitly add an IP, Domain, or URL to the Redis-native blacklist.",
)
async def add_to_blacklist(
    request: BlacklistEntryRequest,
    blacklist_service: BlacklistService = Depends(get_blacklist_service),
) -> BlacklistEntryResponse:
    """Add indicator to blacklist set."""
    try:
        parsed = IndicatorService.parse_and_normalize(request.indicator)
    except InvalidIndicatorError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Validation error: {exc.message}",
        ) from exc

    added = await blacklist_service.add(parsed.indicator_type, parsed.normalized)
    msg = "Indicator added to blacklist" if added else "Indicator was already blacklisted"
    return BlacklistEntryResponse(
        indicator=parsed.normalized,
        indicator_type=parsed.indicator_type,
        blacklisted=True,
        message=msg,
    )


@router.delete(
    "/blacklist/{indicator:path}",
    response_model=BlacklistEntryResponse,
    summary="Remove indicator from blacklist",
    description="Remove an IP, Domain, or URL from the Redis-native blacklist.",
)
async def remove_from_blacklist(
    indicator: str,
    blacklist_service: BlacklistService = Depends(get_blacklist_service),
) -> BlacklistEntryResponse:
    """Remove indicator from blacklist set."""
    try:
        parsed = IndicatorService.parse_and_normalize(indicator)
    except InvalidIndicatorError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Validation error: {exc.message}",
        ) from exc

    removed = await blacklist_service.remove(parsed.indicator_type, parsed.normalized)
    msg = "Indicator removed from blacklist" if removed else "Indicator was not in blacklist"
    return BlacklistEntryResponse(
        indicator=parsed.normalized,
        indicator_type=parsed.indicator_type,
        blacklisted=False,
        message=msg,
    )

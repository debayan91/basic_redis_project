"""Threat lookup endpoint router."""

from fastapi import APIRouter, Depends

from app.api.deps import get_lookup_service
from app.schemas.check import ThreatCheckRequest, ThreatCheckResponse
from app.services.lookup import LookupService

router = APIRouter(tags=["Threat Intelligence"])


@router.post(
    "/check",
    response_model=ThreatCheckResponse,
    summary="Check indicator threat status",
    description="Validate, normalize, and evaluate an IP, Domain, or URL through Redis cache and local CTI.",
)
async def check_indicator(
    request: ThreatCheckRequest,
    lookup_service: LookupService = Depends(get_lookup_service),
) -> ThreatCheckResponse:
    """Evaluate indicator for threats via cache-first lookup pipeline."""
    return await lookup_service.lookup(request.indicator)

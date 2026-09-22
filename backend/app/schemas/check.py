"""Schemas for the /api/check lookup endpoint."""

from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.indicator import IndicatorType


class ThreatCheckRequest(BaseModel):
    """Request payload for checking an indicator."""
    indicator: str = Field(
        ...,
        min_length=1,
        description="The IP address, URL, or domain to evaluate.",
        examples=["198.51.100.25", "https://malicious.org/payload.bin", "google.com"],
    )


class ThreatCheckResponse(BaseModel):
    """Structured threat verdict and caching information."""
    original_indicator: str = Field(..., description="Original raw indicator provided by client")
    normalized_indicator: str = Field(..., description="Canonical normalized representation")
    indicator_type: IndicatorType = Field(..., description="Detected type ('ip', 'domain', 'url')")
    malicious: bool = Field(..., description="Threat verdict")
    threat_score: int = Field(ge=0, le=100, description="Severity score from 0 (benign) to 100 (critical)")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence rating (0.0 to 1.0)")
    categories: list[str] = Field(default_factory=list, description="Associated threat categories")
    source: str = Field(..., description="Authoritative intelligence source or feed")
    is_trusted_domain: bool = Field(
        default=False,
        description="Indicates whether indicator hostname is a verified trusted root domain or subdomain",
    )
    trusted_domain: bool = Field(
        default=False,
        description="Alias for is_trusted_domain indicating trusted domain status",
    )
    cached: bool = Field(..., description="True if returned from Redis cache; False if freshly resolved")
    checked_at: datetime = Field(..., description="Timestamp when threat was evaluated")
    ttl_seconds: int | None = Field(
        default=None,
        description="Remaining TTL in seconds if cached; assigned TTL if freshly cached",
    )

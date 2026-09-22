"""Schemas for Blacklist management endpoints."""

from pydantic import BaseModel, Field

from app.schemas.indicator import IndicatorType


class BlacklistEntryRequest(BaseModel):
    """Payload to add an indicator to the Redis blacklist."""
    indicator: str = Field(
        ...,
        min_length=1,
        description="IP, Domain, or URL to blacklist",
        examples=["198.51.100.99", "malicious-phish.com"],
    )
    reason: str | None = Field(
        default=None,
        description="Optional administrative reason or SOC ticket reference",
    )


class BlacklistEntryResponse(BaseModel):
    """Response returned upon blacklist modification."""
    indicator: str = Field(..., description="Normalized indicator value")
    indicator_type: IndicatorType = Field(..., description="Classification of the blacklisted indicator")
    blacklisted: bool = Field(..., description="True if indicator is active in blacklist")
    message: str = Field(..., description="Action outcome description")


class BlacklistListResponse(BaseModel):
    """Paginated listing of blacklisted indicators."""
    total: int = Field(..., description="Total count of blacklisted entries matching filter")
    indicator_type: IndicatorType | None = Field(default=None, description="Applied indicator type filter")
    items: list[str] = Field(default_factory=list, description="List of blacklisted indicator strings")

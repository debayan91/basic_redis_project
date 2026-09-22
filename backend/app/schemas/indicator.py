"""Indicator schemas and enums."""

from enum import Enum

from pydantic import BaseModel, Field


class IndicatorType(str, Enum):
    """Supported indicator classifications."""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"


class ParsedIndicator(BaseModel):
    """Represents the parsed and normalized indicator, preserving the original input."""
    raw: str = Field(..., description="Original raw user input without modification")
    normalized: str = Field(..., description="Canonical normalized representation")
    indicator_type: IndicatorType = Field(..., description="Classification (ip, domain, url)")
    extracted_domain: str | None = Field(
        default=None,
        description="Extracted hostname/domain where applicable (for domains and URLs)",
    )
    is_ip: bool = False
    is_ipv4: bool = False
    is_ipv6: bool = False
    is_private_or_reserved: bool = False

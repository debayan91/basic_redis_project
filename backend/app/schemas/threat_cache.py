"""Pydantic model and serialization for Redis cached threat records."""

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.indicator import IndicatorType


def generate_cache_key(indicator_type: IndicatorType | str, normalized_indicator: str) -> str:
    """Generate the canonical Redis cache key for a threat record.

    Formats:
    - IP: ti:ip:<normalized_indicator>
    - Domain: ti:domain:<normalized_indicator>
    - URL: ti:url:<sha256_of_normalized_url>
    """
    type_str = (
        indicator_type.value
        if isinstance(indicator_type, IndicatorType)
        else str(indicator_type).lower().strip()
    )
    norm_val = normalized_indicator.strip()

    if type_str == "ip":
        return f"ti:ip:{norm_val}"
    elif type_str == "domain":
        return f"ti:domain:{norm_val.lower().rstrip('.')}"
    elif type_str == "url":
        url_hash = hashlib.sha256(norm_val.encode("utf-8")).hexdigest()
        return f"ti:url:{url_hash}"
    else:
        raise ValueError(f"Unsupported indicator type: '{indicator_type}'")


class CachedThreatRecord(BaseModel):
    """Canonical model for threat intelligence stored in Redis Hashes."""

    indicator: str = Field(..., description="Normalized indicator value")
    indicator_type: IndicatorType = Field(..., description="Indicator classification (ip, domain, url)")
    malicious: bool = Field(..., description="Whether indicator is confirmed malicious")
    threat_score: int = Field(ge=0, le=100, default=0, description="Threat score (0-100)")
    confidence: float = Field(ge=0.0, le=1.0, default=1.0, description="Confidence rating (0.0-1.0)")
    categories: list[str] = Field(default_factory=list, description="Associated threat categories")
    source: str = Field(default="unknown", description="Originating intelligence source")
    is_trusted_domain: bool = Field(
        default=False,
        description="Whether indicator hostname is a trusted root domain or subdomain",
    )
    first_seen: datetime | None = Field(default=None, description="First recorded sighting")
    last_seen: datetime | None = Field(default=None, description="Most recent sighting")
    checked_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp when verdict was cached",
    )
    ttl_seconds: int | None = Field(
        default=None,
        description="Remaining TTL in seconds when retrieved from cache",
    )

    def to_hash_dict(self) -> dict[str, str]:
        """Serialize record into string key-value pairs suitable for Redis Hashes."""
        return {
            "indicator": self.indicator,
            "indicator_type": (
                self.indicator_type.value
                if isinstance(self.indicator_type, IndicatorType)
                else str(self.indicator_type)
            ),
            "malicious": "true" if self.malicious else "false",
            "threat_score": str(self.threat_score),
            "confidence": str(self.confidence),
            "categories": json.dumps(self.categories),
            "source": self.source,
            "is_trusted_domain": "true" if self.is_trusted_domain else "false",
            "first_seen": self.first_seen.isoformat() if self.first_seen else "",
            "last_seen": self.last_seen.isoformat() if self.last_seen else "",
            "checked_at": self.checked_at.isoformat(),
        }

    @classmethod
    def from_hash_dict(
        cls, data: dict[str, str | Any], ttl_seconds: int | None = None
    ) -> "CachedThreatRecord":
        """Deserialize Redis Hash dictionary back into CachedThreatRecord."""
        raw_first_seen = data.get("first_seen")
        first_seen = (
            datetime.fromisoformat(raw_first_seen)
            if raw_first_seen and raw_first_seen != ""
            else None
        )

        raw_last_seen = data.get("last_seen")
        last_seen = (
            datetime.fromisoformat(raw_last_seen)
            if raw_last_seen and raw_last_seen != ""
            else None
        )

        raw_checked_at = data.get("checked_at")
        checked_at = (
            datetime.fromisoformat(raw_checked_at)
            if raw_checked_at and raw_checked_at != ""
            else datetime.now(UTC)
        )

        raw_categories = data.get("categories", "[]")
        if isinstance(raw_categories, str):
            try:
                categories = json.loads(raw_categories)
            except json.JSONDecodeError:
                categories = []
        elif isinstance(raw_categories, list):
            categories = raw_categories
        else:
            categories = []

        raw_malicious = data.get("malicious", "false")
        malicious = (
            raw_malicious.lower() in ("true", "1", "yes")
            if isinstance(raw_malicious, str)
            else bool(raw_malicious)
        )

        raw_is_trusted = data.get("is_trusted_domain", "false")
        is_trusted_domain = (
            raw_is_trusted.lower() in ("true", "1", "yes")
            if isinstance(raw_is_trusted, str)
            else bool(raw_is_trusted)
        )

        return cls(
            indicator=str(data.get("indicator", "")),
            indicator_type=IndicatorType(str(data.get("indicator_type", "ip"))),
            malicious=malicious,
            threat_score=int(data.get("threat_score", 0)),
            confidence=float(data.get("confidence", 1.0)),
            categories=categories,
            source=str(data.get("source", "unknown")),
            is_trusted_domain=is_trusted_domain,
            first_seen=first_seen,
            last_seen=last_seen,
            checked_at=checked_at,
            ttl_seconds=ttl_seconds,
        )

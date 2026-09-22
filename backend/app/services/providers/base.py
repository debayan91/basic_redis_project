"""Threat Intelligence Provider abstract base class."""

from abc import ABC, abstractmethod

from app.schemas.indicator import IndicatorType
from app.schemas.threat_cache import CachedThreatRecord


class ThreatIntelligenceProvider(ABC):
    """Abstract interface for threat intelligence sources (Local DB, External Feeds, etc.)."""

    @abstractmethod
    async def lookup(
        self, indicator: str, indicator_type: IndicatorType
    ) -> CachedThreatRecord | None:
        """Query threat intelligence for a normalized indicator.
        
        Returns CachedThreatRecord if threat intelligence exists, or None if unknown.
        """

    @abstractmethod
    async def is_trusted_domain(self, domain: str) -> bool:
        """Evaluate if a domain or its parent root domains are in the trusted whitelist."""

    async def get_matched_trusted_domain(self, domain: str) -> str | None:
        """Find the matching trusted root domain name if trusted, or None."""
        return None

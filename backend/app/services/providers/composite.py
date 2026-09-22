"""Composite Threat Intelligence Provider delegating across local and external sources."""

import logging

from app.core.exceptions import ProviderError
from app.schemas.indicator import IndicatorType
from app.schemas.threat_cache import CachedThreatRecord
from app.services.providers.base import ThreatIntelligenceProvider

logger = logging.getLogger(__name__)


class CompositeCTIProvider(ThreatIntelligenceProvider):
    """Hybrid provider querying local database first, then delegating to external provider on miss."""

    def __init__(
        self,
        local_provider: ThreatIntelligenceProvider,
        external_provider: ThreatIntelligenceProvider,
        fallback_on_external_error: bool = True,
    ) -> None:
        self.local_provider = local_provider
        self.external_provider = external_provider
        self.fallback_on_external_error = fallback_on_external_error

    async def lookup(
        self, indicator: str, indicator_type: IndicatorType
    ) -> CachedThreatRecord | None:
        """Query local database first; if unknown, query external CTI provider."""
        # 1. Check local CTI catalog
        local_record = await self.local_provider.lookup(indicator, indicator_type)
        if local_record is not None:
            return local_record

        # 2. Query external provider
        try:
            return await self.external_provider.lookup(indicator, indicator_type)
        except ProviderError as exc:
            if self.fallback_on_external_error:
                logger.warning(
                    f"External CTI provider lookup failed for '{indicator}', falling back to clean baseline: {exc.message}"
                )
                return None
            raise

    async def is_trusted_domain(self, domain: str) -> bool:
        """Delegate trusted domain check to local database."""
        return await self.local_provider.is_trusted_domain(domain)

    async def get_matched_trusted_domain(self, domain: str) -> str | None:
        """Delegate matched trusted domain to local database."""
        return await self.local_provider.get_matched_trusted_domain(domain)

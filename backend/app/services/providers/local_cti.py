"""Local Cyber Threat Intelligence provider backed by PostgreSQL."""

from datetime import UTC, datetime

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import DatabaseUnavailableError
from app.repositories.cti_indicator import CTIIndicatorRepository
from app.repositories.trusted_domain import TrustedDomainRepository
from app.schemas.indicator import IndicatorType
from app.schemas.threat_cache import CachedThreatRecord
from app.services.providers.base import ThreatIntelligenceProvider


class LocalCTIProvider(ThreatIntelligenceProvider):
    """Retrieves threat intelligence and trusted domains from the persistent PostgreSQL database."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.cti_repo = CTIIndicatorRepository(session)
        self.trusted_repo = TrustedDomainRepository(session)

    async def lookup(
        self, indicator: str, indicator_type: IndicatorType
    ) -> CachedThreatRecord | None:
        """Query PostgreSQL CTI indicators table for known threat intelligence."""
        try:
            record = await self.cti_repo.get_by_indicator(indicator)
        except (SQLAlchemyError, OSError) as exc:
            raise DatabaseUnavailableError(
                f"PostgreSQL query failed for indicator '{indicator}': {exc}"
            ) from exc

        if not record:
            return None

        # Verify or cast indicator type
        try:
            ind_type = IndicatorType(record.indicator_type)
        except ValueError:
            ind_type = indicator_type

        return CachedThreatRecord(
            indicator=record.indicator,
            indicator_type=ind_type,
            malicious=record.malicious,
            threat_score=record.threat_score,
            confidence=record.confidence,
            categories=record.categories or [],
            source=f"local_cti:{record.source}",
            first_seen=record.first_seen,
            last_seen=record.last_seen,
            checked_at=datetime.now(UTC),
        )

    async def is_trusted_domain(self, domain: str) -> bool:
        """Query PostgreSQL trusted_domains table using domain hierarchy matching."""
        try:
            return await self.trusted_repo.is_trusted(domain)
        except (SQLAlchemyError, OSError) as exc:
            raise DatabaseUnavailableError(
                f"PostgreSQL trusted domain query failed for '{domain}': {exc}"
            ) from exc

    async def get_matched_trusted_domain(self, domain: str) -> str | None:
        """Query PostgreSQL trusted_domains table for matching root domain."""
        try:
            return await self.trusted_repo.get_matched_trusted_domain(domain)
        except (SQLAlchemyError, OSError) as exc:
            raise DatabaseUnavailableError(
                f"PostgreSQL matched trusted domain query failed for '{domain}': {exc}"
            ) from exc

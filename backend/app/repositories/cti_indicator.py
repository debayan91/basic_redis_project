"""Repository for managing persistent Local CTI Indicators."""

from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cti_indicator import CTIIndicator
from app.repositories.base import BaseRepository


class CTIIndicatorRepository(BaseRepository[CTIIndicator]):
    """Repository handling database operations for persistent threat intelligence indicators."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(CTIIndicator, session)

    async def get_by_indicator(self, indicator: str) -> CTIIndicator | None:
        """Find a CTI indicator by its normalized value."""
        clean_indicator = indicator.strip()
        stmt = select(CTIIndicator).where(CTIIndicator.indicator == clean_indicator)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def add_or_update(
        self,
        indicator: str,
        indicator_type: str,
        malicious: bool = False,
        threat_score: int = 0,
        confidence: float = 1.0,
        source: str = "local",
        categories: list[str] | None = None,
        first_seen: datetime | None = None,
        last_seen: datetime | None = None,
    ) -> CTIIndicator:
        """Add a new indicator or update an existing one (upsert)."""
        clean_indicator = indicator.strip()
        cat_list = categories or []
        now = datetime.now(UTC)
        record_first_seen = first_seen or now
        record_last_seen = last_seen or now

        existing = await self.get_by_indicator(clean_indicator)
        if existing:
            existing.indicator_type = indicator_type
            existing.malicious = malicious
            existing.threat_score = threat_score
            existing.confidence = confidence
            existing.source = source
            # Merge categories uniquely
            merged_cats = list(dict.fromkeys(existing.categories + cat_list))
            existing.categories = merged_cats
            existing.last_seen = record_last_seen
            await self.session.flush()
            return existing

        cti = CTIIndicator(
            indicator=clean_indicator,
            indicator_type=indicator_type,
            malicious=malicious,
            threat_score=threat_score,
            confidence=confidence,
            source=source,
            categories=cat_list,
            first_seen=record_first_seen,
            last_seen=record_last_seen,
        )
        self.session.add(cti)
        await self.session.flush()
        return cti

    async def delete(self, indicator: str) -> bool:
        """Delete an indicator by its value. Returns True if deleted, False otherwise."""
        clean_indicator = indicator.strip()
        stmt = delete(CTIIndicator).where(CTIIndicator.indicator == clean_indicator)
        result = await self.session.execute(stmt)
        await self.session.flush()
        return (result.rowcount or 0) > 0

    async def list_indicators(
        self,
        indicator_type: str | None = None,
        malicious: bool | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[CTIIndicator]:
        """Query indicators with optional filtering by type and malicious status."""
        stmt = select(CTIIndicator)
        if indicator_type is not None:
            stmt = stmt.where(CTIIndicator.indicator_type == indicator_type)
        if malicious is not None:
            stmt = stmt.where(CTIIndicator.malicious == malicious)

        stmt = stmt.order_by(CTIIndicator.id.desc()).limit(limit).offset(offset)
        result = await self.session.execute(stmt)
        return result.scalars().all()

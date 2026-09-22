"""Repository for managing Trusted Root Domains."""

from collections.abc import Sequence

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.trusted_domain import TrustedDomain
from app.repositories.base import BaseRepository


class TrustedDomainRepository(BaseRepository[TrustedDomain]):
    """Repository handling database operations for trusted root domains."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(TrustedDomain, session)

    async def get_by_domain(self, domain: str) -> TrustedDomain | None:
        """Find a trusted domain record by exact domain name."""
        clean_domain = domain.strip().lower().rstrip(".")
        stmt = select(TrustedDomain).where(TrustedDomain.domain == clean_domain)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_matched_trusted_domain(self, domain: str) -> str | None:
        """Find the matching trusted root domain from hierarchical candidates, or None."""
        clean_domain = domain.strip().lower().rstrip(".")
        if not clean_domain:
            return None

        # Clean potential URL scheme, path, or port
        if "://" in clean_domain or "/" in clean_domain or ":" in clean_domain:
            parts = clean_domain.split("://")[-1].split("/")[0].split(":")[0]
            clean_domain = parts.strip().lower().rstrip(".")

        labels = clean_domain.split(".")
        if len(labels) < 2:
            return None

        # Generate candidates from most specific to root domain
        # e.g., 'a.b.google.com' -> ['a.b.google.com', 'b.google.com', 'google.com']
        candidate_domains = [
            ".".join(labels[i:]) for i in range(len(labels) - 1)
        ]

        stmt = select(TrustedDomain.domain).where(TrustedDomain.domain.in_(candidate_domains))
        result = await self.session.execute(stmt)
        row = result.first()
        return row[0] if row else None

    async def is_trusted(self, domain: str) -> bool:
        """Check if a domain or any of its parent root domains are trusted.
        
        Example: For 'accounts.google.com', checks 'accounts.google.com' and 'google.com'.
        """
        return (await self.get_matched_trusted_domain(domain)) is not None

    async def add(self, domain: str, description: str | None = None) -> TrustedDomain:
        """Add a new trusted domain to the database."""
        clean_domain = domain.strip().lower().rstrip(".")
        existing = await self.get_by_domain(clean_domain)
        if existing:
            if description is not None:
                existing.description = description
                await self.session.flush()
            return existing

        trusted = TrustedDomain(domain=clean_domain, description=description)
        self.session.add(trusted)
        await self.session.flush()
        return trusted

    async def remove(self, domain: str) -> bool:
        """Remove a trusted domain by name. Returns True if deleted, False otherwise."""
        clean_domain = domain.strip().lower().rstrip(".")
        stmt = delete(TrustedDomain).where(TrustedDomain.domain == clean_domain)
        result = await self.session.execute(stmt)
        await self.session.flush()
        return (result.rowcount or 0) > 0

    async def list_all(self, limit: int = 100, offset: int = 0) -> Sequence[TrustedDomain]:
        """List trusted domains with pagination."""
        stmt = select(TrustedDomain).order_by(TrustedDomain.domain).limit(limit).offset(offset)
        result = await self.session.execute(stmt)
        return result.scalars().all()

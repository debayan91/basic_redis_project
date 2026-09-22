"""SQLAlchemy ORM model for Trusted Root Domains."""

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class TrustedDomain(Base):
    """Trusted root domains (e.g. google.com, microsoft.com) whitelisted from threat scrutiny."""

    __tablename__ = "trusted_domains"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    domain: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
        comment="Normalized fully qualified root domain name (lowercase)",
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Organization or reason for trusting this domain",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<TrustedDomain(id={self.id}, domain='{self.domain}')>"

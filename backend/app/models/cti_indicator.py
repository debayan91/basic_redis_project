"""SQLAlchemy ORM model for Local Cyber Threat Intelligence (CTI) Indicators."""

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, Index, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class CTIIndicator(Base):
    """Persistent local Cyber Threat Intelligence indicators (IPs, URLs, Domains)."""

    __tablename__ = "cti_indicators"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    indicator: Mapped[str] = mapped_column(
        String(2048),
        unique=True,
        index=True,
        nullable=False,
        comment="Normalized indicator value (e.g. IP address, domain, or URL)",
    )
    indicator_type: Mapped[str] = mapped_column(
        String(16),
        index=True,
        nullable=False,
        comment="Indicator classification: 'ip', 'url', or 'domain'",
    )
    malicious: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        index=True,
        nullable=False,
        comment="Whether the indicator is confirmed malicious",
    )
    threat_score: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
        comment="Severity score from 0 (benign) to 100 (critical)",
    )
    confidence: Mapped[float] = mapped_column(
        Float,
        default=1.0,
        nullable=False,
        comment="Confidence rating of the verdict (0.0 to 1.0)",
    )
    source: Mapped[str] = mapped_column(
        String(64),
        default="local",
        nullable=False,
        comment="Authoritative source or feed identifier",
    )
    categories: Mapped[list[str]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
        comment="List of threat categories (e.g. ['phishing', 'c2', 'botnet'])",
    )
    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp when threat was first observed",
    )
    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp when threat was most recently observed",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_cti_type_malicious", "indicator_type", "malicious"),
        Index("ix_cti_threat_score", "threat_score"),
    )

    def __repr__(self) -> str:
        return (
            f"<CTIIndicator(id={self.id}, indicator='{self.indicator}', "
            f"type='{self.indicator_type}', malicious={self.malicious}, score={self.threat_score})>"
        )

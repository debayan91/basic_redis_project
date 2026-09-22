"""Database seed script for populating development and testing sample data."""

import asyncio
import logging

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import close_db_pool, init_db_pool
from app.repositories.cti_indicator import CTIIndicatorRepository
from app.repositories.trusted_domain import TrustedDomainRepository

logger = logging.getLogger(__name__)

SAMPLE_TRUSTED_DOMAINS = [
    {"domain": "google.com", "description": "Google Search and cloud infrastructure"},
    {"domain": "microsoft.com", "description": "Microsoft 365, Azure, and corporate services"},
    {"domain": "apple.com", "description": "Apple ecosystem and services"},
    {"domain": "github.com", "description": "GitHub software development platform"},
    {"domain": "cloudflare.com", "description": "Cloudflare CDN and DNS infrastructure"},
    {"domain": "amazon.com", "description": "Amazon Web Services and retail platform"},
]

SAMPLE_CTI_INDICATORS = [
    # Malicious IPs
    {
        "indicator": "198.51.100.25",
        "indicator_type": "ip",
        "malicious": True,
        "threat_score": 95,
        "confidence": 0.95,
        "source": "c2_tracker",
        "categories": ["c2", "ransomware_distribution"],
    },
    {
        "indicator": "203.0.113.50",
        "indicator_type": "ip",
        "malicious": True,
        "threat_score": 85,
        "confidence": 0.90,
        "source": "botnet_sentinel",
        "categories": ["ssh_bruteforce", "scanner"],
    },
    # Benign IPs
    {
        "indicator": "1.1.1.1",
        "indicator_type": "ip",
        "malicious": False,
        "threat_score": 0,
        "confidence": 1.0,
        "source": "internal_whitelist",
        "categories": ["public_dns"],
    },
    {
        "indicator": "8.8.8.8",
        "indicator_type": "ip",
        "malicious": False,
        "threat_score": 0,
        "confidence": 1.0,
        "source": "internal_whitelist",
        "categories": ["public_dns"],
    },
    # Malicious URLs
    {
        "indicator": "http://phishing-portal.fake-bank.xyz/login",
        "indicator_type": "url",
        "malicious": True,
        "threat_score": 90,
        "confidence": 0.92,
        "source": "phish_tank",
        "categories": ["phishing", "credential_harvesting"],
    },
    {
        "indicator": "http://198.51.100.25:8080/payload.bin",
        "indicator_type": "url",
        "malicious": True,
        "threat_score": 98,
        "confidence": 0.99,
        "source": "sandbox_analysis",
        "categories": ["malware_download", "trojan"],
    },
    # Benign URL
    {
        "indicator": "https://github.com",
        "indicator_type": "url",
        "malicious": False,
        "threat_score": 0,
        "confidence": 1.0,
        "source": "internal_whitelist",
        "categories": ["trusted_platform"],
    },
    # Malicious Domains
    {
        "indicator": "evil-payloads.top",
        "indicator_type": "domain",
        "malicious": True,
        "threat_score": 92,
        "confidence": 0.95,
        "source": "domain_blocklist",
        "categories": ["malware_c2", "fast_flux"],
    },
    {
        "indicator": "stealer-logs.cc",
        "indicator_type": "domain",
        "malicious": True,
        "threat_score": 88,
        "confidence": 0.90,
        "source": "intel_feed",
        "categories": ["infostealer", "data_exfiltration"],
    },
    # Benign Domain
    {
        "indicator": "dns.google",
        "indicator_type": "domain",
        "malicious": False,
        "threat_score": 0,
        "confidence": 1.0,
        "source": "internal_whitelist",
        "categories": ["trusted_service"],
    },
]


async def seed_database(session: AsyncSession) -> dict[str, int]:
    """Populate database with default seed data for trusted domains and CTI indicators."""
    trusted_repo = TrustedDomainRepository(session)
    cti_repo = CTIIndicatorRepository(session)

    trusted_count = 0
    for item in SAMPLE_TRUSTED_DOMAINS:
        await trusted_repo.add(domain=item["domain"], description=item["description"])
        trusted_count += 1

    cti_count = 0
    for item in SAMPLE_CTI_INDICATORS:
        await cti_repo.add_or_update(
            indicator=item["indicator"],
            indicator_type=item["indicator_type"],
            malicious=item["malicious"],
            threat_score=item["threat_score"],
            confidence=item["confidence"],
            source=item["source"],
            categories=item["categories"],
        )
        cti_count += 1

    await session.commit()
    logger.info(f"Seeded {trusted_count} trusted domains and {cti_count} CTI indicators.")
    return {"trusted_domains": trusted_count, "cti_indicators": cti_count}


async def run_seed() -> None:
    """CLI runner to execute database seeding."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    engine = init_db_pool()
    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)

    async with session_factory() as session:
        result = await seed_database(session)
        print(f"Database seeded successfully: {result}")

    await close_db_pool()


if __name__ == "__main__":
    asyncio.run(run_seed())

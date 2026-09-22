"""Comprehensive tests for Stage 6: trusted-domain classification and domain-boundary integrity."""

import pytest
from httpx import AsyncClient
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.repositories.trusted_domain import TrustedDomainRepository
from app.schemas.indicator import IndicatorType
from app.schemas.threat_cache import generate_cache_key
from app.services.indicator import IndicatorService


class TestIndicatorHostnameExtraction:
    """Unit tests for IndicatorService.extract_hostname."""

    @pytest.mark.parametrize(
        ("input_val", "expected_host"),
        [
            ("google.com", "google.com"),
            ("GOOGLE.COM", "google.com"),
            ("mail.google.com", "mail.google.com"),
            ("docs.google.com", "docs.google.com"),
            ("docs.google.com:443", "docs.google.com"),
            ("http://accounts.google.com:8080/signin", "accounts.google.com"),
            ("https://docs.google.com/document/d/abc?query=1#frag", "docs.google.com"),
            ("google.com.evil.com", "google.com.evil.com"),
            ("evilgoogle.com", "evilgoogle.com"),
            ("sub.nested.google.com", "sub.nested.google.com"),
        ],
    )
    def test_valid_hostname_extraction(self, input_val: str, expected_host: str) -> None:
        extracted = IndicatorService.extract_hostname(input_val)
        assert extracted == expected_host

    @pytest.mark.parametrize(
        "invalid_input",
        [
            "198.51.100.25",
            "http://198.51.100.25/path",
            "http://198.51.100.25:8080/",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "http://[2001:db8::1]:8080/test",
            "invalid_domain@@##",
            "",
            "   ",
        ],
    )
    def test_invalid_or_ip_hostname_returns_none(self, invalid_input: str) -> None:
        extracted = IndicatorService.extract_hostname(invalid_input)
        assert extracted is None


class TestTrustedDomainBoundaryCorrectness:
    """Tests verifying PostgreSQL trusted domain hierarchy matching and naive substring rejection."""

    @pytest.mark.asyncio
    async def test_trusted_domain_repo_matching(self, db_session: AsyncSession) -> None:
        repo = TrustedDomainRepository(db_session)

        # google.com is seeded as a trusted root domain
        # Exact match
        assert await repo.is_trusted("google.com") is True
        assert await repo.get_matched_trusted_domain("google.com") == "google.com"

        # Subdomains must match
        assert await repo.is_trusted("mail.google.com") is True
        assert await repo.get_matched_trusted_domain("mail.google.com") == "google.com"

        assert await repo.is_trusted("docs.google.com") is True
        assert await repo.get_matched_trusted_domain("docs.google.com") == "google.com"

        assert await repo.is_trusted("sub.accounts.google.com") is True
        assert await repo.get_matched_trusted_domain("sub.accounts.google.com") == "google.com"

        # Naive substring attacks MUST NOT match
        assert await repo.is_trusted("google.com.evil.com") is False
        assert await repo.get_matched_trusted_domain("google.com.evil.com") is None

        assert await repo.is_trusted("evilgoogle.com") is False
        assert await repo.get_matched_trusted_domain("evilgoogle.com") is None

        assert await repo.is_trusted("fakegoogle.com") is False
        assert await repo.get_matched_trusted_domain("fakegoogle.com") is None

        assert await repo.is_trusted("notgoogle.com") is False
        assert await repo.get_matched_trusted_domain("notgoogle.com") is None

        assert await repo.is_trusted("google.community") is False
        assert await repo.get_matched_trusted_domain("google.community") is None

        assert await repo.is_trusted("mygoogle.com") is False
        assert await repo.get_matched_trusted_domain("mygoogle.com") is None


class TestTrustedDomainLookupAPI:
    """API integration tests for /api/check evaluating trusted-domain classification."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "trusted_indicator",
        [
            "google.com",
            "mail.google.com",
            "docs.google.com",
            "https://docs.google.com/document/d/xyz",
            "https://accounts.google.com:443/login",
            "github.com",
            "https://api.github.com/users",
            "microsoft.com",
        ],
    )
    async def test_trusted_domains_and_subdomains_return_trusted_status(
        self, async_client: AsyncClient, redis_test_client: Redis, trusted_indicator: str
    ) -> None:
        """Verified trusted root domains and subdomains return is_trusted_domain=True and malicious=False."""
        response = await async_client.post("/api/check", json={"indicator": trusted_indicator})
        assert response.status_code == 200

        data = response.json()
        assert data["is_trusted_domain"] is True
        assert data["trusted_domain"] is True
        assert data["malicious"] is False
        assert data["threat_score"] == 0

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "untrusted_indicator",
        [
            "google.com.evil.com",
            "https://google.com.evil.com/login",
            "evilgoogle.com",
            "https://evilgoogle.com/account",
            "fakegoogle.com",
            "notgoogle.com",
            "google.community",
            "198.51.100.25",
            "http://198.51.100.25/index.html",
        ],
    )
    async def test_naive_substring_and_non_domains_are_not_trusted(
        self, async_client: AsyncClient, redis_test_client: Redis, untrusted_indicator: str
    ) -> None:
        """Naive substring patterns, attacker domains, and IPs MUST NOT be classified as trusted."""
        response = await async_client.post("/api/check", json={"indicator": untrusted_indicator})
        assert response.status_code == 200

        data = response.json()
        assert data["is_trusted_domain"] is False
        assert data["trusted_domain"] is False

    @pytest.mark.asyncio
    async def test_malicious_cti_on_trusted_domain_not_overridden(
        self, async_client: AsyncClient, db_session: AsyncSession, redis_test_client: Redis
    ) -> None:
        """Important: Do NOT automatically override a confirmed malicious CTI result merely because

        a domain appears in the trusted-domain table.
        The trusted-domain status must be True, but the malicious verdict and threat_score must remain!
        """
        malicious_url = "https://docs.google.com/malicious-phish"
        cache_key = generate_cache_key(IndicatorType.URL, malicious_url)

        # Clear any prior cache
        await redis_test_client.delete(cache_key)

        from app.repositories.cti_indicator import CTIIndicatorRepository
        repo = CTIIndicatorRepository(db_session)
        await repo.add_or_update(
            indicator=malicious_url,
            indicator_type="url",
            malicious=True,
            threat_score=95,
            confidence=0.98,
            source="threat_intel_soc",
            categories=["credential_harvesting", "phishing"],
        )
        await db_session.commit()

        # Query the lookup endpoint
        response = await async_client.post("/api/check", json={"indicator": malicious_url})
        assert response.status_code == 200

        data = response.json()
        # 1. Malicious verdict MUST NOT be overridden:
        assert data["malicious"] is True
        assert data["threat_score"] == 95
        assert data["confidence"] == 0.98
        assert "phishing" in data["categories"]
        assert "threat_intel_soc" in data["source"]

        # 2. Trusted-domain status MUST accurately report that the host is on a trusted root domain:
        assert data["is_trusted_domain"] is True
        assert data["trusted_domain"] is True

        # 3. Subsequent query hits Redis and maintains both pieces of information:
        cached_resp = await async_client.post("/api/check", json={"indicator": malicious_url})
        assert cached_resp.status_code == 200
        cached_data = cached_resp.json()
        assert cached_data["cached"] is True
        assert cached_data["malicious"] is True
        assert cached_data["threat_score"] == 95
        assert cached_data["is_trusted_domain"] is True
        assert cached_data["trusted_domain"] is True

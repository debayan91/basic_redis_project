"""Tests for TrustedDomainRepository, CTIIndicatorRepository, and database constraints."""

from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.seed import seed_database
from app.repositories.cti_indicator import CTIIndicatorRepository
from app.repositories.trusted_domain import TrustedDomainRepository


class TestTrustedDomainRepository:
    @pytest.mark.asyncio
    async def test_add_and_get_trusted_domain(self, db_session: AsyncSession) -> None:
        repo = TrustedDomainRepository(db_session)
        test_domain = f"test-{int(datetime.now(UTC).timestamp())}.org"

        # Add domain
        created = await repo.add(domain=test_domain, description="Test Domain")
        assert created.domain == test_domain
        assert created.description == "Test Domain"

        # Retrieve domain
        fetched = await repo.get_by_domain(test_domain)
        assert fetched is not None
        assert fetched.domain == test_domain

    @pytest.mark.asyncio
    async def test_trusted_domain_idempotence(self, db_session: AsyncSession) -> None:
        repo = TrustedDomainRepository(db_session)
        test_domain = f"idempotent-{int(datetime.now(UTC).timestamp())}.com"

        first = await repo.add(domain=test_domain, description="First Description")
        second = await repo.add(domain=test_domain, description="Updated Description")

        assert first.id == second.id
        assert second.description == "Updated Description"

    @pytest.mark.asyncio
    async def test_is_trusted_parent_domain_matching(self, db_session: AsyncSession) -> None:
        repo = TrustedDomainRepository(db_session)
        root_domain = f"whitelist-{int(datetime.now(UTC).timestamp())}.com"

        await repo.add(domain=root_domain, description="Root organization")

        # Root itself is trusted
        assert await repo.is_trusted(root_domain) is True
        # Direct subdomain is trusted
        assert await repo.is_trusted(f"mail.{root_domain}") is True
        # Nested subdomain is trusted
        assert await repo.is_trusted(f"api.v1.auth.{root_domain}") is True
        # Unrelated domain is not trusted
        assert await repo.is_trusted(f"not-{root_domain}") is False

    @pytest.mark.asyncio
    async def test_remove_trusted_domain(self, db_session: AsyncSession) -> None:
        repo = TrustedDomainRepository(db_session)
        test_domain = f"remove-me-{int(datetime.now(UTC).timestamp())}.net"

        await repo.add(domain=test_domain)
        assert await repo.get_by_domain(test_domain) is not None

        deleted = await repo.remove(test_domain)
        assert deleted is True
        assert await repo.get_by_domain(test_domain) is None

        # Removing non-existent returns False
        assert await repo.remove("nonexistent-domain-xyz.com") is False


class TestCTIIndicatorRepository:
    @pytest.mark.asyncio
    async def test_add_and_get_indicator(self, db_session: AsyncSession) -> None:
        repo = CTIIndicatorRepository(db_session)
        indicator = "198.51.100.99"

        record = await repo.add_or_update(
            indicator=indicator,
            indicator_type="ip",
            malicious=True,
            threat_score=85,
            confidence=0.9,
            source="unit_test",
            categories=["ransomware"],
        )
        assert record.indicator == indicator
        assert record.malicious is True
        assert record.threat_score == 85
        assert "ransomware" in record.categories

        fetched = await repo.get_by_indicator(indicator)
        assert fetched is not None
        assert fetched.threat_score == 85

    @pytest.mark.asyncio
    async def test_upsert_merges_categories_and_updates_score(
        self, db_session: AsyncSession
    ) -> None:
        repo = CTIIndicatorRepository(db_session)
        indicator = "https://phish-test.example/login"

        # First insert
        await repo.add_or_update(
            indicator=indicator,
            indicator_type="url",
            malicious=True,
            threat_score=70,
            categories=["phishing"],
        )

        # Update
        updated = await repo.add_or_update(
            indicator=indicator,
            indicator_type="url",
            malicious=True,
            threat_score=95,
            categories=["credential_harvesting"],
        )
        assert updated.threat_score == 95
        assert set(updated.categories) == {"phishing", "credential_harvesting"}

    @pytest.mark.asyncio
    async def test_delete_indicator(self, db_session: AsyncSession) -> None:
        repo = CTIIndicatorRepository(db_session)
        indicator = "malware-sample.xyz"

        await repo.add_or_update(indicator=indicator, indicator_type="domain", malicious=True)
        assert await repo.get_by_indicator(indicator) is not None

        deleted = await repo.delete(indicator)
        assert deleted is True
        assert await repo.get_by_indicator(indicator) is None

    @pytest.mark.asyncio
    async def test_list_indicators_filtering(self, db_session: AsyncSession) -> None:
        repo = CTIIndicatorRepository(db_session)
        prefix = f"filter-{int(datetime.now(UTC).timestamp())}"

        await repo.add_or_update(indicator=f"{prefix}.com", indicator_type="domain", malicious=True)
        await repo.add_or_update(indicator=f"http://{prefix}.com/a", indicator_type="url", malicious=False)

        domains = await repo.list_indicators(indicator_type="domain")
        assert any(d.indicator == f"{prefix}.com" for d in domains)

        malicious_records = await repo.list_indicators(malicious=True)
        assert any(m.indicator == f"{prefix}.com" for m in malicious_records)


class TestDatabaseSeed:
    @pytest.mark.asyncio
    async def test_seed_database(self, db_session: AsyncSession) -> None:
        counts = await seed_database(db_session)
        assert counts["trusted_domains"] >= 6
        assert counts["cti_indicators"] >= 10

        # Verify Google is in trusted domains
        trusted_repo = TrustedDomainRepository(db_session)
        assert await trusted_repo.is_trusted("mail.google.com") is True

        # Verify sample malicious indicator
        cti_repo = CTIIndicatorRepository(db_session)
        bad_ip = await cti_repo.get_by_indicator("198.51.100.25")
        assert bad_ip is not None
        assert bad_ip.malicious is True
        assert bad_ip.threat_score == 95

"""Unit tests for LookupService business logic and provider abstraction."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.exceptions import InvalidIndicatorError
from app.schemas.check import ThreatCheckResponse
from app.schemas.indicator import IndicatorType
from app.schemas.threat_cache import CachedThreatRecord
from app.services.lookup import LookupService
from app.services.providers.base import ThreatIntelligenceProvider


class DummyCTIProvider(ThreatIntelligenceProvider):
    """Mock implementation of ThreatIntelligenceProvider interface."""

    def __init__(self) -> None:
        self.lookup_mock = AsyncMock()
        self.is_trusted_domain_mock = AsyncMock(return_value=False)

    async def lookup(
        self, indicator: str, indicator_type: IndicatorType
    ) -> CachedThreatRecord | None:
        return await self.lookup_mock(indicator, indicator_type)

    async def is_trusted_domain(self, domain: str) -> bool:
        return await self.is_trusted_domain_mock(domain)


@pytest.fixture
def mock_cache() -> MagicMock:
    cache = MagicMock()
    cache.get = AsyncMock(return_value=None)
    cache.set = AsyncMock()
    cache.determine_ttl = MagicMock(return_value=3600)
    return cache


@pytest.fixture
def mock_provider() -> DummyCTIProvider:
    return DummyCTIProvider()


@pytest.fixture
def lookup_service(mock_cache: MagicMock, mock_provider: DummyCTIProvider) -> LookupService:
    return LookupService(cache_service=mock_cache, provider=mock_provider)


@pytest.mark.asyncio
async def test_lookup_pipeline_cache_hit(
    lookup_service: LookupService, mock_cache: MagicMock, mock_provider: DummyCTIProvider
) -> None:
    """If Redis returns a cached threat record, provider.lookup must not be invoked."""
    cached_record = CachedThreatRecord(
        indicator="198.51.100.1",
        indicator_type=IndicatorType.IP,
        malicious=True,
        threat_score=90,
        confidence=0.9,
        categories=["botnet"],
        source="local_cti:abuse_feed",
        checked_at=datetime.now(UTC),
        ttl_seconds=3500,
    )
    mock_cache.get.return_value = cached_record

    result = await lookup_service.lookup("198.51.100.1")

    assert isinstance(result, ThreatCheckResponse)
    assert result.cached is True
    assert result.malicious is True
    assert result.threat_score == 90
    assert result.ttl_seconds == 3500
    mock_provider.lookup_mock.assert_not_called()
    mock_cache.set.assert_not_called()


@pytest.mark.asyncio
async def test_lookup_pipeline_cache_miss_cti_hit(
    lookup_service: LookupService, mock_cache: MagicMock, mock_provider: DummyCTIProvider
) -> None:
    """If Redis misses, provider.lookup is queried, cached in Redis, and returned."""
    mock_cache.get.return_value = None
    cti_record = CachedThreatRecord(
        indicator="evil.com",
        indicator_type=IndicatorType.DOMAIN,
        malicious=True,
        threat_score=85,
        confidence=0.85,
        categories=["malware"],
        source="local_cti:phish_feed",
        checked_at=datetime.now(UTC),
    )
    mock_provider.lookup_mock.return_value = cti_record

    result = await lookup_service.lookup("evil.com")

    assert result.cached is False
    assert result.malicious is True
    assert result.threat_score == 85
    assert result.source == "local_cti:phish_feed"
    mock_provider.lookup_mock.assert_called_once_with("evil.com", IndicatorType.DOMAIN)
    mock_cache.set.assert_called_once()


@pytest.mark.asyncio
async def test_lookup_pipeline_cache_miss_clean_indicator(
    lookup_service: LookupService, mock_cache: MagicMock, mock_provider: DummyCTIProvider
) -> None:
    """If indicator is not in cache and not in CTI catalog, baseline clean record is produced."""
    mock_cache.get.return_value = None
    mock_provider.lookup_mock.return_value = None

    result = await lookup_service.lookup("clean-host.org")

    assert result.cached is False
    assert result.malicious is False
    assert result.threat_score == 0
    assert result.confidence == 0.5
    assert result.source == "local_cti_catalog"
    mock_cache.set.assert_called_once()


@pytest.mark.asyncio
async def test_lookup_pipeline_trusted_domain(
    lookup_service: LookupService, mock_cache: MagicMock, mock_provider: DummyCTIProvider
) -> None:
    """Trusted domain with no CTI record produces trusted benign verdict."""
    mock_cache.get.return_value = None
    mock_provider.is_trusted_domain_mock.return_value = True
    mock_provider.lookup_mock.return_value = None

    result = await lookup_service.lookup("sub.trusted.com")

    assert result.cached is False
    assert result.malicious is False
    assert result.threat_score == 0
    assert result.confidence == 1.0
    assert result.is_trusted_domain is True
    assert result.trusted_domain is True
    assert result.source == "trusted_domain_whitelist"
    mock_provider.lookup_mock.assert_called_once()
    mock_cache.set.assert_called_once()


@pytest.mark.asyncio
async def test_lookup_pipeline_malicious_cti_on_trusted_domain(
    lookup_service: LookupService, mock_cache: MagicMock, mock_provider: DummyCTIProvider
) -> None:
    """Confirmed malicious CTI record is NOT overridden even if domain is in trusted table."""
    mock_cache.get.return_value = None
    mock_provider.is_trusted_domain_mock.return_value = True
    malicious_record = CachedThreatRecord(
        indicator="https://docs.google.com/malicious-doc",
        indicator_type=IndicatorType.URL,
        malicious=True,
        threat_score=90,
        confidence=0.95,
        categories=["phishing", "credential_theft"],
        source="local_cti:phish_feed",
        checked_at=datetime.now(UTC),
    )
    mock_provider.lookup_mock.return_value = malicious_record

    result = await lookup_service.lookup("https://docs.google.com/malicious-doc")

    assert result.cached is False
    # Malicious verdict must NOT be overridden!
    assert result.malicious is True
    assert result.threat_score == 90
    assert result.confidence == 0.95
    assert result.source == "local_cti:phish_feed"
    # But trusted-domain status must still be accurately reported as True
    assert result.is_trusted_domain is True
    assert result.trusted_domain is True
    mock_cache.set.assert_called_once()


@pytest.mark.asyncio
async def test_lookup_pipeline_invalid_indicator(lookup_service: LookupService) -> None:
    """Invalid indicator string raises InvalidIndicatorError."""
    with pytest.raises(InvalidIndicatorError):
        await lookup_service.lookup("http://")


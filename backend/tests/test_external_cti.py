"""Unit and integration tests for Stage 7: External CTI Providers and abstractions."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.config import Settings
from app.core.exceptions import (
    ProviderError,
    ProviderRateLimitError,
    ProviderTimeoutError,
    ProviderUnavailableError,
)
from app.schemas.indicator import IndicatorType
from app.schemas.threat_cache import CachedThreatRecord
from app.services.providers.composite import CompositeCTIProvider
from app.services.providers.factory import get_configured_provider
from app.services.providers.local_cti import LocalCTIProvider
from app.services.providers.mock_external import MockExternalCTIProvider
from app.services.providers.virustotal import VirusTotalProvider


class TestMockExternalCTIProvider:
    """Tests verifying the MockExternalCTIProvider and fault injection capabilities."""

    @pytest.mark.asyncio
    async def test_mock_provider_heuristics(self) -> None:
        provider = MockExternalCTIProvider()

        # Malicious keywords
        res1 = await provider.lookup("evil-payload.com", IndicatorType.DOMAIN)
        assert res1 is not None
        assert res1.malicious is True
        assert res1.threat_score >= 80

        # Benign keywords
        res2 = await provider.lookup("clean-portal.org", IndicatorType.DOMAIN)
        assert res2 is not None
        assert res2.malicious is False
        assert res2.threat_score == 0

        # Unlisted / unknown
        res3 = await provider.lookup("unlisted-neutral.net", IndicatorType.DOMAIN)
        assert res3 is None

    @pytest.mark.asyncio
    async def test_mock_provider_preset_registration(self) -> None:
        provider = MockExternalCTIProvider()
        custom = CachedThreatRecord(
            indicator="198.51.100.77",
            indicator_type=IndicatorType.IP,
            malicious=True,
            threat_score=99,
            confidence=1.0,
            categories=["apt"],
            source="custom_preset",
            checked_at=datetime.now(UTC),
        )
        provider.register_record("198.51.100.77", custom)

        res = await provider.lookup("198.51.100.77", IndicatorType.IP)
        assert res is not None
        assert res.threat_score == 99
        assert res.source == "custom_preset"

    @pytest.mark.asyncio
    async def test_mock_provider_fault_injection(self) -> None:
        provider = MockExternalCTIProvider()

        # Timeout simulation
        provider.simulate_timeout = True
        with pytest.raises(ProviderTimeoutError):
            await provider.lookup("test.com", IndicatorType.DOMAIN)
        provider.simulate_timeout = False

        # Rate limit simulation (HTTP 429)
        provider.simulate_rate_limit = True
        with pytest.raises(ProviderRateLimitError):
            await provider.lookup("test.com", IndicatorType.DOMAIN)
        provider.simulate_rate_limit = False

        # Unavailable / 5xx simulation
        provider.simulate_unavailable = True
        with pytest.raises(ProviderUnavailableError):
            await provider.lookup("test.com", IndicatorType.DOMAIN)
        provider.simulate_unavailable = False

        # Malformed response simulation
        provider.simulate_malformed = True
        with pytest.raises(ProviderError):
            await provider.lookup("test.com", IndicatorType.DOMAIN)
        provider.simulate_malformed = False


class TestVirusTotalProvider:
    """Tests verifying VirusTotalProvider request formation and response normalization."""

    def test_encode_url_id(self) -> None:
        url = "https://malicious.com/payload.exe"
        encoded = VirusTotalProvider.encode_url_id(url)
        assert "=" not in encoded
        assert len(encoded) > 10

    @pytest.mark.asyncio
    async def test_lookup_without_api_key_returns_none(self) -> None:
        provider = VirusTotalProvider(api_key=None)
        res = await provider.lookup("198.51.100.1", IndicatorType.IP)
        assert res is None

    @pytest.mark.asyncio
    async def test_virustotal_response_normalization(self) -> None:
        provider = VirusTotalProvider(api_key="test_vt_api_key")

        mock_payload = {
            "data": {
                "id": "198.51.100.10",
                "type": "ip_address",
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 12,
                        "suspicious": 3,
                        "harmless": 40,
                        "undetected": 15,
                    },
                    "categories": {
                        "AlphaEngine": "botnet C2",
                        "BetaEngine": "malware distributor",
                    },
                    "last_analysis_date": 1700000000,
                },
            }
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json = MagicMock(return_value=mock_payload)

        with patch.object(provider, "_safe_get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response

            record = await provider.lookup("198.51.100.10", IndicatorType.IP)
            assert record is not None
            assert record.indicator == "198.51.100.10"
            assert record.indicator_type == IndicatorType.IP
            assert record.malicious is True
            assert record.threat_score >= 80
            assert record.confidence > 0.5
            assert record.source == "virustotal_v3"
            assert "botnet c2" in record.categories or "malware distributor" in record.categories

    @pytest.mark.asyncio
    async def test_virustotal_not_found_returns_none(self) -> None:
        provider = VirusTotalProvider(api_key="test_vt_api_key")
        mock_response = MagicMock()
        mock_response.status_code = 404

        with patch.object(provider, "_safe_get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response
            record = await provider.lookup("clean-never-seen.com", IndicatorType.DOMAIN)
            assert record is None


class TestCompositeCTIProvider:
    """Tests verifying CompositeCTIProvider delegation and fallback."""

    @pytest.mark.asyncio
    async def test_composite_hits_local_first(self) -> None:
        local_mock = MagicMock()
        external_mock = MagicMock()

        local_record = CachedThreatRecord(
            indicator="1.1.1.1",
            indicator_type=IndicatorType.IP,
            malicious=False,
            threat_score=0,
            confidence=1.0,
            categories=[],
            source="local_cti:seed",
            checked_at=datetime.now(UTC),
        )
        local_mock.lookup = AsyncMock(return_value=local_record)
        external_mock.lookup = AsyncMock()

        composite = CompositeCTIProvider(local_provider=local_mock, external_provider=external_mock)
        res = await composite.lookup("1.1.1.1", IndicatorType.IP)

        assert res == local_record
        external_mock.lookup.assert_not_called()

    @pytest.mark.asyncio
    async def test_composite_delegates_to_external_on_local_miss(self) -> None:
        local_mock = MagicMock()
        external_mock = MagicMock()

        local_mock.lookup = AsyncMock(return_value=None)
        ext_record = CachedThreatRecord(
            indicator="evil-ext.com",
            indicator_type=IndicatorType.DOMAIN,
            malicious=True,
            threat_score=85,
            confidence=0.9,
            categories=["phishing"],
            source="external_provider",
            checked_at=datetime.now(UTC),
        )
        external_mock.lookup = AsyncMock(return_value=ext_record)

        composite = CompositeCTIProvider(local_provider=local_mock, external_provider=external_mock)
        res = await composite.lookup("evil-ext.com", IndicatorType.DOMAIN)

        assert res == ext_record
        local_mock.lookup.assert_called_once()
        external_mock.lookup.assert_called_once()

    @pytest.mark.asyncio
    async def test_composite_graceful_fallback_on_external_error(self) -> None:
        local_mock = MagicMock()
        external_mock = MagicMock()

        local_mock.lookup = AsyncMock(return_value=None)
        external_mock.lookup = AsyncMock(side_effect=ProviderRateLimitError("Rate limit 429"))

        composite = CompositeCTIProvider(
            local_provider=local_mock, external_provider=external_mock, fallback_on_external_error=True
        )
        # Should catch error, log warning, and return None (fallback)
        res = await composite.lookup("test.com", IndicatorType.DOMAIN)
        assert res is None


class TestProviderFactory:
    """Tests verifying provider factory instantiations from settings."""

    def test_factory_selection(self) -> None:
        db_mock = MagicMock()

        # Local provider
        cfg_local = Settings(CTI_PROVIDER="local")
        p_local = get_configured_provider(db_mock, settings=cfg_local)
        assert isinstance(p_local, LocalCTIProvider)

        # Mock external provider
        cfg_mock = Settings(CTI_PROVIDER="mock")
        p_mock = get_configured_provider(db_mock, settings=cfg_mock)
        assert isinstance(p_mock, CompositeCTIProvider)

        # VirusTotal provider
        cfg_vt = Settings(CTI_PROVIDER="virustotal", VIRUSTOTAL_API_KEY="test_key")
        p_vt = get_configured_provider(db_mock, settings=cfg_vt)
        assert isinstance(p_vt, CompositeCTIProvider)

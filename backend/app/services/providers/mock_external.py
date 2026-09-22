"""Mock External Threat Intelligence Provider for resilient testing and simulation."""

import logging
from datetime import UTC, datetime

from app.core.config import Settings, get_settings
from app.core.exceptions import (
    ProviderError,
    ProviderRateLimitError,
    ProviderTimeoutError,
    ProviderUnavailableError,
)
from app.schemas.indicator import IndicatorType
from app.schemas.threat_cache import CachedThreatRecord
from app.services.providers.external_base import ExternalCTIProvider

logger = logging.getLogger(__name__)


class MockExternalCTIProvider(ExternalCTIProvider):
    """Configurable mock external provider supporting fault injection for tests."""

    def __init__(
        self,
        api_key: str | None = "mock_test_api_key",
        base_url: str = "https://mock-cti.local",
        timeout: float = 3.0,
        simulated_latency: float = 0.0,
        settings: Settings | None = None,
    ) -> None:
        super().__init__(
            api_key=api_key,
            base_url=base_url,
            timeout=timeout,
            settings=settings or get_settings(),
        )
        self.preset_records: dict[str, CachedThreatRecord | None] = {}
        self.simulated_latency = simulated_latency
        self.simulate_timeout: bool = False
        self.simulate_rate_limit: bool = False
        self.simulate_unavailable: bool = False
        self.simulate_malformed: bool = False

    def register_record(self, indicator: str, record: CachedThreatRecord | None) -> None:
        """Register a predetermined response for a given indicator."""
        self.preset_records[indicator.strip()] = record

    async def lookup(
        self, indicator: str, indicator_type: IndicatorType
    ) -> CachedThreatRecord | None:
        """Simulate external lookup with configurable error injection."""
        clean = indicator.strip()

        if self.simulated_latency > 0:
            import asyncio
            await asyncio.sleep(self.simulated_latency)

        # 1. Fault injection simulations
        if self.simulate_timeout:
            raise ProviderTimeoutError(
                f"Mock external CTI provider request timed out after {self.timeout}s",
                details={"timeout": self.timeout},
            )

        if self.simulate_rate_limit:
            raise ProviderRateLimitError(
                "Mock external CTI provider rate limit exceeded (HTTP 429)",
                details={"status_code": 429},
            )

        if self.simulate_unavailable:
            raise ProviderUnavailableError(
                "Mock external CTI provider is unavailable (HTTP 503)",
                details={"status_code": 503},
            )

        if self.simulate_malformed:
            raise ProviderError(
                "Mock external CTI provider returned malformed response",
                details={"raw_payload": "<html>502 Bad Gateway</html>"},
            )

        # 2. Check preset records
        if clean in self.preset_records:
            return self.preset_records[clean]

        # 3. Deterministic heuristic for testing:
        lower = clean.lower()
        if any(keyword in lower for keyword in ("evil", "malicious", "phish", "c2", "ransomware", "trojan")):
            return CachedThreatRecord(
                indicator=clean,
                indicator_type=indicator_type,
                malicious=True,
                threat_score=88,
                confidence=0.92,
                categories=["malware", "phishing"],
                source="mock_external_feed",
                checked_at=datetime.now(UTC),
            )
        elif any(keyword in lower for keyword in ("clean", "safe", "benign")):
            return CachedThreatRecord(
                indicator=clean,
                indicator_type=indicator_type,
                malicious=False,
                threat_score=0,
                confidence=0.85,
                categories=[],
                source="mock_external_feed",
                checked_at=datetime.now(UTC),
            )

        # Unknown
        return None

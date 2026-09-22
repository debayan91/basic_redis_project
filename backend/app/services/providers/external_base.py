"""Abstract base class for External Threat Intelligence Providers using async HTTP."""

import logging
from abc import abstractmethod
from collections.abc import Mapping
from typing import Any

import httpx

from app.core.config import Settings, get_settings
from app.core.exceptions import (
    ProviderError,
    ProviderRateLimitError,
    ProviderTimeoutError,
    ProviderUnavailableError,
)
from app.schemas.indicator import IndicatorType
from app.schemas.threat_cache import CachedThreatRecord
from app.services.providers.base import ThreatIntelligenceProvider

logger = logging.getLogger(__name__)


class ExternalCTIProvider(ThreatIntelligenceProvider):
    """Base class for external HTTP-based threat intelligence providers.
    
    Provides async HTTP execution, timeout management, rate-limit detection,
    and credential protection (API keys are never logged).
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = "",
        timeout: float = 3.0,
        max_retries: int = 2,
        settings: Settings | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self._api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries

    @property
    def has_credentials(self) -> bool:
        """Check if provider has a configured API key."""
        return bool(self._api_key and self._api_key.strip())

    async def _get_client(self) -> httpx.AsyncClient:
        """Create a configured async HTTP client."""
        return httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            follow_redirects=True,
        )

    async def _safe_get(
        self,
        endpoint: str,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, Any] | None = None,
    ) -> httpx.Response:
        """Execute an async GET request with standardized error handling and retry logic."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        safe_headers = dict(headers or {})

        client = await self._get_client()
        try:
            for attempt in range(self.max_retries + 1):
                try:
                    response = await client.get(url, headers=safe_headers, params=params)
                    # 429 Rate Limit
                    if response.status_code == 429:
                        logger.warning(f"External CTI provider rate limit hit on attempt {attempt + 1}")
                        raise ProviderRateLimitError(
                            "External threat intelligence provider rate limit exceeded (HTTP 429)",
                            details={"status_code": 429, "endpoint": endpoint},
                        )

                    # 404 Not Found is handled by caller as no intelligence available
                    if response.status_code == 404:
                        return response

                    # 5xx Server Errors
                    if response.status_code >= 500:
                        if attempt < self.max_retries:
                            continue
                        raise ProviderUnavailableError(
                            f"External provider returned server error: HTTP {response.status_code}",
                            details={"status_code": response.status_code},
                        )

                    # Other 4xx client errors
                    if response.status_code >= 400:
                        raise ProviderError(
                            f"External provider rejected request: HTTP {response.status_code}",
                            details={"status_code": response.status_code},
                        )

                    return response

                except httpx.TimeoutException as exc:
                    if attempt < self.max_retries:
                        logger.debug(f"External provider request timed out on attempt {attempt + 1}, retrying...")
                        continue
                    raise ProviderTimeoutError(
                        f"External CTI request timed out after {self.timeout}s",
                        details={"timeout": self.timeout},
                    ) from exc
                except httpx.NetworkError as exc:
                    if attempt < self.max_retries:
                        continue
                    raise ProviderUnavailableError(
                        "External CTI provider is unreachable (network/connect error)",
                        details={"url": self.base_url},
                    ) from exc

            raise ProviderUnavailableError("External provider unavailable after maximum retries")
        finally:
            await client.aclose()

    @abstractmethod
    async def lookup(
        self, indicator: str, indicator_type: IndicatorType
    ) -> CachedThreatRecord | None:
        """Execute external lookup for the normalized indicator."""

    async def is_trusted_domain(self, domain: str) -> bool:
        """External CTI providers typically do not own local trusted domain lists."""
        return False

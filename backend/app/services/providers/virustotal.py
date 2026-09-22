"""VirusTotal v3 External Threat Intelligence Provider."""

import base64
import logging
from datetime import UTC, datetime

from app.core.config import Settings, get_settings
from app.core.exceptions import ProviderError
from app.schemas.indicator import IndicatorType
from app.schemas.threat_cache import CachedThreatRecord
from app.services.providers.external_base import ExternalCTIProvider

logger = logging.getLogger(__name__)


class VirusTotalProvider(ExternalCTIProvider):
    """Integrates with the official VirusTotal v3 REST API.
    
    API Endpoints:
    - IP: /ip_addresses/{ip}
    - Domain: /domains/{domain}
    - URL: /urls/{url_id} (Base64 URL-safe encoded)
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float = 3.0,
        settings: Settings | None = None,
    ) -> None:
        cfg = settings or get_settings()
        key = api_key or cfg.VIRUSTOTAL_API_KEY
        url = base_url or cfg.VIRUSTOTAL_BASE_URL
        super().__init__(
            api_key=key,
            base_url=url,
            timeout=timeout,
            max_retries=cfg.EXTERNAL_CTI_MAX_RETRIES,
            settings=cfg,
        )

    def _get_headers(self) -> dict[str, str]:
        """Generate request headers with API key."""
        if not self._api_key:
            raise ProviderError("VirusTotal API key is not configured")
        return {"x-apikey": self._api_key, "Accept": "application/json"}

    @staticmethod
    def encode_url_id(url: str) -> str:
        """Encode a URL to VirusTotal v3 URL ID format (Base64 without trailing '=')."""
        return base64.urlsafe_b64encode(url.strip().encode("utf-8")).decode("utf-8").strip("=")

    async def lookup(
        self, indicator: str, indicator_type: IndicatorType
    ) -> CachedThreatRecord | None:
        """Query VirusTotal v3 for IP, Domain, or URL threat intelligence."""
        if not self.has_credentials:
            logger.warning("VirusTotal lookup skipped: No API key configured")
            return None

        # Format endpoint based on indicator type
        if indicator_type == IndicatorType.IP:
            endpoint = f"/ip_addresses/{indicator.strip()}"
        elif indicator_type == IndicatorType.DOMAIN:
            endpoint = f"/domains/{indicator.strip().lower().rstrip('.')}"
        elif indicator_type == IndicatorType.URL:
            url_id = self.encode_url_id(indicator)
            endpoint = f"/urls/{url_id}"
        else:
            return None

        headers = self._get_headers()
        response = await self._safe_get(endpoint, headers=headers)

        if response.status_code == 404:
            # Indicator is unknown to VirusTotal
            return None

        try:
            payload = response.json()
        except Exception as exc:
            raise ProviderError("Invalid JSON received from VirusTotal API") from exc

        data = payload.get("data")
        if not data or not isinstance(data, dict):
            raise ProviderError("Malformed response structure from VirusTotal API")

        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious_count = int(stats.get("malicious", 0))
        suspicious_count = int(stats.get("suspicious", 0))
        harmless_count = int(stats.get("harmless", 0))
        undetected_count = int(stats.get("undetected", 0))
        total_engines = malicious_count + suspicious_count + harmless_count + undetected_count

        # Calculate threat score
        if malicious_count >= 5:
            threat_score = min(100, max(80, int((malicious_count / max(total_engines, 1)) * 300)))
        elif malicious_count >= 2:
            threat_score = min(79, max(60, int((malicious_count / max(total_engines, 1)) * 250)))
        elif malicious_count == 1:
            threat_score = 45
        elif suspicious_count >= 2:
            threat_score = 35
        else:
            threat_score = 0

        is_malicious = (malicious_count >= 2) or (threat_score >= 60)
        confidence = min(1.0, round(total_engines / 60, 2)) if total_engines > 0 else 0.5

        # Categories
        cat_dict = attributes.get("categories", {})
        categories = list({str(v).lower() for v in cat_dict.values()} if isinstance(cat_dict, dict) else [])

        # Sighting timestamps
        raw_last_analysis = attributes.get("last_analysis_date")
        last_seen = (
            datetime.fromtimestamp(raw_last_analysis, tz=UTC)
            if raw_last_analysis
            else None
        )

        return CachedThreatRecord(
            indicator=indicator,
            indicator_type=indicator_type,
            malicious=is_malicious,
            threat_score=threat_score,
            confidence=confidence,
            categories=categories,
            source="virustotal_v3",
            first_seen=None,
            last_seen=last_seen,
            checked_at=datetime.now(UTC),
        )

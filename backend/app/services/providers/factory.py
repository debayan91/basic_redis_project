"""Factory for instantiating configured ThreatIntelligenceProvider instances."""

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.services.providers.base import ThreatIntelligenceProvider
from app.services.providers.composite import CompositeCTIProvider
from app.services.providers.local_cti import LocalCTIProvider
from app.services.providers.mock_external import MockExternalCTIProvider
from app.services.providers.virustotal import VirusTotalProvider


def get_configured_provider(
    session: AsyncSession,
    settings: Settings | None = None,
) -> ThreatIntelligenceProvider:
    """Create and return the threat intelligence provider specified by application settings."""
    cfg = settings or get_settings()
    provider_type = cfg.CTI_PROVIDER.lower().strip()

    local_provider = LocalCTIProvider(session)

    if provider_type == "local":
        return local_provider

    if provider_type in ("virustotal", "vt"):
        external = VirusTotalProvider(
            api_key=cfg.VIRUSTOTAL_API_KEY,
            base_url=cfg.VIRUSTOTAL_BASE_URL,
            timeout=cfg.EXTERNAL_CTI_TIMEOUT,
            settings=cfg,
        )
        return CompositeCTIProvider(local_provider=local_provider, external_provider=external)

    if provider_type in ("mock", "mock_external"):
        external = MockExternalCTIProvider(timeout=cfg.EXTERNAL_CTI_TIMEOUT, settings=cfg)
        return CompositeCTIProvider(local_provider=local_provider, external_provider=external)

    if provider_type == "composite":
        external = (
            VirusTotalProvider(settings=cfg)
            if cfg.VIRUSTOTAL_API_KEY
            else MockExternalCTIProvider(settings=cfg)
        )
        return CompositeCTIProvider(local_provider=local_provider, external_provider=external)

    # Fallback to local provider
    return local_provider

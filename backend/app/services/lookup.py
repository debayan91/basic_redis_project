"""Cache-first threat intelligence lookup service orchestrating validation, caching, security checks, and CTI query pipeline."""

import logging
import time
from datetime import UTC, datetime

from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError

from app.core.config import Settings, get_settings
from app.core.exceptions import (
    DatabaseUnavailableError,
    ProviderError,
    ProviderRateLimitError,
    ProviderTimeoutError,
    ProviderUnavailableError,
)
from app.schemas.check import ThreatCheckResponse
from app.schemas.indicator import IndicatorType
from app.schemas.threat_cache import CachedThreatRecord
from app.services.alerts import AlertService
from app.services.blacklist import BlacklistService
from app.services.indicator import IndicatorService
from app.services.metrics import MetricsService
from app.services.providers.base import ThreatIntelligenceProvider
from app.services.ranking import RankingService
from app.services.threat_cache import ThreatCacheService

logger = logging.getLogger(__name__)


class LookupService:
    """Orchestrates the threat lookup pipeline with Redis caching, blacklists, metrics, and alerts."""

    def __init__(
        self,
        cache_service: ThreatCacheService,
        provider: ThreatIntelligenceProvider,
        indicator_service: type[IndicatorService] = IndicatorService,
        blacklist_service: BlacklistService | None = None,
        metrics_service: MetricsService | None = None,
        ranking_service: RankingService | None = None,
        alert_service: AlertService | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.cache = cache_service
        self.provider = provider
        self.indicator_service = indicator_service
        self.blacklist = blacklist_service
        self.metrics = metrics_service
        self.ranking = ranking_service
        self.alerts = alert_service
        self.settings = settings or get_settings()

    async def lookup(self, raw_indicator: str, force_refresh: bool = False) -> ThreatCheckResponse:
        """Execute the complete threat lookup pipeline.

        Pipeline stages:
        1. Validate & normalize indicator
        2. Check Redis blacklist sets (immediate block if blacklisted)
        3. Extract hostname & check trusted-domain whitelist
        4. Check Redis cache (unless force_refresh=True)
        5. If cache hit -> return cached result immediately
        6. If cache miss / expired / force_refresh -> query CTI provider
        7. Store result in Redis with dynamic TTL
        8. Record metrics, update threat ranking, and publish alert if high-risk
        9. Return structured threat response
        """
        start_time = time.perf_counter()
        provider_queried = False

        # 1. Validate, normalize, and detect indicator type
        parsed = self.indicator_service.parse_and_normalize(raw_indicator)

        # 2. Check Blacklist Set (O(1) fast block)
        if self.blacklist:
            try:
                is_bl = await self.blacklist.is_blacklisted(parsed.indicator_type, parsed.normalized)
                if is_bl:
                    latency_ms = (time.perf_counter() - start_time) * 1000
                    if self.metrics:
                        await self.metrics.record_lookup(
                            cached=True, malicious=True, latency_ms=latency_ms, provider_queried=False
                        )
                    return ThreatCheckResponse(
                        original_indicator=parsed.raw,
                        normalized_indicator=parsed.normalized,
                        indicator_type=parsed.indicator_type,
                        malicious=True,
                        threat_score=100,
                        confidence=1.0,
                        categories=["blacklisted"],
                        source="redis_blacklist",
                        is_trusted_domain=False,
                        trusted_domain=False,
                        cached=True,
                        checked_at=datetime.now(UTC),
                        ttl_seconds=self.settings.CACHE_TTL_MALICIOUS,
                    )
            except (RedisError, RedisConnectionError, OSError) as exc:
                logger.warning(f"Redis error checking blacklist for '{parsed.normalized}': {exc}")
                if self.metrics:
                    await self.metrics.record_error()

        # 3. Extract hostname and check trusted-domain logic where applicable (Domain or URL)
        is_trusted = False
        if parsed.indicator_type in (IndicatorType.DOMAIN, IndicatorType.URL):
            hostname = (
                self.indicator_service.extract_hostname(parsed.normalized)
                or parsed.extracted_domain
            )
            if hostname:
                try:
                    is_trusted = await self.provider.is_trusted_domain(hostname)
                except Exception as exc:
                    logger.warning(f"Failed checking trusted domain for '{hostname}': {exc}")

        # 4. Check Redis cache first (unless force_refresh is requested)
        cached_record: CachedThreatRecord | None = None
        if not force_refresh:
            try:
                cached_record = await self.cache.get(parsed.indicator_type, parsed.normalized)
            except (RedisError, RedisConnectionError, OSError) as exc:
                logger.warning(f"Redis cache unavailable during get for '{parsed.normalized}': {exc}")
                if self.metrics:
                    await self.metrics.record_error()

        if cached_record is not None:
            # 5. Cache hit -> return immediately
            latency_ms = (time.perf_counter() - start_time) * 1000
            if self.metrics:
                await self.metrics.record_lookup(
                    cached=True,
                    malicious=cached_record.malicious,
                    latency_ms=latency_ms,
                    provider_queried=False,
                )
            return ThreatCheckResponse(
                original_indicator=parsed.raw,
                normalized_indicator=cached_record.indicator,
                indicator_type=cached_record.indicator_type,
                malicious=cached_record.malicious,
                threat_score=cached_record.threat_score,
                confidence=cached_record.confidence,
                categories=cached_record.categories,
                source=cached_record.source,
                is_trusted_domain=cached_record.is_trusted_domain,
                trusted_domain=cached_record.is_trusted_domain,
                cached=True,
                checked_at=cached_record.checked_at,
                ttl_seconds=cached_record.ttl_seconds,
            )

        # 6. Cache miss or expired -> query CTI provider
        provider_queried = True
        record: CachedThreatRecord | None = None
        try:
            record = await self.provider.lookup(parsed.normalized, parsed.indicator_type)
        except (ProviderRateLimitError, ProviderTimeoutError, ProviderUnavailableError, ProviderError, DatabaseUnavailableError) as exc:
            logger.error(f"Provider lookup failed for '{parsed.normalized}': {exc}")
            if self.metrics:
                await self.metrics.record_error()

            # Resilience fallback: if we have any cached record (e.g. during refresh), return it
            if cached_record is None:
                try:
                    cached_record = await self.cache.get(parsed.indicator_type, parsed.normalized)
                except Exception as cache_exc:
                    logger.debug(f"Failed to fetch cache fallback for '{parsed.normalized}': {cache_exc}")

            if cached_record is not None:
                logger.info(f"Serving cached fallback for '{parsed.normalized}' after provider failure")
                return ThreatCheckResponse(
                    original_indicator=parsed.raw,
                    normalized_indicator=cached_record.indicator,
                    indicator_type=cached_record.indicator_type,
                    malicious=cached_record.malicious,
                    threat_score=cached_record.threat_score,
                    confidence=cached_record.confidence,
                    categories=cached_record.categories,
                    source=f"cache_fallback:{cached_record.source}",
                    is_trusted_domain=cached_record.is_trusted_domain,
                    trusted_domain=cached_record.is_trusted_domain,
                    cached=True,
                    checked_at=cached_record.checked_at,
                    ttl_seconds=cached_record.ttl_seconds,
                )
            raise

        now = datetime.now(UTC)
        if record is not None:
            # Found in CTI! Preserve malicious verdict and attach trusted domain classification
            record.is_trusted_domain = is_trusted
        else:
            # Not found in CTI
            if is_trusted:
                record = CachedThreatRecord(
                    indicator=parsed.normalized,
                    indicator_type=parsed.indicator_type,
                    malicious=False,
                    threat_score=0,
                    confidence=1.0,
                    categories=["trusted_whitelist"],
                    source="trusted_domain_whitelist",
                    is_trusted_domain=True,
                    checked_at=now,
                )
            else:
                # Clean baseline record
                record = CachedThreatRecord(
                    indicator=parsed.normalized,
                    indicator_type=parsed.indicator_type,
                    malicious=False,
                    threat_score=0,
                    confidence=0.5,
                    categories=[],
                    source="local_cti_catalog",
                    is_trusted_domain=False,
                    checked_at=now,
                )

        # 7. Store result in Redis with TTL (resilient to Redis outages)
        ttl = self.cache.determine_ttl(record)
        try:
            await self.cache.set(record, ttl_seconds=ttl)
        except (RedisError, RedisConnectionError, OSError) as exc:
            logger.warning(f"Redis cache write failed for '{record.indicator}': {exc}")
            if self.metrics:
                await self.metrics.record_error()

        # 8. High-risk actions: Alerts, Threat Rankings, and Auto-Blacklist
        try:
            # Publish Pub/Sub alert when threat meets or exceeds alert threshold
            if record.threat_score >= self.settings.ALERT_THRESHOLD:
                if self.alerts:
                    await self.alerts.publish_alert(
                        indicator=record.indicator,
                        indicator_type=record.indicator_type,
                        threat_score=record.threat_score,
                        confidence=record.confidence,
                        source=record.source,
                        categories=record.categories,
                    )

            # Update threat ranking in Redis Sorted Set
            if self.ranking and (record.malicious or record.threat_score >= 50):
                score_delta = max(1.0, float(record.threat_score) / 10.0)
                await self.ranking.increment_threat(record.indicator, score_delta=score_delta)

            # Auto-blacklist severe threats if enabled by policy
            if (
                self.blacklist
                and self.settings.ENABLE_AUTO_BLACKLIST
                and record.threat_score >= self.settings.AUTO_BLACKLIST_THRESHOLD
            ):
                await self.blacklist.add(record.indicator_type, record.indicator)
        except Exception as exc:
            logger.warning(f"Operational post-processing warning for '{record.indicator}': {exc}")

        # Record operational metrics
        latency_ms = (time.perf_counter() - start_time) * 1000
        if self.metrics:
            try:
                await self.metrics.record_lookup(
                    cached=False,
                    malicious=record.malicious,
                    latency_ms=latency_ms,
                    provider_queried=provider_queried,
                )
            except Exception as exc:
                logger.warning(f"Failed recording metrics for '{record.indicator}': {exc}")

        # 9. Return structured response
        return ThreatCheckResponse(
            original_indicator=parsed.raw,
            normalized_indicator=record.indicator,
            indicator_type=record.indicator_type,
            malicious=record.malicious,
            threat_score=record.threat_score,
            confidence=record.confidence,
            categories=record.categories,
            source=record.source,
            is_trusted_domain=record.is_trusted_domain,
            trusted_domain=record.is_trusted_domain,
            cached=False,
            checked_at=record.checked_at,
            ttl_seconds=ttl,
        )

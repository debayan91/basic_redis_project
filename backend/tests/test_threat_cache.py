"""Tests for Redis Threat Intelligence Cache Service (Hashes, TTL, Key Generation)."""

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from redis.asyncio import Redis

from app.core.config import Settings
from app.schemas.threat_cache import CachedThreatRecord, generate_cache_key
from app.services.indicator import IndicatorType
from app.services.threat_cache import ThreatCacheService


class TestCacheKeyGeneration:
    def test_ip_key_generation(self) -> None:
        key = generate_cache_key(IndicatorType.IP, "198.51.100.1")
        assert key == "ti:ip:198.51.100.1"

    def test_domain_key_generation(self) -> None:
        key = generate_cache_key(IndicatorType.DOMAIN, "threat-actor.org")
        assert key == "ti:domain:threat-actor.org"

        # Trailing dots and casing normalized in key
        key_upper = generate_cache_key(IndicatorType.DOMAIN, "THREAT-ACTOR.ORG.")
        assert key_upper == "ti:domain:threat-actor.org"

    def test_url_key_generation_uses_sha256(self) -> None:
        url = "https://evil-portal.xyz/login.php?user=admin"
        expected_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()
        key = generate_cache_key(IndicatorType.URL, url)
        assert key == f"ti:url:{expected_hash}"
        assert len(expected_hash) == 64

    def test_different_urls_produce_distinct_keys(self) -> None:
        url_a = "https://example.com/malware.exe"
        url_b = "https://example.com/payload.bin"
        url_c = "https://example.com/malware.exe?variant=2"

        key_a = generate_cache_key(IndicatorType.URL, url_a)
        key_b = generate_cache_key(IndicatorType.URL, url_b)
        key_c = generate_cache_key(IndicatorType.URL, url_c)

        assert key_a != key_b
        assert key_a != key_c
        assert key_b != key_c

        # Identical URL must produce identical key
        assert generate_cache_key(IndicatorType.URL, url_a) == key_a

    def test_unsupported_indicator_type_raises_error(self) -> None:
        with pytest.raises(ValueError):
            generate_cache_key("unsupported_type", "value")


class TestSerializationDeserialization:
    def test_record_hash_roundtrip(self) -> None:
        now = datetime.now(UTC)
        first_seen = now - timedelta(days=7)
        last_seen = now - timedelta(hours=1)

        original = CachedThreatRecord(
            indicator="198.51.100.25",
            indicator_type=IndicatorType.IP,
            malicious=True,
            threat_score=95,
            confidence=0.98,
            categories=["c2", "ransomware"],
            source="threat_feed_alpha",
            first_seen=first_seen,
            last_seen=last_seen,
            checked_at=now,
        )

        hash_dict = original.to_hash_dict()

        # All Hash values must be strings for Redis storage
        for k, v in hash_dict.items():
            assert isinstance(v, str), f"Field '{k}' must be str for Redis Hash, got {type(v)}"

        assert hash_dict["malicious"] == "true"
        assert hash_dict["threat_score"] == "95"
        assert hash_dict["confidence"] == "0.98"

        reconstructed = CachedThreatRecord.from_hash_dict(hash_dict, ttl_seconds=3599)
        assert reconstructed.indicator == original.indicator
        assert reconstructed.indicator_type == original.indicator_type
        assert reconstructed.malicious is True
        assert reconstructed.threat_score == 95
        assert reconstructed.confidence == 0.98
        assert reconstructed.categories == ["c2", "ransomware"]
        assert reconstructed.source == "threat_feed_alpha"
        assert reconstructed.first_seen == first_seen
        assert reconstructed.last_seen == last_seen
        assert reconstructed.ttl_seconds == 3599

    def test_deserialization_with_optional_and_empty_fields(self) -> None:
        hash_dict = {
            "indicator": "safe-domain.org",
            "indicator_type": "domain",
            "malicious": "false",
            "threat_score": "0",
            "confidence": "1.0",
            "categories": "[]",
            "source": "whitelist",
            "first_seen": "",
            "last_seen": "",
            "checked_at": datetime.now(UTC).isoformat(),
        }

        record = CachedThreatRecord.from_hash_dict(hash_dict)
        assert record.indicator == "safe-domain.org"
        assert record.malicious is False
        assert record.threat_score == 0
        assert record.first_seen is None
        assert record.last_seen is None
        assert record.categories == []


class TestThreatCacheServiceIntegration:
    @pytest.mark.asyncio
    async def test_cache_miss_returns_none(
        self, redis_test_client: Redis, settings: Settings
    ) -> None:
        service = ThreatCacheService(redis_test_client, settings)
        non_existent_ip = "192.0.2.222"

        # Ensure not in cache
        await service.delete(IndicatorType.IP, non_existent_ip)

        cached = await service.get(IndicatorType.IP, non_existent_ip)
        assert cached is None

    @pytest.mark.asyncio
    async def test_cache_set_and_hit(
        self, redis_test_client: Redis, settings: Settings
    ) -> None:
        service = ThreatCacheService(redis_test_client, settings)
        indicator = "203.0.113.88"

        record = CachedThreatRecord(
            indicator=indicator,
            indicator_type=IndicatorType.IP,
            malicious=True,
            threat_score=85,
            confidence=0.92,
            categories=["ssh_bruteforce"],
            source="integration_test",
        )

        # Set in cache with 60 second TTL
        await service.set(record, ttl_seconds=60)

        # Retrieve (Cache Hit)
        cached = await service.get(IndicatorType.IP, indicator)
        assert cached is not None
        assert cached.indicator == indicator
        assert cached.malicious is True
        assert cached.threat_score == 85
        assert cached.categories == ["ssh_bruteforce"]
        assert cached.ttl_seconds is not None
        assert 0 < cached.ttl_seconds <= 60

        # Verify underlying Redis key type is 'hash'
        key = generate_cache_key(IndicatorType.IP, indicator)
        key_type = await redis_test_client.type(key)
        assert key_type == "hash"

        # Clean up
        deleted = await service.delete(IndicatorType.IP, indicator)
        assert deleted is True

        # Verify miss after deletion
        assert await service.get(IndicatorType.IP, indicator) is None

    @pytest.mark.asyncio
    async def test_cache_expiration(
        self, redis_test_client: Redis, settings: Settings
    ) -> None:
        service = ThreatCacheService(redis_test_client, settings)
        indicator = "https://temp-phish.xyz/landing"

        record = CachedThreatRecord(
            indicator=indicator,
            indicator_type=IndicatorType.URL,
            malicious=True,
            threat_score=90,
            confidence=0.95,
            categories=["phishing"],
            source="integration_test",
        )

        # Set short TTL of 1 second
        await service.set(record, ttl_seconds=1)

        # Immediate check: must exist with remaining TTL
        initial_ttl = await service.get_ttl(IndicatorType.URL, indicator)
        assert 0 < initial_ttl <= 1

        # Wait for TTL expiration
        await asyncio.sleep(1.2)

        # After expiration: get must return None (cache miss)
        cached_after_expire = await service.get(IndicatorType.URL, indicator)
        assert cached_after_expire is None

        # TTL must return -2 (key does not exist)
        expired_ttl = await service.get_ttl(IndicatorType.URL, indicator)
        assert expired_ttl == -2

    @pytest.mark.asyncio
    async def test_configurable_ttl_from_settings(
        self, redis_test_client: Redis, settings: Settings
    ) -> None:
        service = ThreatCacheService(redis_test_client, settings)

        malicious_record = CachedThreatRecord(
            indicator="evil.com",
            indicator_type=IndicatorType.DOMAIN,
            malicious=True,
            threat_score=90,
        )
        assert service.determine_ttl(malicious_record) == settings.CACHE_TTL_MALICIOUS

        benign_record = CachedThreatRecord(
            indicator="safe.com",
            indicator_type=IndicatorType.DOMAIN,
            malicious=False,
            threat_score=0,
        )
        assert service.determine_ttl(benign_record) == settings.CACHE_TTL_BENIGN

        suspicious_record = CachedThreatRecord(
            indicator="suspect.com",
            indicator_type=IndicatorType.DOMAIN,
            malicious=False,
            threat_score=65,
        )
        assert service.determine_ttl(suspicious_record) == settings.CACHE_TTL_SUSPICIOUS

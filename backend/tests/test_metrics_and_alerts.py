"""Unit and integration tests for Stage 9: Operational Metrics, GET /api/stats, and WebSocket alerts."""

import asyncio

import pytest
from httpx import AsyncClient
from redis.asyncio import Redis

from app.schemas.indicator import IndicatorType
from app.services.alerts import AlertService
from app.services.metrics import MetricsService


class TestMetricsService:
    """Tests verifying MetricsService atomic counters and latency calculations."""

    @pytest.mark.asyncio
    async def test_metrics_counters_and_latency(self, redis_test_client: Redis) -> None:
        metrics = MetricsService(redis_test_client)
        await metrics.reset()

        # Record lookups
        await metrics.record_lookup(cached=False, malicious=False, latency_ms=10.0, provider_queried=True)
        await metrics.record_lookup(cached=True, malicious=True, latency_ms=2.0, provider_queried=False)
        await metrics.record_lookup(cached=True, malicious=False, latency_ms=3.0, provider_queried=False)
        await metrics.record_error()

        stats = await metrics.get_stats()
        assert stats["total_lookups"] == 3
        assert stats["cache_hits"] == 2
        assert stats["cache_misses"] == 1
        assert stats["cache_hit_rate"] == 66.67
        assert stats["provider_lookups"] == 1
        assert stats["malicious_detections"] == 1
        assert stats["error_count"] == 1

        lat = stats["latency_stats"]
        assert lat["sample_count"] == 3
        assert lat["min_ms"] == 2.0
        assert lat["max_ms"] == 10.0
        assert lat["avg_ms"] == 5.0
        assert lat["p50_ms"] == 3.0


class TestStatsAPI:
    """Integration test for GET /api/stats."""

    @pytest.mark.asyncio
    async def test_get_stats_endpoint(self, async_client: AsyncClient, redis_test_client: Redis) -> None:
        # Perform lookups to generate metrics
        await async_client.post("/api/check", json={"indicator": "google.com"})
        await async_client.post("/api/check", json={"indicator": "google.com"})

        response = await async_client.get("/api/stats")
        assert response.status_code == 200

        data = response.json()
        assert "total_lookups" in data
        assert data["total_lookups"] >= 2
        assert "cache_hits" in data
        assert "cache_misses" in data
        assert "cache_hit_rate" in data
        assert "latency_stats" in data
        assert "p50_ms" in data["latency_stats"]
        assert "p95_ms" in data["latency_stats"]


class TestPubSubAlertsAndWebSocket:
    """Tests verifying Redis Pub/Sub alert emission and WebSocket streaming."""

    @pytest.mark.asyncio
    async def test_alert_publishing_and_subscription(self, redis_test_client: Redis) -> None:
        alerts = AlertService(redis_test_client)

        received_alerts: list[dict] = []

        async def listen_task() -> None:
            async for alert in alerts.subscribe_alerts():
                received_alerts.append(alert)
                break

        task = asyncio.create_task(listen_task())
        await asyncio.sleep(0.1)  # Allow subscription to establish

        # Publish high-risk alert
        subscribers = await alerts.publish_alert(
            indicator="198.51.100.99",
            indicator_type=IndicatorType.IP,
            threat_score=95,
            confidence=0.99,
            source="test_feed",
            categories=["ransomware_c2"],
        )

        await asyncio.wait_for(task, timeout=2.0)
        assert len(received_alerts) == 1
        ev = received_alerts[0]
        assert ev["indicator"] == "198.51.100.99"
        assert ev["threat_score"] == 95
        assert ev["source"] == "test_feed"
        assert "ransomware_c2" in ev["categories"]
        assert "timestamp" in ev

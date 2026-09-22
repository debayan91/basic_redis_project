"""Unit and integration tests for Stage 8: Redis Blacklists, Counters, and Threat Rankings."""

import pytest
from httpx import AsyncClient
from redis.asyncio import Redis

from app.schemas.indicator import IndicatorType
from app.services.blacklist import BlacklistService
from app.services.ranking import RankingService


class TestBlacklistService:
    """Tests verifying BlacklistService Redis Sets."""

    @pytest.mark.asyncio
    async def test_blacklist_crud_operations(self, redis_test_client: Redis) -> None:
        service = BlacklistService(redis_test_client)

        # 1. Add indicators
        assert await service.add(IndicatorType.IP, "198.51.100.100") is True
        # Idempotent re-add returns False
        assert await service.add(IndicatorType.IP, "198.51.100.100") is False

        assert await service.add(IndicatorType.DOMAIN, "malicious-phish.com") is True
        assert await service.add(IndicatorType.URL, "https://evil.org/malware.exe") is True

        # 2. Membership check
        assert await service.is_blacklisted(IndicatorType.IP, "198.51.100.100") is True
        assert await service.is_blacklisted(IndicatorType.IP, "198.51.100.101") is False
        assert await service.is_blacklisted(IndicatorType.DOMAIN, "malicious-phish.com") is True
        assert await service.is_blacklisted(IndicatorType.URL, "https://evil.org/malware.exe") is True

        # 3. Counts
        assert await service.count(IndicatorType.IP) == 1
        assert await service.count(IndicatorType.DOMAIN) == 1
        assert await service.count() == 3

        # 4. Listing
        ip_list = await service.list_all(IndicatorType.IP)
        assert ip_list == ["198.51.100.100"]

        all_items = await service.list_all()
        assert len(all_items) == 3

        # 5. Removal
        assert await service.remove(IndicatorType.IP, "198.51.100.100") is True
        assert await service.is_blacklisted(IndicatorType.IP, "198.51.100.100") is False
        assert await service.remove(IndicatorType.IP, "198.51.100.100") is False


class TestRankingService:
    """Tests verifying RankingService Redis Sorted Sets."""

    @pytest.mark.asyncio
    async def test_ranking_operations(self, redis_test_client: Redis) -> None:
        ranking = RankingService(redis_test_client)
        await ranking.reset()

        # Increment threats
        score1 = await ranking.increment_threat("bad-domain.com", 10.0)
        assert score1 == 10.0

        await ranking.increment_threat("super-bad.org", 50.0)
        await ranking.increment_threat("bad-domain.com", 5.0)  # total 15.0
        await ranking.increment_threat("low-risk.net", 2.0)

        # Top threats
        top = await ranking.get_top_threats(limit=2)
        assert len(top) == 2
        assert top[0]["indicator"] == "super-bad.org"
        assert top[0]["score"] == 50.0
        assert top[0]["rank"] == 1
        assert top[1]["indicator"] == "bad-domain.com"
        assert top[1]["score"] == 15.0
        assert top[1]["rank"] == 2

        # Specific indicator checks
        assert await ranking.get_indicator_score("super-bad.org") == 50.0
        assert await ranking.get_indicator_rank("super-bad.org") == 1
        assert await ranking.get_indicator_rank("bad-domain.com") == 2
        assert await ranking.get_indicator_rank("unknown.com") is None


class TestBlacklistAPI:
    """Integration tests for /api/blacklist administrative routes."""

    @pytest.mark.asyncio
    async def test_blacklist_api_flow(self, async_client: AsyncClient, redis_test_client: Redis) -> None:
        indicator = "192.0.2.200"

        # 1. Add to blacklist
        add_resp = await async_client.post(
            "/api/blacklist",
            json={"indicator": indicator, "reason": "Confirmed Ransomware C2"},
        )
        assert add_resp.status_code == 201
        add_data = add_resp.json()
        assert add_data["blacklisted"] is True
        assert add_data["indicator"] == indicator

        # 2. Check that lookup immediately reports blacklisted verdict with threat_score=100
        lookup_resp = await async_client.post("/api/check", json={"indicator": indicator})
        assert lookup_resp.status_code == 200
        lookup_data = lookup_resp.json()
        assert lookup_data["malicious"] is True
        assert lookup_data["threat_score"] == 100
        assert lookup_data["source"] == "redis_blacklist"

        # 3. List blacklist
        list_resp = await async_client.get("/api/blacklist")
        assert list_resp.status_code == 200
        assert indicator in list_resp.json()["items"]

        # 4. Remove from blacklist
        del_resp = await async_client.delete(f"/api/blacklist/{indicator}")
        assert del_resp.status_code == 200
        assert del_resp.json()["blacklisted"] is False

        # 5. Ensure removed from listing
        list_resp2 = await async_client.get("/api/blacklist")
        assert indicator not in list_resp2.json()["items"]

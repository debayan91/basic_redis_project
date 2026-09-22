"""API v1 routers."""

from fastapi import APIRouter

from app.api.v1.blacklist import router as blacklist_router
from app.api.v1.check import router as check_router
from app.api.v1.health import router as health_router
from app.api.v1.refresh import router as refresh_router
from app.api.v1.stats import router as stats_router
from app.api.v1.websocket import router as ws_router

api_v1_router = APIRouter()
api_v1_router.include_router(health_router)
api_v1_router.include_router(check_router)
api_v1_router.include_router(blacklist_router)
api_v1_router.include_router(stats_router)
api_v1_router.include_router(refresh_router)
api_v1_router.include_router(ws_router)

__all__ = [
    "api_v1_router",
    "blacklist_router",
    "check_router",
    "health_router",
    "refresh_router",
    "stats_router",
    "ws_router",
]

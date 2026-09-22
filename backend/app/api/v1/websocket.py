"""WebSocket endpoint for real-time threat detection alerts streaming."""

import asyncio
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.config import get_settings
from app.services.alerts import AlertService
from app.services.redis import get_redis_client

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Real-Time Alerts WebSocket"])


@router.websocket("/ws/alerts")
async def websocket_alerts_endpoint(websocket: WebSocket) -> None:
    """Stream real-time high-risk threat alerts to connected clients."""
    await websocket.accept()
    logger.info("WebSocket client connected to real-time alerts stream")

    settings = get_settings()
    redis = get_redis_client()
    alert_service = AlertService(redis, settings=settings)

    try:
        async for alert in alert_service.subscribe_alerts():
            await websocket.send_json(alert)
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected from alerts stream")
    except asyncio.CancelledError:
        logger.info("WebSocket alerts stream task cancelled")
    except Exception as exc:
        logger.error(f"Unexpected error in alerts WebSocket stream: {exc}")
    finally:
        try:
            await websocket.close()
        except Exception:
            pass

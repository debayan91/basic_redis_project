"""Pydantic schemas for service health and diagnostic endpoints."""

from datetime import UTC, datetime

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str = Field(..., description="Overall service status ('healthy', 'degraded', 'unhealthy')")
    postgres: str = Field(..., description="PostgreSQL connection status ('connected', 'disconnected')")
    redis: str = Field(..., description="Redis connection status ('connected', 'disconnected')")
    version: str = Field(..., description="Application version")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Health check timestamp in UTC",
    )

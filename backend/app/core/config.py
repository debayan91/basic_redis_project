from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    PROJECT_NAME: str = "Real-Time Threat Intelligence Cache"
    VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    LOG_LEVEL: str = "INFO"

    # API Server
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    API_PREFIX: str = "/api/v1"

    # PostgreSQL
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "threat_intel_db"
    POSTGRES_USER: str = "threat_user"
    POSTGRES_PASSWORD: str = "threat_password"
    POSTGRES_POOL_SIZE: int = 10
    POSTGRES_MAX_OVERFLOW: int = 20

    # Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_PASSWORD: str | None = None
    REDIS_MAX_CONNECTIONS: int = 20
    REDIS_SOCKET_TIMEOUT: float = 2.0

    # Cache TTL Configuration (seconds)
    CACHE_DEFAULT_TTL: int = 3600        # Default 1 hour
    CACHE_TTL_MALICIOUS: int = 86400    # 24 hours
    CACHE_TTL_SUSPICIOUS: int = 14400   # 4 hours
    CACHE_TTL_BENIGN: int = 3600        # 1 hour
    CACHE_TTL_UNKNOWN: int = 600        # 10 minutes

    # Threat Intelligence Provider Configuration
    CTI_PROVIDER: str = "local"         # "local" | "virustotal" | "mock" | "composite"
    VIRUSTOTAL_API_KEY: str | None = None
    VIRUSTOTAL_BASE_URL: str = "https://www.virustotal.com/api/v3"
    EXTERNAL_CTI_TIMEOUT: float = 3.0   # seconds
    EXTERNAL_CTI_MAX_RETRIES: int = 2

    # Operational Alerts & Security Policies
    ALERT_THRESHOLD: int = 70           # Threat score >= 70 publishes real-time alert event
    ENABLE_AUTO_BLACKLIST: bool = False # Whether severe threats are automatically blacklisted
    AUTO_BLACKLIST_THRESHOLD: int = 90  # Threat score >= 90 automatically blacklists indicator if enabled
    REDIS_PUBSUB_CHANNEL: str = "malicious_indicator_detected"


    @property
    def async_database_url(self) -> str:
        """PostgreSQL asyncpg URL for SQLAlchemy 2.x async engine."""
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def sync_database_url(self) -> str:
        """PostgreSQL sync URL (for Alembic migrations)."""
        return (
            f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def redis_url(self) -> str:
        """Redis connection URL."""
        auth = f":{self.REDIS_PASSWORD}@" if self.REDIS_PASSWORD else ""
        return f"redis://{auth}{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"


@lru_cache
def get_settings() -> Settings:
    """Return a cached singleton instance of application settings."""
    return Settings()

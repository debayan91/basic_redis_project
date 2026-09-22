"""Custom exceptions for threat intelligence operations and validation."""


class ThreatIntelException(Exception):
    """Base exception for all application errors."""

    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class InvalidIndicatorError(ThreatIntelException):
    """Raised when an indicator is malformed or fails validation."""


class UnsupportedIndicatorTypeError(ThreatIntelException):
    """Raised when an indicator type is unsupported."""


class ProviderError(ThreatIntelException):
    """Base exception for threat intelligence provider failures."""


class ProviderTimeoutError(ProviderError):
    """Raised when an external threat intelligence provider times out."""


class ProviderRateLimitError(ProviderError):
    """Raised when an external threat intelligence provider returns HTTP 429 Rate Limit."""


class ProviderUnavailableError(ProviderError):
    """Raised when an external threat intelligence provider is unreachable or down."""


class DatabaseUnavailableError(ThreatIntelException):
    """Raised when PostgreSQL database connectivity fails during critical path."""


class RedisUnavailableError(ThreatIntelException):
    """Raised when Redis operational cache/storage is unreachable."""


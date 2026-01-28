"""
ZoneWise Lobster - Custom Exceptions

Centralized exception definitions for consistent error handling
across all components. Each exception includes:
- Descriptive message
- Relevant context attributes
- Suggested retry behavior

Author: BidDeed.AI
Version: 1.0.0
"""

from __future__ import annotations
from typing import Optional, Dict, Any


class ZoneWiseLobsterError(Exception):
    """
    Base exception for all ZoneWise Lobster errors.
    
    All custom exceptions inherit from this class to enable
    catching all ZoneWise-specific errors with a single handler.
    
    Attributes:
        message: Human-readable error description
        details: Additional context about the error
        retryable: Whether the operation can be retried
    """
    
    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        retryable: bool = False
    ) -> None:
        """
        Initialize base exception.
        
        Args:
            message: Human-readable error description
            details: Additional context dictionary
            retryable: Whether operation can be retried
        """
        super().__init__(message)
        self.message: str = message
        self.details: Dict[str, Any] = details or {}
        self.retryable: bool = retryable
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert exception to dictionary for logging/serialization.
        
        Returns:
            Dictionary with error details
        """
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "details": self.details,
            "retryable": self.retryable,
        }


# =============================================================================
# INPUT VALIDATION EXCEPTIONS
# =============================================================================

class ValidationError(ZoneWiseLobsterError):
    """
    Raised when input validation fails.
    
    Attributes:
        field: Name of the field that failed validation
        value: The invalid value (truncated for security)
        reason: Specific reason for validation failure
    """
    
    def __init__(
        self,
        message: str,
        field: str,
        value: Any = None,
        reason: str = ""
    ) -> None:
        """
        Initialize validation error.
        
        Args:
            message: Error description
            field: Field that failed validation
            value: Invalid value (will be truncated)
            reason: Specific validation failure reason
        """
        # Truncate value for security
        safe_value = str(value)[:50] if value else None
        
        super().__init__(
            message=message,
            details={
                "field": field,
                "value": safe_value,
                "reason": reason,
            },
            retryable=False
        )
        self.field: str = field
        self.value: Any = safe_value
        self.reason: str = reason


class InvalidFIPSError(ValidationError):
    """Raised when a FIPS code is invalid."""
    
    def __init__(self, fips: str, reason: str = "Invalid format") -> None:
        super().__init__(
            message=f"Invalid FIPS code: {fips[:10]}",
            field="fips",
            value=fips,
            reason=reason
        )


class InvalidCountyNameError(ValidationError):
    """Raised when a county name is invalid."""
    
    def __init__(self, name: str, reason: str = "Invalid characters") -> None:
        super().__init__(
            message=f"Invalid county name: {name[:20]}",
            field="county_name",
            value=name,
            reason=reason
        )


class InvalidURLError(ValidationError):
    """Raised when a URL fails validation."""
    
    def __init__(self, url: str, reason: str = "Not in whitelist") -> None:
        super().__init__(
            message=f"Invalid URL: {url[:50]}",
            field="url",
            value=url,
            reason=reason
        )


# =============================================================================
# RATE LIMITING EXCEPTIONS
# =============================================================================

class RateLimitError(ZoneWiseLobsterError):
    """
    Base class for rate limiting errors.
    
    Attributes:
        domain: The domain that was rate limited
        retry_after: Suggested seconds to wait before retrying
    """
    
    def __init__(
        self,
        message: str,
        domain: str,
        retry_after: int = 60
    ) -> None:
        """
        Initialize rate limit error.
        
        Args:
            message: Error description
            domain: Rate limited domain
            retry_after: Seconds to wait
        """
        super().__init__(
            message=message,
            details={
                "domain": domain,
                "retry_after": retry_after,
            },
            retryable=True
        )
        self.domain: str = domain
        self.retry_after: int = retry_after


class BurstLimitExceededError(RateLimitError):
    """Raised when burst rate limit is exceeded."""
    
    def __init__(self, domain: str, cooldown: int = 60) -> None:
        super().__init__(
            message=f"Burst limit exceeded for {domain}",
            domain=domain,
            retry_after=cooldown
        )


class HourlyLimitExceededError(RateLimitError):
    """Raised when hourly rate limit is exceeded."""
    
    def __init__(self, domain: str, limit: int) -> None:
        super().__init__(
            message=f"Hourly limit ({limit}/hr) exceeded for {domain}",
            domain=domain,
            retry_after=3600  # 1 hour
        )


class DailyLimitExceededError(RateLimitError):
    """Raised when daily rate limit is exceeded."""
    
    def __init__(self, domain: str, limit: int) -> None:
        super().__init__(
            message=f"Daily limit ({limit}/day) exceeded for {domain}",
            domain=domain,
            retry_after=86400  # 24 hours
        )


# =============================================================================
# CREDENTIAL EXCEPTIONS
# =============================================================================

class CredentialError(ZoneWiseLobsterError):
    """
    Base class for credential-related errors.
    
    Attributes:
        credential_type: Type of credential that failed
    """
    
    def __init__(
        self,
        message: str,
        credential_type: str,
        retryable: bool = False
    ) -> None:
        """
        Initialize credential error.
        
        Args:
            message: Error description
            credential_type: Type of credential
            retryable: Whether operation can be retried
        """
        super().__init__(
            message=message,
            details={"credential_type": credential_type},
            retryable=retryable
        )
        self.credential_type: str = credential_type


class InvalidCredentialError(CredentialError):
    """Raised when a credential is invalid or malformed."""
    
    def __init__(self, credential_type: str, reason: str = "") -> None:
        super().__init__(
            message=f"Invalid {credential_type} credential: {reason}",
            credential_type=credential_type,
            retryable=False
        )


class ExpiredCredentialError(CredentialError):
    """Raised when a credential has expired."""
    
    def __init__(self, credential_type: str) -> None:
        super().__init__(
            message=f"{credential_type} credential has expired",
            credential_type=credential_type,
            retryable=True  # Can retry after rotation
        )


class CredentialRotationError(CredentialError):
    """Raised when credential rotation fails."""
    
    def __init__(self, credential_type: str, reason: str = "") -> None:
        super().__init__(
            message=f"Failed to rotate {credential_type}: {reason}",
            credential_type=credential_type,
            retryable=True
        )


# =============================================================================
# SCRAPING EXCEPTIONS
# =============================================================================

class ScrapeError(ZoneWiseLobsterError):
    """
    Base class for scraping errors.
    
    Attributes:
        url: URL that failed to scrape
        status_code: HTTP status code if applicable
    """
    
    def __init__(
        self,
        message: str,
        url: str,
        status_code: Optional[int] = None,
        retryable: bool = True
    ) -> None:
        """
        Initialize scrape error.
        
        Args:
            message: Error description
            url: Failed URL
            status_code: HTTP status code
            retryable: Whether operation can be retried
        """
        super().__init__(
            message=message,
            details={
                "url": url[:100],
                "status_code": status_code,
            },
            retryable=retryable
        )
        self.url: str = url
        self.status_code: Optional[int] = status_code


class ScrapeTimeoutError(ScrapeError):
    """Raised when scraping times out."""
    
    def __init__(self, url: str, timeout: int) -> None:
        super().__init__(
            message=f"Scrape timeout after {timeout}s",
            url=url,
            retryable=True
        )


class ScrapeHTTPError(ScrapeError):
    """Raised for HTTP errors during scraping."""
    
    def __init__(self, url: str, status_code: int) -> None:
        # 4xx errors are usually not retryable, 5xx are
        retryable = status_code >= 500
        super().__init__(
            message=f"HTTP {status_code} from {url[:50]}",
            url=url,
            status_code=status_code,
            retryable=retryable
        )


class ScrapeParseError(ScrapeError):
    """Raised when parsing scraped content fails."""
    
    def __init__(self, url: str, reason: str = "") -> None:
        super().__init__(
            message=f"Failed to parse content: {reason}",
            url=url,
            retryable=False  # Parsing errors won't fix on retry
        )


# =============================================================================
# AUDIT EXCEPTIONS
# =============================================================================

class AuditError(ZoneWiseLobsterError):
    """
    Base class for audit logging errors.
    
    Note: Audit errors should not block operations, they should
    be logged separately and operations should continue.
    """
    
    def __init__(self, message: str, event_id: Optional[str] = None) -> None:
        super().__init__(
            message=message,
            details={"event_id": event_id},
            retryable=True
        )


class AuditPersistenceError(AuditError):
    """Raised when audit log fails to persist to database."""
    
    def __init__(self, event_id: str, reason: str = "") -> None:
        super().__init__(
            message=f"Failed to persist audit log: {reason}",
            event_id=event_id
        )


# =============================================================================
# MONITORING EXCEPTIONS
# =============================================================================

class MonitoringError(ZoneWiseLobsterError):
    """Base class for monitoring errors."""
    pass


class MetricsPersistenceError(MonitoringError):
    """Raised when metrics fail to persist."""
    
    def __init__(self, metric_name: str, reason: str = "") -> None:
        super().__init__(
            message=f"Failed to persist metric {metric_name}: {reason}",
            details={"metric_name": metric_name},
            retryable=True
        )


class AlertNotificationError(MonitoringError):
    """Raised when alert notification fails."""
    
    def __init__(self, alert_name: str, reason: str = "") -> None:
        super().__init__(
            message=f"Failed to send alert {alert_name}: {reason}",
            details={"alert_name": alert_name},
            retryable=True
        )

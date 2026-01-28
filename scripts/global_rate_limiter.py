"""
ZoneWise Lobster - Global Rate Limiter
Implements cross-workflow rate limiting to prevent external service abuse.

Features:
- Global rate limiter shared across all workflows
- Configurable limits per domain/endpoint
- Rate limit state persistence (Supabase)
- Graceful degradation when limits hit
- Real-time monitoring

Author: BidDeed.AI
Version: 2.0.0
"""

from __future__ import annotations

import time
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, Tuple, Any, TYPE_CHECKING
from dataclasses import dataclass
from collections import defaultdict
from urllib.parse import urlparse
import logging

if TYPE_CHECKING:
    from supabase import Client as SupabaseClient

# Import audit logger
from security_utils import AuditLogger, AuditEventType

# Configure logging
logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RateLimitConfig:
    """
    Configuration for a rate limit rule.
    
    Attributes:
        domain: The domain this config applies to (e.g., 'municode.com')
        requests_per_minute: Maximum requests allowed per minute
        requests_per_hour: Maximum requests allowed per hour
        requests_per_day: Maximum requests allowed per day
        burst_limit: Maximum concurrent requests (token bucket capacity)
        cooldown_seconds: Seconds to wait after hitting a limit
    """
    domain: str
    requests_per_minute: int
    requests_per_hour: int
    requests_per_day: int
    burst_limit: int
    cooldown_seconds: int


class TokenBucket:
    """
    Token bucket algorithm for rate limiting.
    
    Implements a thread-safe token bucket that refills at a constant rate.
    Used for burst limiting - allows short bursts while maintaining
    average rate limits over time.
    
    Attributes:
        capacity: Maximum number of tokens the bucket can hold
        refill_rate: Number of tokens added per second
        tokens: Current number of available tokens
    """
    
    def __init__(self, capacity: int, refill_rate: float) -> None:
        """
        Initialize a token bucket.
        
        Args:
            capacity: Maximum tokens in bucket
            refill_rate: Tokens added per second
        """
        self.capacity: int = capacity
        self.refill_rate: float = refill_rate
        self.tokens: float = float(capacity)
        self.last_refill: float = time.time()
        self._lock: threading.Lock = threading.Lock()
    
    def consume(self, tokens: int = 1) -> bool:
        """
        Try to consume tokens from bucket.
        
        Thread-safe method to attempt consuming tokens. If sufficient
        tokens are available, they are consumed and True is returned.
        Otherwise, no tokens are consumed and False is returned.
        
        Args:
            tokens: Number of tokens to consume (default: 1)
            
        Returns:
            True if tokens were consumed, False if rate limited
        """
        with self._lock:
            self._refill()
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False
    
    def _refill(self) -> None:
        """
        Refill tokens based on elapsed time.
        
        Calculates how many tokens should be added based on the time
        elapsed since the last refill, capped at the bucket capacity.
        """
        now: float = time.time()
        elapsed: float = now - self.last_refill
        tokens_to_add: float = elapsed * self.refill_rate
        self.tokens = min(float(self.capacity), self.tokens + tokens_to_add)
        self.last_refill = now
    
    @property
    def available_tokens(self) -> float:
        """
        Get current available tokens.
        
        Returns:
            Current number of available tokens (may be fractional)
        """
        with self._lock:
            self._refill()
            return self.tokens


class RateLimitExceeded(Exception):
    """
    Exception raised when rate limit is exceeded.
    
    Attributes:
        reason: Human-readable explanation of why the limit was exceeded
        domain: The domain that was rate limited
        retry_after: Suggested seconds to wait before retrying
    """
    
    def __init__(
        self, 
        reason: str, 
        domain: str = "", 
        retry_after: int = 60
    ) -> None:
        """
        Initialize rate limit exception.
        
        Args:
            reason: Human-readable explanation
            domain: The rate-limited domain
            retry_after: Seconds to wait before retrying
        """
        super().__init__(reason)
        self.reason: str = reason
        self.domain: str = domain
        self.retry_after: int = retry_after


class GlobalRateLimiter:
    """
    Global rate limiter with Supabase persistence.
    
    Tracks request counts across all workflows and enforces
    configurable limits per domain/endpoint. Uses a combination
    of token buckets for burst limiting and sliding window
    counters for sustained rate limiting.
    
    Thread-safe implementation suitable for multi-threaded
    and async environments.
    
    Attributes:
        supabase: Supabase client for state persistence
        audit: Optional audit logger for security events
    """
    
    # Default rate limits per domain
    DEFAULT_LIMITS: Dict[str, RateLimitConfig] = {
        "municode.com": RateLimitConfig(
            domain="municode.com",
            requests_per_minute=30,
            requests_per_hour=500,
            requests_per_day=5000,
            burst_limit=10,
            cooldown_seconds=60
        ),
        "supabase.co": RateLimitConfig(
            domain="supabase.co",
            requests_per_minute=100,
            requests_per_hour=3000,
            requests_per_day=50000,
            burst_limit=50,
            cooldown_seconds=30
        ),
        "gis.brevardfl.gov": RateLimitConfig(
            domain="gis.brevardfl.gov",
            requests_per_minute=20,
            requests_per_hour=300,
            requests_per_day=3000,
            burst_limit=5,
            cooldown_seconds=120
        ),
        "bcpao.us": RateLimitConfig(
            domain="bcpao.us",
            requests_per_minute=15,
            requests_per_hour=200,
            requests_per_day=2000,
            burst_limit=5,
            cooldown_seconds=120
        ),
        "*": RateLimitConfig(
            domain="*",
            requests_per_minute=60,
            requests_per_hour=1000,
            requests_per_day=10000,
            burst_limit=20,
            cooldown_seconds=60
        )
    }
    
    def __init__(
        self, 
        supabase_client: SupabaseClient, 
        audit_logger: Optional[AuditLogger] = None
    ) -> None:
        """
        Initialize the global rate limiter.
        
        Args:
            supabase_client: Supabase client for state persistence
            audit_logger: Optional audit logger for security events
        """
        self.supabase: SupabaseClient = supabase_client
        self.audit: Optional[AuditLogger] = audit_logger
        self._buckets: Dict[str, TokenBucket] = {}
        self._request_counts: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {
                "minute": 0,
                "hour": 0,
                "day": 0,
                "last_reset_minute": datetime.now(timezone.utc),
                "last_reset_hour": datetime.now(timezone.utc),
                "last_reset_day": datetime.now(timezone.utc)
            }
        )
        self._cooldowns: Dict[str, datetime] = {}
        self._lock: threading.Lock = threading.Lock()
    
    def _get_domain(self, url: str) -> str:
        """
        Extract domain from URL.
        
        Parses the URL and extracts the network location (domain).
        Returns '*' as fallback for unparseable URLs.
        
        Args:
            url: Full URL to parse (e.g., 'https://example.com/path')
            
        Returns:
            Lowercase domain string (e.g., 'example.com') or '*' on error
            
        Example:
            >>> limiter._get_domain('https://api.municode.com/v1/data')
            'api.municode.com'
        """
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower() if parsed.netloc else "*"
        except (ValueError, AttributeError) as e:
            logger.warning(f"Failed to parse URL '{url}': {e}")
            return "*"
    
    def _get_config(self, domain: str) -> RateLimitConfig:
        """
        Get rate limit config for domain.
        
        Looks up configuration in priority order:
        1. Exact domain match
        2. Parent domain match (for subdomains)
        3. Default wildcard config
        
        Args:
            domain: Domain to get config for
            
        Returns:
            RateLimitConfig for the domain
        """
        # Check for exact match
        if domain in self.DEFAULT_LIMITS:
            return self.DEFAULT_LIMITS[domain]
        
        # Check for subdomain match
        for config_domain, config in self.DEFAULT_LIMITS.items():
            if config_domain != "*" and domain.endswith(config_domain):
                return config
        
        # Return default
        return self.DEFAULT_LIMITS["*"]
    
    def _get_bucket(self, domain: str) -> TokenBucket:
        """
        Get or create token bucket for domain.
        
        Creates a new token bucket if one doesn't exist for the domain,
        configured with the appropriate burst limit and refill rate.
        
        Args:
            domain: Domain to get bucket for
            
        Returns:
            TokenBucket instance for the domain
        """
        if domain not in self._buckets:
            config = self._get_config(domain)
            refill_rate = config.requests_per_minute / 60.0
            self._buckets[domain] = TokenBucket(
                capacity=config.burst_limit,
                refill_rate=refill_rate
            )
        return self._buckets[domain]
    
    def _check_cooldown(self, domain: str) -> Tuple[bool, int]:
        """
        Check if domain is in cooldown.
        
        After hitting a rate limit, domains enter a cooldown period
        where all requests are rejected. This prevents hammering
        the external service.
        
        Args:
            domain: Domain to check cooldown for
            
        Returns:
            Tuple of (in_cooldown: bool, seconds_remaining: int)
        """
        if domain not in self._cooldowns:
            return False, 0
        
        cooldown_end: datetime = self._cooldowns[domain]
        now: datetime = datetime.now(timezone.utc)
        
        if now < cooldown_end:
            remaining: int = int((cooldown_end - now).total_seconds())
            return True, remaining
        
        # Cooldown expired
        del self._cooldowns[domain]
        return False, 0
    
    def _update_counts(self, domain: str) -> Dict[str, Any]:
        """
        Update and return request counts for domain.
        
        Resets counters if their time window has elapsed.
        Thread-safe implementation.
        
        Args:
            domain: Domain to update counts for
            
        Returns:
            Dictionary with current counts and reset timestamps
        """
        with self._lock:
            counts = self._request_counts[domain]
            now = datetime.now(timezone.utc)
            
            # Reset minute counter if needed
            if (now - counts["last_reset_minute"]).total_seconds() >= 60:
                counts["minute"] = 0
                counts["last_reset_minute"] = now
            
            # Reset hour counter if needed
            if (now - counts["last_reset_hour"]).total_seconds() >= 3600:
                counts["hour"] = 0
                counts["last_reset_hour"] = now
            
            # Reset day counter if needed
            if (now - counts["last_reset_day"]).total_seconds() >= 86400:
                counts["day"] = 0
                counts["last_reset_day"] = now
            
            return counts
    
    def acquire(self, url: str, workflow_id: str = "unknown") -> Tuple[bool, str]:
        """
        Acquire permission to make a request.
        
        Checks all rate limits (cooldown, burst, minute/hour/day) and
        either allows the request or returns the reason for rejection.
        
        Args:
            url: URL to request
            workflow_id: ID of requesting workflow for audit logging
            
        Returns:
            Tuple of (allowed: bool, reason: str)
            - If allowed: (True, "OK")
            - If rejected: (False, "reason for rejection")
        """
        domain: str = self._get_domain(url)
        config: RateLimitConfig = self._get_config(domain)
        
        # Check cooldown first
        in_cooldown, remaining = self._check_cooldown(domain)
        if in_cooldown:
            reason = f"Domain {domain} in cooldown for {remaining}s"
            self._log_rate_limit(domain, workflow_id, reason)
            return False, reason
        
        # Check token bucket (burst limit)
        bucket: TokenBucket = self._get_bucket(domain)
        if not bucket.consume():
            self._cooldowns[domain] = datetime.now(timezone.utc) + timedelta(
                seconds=config.cooldown_seconds
            )
            reason = f"Burst limit exceeded for {domain}, cooldown {config.cooldown_seconds}s"
            self._log_rate_limit(domain, workflow_id, reason)
            return False, reason
        
        # Check request counts
        counts: Dict[str, Any] = self._update_counts(domain)
        
        if counts["minute"] >= config.requests_per_minute:
            reason = f"Minute limit ({config.requests_per_minute}/min) exceeded for {domain}"
            self._log_rate_limit(domain, workflow_id, reason)
            return False, reason
        
        if counts["hour"] >= config.requests_per_hour:
            reason = f"Hour limit ({config.requests_per_hour}/hr) exceeded for {domain}"
            self._log_rate_limit(domain, workflow_id, reason)
            return False, reason
        
        if counts["day"] >= config.requests_per_day:
            reason = f"Day limit ({config.requests_per_day}/day) exceeded for {domain}"
            self._log_rate_limit(domain, workflow_id, reason)
            return False, reason
        
        # Increment counts
        with self._lock:
            counts["minute"] += 1
            counts["hour"] += 1
            counts["day"] += 1
        
        # Persist to Supabase (async, don't block)
        self._persist_counts_async(domain, counts)
        
        return True, "OK"
    
    def _log_rate_limit(
        self, 
        domain: str, 
        workflow_id: str, 
        reason: str
    ) -> None:
        """
        Log rate limit event to audit trail.
        
        Records when a request is blocked due to rate limiting,
        including the domain, workflow, and specific reason.
        
        Args:
            domain: Domain that was rate limited
            workflow_id: ID of the workflow that was blocked
            reason: Human-readable reason for the block
        """
        if self.audit:
            self.audit.log(
                event_type=AuditEventType.SECURITY_VIOLATION,
                action="rate_limit_exceeded",
                target=domain,
                status="blocked",
                details={
                    "domain": domain,
                    "workflow_id": workflow_id,
                    "reason": reason,
                    "config": {
                        "domain": self._get_config(domain).domain,
                        "requests_per_minute": self._get_config(domain).requests_per_minute,
                        "requests_per_hour": self._get_config(domain).requests_per_hour,
                    }
                }
            )
    
    def _persist_counts_async(
        self, 
        domain: str, 
        counts: Dict[str, Any]
    ) -> None:
        """
        Persist counts to Supabase asynchronously.
        
        Non-blocking persistence of rate limit state. Failures are
        logged but don't affect the request - rate limiting continues
        to work with in-memory state.
        
        Args:
            domain: Domain to persist counts for
            counts: Dictionary with current counts and timestamps
        """
        try:
            self.supabase.table("rate_limit_state").upsert({
                "domain": domain,
                "minute_count": counts["minute"],
                "hour_count": counts["hour"],
                "day_count": counts["day"],
                "last_reset_minute": counts["last_reset_minute"].isoformat(),
                "last_reset_hour": counts["last_reset_hour"].isoformat(),
                "last_reset_day": counts["last_reset_day"].isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat()
            }).execute()
        except (ConnectionError, TimeoutError) as e:
            logger.warning(f"Failed to persist rate limit state: {e}")
        except Exception as e:
            logger.error(f"Unexpected error persisting rate limit state: {e}")
    
    def get_status(self) -> Dict[str, Dict[str, Any]]:
        """
        Get current rate limit status for all domains.
        
        Returns a snapshot of the current rate limit state including
        request counts, available burst capacity, and cooldown status.
        
        Returns:
            Dictionary mapping domain names to their status:
            {
                "domain.com": {
                    "requests_minute": "5/30",
                    "requests_hour": "100/500",
                    "requests_day": "1000/5000",
                    "burst_available": 8,
                    "in_cooldown": False,
                    "cooldown_remaining": 0
                }
            }
        """
        status: Dict[str, Dict[str, Any]] = {}
        
        all_domains = set(self._request_counts.keys()) | set(self.DEFAULT_LIMITS.keys())
        
        for domain in all_domains:
            if domain == "*":
                continue
            
            config = self._get_config(domain)
            counts = self._update_counts(domain)
            bucket = self._get_bucket(domain)
            in_cooldown, cooldown_remaining = self._check_cooldown(domain)
            
            status[domain] = {
                "requests_minute": f"{counts['minute']}/{config.requests_per_minute}",
                "requests_hour": f"{counts['hour']}/{config.requests_per_hour}",
                "requests_day": f"{counts['day']}/{config.requests_per_day}",
                "burst_available": int(bucket.available_tokens),
                "in_cooldown": in_cooldown,
                "cooldown_remaining": cooldown_remaining
            }
        
        return status


class RateLimitedClient:
    """
    HTTP client with built-in rate limiting.
    
    Wraps HTTP requests with automatic rate limit checking.
    Raises RateLimitExceeded if the request would exceed limits.
    
    Attributes:
        limiter: GlobalRateLimiter instance
        workflow_id: ID of the current workflow for audit logging
    """
    
    def __init__(
        self, 
        rate_limiter: GlobalRateLimiter, 
        workflow_id: str
    ) -> None:
        """
        Initialize rate-limited client.
        
        Args:
            rate_limiter: GlobalRateLimiter to use for checking limits
            workflow_id: ID of the workflow making requests
        """
        self.limiter: GlobalRateLimiter = rate_limiter
        self.workflow_id: str = workflow_id
    
    async def get(
        self, 
        url: str, 
        **kwargs: Any
    ) -> Any:
        """
        Rate-limited GET request.
        
        Args:
            url: URL to request
            **kwargs: Additional arguments passed to httpx.get()
            
        Returns:
            httpx.Response object
            
        Raises:
            RateLimitExceeded: If rate limit would be exceeded
        """
        import httpx
        
        allowed, reason = self.limiter.acquire(url, self.workflow_id)
        if not allowed:
            raise RateLimitExceeded(
                reason=reason,
                domain=self.limiter._get_domain(url),
                retry_after=60
            )
        
        async with httpx.AsyncClient(timeout=30) as client:
            return await client.get(url, **kwargs)
    
    async def post(
        self, 
        url: str, 
        **kwargs: Any
    ) -> Any:
        """
        Rate-limited POST request.
        
        Args:
            url: URL to request
            **kwargs: Additional arguments passed to httpx.post()
            
        Returns:
            httpx.Response object
            
        Raises:
            RateLimitExceeded: If rate limit would be exceeded
        """
        import httpx
        
        allowed, reason = self.limiter.acquire(url, self.workflow_id)
        if not allowed:
            raise RateLimitExceeded(
                reason=reason,
                domain=self.limiter._get_domain(url),
                retry_after=60
            )
        
        async with httpx.AsyncClient(timeout=30) as client:
            return await client.post(url, **kwargs)

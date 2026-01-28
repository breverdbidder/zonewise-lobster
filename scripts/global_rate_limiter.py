"""
ZoneWise Lobster - Global Rate Limiter
Implements cross-workflow rate limiting to prevent external service abuse.

Features:
- Global rate limiter shared across all workflows
- Configurable limits per domain/endpoint
- Rate limit state persistence (Supabase)
- Graceful degradation when limits hit
- Real-time monitoring
"""

import time
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict
import threading

# Import audit logger
from security_utils import AuditLogger, AuditEventType


@dataclass
class RateLimitConfig:
    """Configuration for a rate limit rule."""
    domain: str
    requests_per_minute: int
    requests_per_hour: int
    requests_per_day: int
    burst_limit: int  # Max concurrent requests
    cooldown_seconds: int  # Cooldown after hitting limit


class TokenBucket:
    """Token bucket algorithm for rate limiting."""
    
    def __init__(self, capacity: int, refill_rate: float):
        """
        Args:
            capacity: Maximum tokens in bucket
            refill_rate: Tokens added per second
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_refill = time.time()
        self._lock = threading.Lock()
    
    def consume(self, tokens: int = 1) -> bool:
        """
        Try to consume tokens from bucket.
        
        Returns:
            True if tokens were consumed, False if rate limited
        """
        with self._lock:
            self._refill()
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False
    
    def _refill(self):
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_refill
        tokens_to_add = elapsed * self.refill_rate
        self.tokens = min(self.capacity, self.tokens + tokens_to_add)
        self.last_refill = now
    
    @property
    def available_tokens(self) -> float:
        """Get current available tokens."""
        with self._lock:
            self._refill()
            return self.tokens


class GlobalRateLimiter:
    """
    Global rate limiter with Supabase persistence.
    
    Tracks request counts across all workflows and enforces
    configurable limits per domain/endpoint.
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
        "*": RateLimitConfig(  # Default for unknown domains
            domain="*",
            requests_per_minute=60,
            requests_per_hour=1000,
            requests_per_day=10000,
            burst_limit=20,
            cooldown_seconds=60
        )
    }
    
    def __init__(self, supabase_client, audit_logger: Optional[AuditLogger] = None):
        self.supabase = supabase_client
        self.audit = audit_logger
        self._buckets: Dict[str, TokenBucket] = {}
        self._request_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: {
            "minute": 0,
            "hour": 0,
            "day": 0,
            "last_reset_minute": datetime.now(timezone.utc),
            "last_reset_hour": datetime.now(timezone.utc),
            "last_reset_day": datetime.now(timezone.utc)
        })
        self._cooldowns: Dict[str, datetime] = {}
        self._lock = threading.Lock()
    
    def _get_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except Exception:
            return "*"
    
    def _get_config(self, domain: str) -> RateLimitConfig:
        """Get rate limit config for domain."""
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
        """Get or create token bucket for domain."""
        if domain not in self._buckets:
            config = self._get_config(domain)
            # Refill rate = requests per minute / 60 seconds
            refill_rate = config.requests_per_minute / 60.0
            self._buckets[domain] = TokenBucket(
                capacity=config.burst_limit,
                refill_rate=refill_rate
            )
        return self._buckets[domain]
    
    def _check_cooldown(self, domain: str) -> Tuple[bool, int]:
        """
        Check if domain is in cooldown.
        
        Returns:
            Tuple of (in_cooldown, seconds_remaining)
        """
        if domain not in self._cooldowns:
            return False, 0
        
        cooldown_end = self._cooldowns[domain]
        now = datetime.now(timezone.utc)
        
        if now < cooldown_end:
            remaining = (cooldown_end - now).total_seconds()
            return True, int(remaining)
        
        # Cooldown expired
        del self._cooldowns[domain]
        return False, 0
    
    def _update_counts(self, domain: str) -> Dict[str, int]:
        """Update and return request counts for domain."""
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
        
        Args:
            url: URL to request
            workflow_id: ID of requesting workflow
            
        Returns:
            Tuple of (allowed, reason)
        """
        domain = self._get_domain(url)
        config = self._get_config(domain)
        
        # Check cooldown first
        in_cooldown, remaining = self._check_cooldown(domain)
        if in_cooldown:
            reason = f"Domain {domain} in cooldown for {remaining}s"
            self._log_rate_limit(domain, workflow_id, reason)
            return False, reason
        
        # Check token bucket (burst limit)
        bucket = self._get_bucket(domain)
        if not bucket.consume():
            # Enter cooldown
            self._cooldowns[domain] = datetime.now(timezone.utc) + timedelta(
                seconds=config.cooldown_seconds
            )
            reason = f"Burst limit exceeded for {domain}, cooldown {config.cooldown_seconds}s"
            self._log_rate_limit(domain, workflow_id, reason)
            return False, reason
        
        # Check request counts
        counts = self._update_counts(domain)
        
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
    
    def _log_rate_limit(self, domain: str, workflow_id: str, reason: str):
        """Log rate limit event."""
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
                    "config": self._get_config(domain).__dict__
                }
            )
    
    def _persist_counts_async(self, domain: str, counts: Dict):
        """Persist counts to Supabase asynchronously."""
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
        except Exception:
            pass  # Non-critical, don't fail request
    
    def get_status(self) -> Dict[str, Dict]:
        """Get current rate limit status for all domains."""
        status = {}
        for domain in list(self._request_counts.keys()) + list(self.DEFAULT_LIMITS.keys()):
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


# =============================================================================
# Rate-Limited HTTP Client
# =============================================================================

class RateLimitedClient:
    """HTTP client with built-in rate limiting."""
    
    def __init__(self, rate_limiter: GlobalRateLimiter, workflow_id: str):
        self.limiter = rate_limiter
        self.workflow_id = workflow_id
    
    async def get(self, url: str, **kwargs) -> Optional[object]:
        """Rate-limited GET request."""
        import httpx
        
        allowed, reason = self.limiter.acquire(url, self.workflow_id)
        if not allowed:
            raise RateLimitExceeded(reason)
        
        async with httpx.AsyncClient(timeout=30) as client:
            return await client.get(url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> Optional[object]:
        """Rate-limited POST request."""
        import httpx
        
        allowed, reason = self.limiter.acquire(url, self.workflow_id)
        if not allowed:
            raise RateLimitExceeded(reason)
        
        async with httpx.AsyncClient(timeout=30) as client:
            return await client.post(url, **kwargs)


class RateLimitExceeded(Exception):
    """Raised when rate limit is exceeded."""
    pass

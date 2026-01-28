"""
ZoneWise Lobster - Rate Limiter Unit Tests

Granular unit tests for GlobalRateLimiter and TokenBucket classes.
Tests rate limiting algorithms and configuration.

Run with: pytest tests/test_rate_limiter.py -v
"""

import pytest
import time
from unittest.mock import MagicMock
from typing import Any


class TestTokenBucket:
    """Tests for TokenBucket class."""
    
    def test_initial_capacity(self) -> None:
        """Test bucket starts at full capacity."""
        from scripts.global_rate_limiter import TokenBucket
        bucket = TokenBucket(capacity=10, refill_rate=1.0)
        assert bucket.available_tokens == 10.0
    
    def test_consume_single_token(self) -> None:
        """Test consuming a single token."""
        from scripts.global_rate_limiter import TokenBucket
        bucket = TokenBucket(capacity=10, refill_rate=0.0)
        
        assert bucket.consume(1) is True
        assert bucket.available_tokens == 9.0
    
    def test_consume_multiple_tokens(self) -> None:
        """Test consuming multiple tokens at once."""
        from scripts.global_rate_limiter import TokenBucket
        bucket = TokenBucket(capacity=10, refill_rate=0.0)
        
        assert bucket.consume(5) is True
        assert bucket.available_tokens == 5.0
    
    def test_consume_fails_insufficient_tokens(self) -> None:
        """Test consume fails when insufficient tokens."""
        from scripts.global_rate_limiter import TokenBucket
        bucket = TokenBucket(capacity=5, refill_rate=0.0)
        
        assert bucket.consume(3) is True
        assert bucket.consume(3) is False  # Only 2 left
    
    def test_consume_exact_remaining(self) -> None:
        """Test consuming exactly remaining tokens."""
        from scripts.global_rate_limiter import TokenBucket
        bucket = TokenBucket(capacity=5, refill_rate=0.0)
        
        bucket.consume(3)
        assert bucket.consume(2) is True
        assert bucket.available_tokens == 0.0
    
    def test_consume_empty_bucket(self) -> None:
        """Test consuming from empty bucket fails."""
        from scripts.global_rate_limiter import TokenBucket
        bucket = TokenBucket(capacity=2, refill_rate=0.0)
        
        bucket.consume(2)
        assert bucket.consume(1) is False
    
    def test_refill_over_time(self) -> None:
        """Test tokens refill over time."""
        from scripts.global_rate_limiter import TokenBucket
        bucket = TokenBucket(capacity=10, refill_rate=100.0)  # 100/sec
        
        bucket.consume(10)  # Empty the bucket
        assert bucket.available_tokens == 0.0
        
        time.sleep(0.05)  # Wait 50ms
        
        # Should have ~5 tokens refilled
        tokens = bucket.available_tokens
        assert tokens >= 4.0
        assert tokens <= 6.0
    
    def test_refill_capped_at_capacity(self) -> None:
        """Test refill doesn't exceed capacity."""
        from scripts.global_rate_limiter import TokenBucket
        bucket = TokenBucket(capacity=10, refill_rate=1000.0)
        
        bucket.consume(5)
        time.sleep(0.1)
        
        assert bucket.available_tokens <= 10.0


class TestGlobalRateLimiter:
    """Tests for GlobalRateLimiter class."""
    
    @pytest.fixture
    def mock_supabase(self) -> MagicMock:
        """Create mock Supabase client."""
        mock = MagicMock()
        mock.table.return_value.upsert.return_value.execute.return_value = {"data": []}
        mock.table.return_value.insert.return_value.execute.return_value = {"data": []}
        return mock
    
    def test_acquire_first_request_allowed(self, mock_supabase: MagicMock) -> None:
        """Test first request is always allowed."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        
        limiter = GlobalRateLimiter(mock_supabase)
        allowed, reason = limiter.acquire("https://municode.com/test", "wf_test")
        
        assert allowed is True
        assert reason == "OK"
    
    def test_acquire_respects_burst_limit(self, mock_supabase: MagicMock) -> None:
        """Test burst limit is enforced."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        
        limiter = GlobalRateLimiter(mock_supabase)
        
        # Municode burst limit is 10
        for i in range(10):
            allowed, _ = limiter.acquire("https://municode.com/test", "wf_test")
            assert allowed is True, f"Request {i+1} should be allowed"
        
        # 11th should fail
        allowed, reason = limiter.acquire("https://municode.com/test", "wf_test")
        assert allowed is False
        assert "Burst limit" in reason
    
    def test_get_domain_basic(self, mock_supabase: MagicMock) -> None:
        """Test basic domain extraction."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        
        limiter = GlobalRateLimiter(mock_supabase)
        
        assert limiter._get_domain("https://municode.com/path") == "municode.com"
        assert limiter._get_domain("https://api.supabase.co/rest") == "api.supabase.co"
    
    def test_get_domain_with_port(self, mock_supabase: MagicMock) -> None:
        """Test domain extraction with port."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        
        limiter = GlobalRateLimiter(mock_supabase)
        
        result = limiter._get_domain("https://localhost:8080/api")
        assert "localhost" in result
    
    def test_get_domain_invalid_url(self, mock_supabase: MagicMock) -> None:
        """Test domain extraction with invalid URL."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        
        limiter = GlobalRateLimiter(mock_supabase)
        
        assert limiter._get_domain("invalid") == "*"
        assert limiter._get_domain("") == "*"
    
    def test_get_config_exact_match(self, mock_supabase: MagicMock) -> None:
        """Test config lookup for exact domain match."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        
        limiter = GlobalRateLimiter(mock_supabase)
        config = limiter._get_config("municode.com")
        
        assert config.domain == "municode.com"
        assert config.requests_per_minute == 30
        assert config.burst_limit == 10
    
    def test_get_config_subdomain_inherits(self, mock_supabase: MagicMock) -> None:
        """Test subdomain inherits parent config."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        
        limiter = GlobalRateLimiter(mock_supabase)
        config = limiter._get_config("library.municode.com")
        
        assert config.requests_per_minute == 30  # Same as municode.com
    
    def test_get_config_unknown_domain(self, mock_supabase: MagicMock) -> None:
        """Test unknown domain gets default config."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        
        limiter = GlobalRateLimiter(mock_supabase)
        config = limiter._get_config("unknown.example.com")
        
        assert config.domain == "*"
        assert config.requests_per_minute == 60
    
    def test_domains_independent(self, mock_supabase: MagicMock) -> None:
        """Test different domains have independent limits."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        
        limiter = GlobalRateLimiter(mock_supabase)
        
        # Exhaust municode.com
        for _ in range(10):
            limiter.acquire("https://municode.com/test", "wf_test")
        
        # Municode should be blocked
        allowed_m, _ = limiter.acquire("https://municode.com/test", "wf_test")
        assert allowed_m is False
        
        # Supabase should still work
        allowed_s, _ = limiter.acquire("https://supabase.co/test", "wf_test")
        assert allowed_s is True
    
    def test_get_status(self, mock_supabase: MagicMock) -> None:
        """Test status returns current limits."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        
        limiter = GlobalRateLimiter(mock_supabase)
        
        # Make some requests
        for _ in range(5):
            limiter.acquire("https://municode.com/test", "wf_test")
        
        status = limiter.get_status()
        
        assert "municode.com" in status
        assert "requests_minute" in status["municode.com"]
        assert "burst_available" in status["municode.com"]


class TestRateLimitExceeded:
    """Tests for RateLimitExceeded exception."""
    
    def test_exception_message(self) -> None:
        """Test exception has correct message."""
        from scripts.global_rate_limiter import RateLimitExceeded
        
        exc = RateLimitExceeded("Rate limit exceeded", "example.com", 60)
        
        assert str(exc) == "Rate limit exceeded"
        assert exc.domain == "example.com"
        assert exc.retry_after == 60
    
    def test_exception_defaults(self) -> None:
        """Test exception defaults."""
        from scripts.global_rate_limiter import RateLimitExceeded
        
        exc = RateLimitExceeded("Limit hit")
        
        assert exc.domain == ""
        assert exc.retry_after == 60


class TestRateLimitConfig:
    """Tests for RateLimitConfig dataclass."""
    
    def test_config_creation(self) -> None:
        """Test creating a config."""
        from scripts.global_rate_limiter import RateLimitConfig
        
        config = RateLimitConfig(
            domain="test.com",
            requests_per_minute=100,
            requests_per_hour=1000,
            requests_per_day=10000,
            burst_limit=20,
            cooldown_seconds=30
        )
        
        assert config.domain == "test.com"
        assert config.requests_per_minute == 100
        assert config.burst_limit == 20
    
    def test_config_immutable(self) -> None:
        """Test config is immutable (frozen dataclass)."""
        from scripts.global_rate_limiter import RateLimitConfig
        
        config = RateLimitConfig(
            domain="test.com",
            requests_per_minute=100,
            requests_per_hour=1000,
            requests_per_day=10000,
            burst_limit=20,
            cooldown_seconds=30
        )
        
        # Should raise FrozenInstanceError
        with pytest.raises(Exception):
            config.domain = "modified.com"  # type: ignore


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

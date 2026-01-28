"""
ZoneWise Lobster - Unit Tests for Security Utilities

Comprehensive test coverage for:
- InputSanitizer
- AuditLogger
- CredentialValidator
- Global Rate Limiter

Run with: pytest tests/ -v --cov=scripts
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, MagicMock, patch, AsyncMock
import hashlib


# =============================================================================
# INPUT SANITIZER TESTS
# =============================================================================

class TestInputSanitizer:
    """Tests for InputSanitizer class."""
    
    def test_sanitize_fips_valid(self):
        """Test valid Florida FIPS codes are accepted."""
        from scripts.security_utils import InputSanitizer
        
        # Valid Florida FIPS codes (odd numbers 12001-12133)
        assert InputSanitizer.sanitize_fips("12001") == "12001"
        assert InputSanitizer.sanitize_fips("12009") == "12009"  # Brevard
        assert InputSanitizer.sanitize_fips("12057") == "12057"  # Hillsborough
        assert InputSanitizer.sanitize_fips("12133") == "12133"  # Last valid
    
    def test_sanitize_fips_invalid_format(self):
        """Test invalid FIPS formats are rejected."""
        from scripts.security_utils import InputSanitizer
        
        assert InputSanitizer.sanitize_fips("") is None
        assert InputSanitizer.sanitize_fips("12") is None
        assert InputSanitizer.sanitize_fips("123456") is None
        assert InputSanitizer.sanitize_fips("ABCDE") is None
        assert InputSanitizer.sanitize_fips("13001") is None  # Wrong state
    
    def test_sanitize_fips_invalid_county(self):
        """Test non-existent Florida county FIPS codes are rejected."""
        from scripts.security_utils import InputSanitizer
        
        # Even numbers are not valid Florida county FIPS
        assert InputSanitizer.sanitize_fips("12002") is None
        assert InputSanitizer.sanitize_fips("12134") is None  # Beyond range
    
    def test_sanitize_fips_whitespace(self):
        """Test FIPS codes with whitespace are handled."""
        from scripts.security_utils import InputSanitizer
        
        assert InputSanitizer.sanitize_fips("  12009  ") == "12009"
        assert InputSanitizer.sanitize_fips("\t12009\n") == "12009"
    
    def test_sanitize_fips_injection_attempt(self):
        """Test SQL injection attempts are blocked."""
        from scripts.security_utils import InputSanitizer
        
        assert InputSanitizer.sanitize_fips("12009; DROP TABLE--") is None
        assert InputSanitizer.sanitize_fips("12009' OR '1'='1") is None
    
    def test_sanitize_county_name_valid(self):
        """Test valid county names are accepted."""
        from scripts.security_utils import InputSanitizer
        
        assert InputSanitizer.sanitize_county_name("Brevard") == "Brevard"
        assert InputSanitizer.sanitize_county_name("Miami-Dade") == "Miami-Dade"
        assert InputSanitizer.sanitize_county_name("St. Johns") == "St. Johns"
    
    def test_sanitize_county_name_xss(self):
        """Test XSS attempts are sanitized."""
        from scripts.security_utils import InputSanitizer
        
        result = InputSanitizer.sanitize_county_name("<script>alert('xss')</script>")
        assert "<script>" not in result
        assert "alert" in result  # Text content preserved, tags removed
    
    def test_sanitize_county_name_sql_injection(self):
        """Test SQL injection attempts are sanitized."""
        from scripts.security_utils import InputSanitizer
        
        result = InputSanitizer.sanitize_county_name("Brevard'; DROP TABLE--")
        assert "'" not in result
        assert ";" not in result
    
    def test_sanitize_county_name_length_limit(self):
        """Test county names are truncated to 50 chars."""
        from scripts.security_utils import InputSanitizer
        
        long_name = "A" * 100
        result = InputSanitizer.sanitize_county_name(long_name)
        assert len(result) <= 50
    
    def test_sanitize_county_name_minimum_length(self):
        """Test minimum length requirement."""
        from scripts.security_utils import InputSanitizer
        
        assert InputSanitizer.sanitize_county_name("") is None
        assert InputSanitizer.sanitize_county_name("A") is None
        assert InputSanitizer.sanitize_county_name("AB") == "AB"
    
    def test_sanitize_url_valid(self):
        """Test valid URLs are accepted."""
        from scripts.security_utils import InputSanitizer
        
        assert InputSanitizer.sanitize_url("https://municode.com/path") is not None
        assert InputSanitizer.sanitize_url("https://library.municode.com/fl/brevard") is not None
        assert InputSanitizer.sanitize_url("https://supabase.co/rest/v1/") is not None
    
    def test_sanitize_url_http_rejected(self):
        """Test HTTP (non-HTTPS) URLs are rejected."""
        from scripts.security_utils import InputSanitizer
        
        assert InputSanitizer.sanitize_url("http://municode.com") is None
    
    def test_sanitize_url_invalid_domain(self):
        """Test non-whitelisted domains are rejected."""
        from scripts.security_utils import InputSanitizer
        
        assert InputSanitizer.sanitize_url("https://evil.com/steal") is None
        assert InputSanitizer.sanitize_url("https://malicious.io/api") is None
    
    def test_sanitize_url_none_input(self):
        """Test None input is handled."""
        from scripts.security_utils import InputSanitizer
        
        assert InputSanitizer.sanitize_url(None) is None
        assert InputSanitizer.sanitize_url("") is None


# =============================================================================
# AUDIT LOGGER TESTS
# =============================================================================

class TestAuditLogger:
    """Tests for AuditLogger class."""
    
    @pytest.fixture
    def mock_supabase(self):
        """Create a mock Supabase client."""
        mock = MagicMock()
        mock.table.return_value.insert.return_value.execute.return_value = {"data": []}
        return mock
    
    def test_audit_log_creates_event(self, mock_supabase):
        """Test audit log creates event with correct structure."""
        from scripts.security_utils import AuditLogger, AuditEventType
        
        logger = AuditLogger(mock_supabase, "test_workflow_123")
        
        event = logger.log(
            event_type=AuditEventType.WORKFLOW_START,
            action="test_action",
            target="test_target",
            status="success",
            details={"key": "value"}
        )
        
        assert event.event_type == AuditEventType.WORKFLOW_START
        assert event.action == "test_action"
        assert event.target == "test_target"
        assert event.status == "success"
        assert event.workflow_id == "test_workflow_123"
    
    def test_audit_log_checksum_format(self, mock_supabase):
        """Test checksum is 16 characters hex."""
        from scripts.security_utils import AuditLogger, AuditEventType
        
        logger = AuditLogger(mock_supabase, "test_workflow")
        event = logger.log(
            event_type=AuditEventType.SCRAPE_START,
            action="scrape",
            target="county",
            status="started"
        )
        
        assert len(event.checksum) == 16
        assert all(c in '0123456789abcdef' for c in event.checksum)
    
    def test_audit_log_approval(self, mock_supabase):
        """Test approval logging."""
        from scripts.security_utils import AuditLogger
        
        logger = AuditLogger(mock_supabase, "test_workflow")
        
        event = logger.log_approval(
            approval_type="pre_scrape",
            approved=True,
            approver="test@example.com",
            reason="Test approval"
        )
        
        assert "approval_type" in event.details
        assert event.details["approved"] is True
    
    def test_audit_log_security_violation(self, mock_supabase):
        """Test security violation logging."""
        from scripts.security_utils import AuditLogger
        
        logger = AuditLogger(mock_supabase, "test_workflow")
        
        event = logger.log_security_violation(
            violation_type="invalid_input",
            details={"input": "malicious", "blocked": True}
        )
        
        assert event.status == "blocked"
        assert "violation_type" in event.details


# =============================================================================
# CREDENTIAL VALIDATOR TESTS
# =============================================================================

class TestCredentialValidator:
    """Tests for CredentialValidator class."""
    
    def test_validate_supabase_key_valid(self):
        """Test valid Supabase JWT is accepted."""
        from scripts.security_utils import CredentialValidator
        
        # Valid JWT format (starts with eyJ, has 3 parts)
        valid_key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRlc3QiLCJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNjAwMDAwMDAwLCJleHAiOjIwMDAwMDAwMDB9.signature_here_with_enough_length_to_pass"
        
        assert CredentialValidator.validate_supabase_key(valid_key) is True
    
    def test_validate_supabase_key_invalid_prefix(self):
        """Test non-JWT keys are rejected."""
        from scripts.security_utils import CredentialValidator
        
        assert CredentialValidator.validate_supabase_key("sk_live_12345") is False
        assert CredentialValidator.validate_supabase_key("invalid") is False
    
    def test_validate_supabase_key_too_short(self):
        """Test short keys are rejected."""
        from scripts.security_utils import CredentialValidator
        
        assert CredentialValidator.validate_supabase_key("eyJhbGciOiJIUzI1NiJ9.short.sig") is False
    
    def test_validate_supabase_key_wrong_parts(self):
        """Test keys without 3 parts are rejected."""
        from scripts.security_utils import CredentialValidator
        
        assert CredentialValidator.validate_supabase_key("eyJhbGciOiJIUzI1NiJ9.only_two") is False
        assert CredentialValidator.validate_supabase_key("eyJhbGciOiJIUzI1NiJ9") is False


# =============================================================================
# GLOBAL RATE LIMITER TESTS
# =============================================================================

class TestGlobalRateLimiter:
    """Tests for GlobalRateLimiter class."""
    
    @pytest.fixture
    def mock_supabase(self):
        """Create a mock Supabase client."""
        mock = MagicMock()
        mock.table.return_value.upsert.return_value.execute.return_value = {"data": []}
        return mock
    
    def test_acquire_allows_first_request(self, mock_supabase):
        """Test first request is always allowed."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        
        limiter = GlobalRateLimiter(mock_supabase)
        allowed, reason = limiter.acquire("https://municode.com/test", "wf_test")
        
        assert allowed is True
        assert reason == "OK"
    
    def test_acquire_blocks_after_burst_limit(self, mock_supabase):
        """Test requests are blocked after burst limit."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        
        limiter = GlobalRateLimiter(mock_supabase)
        
        # Exhaust burst limit for municode.com (10 requests)
        for _ in range(10):
            limiter.acquire("https://municode.com/test", "wf_test")
        
        # Next request should be blocked
        allowed, reason = limiter.acquire("https://municode.com/test", "wf_test")
        
        assert allowed is False
        assert "Burst limit exceeded" in reason
    
    def test_get_domain_extraction(self, mock_supabase):
        """Test domain extraction from URLs."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        
        limiter = GlobalRateLimiter(mock_supabase)
        
        assert limiter._get_domain("https://municode.com/path") == "municode.com"
        assert limiter._get_domain("https://api.supabase.co/rest") == "api.supabase.co"
        assert limiter._get_domain("invalid") == "*"
    
    def test_get_config_exact_match(self, mock_supabase):
        """Test config retrieval for exact domain match."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        
        limiter = GlobalRateLimiter(mock_supabase)
        config = limiter._get_config("municode.com")
        
        assert config.requests_per_minute == 30
        assert config.burst_limit == 10
    
    def test_get_config_subdomain_match(self, mock_supabase):
        """Test config retrieval for subdomain."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        
        limiter = GlobalRateLimiter(mock_supabase)
        config = limiter._get_config("library.municode.com")
        
        # Should match parent domain config
        assert config.requests_per_minute == 30
    
    def test_get_config_unknown_domain(self, mock_supabase):
        """Test default config for unknown domains."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        
        limiter = GlobalRateLimiter(mock_supabase)
        config = limiter._get_config("unknown.example.com")
        
        # Should return default config
        assert config.domain == "*"
        assert config.requests_per_minute == 60
    
    def test_cooldown_after_limit_exceeded(self, mock_supabase):
        """Test domain enters cooldown after limit exceeded."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        
        limiter = GlobalRateLimiter(mock_supabase)
        
        # Exhaust burst limit
        for _ in range(10):
            limiter.acquire("https://municode.com/test", "wf_test")
        
        # Trigger cooldown
        limiter.acquire("https://municode.com/test", "wf_test")
        
        # Check cooldown is active
        in_cooldown, remaining = limiter._check_cooldown("municode.com")
        assert in_cooldown is True
        assert remaining > 0
    
    def test_get_status_returns_all_domains(self, mock_supabase):
        """Test status returns info for all tracked domains."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        
        limiter = GlobalRateLimiter(mock_supabase)
        
        # Make some requests
        limiter.acquire("https://municode.com/test", "wf_test")
        limiter.acquire("https://supabase.co/test", "wf_test")
        
        status = limiter.get_status()
        
        assert "municode.com" in status
        assert "supabase.co" in status
        assert "requests_minute" in status["municode.com"]


# =============================================================================
# TOKEN BUCKET TESTS
# =============================================================================

class TestTokenBucket:
    """Tests for TokenBucket class."""
    
    def test_initial_capacity(self):
        """Test bucket starts at full capacity."""
        from scripts.global_rate_limiter import TokenBucket
        
        bucket = TokenBucket(capacity=10, refill_rate=1.0)
        assert bucket.available_tokens == 10
    
    def test_consume_reduces_tokens(self):
        """Test consuming tokens reduces available count."""
        from scripts.global_rate_limiter import TokenBucket
        
        bucket = TokenBucket(capacity=10, refill_rate=1.0)
        
        assert bucket.consume(1) is True
        assert bucket.available_tokens == 9
    
    def test_consume_fails_when_empty(self):
        """Test consume fails when bucket is empty."""
        from scripts.global_rate_limiter import TokenBucket
        
        bucket = TokenBucket(capacity=2, refill_rate=0.0)  # No refill
        
        assert bucket.consume(1) is True
        assert bucket.consume(1) is True
        assert bucket.consume(1) is False
    
    def test_consume_multiple_tokens(self):
        """Test consuming multiple tokens at once."""
        from scripts.global_rate_limiter import TokenBucket
        
        bucket = TokenBucket(capacity=10, refill_rate=0.0)
        
        assert bucket.consume(5) is True
        assert bucket.available_tokens == 5
        assert bucket.consume(6) is False  # Not enough tokens


# =============================================================================
# RATE LIMIT EXCEPTION TESTS
# =============================================================================

class TestRateLimitExceeded:
    """Tests for RateLimitExceeded exception."""
    
    def test_exception_attributes(self):
        """Test exception has correct attributes."""
        from scripts.global_rate_limiter import RateLimitExceeded
        
        exc = RateLimitExceeded(
            reason="Burst limit exceeded",
            domain="municode.com",
            retry_after=60
        )
        
        assert exc.reason == "Burst limit exceeded"
        assert exc.domain == "municode.com"
        assert exc.retry_after == 60
        assert str(exc) == "Burst limit exceeded"


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestSecurityIntegration:
    """Integration tests for security components working together."""
    
    @pytest.fixture
    def mock_supabase(self):
        """Create a mock Supabase client."""
        mock = MagicMock()
        mock.table.return_value.insert.return_value.execute.return_value = {"data": []}
        mock.table.return_value.upsert.return_value.execute.return_value = {"data": []}
        return mock
    
    def test_rate_limiter_logs_to_audit(self, mock_supabase):
        """Test rate limiter logs violations to audit trail."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        from scripts.security_utils import AuditLogger
        
        audit = AuditLogger(mock_supabase, "test_workflow")
        limiter = GlobalRateLimiter(mock_supabase, audit)
        
        # Exhaust burst limit
        for _ in range(10):
            limiter.acquire("https://municode.com/test", "wf_test")
        
        # This should log a security violation
        allowed, reason = limiter.acquire("https://municode.com/test", "wf_test")
        
        assert allowed is False
        # Verify audit log was called
        assert mock_supabase.table.called


# =============================================================================
# PYTEST CONFIGURATION
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

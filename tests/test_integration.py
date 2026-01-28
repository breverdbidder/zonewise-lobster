"""
ZoneWise Lobster - Integration Tests

End-to-end tests that verify components work together correctly.
Tests the full workflow from input validation through audit logging.

Run with: pytest tests/test_integration.py -v -m integration
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, AsyncMock, patch
from typing import Dict, Any


# Mark all tests in this file as integration tests
pytestmark = pytest.mark.integration


class TestSecurityPipelineIntegration:
    """
    Integration tests for the complete security pipeline.
    
    Tests the flow: Input → Sanitization → Rate Limiting → Audit Logging
    """
    
    @pytest.fixture
    def mock_supabase(self) -> MagicMock:
        """Create a comprehensive mock Supabase client."""
        mock = MagicMock()
        mock.table.return_value.insert.return_value.execute.return_value = {
            "data": [{"id": 1}]
        }
        mock.table.return_value.upsert.return_value.execute.return_value = {
            "data": [{"id": 1}]
        }
        return mock
    
    def test_full_input_validation_pipeline(self, mock_supabase: MagicMock) -> None:
        """Test complete input validation flow."""
        from scripts.security_utils import InputSanitizer, AuditLogger, AuditEventType
        
        # Initialize audit logger
        audit = AuditLogger(mock_supabase, "wf_integration_test")
        
        # Test valid inputs
        fips = InputSanitizer.sanitize_fips("12009")
        name = InputSanitizer.sanitize_county_name("Brevard")
        url = InputSanitizer.sanitize_url("https://municode.com/fl/brevard")
        
        assert fips == "12009"
        assert name == "Brevard"
        assert url is not None
        
        # Log successful validation
        event = audit.log(
            event_type=AuditEventType.WORKFLOW_START,
            action="input_validation",
            target=f"{fips}:{name}",
            status="success",
            details={"fips": fips, "name": name, "url_valid": True}
        )
        
        # Verify audit event was created correctly
        assert event.workflow_id == "wf_integration_test"
        assert event.status == "success"
        assert len(event.checksum) == 16
    
    def test_invalid_input_logs_security_violation(self, mock_supabase: MagicMock) -> None:
        """Test that invalid inputs trigger security violation logging."""
        from scripts.security_utils import InputSanitizer, AuditLogger
        
        audit = AuditLogger(mock_supabase, "wf_security_test")
        
        # Attempt SQL injection
        malicious_fips = "12009'; DROP TABLE--"
        result = InputSanitizer.sanitize_fips(malicious_fips)
        
        assert result is None
        
        # Log security violation
        event = audit.log_security_violation(
            violation_type="sql_injection_attempt",
            details={
                "input": malicious_fips[:50],
                "field": "fips",
                "blocked": True
            }
        )
        
        assert event.status == "blocked"
        assert "sql_injection_attempt" in event.details["violation_type"]
    
    def test_rate_limiter_with_audit_logging(self, mock_supabase: MagicMock) -> None:
        """Test rate limiter integrates with audit logging."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        from scripts.security_utils import AuditLogger
        
        audit = AuditLogger(mock_supabase, "wf_rate_test")
        limiter = GlobalRateLimiter(mock_supabase, audit)
        
        # Make requests until rate limit is hit
        domain = "https://municode.com/test"
        workflow_id = "wf_rate_test"
        
        # First 10 requests should succeed (burst limit)
        for i in range(10):
            allowed, reason = limiter.acquire(domain, workflow_id)
            assert allowed is True, f"Request {i+1} should be allowed"
        
        # 11th request should be blocked
        allowed, reason = limiter.acquire(domain, workflow_id)
        assert allowed is False
        assert "Burst limit exceeded" in reason
    
    def test_credential_validation_flow(self, mock_supabase: MagicMock) -> None:
        """Test credential validation with audit logging."""
        from scripts.security_utils import AuditLogger, AuditEventType
        
        audit = AuditLogger(mock_supabase, "wf_cred_test")
        
        # Valid JWT format
        valid_key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSJ9." + "x" * 50
        
        # Log credential validation
        event = audit.log(
            event_type=AuditEventType.CREDENTIAL_VALIDATION,
            action="validate_supabase_key",
            target="supabase_service_role",
            status="success",
            details={"key_prefix": valid_key[:8] + "..."}
        )
        
        assert event.event_type == AuditEventType.CREDENTIAL_VALIDATION
        assert "eyJhbGci..." in event.details["key_prefix"]


class TestWorkflowIntegration:
    """
    Integration tests for workflow execution.
    
    Tests the complete scrape workflow with all security components.
    """
    
    @pytest.fixture
    def mock_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Set up mock environment variables."""
        monkeypatch.setenv("SUPABASE_URL", "https://test.supabase.co")
        monkeypatch.setenv("SUPABASE_KEY", "eyJhbGciOiJIUzI1NiJ9.test.signature" + "x" * 50)
    
    def test_scrape_workflow_security_checks(
        self, 
        mock_supabase: MagicMock,
        mock_environment: None
    ) -> None:
        """Test scrape workflow applies all security checks."""
        from scripts.security_utils import InputSanitizer, AuditLogger, AuditEventType
        from scripts.global_rate_limiter import GlobalRateLimiter
        
        workflow_id = "wf_scrape_integration"
        audit = AuditLogger(mock_supabase, workflow_id)
        limiter = GlobalRateLimiter(mock_supabase, audit)
        
        # Step 1: Validate inputs
        fips = InputSanitizer.sanitize_fips("12009")
        name = InputSanitizer.sanitize_county_name("Brevard")
        
        assert fips is not None
        assert name is not None
        
        # Step 2: Log workflow start
        start_event = audit.log(
            event_type=AuditEventType.WORKFLOW_START,
            action="scrape_county",
            target=f"{fips}:{name}",
            status="started"
        )
        
        # Step 3: Check rate limit
        url = f"https://library.municode.com/fl/{name.lower()}"
        allowed, reason = limiter.acquire(url, workflow_id)
        assert allowed is True
        
        # Step 4: Log scrape start
        scrape_event = audit.log(
            event_type=AuditEventType.SCRAPE_START,
            action="fetch_municode",
            target=url,
            status="started"
        )
        
        # Step 5: Simulate scrape success
        success_event = audit.log(
            event_type=AuditEventType.SCRAPE_SUCCESS,
            action="fetch_municode",
            target=url,
            status="success",
            details={"districts_found": 15, "quality_score": 85}
        )
        
        # Step 6: Log workflow end
        end_event = audit.log(
            event_type=AuditEventType.WORKFLOW_END,
            action="scrape_county",
            target=f"{fips}:{name}",
            status="completed",
            details={
                "districts": 15,
                "quality_score": 85,
                "duration_seconds": 12.5
            }
        )
        
        # Verify complete audit trail
        assert start_event.event_type == AuditEventType.WORKFLOW_START
        assert end_event.event_type == AuditEventType.WORKFLOW_END
        assert end_event.details["districts"] == 15
    
    @pytest.fixture
    def mock_supabase(self) -> MagicMock:
        """Create mock Supabase client."""
        mock = MagicMock()
        mock.table.return_value.insert.return_value.execute.return_value = {"data": [{"id": 1}]}
        mock.table.return_value.upsert.return_value.execute.return_value = {"data": [{"id": 1}]}
        return mock


class TestRateLimiterIntegration:
    """
    Integration tests for rate limiter across multiple domains.
    """
    
    @pytest.fixture
    def mock_supabase(self) -> MagicMock:
        """Create mock Supabase client."""
        mock = MagicMock()
        mock.table.return_value.upsert.return_value.execute.return_value = {"data": []}
        return mock
    
    def test_multi_domain_rate_limiting(self, mock_supabase: MagicMock) -> None:
        """Test rate limiting works independently per domain."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        
        limiter = GlobalRateLimiter(mock_supabase)
        
        # Exhaust municode.com burst limit (10)
        for _ in range(10):
            limiter.acquire("https://municode.com/test", "wf_test")
        
        # municode.com should now be blocked
        allowed_municode, _ = limiter.acquire("https://municode.com/test", "wf_test")
        assert allowed_municode is False
        
        # But supabase.co should still work (different domain, limit 50)
        allowed_supabase, _ = limiter.acquire("https://supabase.co/test", "wf_test")
        assert allowed_supabase is True
    
    def test_subdomain_inherits_parent_limits(self, mock_supabase: MagicMock) -> None:
        """Test subdomains use parent domain rate limits."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        
        limiter = GlobalRateLimiter(mock_supabase)
        
        # Get config for subdomain
        config = limiter._get_config("library.municode.com")
        
        # Should inherit municode.com limits
        assert config.requests_per_minute == 30
        assert config.burst_limit == 10
    
    def test_rate_limit_status_tracking(self, mock_supabase: MagicMock) -> None:
        """Test rate limit status is accurately tracked."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        
        limiter = GlobalRateLimiter(mock_supabase)
        
        # Make some requests
        for _ in range(5):
            limiter.acquire("https://municode.com/test", "wf_test")
        
        # Check status
        status = limiter.get_status()
        
        assert "municode.com" in status
        assert status["municode.com"]["requests_minute"] == "5/30"
        assert status["municode.com"]["burst_available"] == 5


class TestAuditTrailIntegrity:
    """
    Integration tests for audit trail integrity.
    """
    
    @pytest.fixture
    def mock_supabase(self) -> MagicMock:
        """Create mock Supabase client."""
        mock = MagicMock()
        mock.table.return_value.insert.return_value.execute.return_value = {"data": [{"id": 1}]}
        return mock
    
    def test_checksum_uniqueness(self, mock_supabase: MagicMock) -> None:
        """Test each audit event has a unique checksum."""
        from scripts.security_utils import AuditLogger, AuditEventType
        
        audit = AuditLogger(mock_supabase, "wf_checksum_test")
        checksums = set()
        
        # Create multiple events
        for i in range(10):
            event = audit.log(
                event_type=AuditEventType.WORKFLOW_START,
                action=f"test_action_{i}",
                target=f"target_{i}",
                status="success"
            )
            checksums.add(event.checksum)
        
        # All checksums should be unique
        assert len(checksums) == 10
    
    def test_event_id_format(self, mock_supabase: MagicMock) -> None:
        """Test event IDs follow expected format."""
        from scripts.security_utils import AuditLogger, AuditEventType
        
        audit = AuditLogger(mock_supabase, "wf_format_test")
        
        event = audit.log(
            event_type=AuditEventType.SCRAPE_START,
            action="test",
            target="test",
            status="success"
        )
        
        # Event ID should start with evt_ and include workflow ID
        assert event.event_id.startswith("evt_")
        assert "wf_format_test" in event.event_id


# =============================================================================
# PYTEST CONFIGURATION
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "integration"])

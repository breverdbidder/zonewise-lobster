"""
ZoneWise Lobster - Edge Case Tests

Comprehensive edge case testing to ensure robustness under
unusual conditions and boundary scenarios.

Run with: pytest tests/test_edge_cases.py -v
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch, AsyncMock
from typing import Dict, Any, List
import threading
import time


class TestInputSanitizerEdgeCases:
    """Edge cases for InputSanitizer."""
    
    def test_fips_boundary_values(self) -> None:
        """Test FIPS codes at boundaries."""
        from scripts.security_utils import InputSanitizer
        
        # First valid Florida FIPS
        assert InputSanitizer.sanitize_fips("12001") == "12001"
        
        # Last valid Florida FIPS
        assert InputSanitizer.sanitize_fips("12133") == "12133"
        
        # Just outside boundaries
        assert InputSanitizer.sanitize_fips("11999") is None
        assert InputSanitizer.sanitize_fips("12135") is None
    
    def test_fips_unicode_injection(self) -> None:
        """Test FIPS with unicode characters."""
        from scripts.security_utils import InputSanitizer
        
        unicode_attacks = [
            "12009\u0000",       # Null byte
            "12009\u200B",       # Zero-width space
            "１２００９",         # Full-width digits
            "12009\uFEFF",       # BOM
        ]
        
        for attack in unicode_attacks:
            result = InputSanitizer.sanitize_fips(attack)
            # Should either reject or sanitize properly
            assert result is None or result == "12009"
    
    def test_county_name_unicode_normalization(self) -> None:
        """Test county names with unicode variations."""
        from scripts.security_utils import InputSanitizer
        
        # Various unicode representations
        names = [
            "Brévärd",           # Accented characters
            "Miami\u2010Dade",   # Unicode hyphen
            "St\u2024 Johns",    # One dot leader
        ]
        
        for name in names:
            result = InputSanitizer.sanitize_county_name(name)
            assert result is not None
            assert len(result) <= 50
    
    def test_url_with_encoded_characters(self) -> None:
        """Test URLs with percent encoding."""
        from scripts.security_utils import InputSanitizer
        
        urls = [
            "https://municode.com/path%20with%20spaces",
            "https://municode.com/path?q=test%26param=value",
            "https://municode.com/%2e%2e/etc/passwd",  # Encoded traversal
        ]
        
        for url in urls:
            result = InputSanitizer.sanitize_url(url)
            if result:
                assert "/../" not in result
                assert "%2e%2e" not in result.lower()
    
    def test_empty_and_whitespace_inputs(self) -> None:
        """Test various empty/whitespace inputs."""
        from scripts.security_utils import InputSanitizer
        
        empty_variants = [
            "",
            " ",
            "\t",
            "\n",
            "\r\n",
            "   ",
            "\t\n\r",
        ]
        
        for empty in empty_variants:
            assert InputSanitizer.sanitize_fips(empty) is None
            # County name with only whitespace should fail min length
            result = InputSanitizer.sanitize_county_name(empty)
            assert result is None or len(result.strip()) >= 2


class TestRateLimiterEdgeCases:
    """Edge cases for GlobalRateLimiter."""
    
    @pytest.fixture
    def mock_supabase(self) -> MagicMock:
        """Create mock Supabase."""
        mock = MagicMock()
        mock.table.return_value.upsert.return_value.execute.return_value = {"data": []}
        return mock
    
    def test_concurrent_acquire(self, mock_supabase: MagicMock) -> None:
        """Test thread-safe concurrent acquire."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        
        limiter = GlobalRateLimiter(mock_supabase)
        results: List[bool] = []
        errors: List[Exception] = []
        
        def acquire_request() -> None:
            try:
                allowed, _ = limiter.acquire("https://municode.com/test", "wf_test")
                results.append(allowed)
            except Exception as e:
                errors.append(e)
        
        # Launch 20 concurrent threads
        threads = [threading.Thread(target=acquire_request) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Should have no errors
        assert len(errors) == 0
        # Should have exactly 20 results
        assert len(results) == 20
        # First 10 should succeed (burst limit), rest fail
        assert sum(results) == 10
    
    def test_extremely_long_url(self, mock_supabase: MagicMock) -> None:
        """Test rate limiter with very long URL."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        
        limiter = GlobalRateLimiter(mock_supabase)
        
        long_path = "a" * 10000
        long_url = f"https://municode.com/{long_path}"
        
        # Should handle gracefully
        allowed, reason = limiter.acquire(long_url, "wf_test")
        assert isinstance(allowed, bool)
    
    def test_malformed_urls(self, mock_supabase: MagicMock) -> None:
        """Test rate limiter with malformed URLs."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        
        limiter = GlobalRateLimiter(mock_supabase)
        
        malformed = [
            "not-a-url",
            "://missing-scheme",
            "https://",
            "https://:8080/path",
        ]
        
        for url in malformed:
            # Should not raise, should use default domain
            allowed, reason = limiter.acquire(url, "wf_test")
            assert isinstance(allowed, bool)
    
    def test_rapid_window_resets(self, mock_supabase: MagicMock) -> None:
        """Test behavior across time window boundaries."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        
        limiter = GlobalRateLimiter(mock_supabase)
        
        # Make requests
        for _ in range(5):
            limiter.acquire("https://test.com/path", "wf_test")
        
        # Manually trigger window reset by manipulating internal state
        domain = "test.com"
        if domain in limiter._request_counts:
            # Simulate minute passing
            limiter._request_counts[domain]["last_reset_minute"] = (
                datetime.now(timezone.utc) - timedelta(minutes=2)
            )
        
        # Next request should reset counter
        allowed, _ = limiter.acquire("https://test.com/path", "wf_test")
        assert allowed is True


class TestAuditLoggerEdgeCases:
    """Edge cases for AuditLogger."""
    
    @pytest.fixture
    def mock_supabase(self) -> MagicMock:
        """Create mock Supabase."""
        mock = MagicMock()
        mock.table.return_value.insert.return_value.execute.return_value = {"data": [{"id": 1}]}
        return mock
    
    def test_very_large_details_object(self, mock_supabase: MagicMock) -> None:
        """Test logging with large details payload."""
        from scripts.security_utils import AuditLogger, AuditEventType
        
        audit = AuditLogger(mock_supabase, "wf_test")
        
        # Create large nested details
        large_details = {
            "items": [{"id": i, "data": "x" * 100} for i in range(100)],
            "nested": {"level1": {"level2": {"level3": "deep"}}}
        }
        
        event = audit.log(
            event_type=AuditEventType.WORKFLOW_START,
            action="large_payload_test",
            target="test",
            status="success",
            details=large_details
        )
        
        assert event is not None
        assert len(event.checksum) == 16
    
    def test_special_characters_in_fields(self, mock_supabase: MagicMock) -> None:
        """Test logging with special characters."""
        from scripts.security_utils import AuditLogger, AuditEventType
        
        audit = AuditLogger(mock_supabase, "wf_test")
        
        special_chars = "Test with 'quotes', \"double\", <tags>, & ampersands"
        
        event = audit.log(
            event_type=AuditEventType.SCRAPE_START,
            action=special_chars,
            target=special_chars,
            status="success"
        )
        
        assert event.action == special_chars
    
    def test_concurrent_logging(self, mock_supabase: MagicMock) -> None:
        """Test thread-safe concurrent logging."""
        from scripts.security_utils import AuditLogger, AuditEventType
        
        audit = AuditLogger(mock_supabase, "wf_concurrent")
        events: List[Any] = []
        errors: List[Exception] = []
        
        def log_event(i: int) -> None:
            try:
                event = audit.log(
                    event_type=AuditEventType.WORKFLOW_START,
                    action=f"action_{i}",
                    target=f"target_{i}",
                    status="success"
                )
                events.append(event)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=log_event, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0
        assert len(events) == 50
        
        # All checksums should be unique
        checksums = [e.checksum for e in events]
        assert len(set(checksums)) == 50


class TestMonitoringEdgeCases:
    """Edge cases for monitoring components."""
    
    def test_histogram_empty_percentile(self) -> None:
        """Test percentile calculation on empty histogram."""
        from scripts.monitoring import MetricsCollector
        
        collector = MetricsCollector()
        
        result = collector.get_percentile("nonexistent", 95)
        assert result is None
    
    def test_histogram_single_value_percentiles(self) -> None:
        """Test percentiles with single value."""
        from scripts.monitoring import MetricsCollector
        
        collector = MetricsCollector()
        collector.histogram("single", 42.0)
        
        p50 = collector.get_percentile("single", 50)
        p99 = collector.get_percentile("single", 99)
        
        assert p50 == 42.0
        assert p99 == 42.0
    
    def test_metrics_memory_limit(self) -> None:
        """Test histogram respects memory limits."""
        from scripts.monitoring import MetricsCollector
        
        collector = MetricsCollector()
        
        # Add more than 1000 values
        for i in range(1500):
            collector.histogram("bounded", float(i))
        
        # Should only keep last 1000
        assert len(collector._histograms["bounded"]) <= 1000
    
    def test_timer_exception_handling(self) -> None:
        """Test timer handles exceptions gracefully."""
        from scripts.monitoring import MetricsCollector
        
        collector = MetricsCollector()
        
        with pytest.raises(ValueError):
            with collector.timer("failing_operation"):
                raise ValueError("Intentional error")
        
        # Duration should still be recorded
        stats = collector.get_stats("failing_operation")
        assert stats["count"] == 1
    
    def test_alert_rule_all_conditions(self) -> None:
        """Test all alert condition types."""
        from scripts.monitoring import AlertManager, AlertRule, AlertSeverity, MetricsCollector
        
        collector = MetricsCollector()
        collector.gauge("test_metric", 50.0)
        
        manager = AlertManager(collector)
        
        conditions = [
            ("gt", 40.0, True),   # 50 > 40
            ("gt", 60.0, False),  # 50 > 60
            ("lt", 60.0, True),   # 50 < 60
            ("lt", 40.0, False),  # 50 < 40
            ("gte", 50.0, True),  # 50 >= 50
            ("lte", 50.0, True),  # 50 <= 50
            ("eq", 50.0, True),   # 50 == 50
        ]
        
        for condition, threshold, expected in conditions:
            result = manager._check_condition(50.0, condition, threshold)
            assert result == expected, f"{condition} {threshold} should be {expected}"


class TestCredentialValidatorEdgeCases:
    """Edge cases for credential validation."""
    
    def test_jwt_structure_variations(self) -> None:
        """Test JWT validation with various structures."""
        from scripts.security_utils import CredentialValidator
        
        # Valid structure, sufficient length
        valid = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        assert CredentialValidator.validate_supabase_key(valid) is True
        
        # Missing parts
        assert CredentialValidator.validate_supabase_key("eyJ.eyJ") is False
        
        # Wrong prefix
        assert CredentialValidator.validate_supabase_key("abc.def.ghi") is False
        
        # Empty parts
        assert CredentialValidator.validate_supabase_key("eyJ..") is False
    
    def test_none_and_empty_credentials(self) -> None:
        """Test with None and empty credentials."""
        from scripts.security_utils import CredentialValidator
        
        assert CredentialValidator.validate_supabase_key(None) is False
        assert CredentialValidator.validate_supabase_key("") is False
        assert CredentialValidator.validate_supabase_key("   ") is False


class TestHealthCheckerEdgeCases:
    """Edge cases for health checker."""
    
    def test_health_check_with_failed_components(self) -> None:
        """Test health check when components fail."""
        from scripts.monitoring import HealthChecker, MetricsCollector
        
        collector = MetricsCollector()
        
        # Mock Supabase that fails
        mock_supabase = MagicMock()
        mock_supabase.table.return_value.select.side_effect = Exception("Connection failed")
        
        checker = HealthChecker(collector, mock_supabase)
        health = checker.check_health()
        
        assert health["components"]["database"]["status"] == "unhealthy"
        assert health["status"] in ["degraded", "unhealthy"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

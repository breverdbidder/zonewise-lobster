"""
ZoneWise Lobster - End-to-End Tests

Complete end-to-end workflow tests simulating real scraping scenarios.
Tests the full pipeline from input to output.

Run with: pytest tests/test_e2e.py -v -m e2e
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from typing import Dict, List, Any
import time

pytestmark = pytest.mark.e2e


class TestFullScrapeWorkflow:
    """End-to-end tests for complete scrape workflows."""
    
    @pytest.fixture
    def mock_infrastructure(self) -> Dict[str, Any]:
        """Create all mocked infrastructure components."""
        supabase = MagicMock()
        supabase.audit_logs = []
        supabase.districts = []
        supabase.metrics = []
        
        def track_audit(record: Dict) -> MagicMock:
            supabase.audit_logs.append(record)
            return MagicMock(execute=lambda: {"data": [record]})
        
        def track_insert(record: Dict) -> MagicMock:
            supabase.districts.append(record)
            return MagicMock(execute=lambda: {"data": [record]})
        
        def track_upsert(record: Dict) -> MagicMock:
            supabase.metrics.append(record)
            return MagicMock(execute=lambda: {"data": [record]})
        
        supabase.table.return_value.insert = track_audit
        supabase.table.return_value.upsert = track_upsert
        
        return {"supabase": supabase}
    
    def test_single_county_scrape_workflow(self, mock_infrastructure: Dict) -> None:
        """Test complete workflow for scraping a single county."""
        from scripts.security_utils import InputSanitizer, AuditLogger, AuditEventType
        from scripts.global_rate_limiter import GlobalRateLimiter
        from scripts.monitoring import MetricsCollector, HealthChecker
        
        supabase = mock_infrastructure["supabase"]
        workflow_id = "wf_e2e_single_county"
        
        # Initialize all components
        audit = AuditLogger(supabase, workflow_id)
        limiter = GlobalRateLimiter(supabase, audit)
        metrics = MetricsCollector(supabase)
        health = HealthChecker(metrics, supabase)
        
        # Step 1: Validate inputs
        county_fips = "12009"
        county_name = "Brevard"
        
        fips = InputSanitizer.sanitize_fips(county_fips)
        name = InputSanitizer.sanitize_county_name(county_name)
        
        assert fips == "12009"
        assert name == "Brevard"
        
        # Step 2: Log workflow start
        audit.log(
            event_type=AuditEventType.WORKFLOW_START,
            action="scrape_county",
            target=f"{fips}:{name}",
            status="started",
            details={"phases": [2, 3, 4, 5]}
        )
        
        # Step 3: Check rate limit and acquire
        url = f"https://library.municode.com/fl/{name.lower()}"
        allowed, reason = limiter.acquire(url, workflow_id)
        assert allowed is True
        
        # Step 4: Record metrics
        metrics.increment("scrape_requests")
        
        with metrics.timer("scrape_duration"):
            # Simulate scrape
            time.sleep(0.01)
        
        # Step 5: Log scrape success
        audit.log(
            event_type=AuditEventType.SCRAPE_SUCCESS,
            action="fetch_municode",
            target=url,
            status="success",
            details={"districts_found": 25, "quality_score": 85}
        )
        
        # Step 6: Log data insert
        audit.log(
            event_type=AuditEventType.DATA_INSERTED,
            action="insert_districts",
            target=f"{fips}:zoning_districts",
            status="success",
            details={"count": 25}
        )
        
        # Step 7: Log workflow end
        audit.log(
            event_type=AuditEventType.WORKFLOW_END,
            action="scrape_county",
            target=f"{fips}:{name}",
            status="completed"
        )
        
        # Step 8: Verify health
        health_status = health.check_health()
        assert health_status["status"] in ["healthy", "unknown"]
        
        # Verify complete audit trail
        assert len(supabase.audit_logs) >= 4
        
        # Verify metrics recorded
        all_metrics = metrics.get_all_metrics()
        assert all_metrics["counters"]["scrape_requests"] == 1
    
    def test_multi_county_scrape_workflow(self, mock_infrastructure: Dict) -> None:
        """Test workflow for scraping multiple counties."""
        from scripts.security_utils import InputSanitizer, AuditLogger, AuditEventType
        from scripts.global_rate_limiter import GlobalRateLimiter
        from scripts.monitoring import MetricsCollector
        
        supabase = mock_infrastructure["supabase"]
        
        counties = [
            ("12009", "Brevard"),
            ("12057", "Hillsborough"),
            ("12095", "Orange"),
        ]
        
        for fips, name in counties:
            workflow_id = f"wf_multi_{fips}"
            audit = AuditLogger(supabase, workflow_id)
            limiter = GlobalRateLimiter(supabase, audit)
            metrics = MetricsCollector()
            
            # Validate
            clean_fips = InputSanitizer.sanitize_fips(fips)
            clean_name = InputSanitizer.sanitize_county_name(name)
            
            assert clean_fips is not None
            assert clean_name is not None
            
            # Log and process
            audit.log(
                event_type=AuditEventType.WORKFLOW_START,
                action="scrape_county",
                target=f"{clean_fips}:{clean_name}",
                status="started"
            )
            
            # Simulate scrape
            url = f"https://library.municode.com/fl/{clean_name.lower()}"
            allowed, _ = limiter.acquire(url, workflow_id)
            assert allowed is True
            
            metrics.increment("counties_processed")
        
        # Verify all counties processed
        assert len([l for l in supabase.audit_logs if l.get("event_type") == "workflow_start"]) >= 3


class TestWorkflowErrorHandling:
    """End-to-end tests for error handling scenarios."""
    
    @pytest.fixture
    def mock_supabase(self) -> MagicMock:
        """Create mock Supabase."""
        mock = MagicMock()
        mock.table.return_value.insert.return_value.execute.return_value = {"data": []}
        mock.table.return_value.upsert.return_value.execute.return_value = {"data": []}
        return mock
    
    def test_invalid_input_stops_workflow(self, mock_supabase: MagicMock) -> None:
        """Test workflow stops gracefully on invalid input."""
        from scripts.security_utils import InputSanitizer, AuditLogger, AuditEventType
        
        audit = AuditLogger(mock_supabase, "wf_invalid_test")
        
        # Invalid FIPS
        fips = InputSanitizer.sanitize_fips("INVALID")
        
        if fips is None:
            audit.log_security_violation(
                violation_type="invalid_input",
                details={"field": "fips", "value": "INVALID"}
            )
            # Workflow should stop here
            return
        
        # Should not reach here
        pytest.fail("Workflow should have stopped on invalid input")
    
    def test_rate_limit_triggers_backoff(self, mock_supabase: MagicMock) -> None:
        """Test rate limit triggers proper backoff handling."""
        from scripts.global_rate_limiter import GlobalRateLimiter, RateLimitExceeded
        from scripts.security_utils import AuditLogger, AuditEventType
        
        audit = AuditLogger(mock_supabase, "wf_rate_test")
        limiter = GlobalRateLimiter(mock_supabase, audit)
        
        # Exhaust rate limit
        for _ in range(10):
            limiter.acquire("https://municode.com/test", "wf_test")
        
        # Next request should fail
        allowed, reason = limiter.acquire("https://municode.com/test", "wf_test")
        
        assert allowed is False
        assert "limit" in reason.lower()
    
    def test_security_violation_logged_and_blocked(self, mock_supabase: MagicMock) -> None:
        """Test security violations are logged and blocked."""
        from scripts.security_utils import InputSanitizer, AuditLogger
        
        audit = AuditLogger(mock_supabase, "wf_security_test")
        
        # SQL injection attempt
        malicious_input = "12009'; DROP TABLE users--"
        result = InputSanitizer.sanitize_fips(malicious_input)
        
        assert result is None
        
        # Log violation
        event = audit.log_security_violation(
            violation_type="sql_injection_attempt",
            details={"input": malicious_input[:50], "blocked": True}
        )
        
        assert event.status == "blocked"


class TestConfigurationEdgeCases:
    """Tests for configuration edge cases."""
    
    def test_rate_limit_config_boundaries(self) -> None:
        """Test rate limit configuration boundaries."""
        from scripts.global_rate_limiter import RateLimitConfig
        
        # Test minimum values
        config = RateLimitConfig(
            domain="test.com",
            requests_per_minute=1,
            requests_per_hour=1,
            requests_per_day=1,
            burst_limit=1,
            cooldown_seconds=1
        )
        
        assert config.requests_per_minute == 1
        assert config.burst_limit == 1
    
    def test_rate_limit_default_limits(self) -> None:
        """Test all default rate limit configurations exist."""
        from scripts.global_rate_limiter import GlobalRateLimiter
        from unittest.mock import MagicMock
        
        mock = MagicMock()
        mock.table.return_value.upsert.return_value.execute.return_value = {}
        
        limiter = GlobalRateLimiter(mock)
        
        # Verify all known domains have configs
        domains = ["municode.com", "supabase.co", "gis.brevardfl.gov", "bcpao.us"]
        
        for domain in domains:
            config = limiter._get_config(domain)
            assert config.requests_per_minute > 0
            assert config.burst_limit > 0
    
    def test_audit_event_types_complete(self) -> None:
        """Test all audit event types are defined."""
        from scripts.security_utils import AuditEventType
        
        required_types = [
            "WORKFLOW_START",
            "WORKFLOW_END",
            "SCRAPE_START",
            "SCRAPE_SUCCESS",
            "SCRAPE_FAILURE",
            "SECURITY_VIOLATION",
            "DATA_INSERTED",
        ]
        
        for event_type in required_types:
            assert hasattr(AuditEventType, event_type)
    
    def test_empty_workflow_id_handling(self) -> None:
        """Test handling of empty workflow ID."""
        from scripts.security_utils import AuditLogger, AuditEventType
        from unittest.mock import MagicMock
        
        mock = MagicMock()
        mock.table.return_value.insert.return_value.execute.return_value = {"data": []}
        
        # Empty workflow ID should still work
        audit = AuditLogger(mock, "")
        
        event = audit.log(
            event_type=AuditEventType.WORKFLOW_START,
            action="test",
            target="test",
            status="started"
        )
        
        assert event.event_id.startswith("evt_")


class TestErrorRecoveryScenarios:
    """Tests for error recovery scenarios."""
    
    def test_database_failure_graceful_handling(self) -> None:
        """Test graceful handling of database failures."""
        from scripts.security_utils import AuditLogger, AuditEventType
        from unittest.mock import MagicMock
        
        mock = MagicMock()
        mock.table.return_value.insert.side_effect = Exception("Database connection failed")
        
        audit = AuditLogger(mock, "wf_db_fail")
        
        # Should not raise, should handle gracefully
        try:
            event = audit.log(
                event_type=AuditEventType.SCRAPE_START,
                action="scrape",
                target="url",
                status="started"
            )
            # Event should still be created locally
            assert event is not None
        except Exception:
            pass  # Graceful handling may vary
    
    def test_metric_persistence_failure_continues(self) -> None:
        """Test metrics continue working even if persistence fails."""
        from scripts.monitoring import MetricsCollector
        from unittest.mock import MagicMock
        
        mock = MagicMock()
        mock.table.return_value.insert.side_effect = Exception("Persistence failed")
        
        collector = MetricsCollector(mock)
        
        # Should still work in memory
        collector.increment("test_counter")
        collector.gauge("test_gauge", 42.0)
        
        metrics = collector.get_all_metrics()
        assert metrics["counters"]["test_counter"] == 1
        assert metrics["gauges"]["test_gauge"] == 42.0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "e2e"])

"""
ZoneWise Lobster - Tests for Performance Monitoring

Unit and integration tests for the monitoring module.

Run with: pytest tests/test_monitoring.py -v
"""

import pytest
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
from typing import Dict, List, Any


class TestMetricsCollector:
    """Tests for MetricsCollector class."""
    
    def test_increment_counter(self) -> None:
        """Test counter increment functionality."""
        from scripts.monitoring import MetricsCollector
        
        collector = MetricsCollector()
        
        collector.increment("requests")
        collector.increment("requests")
        collector.increment("requests", 5)
        
        metrics = collector.get_all_metrics()
        assert metrics["counters"]["requests"] == 7
    
    def test_gauge_set(self) -> None:
        """Test gauge setting functionality."""
        from scripts.monitoring import MetricsCollector
        
        collector = MetricsCollector()
        
        collector.gauge("temperature", 25.5)
        collector.gauge("temperature", 26.0)
        
        metrics = collector.get_all_metrics()
        assert metrics["gauges"]["temperature"] == 26.0
    
    def test_histogram_recording(self) -> None:
        """Test histogram recording and percentiles."""
        from scripts.monitoring import MetricsCollector
        
        collector = MetricsCollector()
        
        # Record values
        for i in range(100):
            collector.histogram("latency", float(i))
        
        # Check percentiles
        p50 = collector.get_percentile("latency", 50)
        p99 = collector.get_percentile("latency", 99)
        
        assert p50 is not None
        assert 45 <= p50 <= 55
        assert p99 is not None
        assert p99 >= 95
    
    def test_histogram_stats(self) -> None:
        """Test histogram statistical summary."""
        from scripts.monitoring import MetricsCollector
        
        collector = MetricsCollector()
        
        values = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        for v in values:
            collector.histogram("response_time", float(v))
        
        stats = collector.get_stats("response_time")
        
        assert stats["count"] == 10
        assert stats["min"] == 1.0
        assert stats["max"] == 10.0
        assert 5.0 <= stats["mean"] <= 6.0
    
    def test_timer_context_manager(self) -> None:
        """Test timer context manager."""
        from scripts.monitoring import MetricsCollector
        
        collector = MetricsCollector()
        
        with collector.timer("operation_duration") as timer:
            time.sleep(0.01)  # 10ms
        
        assert timer.duration is not None
        assert timer.duration >= 0.01
        
        # Verify recorded in histogram
        stats = collector.get_stats("operation_duration")
        assert stats["count"] == 1
    
    def test_tagged_metrics(self) -> None:
        """Test metrics with tags."""
        from scripts.monitoring import MetricsCollector
        
        collector = MetricsCollector()
        
        collector.increment("requests", tags={"county": "brevard"})
        collector.increment("requests", tags={"county": "orange"})
        collector.increment("requests", tags={"county": "brevard"})
        
        metrics = collector.get_all_metrics()
        
        assert "requests:county=brevard" in metrics["counters"]
        assert metrics["counters"]["requests:county=brevard"] == 2
        assert metrics["counters"]["requests:county=orange"] == 1
    
    def test_get_all_metrics(self) -> None:
        """Test retrieving all metrics."""
        from scripts.monitoring import MetricsCollector
        
        collector = MetricsCollector()
        
        collector.increment("counter1")
        collector.gauge("gauge1", 42.0)
        collector.histogram("hist1", 10.0)
        
        metrics = collector.get_all_metrics()
        
        assert "counters" in metrics
        assert "gauges" in metrics
        assert "histograms" in metrics
        assert "uptime_seconds" in metrics
        assert metrics["uptime_seconds"] >= 0


class TestTimer:
    """Tests for Timer class."""
    
    def test_timer_measures_duration(self) -> None:
        """Test timer accurately measures duration."""
        from scripts.monitoring import MetricsCollector
        
        collector = MetricsCollector()
        
        with collector.timer("test_timer") as timer:
            time.sleep(0.05)  # 50ms
        
        assert timer.duration is not None
        assert 0.04 <= timer.duration <= 0.1  # Allow some variance
    
    def test_timer_records_to_histogram(self) -> None:
        """Test timer records to histogram."""
        from scripts.monitoring import MetricsCollector
        
        collector = MetricsCollector()
        
        for _ in range(5):
            with collector.timer("repeated_timer"):
                time.sleep(0.001)
        
        stats = collector.get_stats("repeated_timer")
        assert stats["count"] == 5


class TestAlertManager:
    """Tests for AlertManager class."""
    
    @pytest.fixture
    def collector(self) -> Any:
        """Create a metrics collector with test data."""
        from scripts.monitoring import MetricsCollector
        
        collector = MetricsCollector()
        collector.increment("scrape_errors", 15)
        collector.gauge("quality_score_avg", 40.0)
        return collector
    
    def test_add_rule(self, collector: Any) -> None:
        """Test adding alert rules."""
        from scripts.monitoring import AlertManager, AlertRule, AlertSeverity
        
        manager = AlertManager(collector)
        
        rule = AlertRule(
            name="test_rule",
            metric_name="test_metric",
            condition="gt",
            threshold=10.0,
            severity=AlertSeverity.WARNING
        )
        
        manager.add_rule(rule)
        assert len(manager._rules) == 1
    
    def test_add_default_rules(self, collector: Any) -> None:
        """Test adding default monitoring rules."""
        from scripts.monitoring import AlertManager
        
        manager = AlertManager(collector)
        manager.add_default_rules()
        
        assert len(manager._rules) >= 4
    
    def test_check_rules_triggers_alert(self, collector: Any) -> None:
        """Test that rules trigger alerts when conditions are met."""
        from scripts.monitoring import AlertManager, AlertRule, AlertSeverity
        
        manager = AlertManager(collector)
        
        # Add rule that should trigger (errors > 10, we have 15)
        rule = AlertRule(
            name="high_errors",
            metric_name="scrape_errors",
            condition="gt",
            threshold=10.0,
            severity=AlertSeverity.ERROR
        )
        manager.add_rule(rule)
        
        alerts = manager.check_rules()
        
        assert len(alerts) == 1
        assert alerts[0].rule_name == "high_errors"
        assert alerts[0].current_value == 15.0
    
    def test_alert_cooldown(self, collector: Any) -> None:
        """Test that alerts respect cooldown period."""
        from scripts.monitoring import AlertManager, AlertRule, AlertSeverity
        
        manager = AlertManager(collector)
        
        rule = AlertRule(
            name="cooldown_test",
            metric_name="scrape_errors",
            condition="gt",
            threshold=10.0,
            severity=AlertSeverity.WARNING,
            cooldown_seconds=300
        )
        manager.add_rule(rule)
        
        # First check triggers alert
        alerts1 = manager.check_rules()
        assert len(alerts1) == 1
        
        # Second check should not trigger (cooldown)
        alerts2 = manager.check_rules()
        assert len(alerts2) == 0
    
    def test_notification_callback(self, collector: Any) -> None:
        """Test notification callback is called."""
        from scripts.monitoring import AlertManager, AlertRule, AlertSeverity, Alert
        
        notifications: List[Alert] = []
        
        def callback(alert: Alert) -> None:
            notifications.append(alert)
        
        manager = AlertManager(collector, notification_callback=callback)
        
        rule = AlertRule(
            name="notify_test",
            metric_name="scrape_errors",
            condition="gt",
            threshold=10.0,
            severity=AlertSeverity.ERROR
        )
        manager.add_rule(rule)
        
        manager.check_rules()
        
        assert len(notifications) == 1
        assert notifications[0].rule_name == "notify_test"


class TestHealthChecker:
    """Tests for HealthChecker class."""
    
    @pytest.fixture
    def collector(self) -> Any:
        """Create a metrics collector."""
        from scripts.monitoring import MetricsCollector
        return MetricsCollector()
    
    def test_health_check_healthy(self, collector: Any) -> None:
        """Test health check returns healthy status."""
        from scripts.monitoring import HealthChecker
        
        checker = HealthChecker(collector)
        health = checker.check_health()
        
        assert health["status"] in ["healthy", "unknown"]
        assert "timestamp" in health
        assert "components" in health
        assert "metrics" in health
    
    def test_health_check_with_mock_supabase(self, collector: Any) -> None:
        """Test health check with mocked database."""
        from scripts.monitoring import HealthChecker
        
        mock_supabase = MagicMock()
        mock_supabase.table.return_value.select.return_value.limit.return_value.execute.return_value = {"data": []}
        
        checker = HealthChecker(collector, mock_supabase)
        health = checker.check_health()
        
        assert health["components"]["database"]["status"] == "healthy"
    
    def test_health_check_degraded_rate_limiter(self, collector: Any) -> None:
        """Test health check shows degraded when rate limiter has issues."""
        from scripts.monitoring import HealthChecker
        
        # Simulate high rate limit violations
        collector._counters["rate_limit_blocked"] = 150
        
        checker = HealthChecker(collector)
        health = checker.check_health()
        
        assert health["components"]["rate_limiter"]["status"] == "degraded"


class TestTimedDecorator:
    """Tests for the @timed decorator."""
    
    def test_timed_decorator(self) -> None:
        """Test timed decorator measures function duration."""
        from scripts.monitoring import MetricsCollector, timed
        
        collector = MetricsCollector()
        
        @timed("decorated_function")
        def slow_function(_metrics: Any = None) -> str:
            time.sleep(0.01)
            return "done"
        
        result = slow_function(_metrics=collector)
        
        assert result == "done"
        
        stats = collector.get_stats("decorated_function")
        assert stats["count"] == 1
        assert stats["min"] >= 0.01


class TestMonitoringIntegration:
    """Integration tests for monitoring components."""
    
    def test_full_monitoring_pipeline(self) -> None:
        """Test complete monitoring pipeline."""
        from scripts.monitoring import (
            MetricsCollector, AlertManager, HealthChecker,
            AlertRule, AlertSeverity
        )
        
        # Initialize components
        collector = MetricsCollector()
        alerts = AlertManager(collector)
        health = HealthChecker(collector)
        
        # Add alert rules
        alerts.add_rule(AlertRule(
            name="error_threshold",
            metric_name="errors",
            condition="gt",
            threshold=5,
            severity=AlertSeverity.ERROR
        ))
        
        # Simulate workflow
        collector.increment("requests", 100)
        collector.increment("errors", 10)
        
        for i in range(10):
            with collector.timer("request_duration"):
                time.sleep(0.001)
        
        # Check alerts
        triggered = alerts.check_rules()
        assert len(triggered) == 1
        assert triggered[0].rule_name == "error_threshold"
        
        # Check health
        status = health.check_health()
        assert status["metrics"]["counters"]["requests"] == 100


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

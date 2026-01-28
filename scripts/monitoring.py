"""
ZoneWise Lobster - Performance Monitoring & Alerting

Provides real-time metrics collection, health checks, and alerting
for the scraping infrastructure.

Features:
- Metrics collection (latency, throughput, error rates)
- Health check endpoints
- Configurable alerting thresholds
- Supabase metrics persistence

Author: BidDeed.AI
Version: 1.0.0
"""

from __future__ import annotations

import time
import statistics
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Callable, TypeVar
from dataclasses import dataclass, field, asdict
from functools import wraps
from enum import Enum
import threading
import logging

logger = logging.getLogger(__name__)

T = TypeVar('T')


class MetricType(Enum):
    """Types of metrics that can be collected."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


class AlertSeverity(Enum):
    """Severity levels for alerts."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class MetricPoint:
    """A single metric data point."""
    name: str
    value: float
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tags: Dict[str, str] = field(default_factory=dict)
    metric_type: MetricType = MetricType.GAUGE


@dataclass
class AlertRule:
    """Configuration for an alert rule."""
    name: str
    metric_name: str
    condition: str  # "gt", "lt", "eq", "gte", "lte"
    threshold: float
    severity: AlertSeverity
    cooldown_seconds: int = 300  # 5 minutes default
    description: str = ""


@dataclass
class Alert:
    """An alert that has been triggered."""
    rule_name: str
    metric_name: str
    current_value: float
    threshold: float
    severity: AlertSeverity
    triggered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    message: str = ""


class MetricsCollector:
    """
    Collects and aggregates performance metrics.
    
    Thread-safe implementation for collecting metrics across
    multiple workflows and components.
    
    Attributes:
        metrics: Dictionary of collected metrics
        histograms: Dictionary of histogram data for percentile calculations
    """
    
    def __init__(self, supabase_client: Optional[Any] = None) -> None:
        """
        Initialize metrics collector.
        
        Args:
            supabase_client: Optional Supabase client for persistence
        """
        self.supabase = supabase_client
        self._metrics: Dict[str, List[MetricPoint]] = {}
        self._counters: Dict[str, float] = {}
        self._gauges: Dict[str, float] = {}
        self._histograms: Dict[str, List[float]] = {}
        self._lock = threading.Lock()
        self._start_time = datetime.now(timezone.utc)
    
    def increment(
        self, 
        name: str, 
        value: float = 1.0, 
        tags: Optional[Dict[str, str]] = None
    ) -> None:
        """
        Increment a counter metric.
        
        Args:
            name: Metric name
            value: Amount to increment (default: 1)
            tags: Optional tags for the metric
        """
        with self._lock:
            key = self._make_key(name, tags)
            self._counters[key] = self._counters.get(key, 0.0) + value
            self._record_point(name, self._counters[key], MetricType.COUNTER, tags)
    
    def gauge(
        self, 
        name: str, 
        value: float, 
        tags: Optional[Dict[str, str]] = None
    ) -> None:
        """
        Set a gauge metric to a specific value.
        
        Args:
            name: Metric name
            value: Current value
            tags: Optional tags for the metric
        """
        with self._lock:
            key = self._make_key(name, tags)
            self._gauges[key] = value
            self._record_point(name, value, MetricType.GAUGE, tags)
    
    def histogram(
        self, 
        name: str, 
        value: float, 
        tags: Optional[Dict[str, str]] = None
    ) -> None:
        """
        Record a value in a histogram for percentile calculations.
        
        Args:
            name: Metric name
            value: Value to record
            tags: Optional tags for the metric
        """
        with self._lock:
            key = self._make_key(name, tags)
            if key not in self._histograms:
                self._histograms[key] = []
            self._histograms[key].append(value)
            
            # Keep last 1000 values for memory efficiency
            if len(self._histograms[key]) > 1000:
                self._histograms[key] = self._histograms[key][-1000:]
            
            self._record_point(name, value, MetricType.HISTOGRAM, tags)
    
    def timer(self, name: str, tags: Optional[Dict[str, str]] = None) -> 'Timer':
        """
        Create a timer context manager for measuring duration.
        
        Args:
            name: Metric name for the timing
            tags: Optional tags for the metric
            
        Returns:
            Timer context manager
        """
        return Timer(self, name, tags)
    
    def _make_key(self, name: str, tags: Optional[Dict[str, str]]) -> str:
        """Create a unique key for a metric with tags."""
        if not tags:
            return name
        tag_str = ",".join(f"{k}={v}" for k, v in sorted(tags.items()))
        return f"{name}:{tag_str}"
    
    def _record_point(
        self, 
        name: str, 
        value: float, 
        metric_type: MetricType,
        tags: Optional[Dict[str, str]]
    ) -> None:
        """Record a metric point for persistence."""
        point = MetricPoint(
            name=name,
            value=value,
            metric_type=metric_type,
            tags=tags or {}
        )
        
        if name not in self._metrics:
            self._metrics[name] = []
        self._metrics[name].append(point)
        
        # Keep last 100 points per metric
        if len(self._metrics[name]) > 100:
            self._metrics[name] = self._metrics[name][-100:]
    
    def get_percentile(
        self, 
        name: str, 
        percentile: float,
        tags: Optional[Dict[str, str]] = None
    ) -> Optional[float]:
        """
        Get a percentile value from a histogram.
        
        Args:
            name: Metric name
            percentile: Percentile to calculate (0-100)
            tags: Optional tags to filter by
            
        Returns:
            Percentile value or None if no data
        """
        key = self._make_key(name, tags)
        with self._lock:
            if key not in self._histograms or not self._histograms[key]:
                return None
            
            sorted_values = sorted(self._histograms[key])
            index = int(len(sorted_values) * percentile / 100)
            return sorted_values[min(index, len(sorted_values) - 1)]
    
    def get_stats(
        self, 
        name: str,
        tags: Optional[Dict[str, str]] = None
    ) -> Dict[str, float]:
        """
        Get statistical summary for a histogram metric.
        
        Args:
            name: Metric name
            tags: Optional tags to filter by
            
        Returns:
            Dictionary with min, max, mean, median, p95, p99
        """
        key = self._make_key(name, tags)
        with self._lock:
            if key not in self._histograms or not self._histograms[key]:
                return {}
            
            values = self._histograms[key]
            sorted_values = sorted(values)
            
            return {
                "count": len(values),
                "min": min(values),
                "max": max(values),
                "mean": statistics.mean(values),
                "median": statistics.median(values),
                "stddev": statistics.stdev(values) if len(values) > 1 else 0,
                "p95": sorted_values[int(len(sorted_values) * 0.95)],
                "p99": sorted_values[int(len(sorted_values) * 0.99)],
            }
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """
        Get all current metric values.
        
        Returns:
            Dictionary with counters, gauges, and histogram stats
        """
        with self._lock:
            return {
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "histograms": {
                    name: self.get_stats(name) 
                    for name in set(k.split(":")[0] for k in self._histograms.keys())
                },
                "uptime_seconds": (datetime.now(timezone.utc) - self._start_time).total_seconds()
            }
    
    def persist_to_supabase(self) -> bool:
        """
        Persist current metrics to Supabase.
        
        Returns:
            True if persistence successful
        """
        if not self.supabase:
            return False
        
        try:
            metrics = self.get_all_metrics()
            self.supabase.table("daily_metrics").insert({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "metrics": metrics,
                "workflow_id": "monitoring"
            }).execute()
            return True
        except Exception as e:
            logger.error(f"Failed to persist metrics: {e}")
            return False


class Timer:
    """
    Context manager for timing code blocks.
    
    Usage:
        with metrics.timer("scrape_duration"):
            scrape_page()
    """
    
    def __init__(
        self, 
        collector: MetricsCollector, 
        name: str,
        tags: Optional[Dict[str, str]] = None
    ) -> None:
        """
        Initialize timer.
        
        Args:
            collector: MetricsCollector to record to
            name: Metric name
            tags: Optional tags
        """
        self.collector = collector
        self.name = name
        self.tags = tags
        self.start_time: Optional[float] = None
        self.duration: Optional[float] = None
    
    def __enter__(self) -> 'Timer':
        """Start the timer."""
        self.start_time = time.perf_counter()
        return self
    
    def __exit__(self, *args: Any) -> None:
        """Stop the timer and record the duration."""
        if self.start_time:
            self.duration = time.perf_counter() - self.start_time
            self.collector.histogram(self.name, self.duration, self.tags)


class AlertManager:
    """
    Manages alert rules and triggers alerts when thresholds are exceeded.
    
    Attributes:
        rules: List of configured alert rules
        triggered_alerts: Recently triggered alerts
    """
    
    def __init__(
        self, 
        metrics_collector: MetricsCollector,
        notification_callback: Optional[Callable[[Alert], None]] = None
    ) -> None:
        """
        Initialize alert manager.
        
        Args:
            metrics_collector: MetricsCollector to monitor
            notification_callback: Optional callback for alert notifications
        """
        self.metrics = metrics_collector
        self.notify = notification_callback
        self._rules: List[AlertRule] = []
        self._triggered: Dict[str, datetime] = {}
        self._alerts: List[Alert] = []
    
    def add_rule(self, rule: AlertRule) -> None:
        """
        Add an alert rule.
        
        Args:
            rule: AlertRule to add
        """
        self._rules.append(rule)
    
    def add_default_rules(self) -> None:
        """Add default monitoring rules for ZoneWise Lobster."""
        default_rules = [
            AlertRule(
                name="high_error_rate",
                metric_name="scrape_errors",
                condition="gt",
                threshold=10,
                severity=AlertSeverity.ERROR,
                description="Scrape error count exceeded threshold"
            ),
            AlertRule(
                name="slow_scrape",
                metric_name="scrape_duration_p95",
                condition="gt",
                threshold=30.0,  # 30 seconds
                severity=AlertSeverity.WARNING,
                description="95th percentile scrape duration is too high"
            ),
            AlertRule(
                name="rate_limit_violations",
                metric_name="rate_limit_blocked",
                condition="gt",
                threshold=50,
                severity=AlertSeverity.WARNING,
                description="Too many rate limit violations"
            ),
            AlertRule(
                name="low_quality_score",
                metric_name="quality_score_avg",
                condition="lt",
                threshold=50.0,
                severity=AlertSeverity.ERROR,
                description="Average quality score is below threshold"
            ),
        ]
        
        for rule in default_rules:
            self.add_rule(rule)
    
    def check_rules(self) -> List[Alert]:
        """
        Check all rules against current metrics.
        
        Returns:
            List of triggered alerts
        """
        new_alerts: List[Alert] = []
        metrics = self.metrics.get_all_metrics()
        
        for rule in self._rules:
            # Check cooldown
            if rule.name in self._triggered:
                elapsed = (datetime.now(timezone.utc) - self._triggered[rule.name]).total_seconds()
                if elapsed < rule.cooldown_seconds:
                    continue
            
            # Get metric value
            value = self._get_metric_value(rule.metric_name, metrics)
            if value is None:
                continue
            
            # Check condition
            triggered = self._check_condition(value, rule.condition, rule.threshold)
            
            if triggered:
                alert = Alert(
                    rule_name=rule.name,
                    metric_name=rule.metric_name,
                    current_value=value,
                    threshold=rule.threshold,
                    severity=rule.severity,
                    message=f"{rule.description}: {value} {rule.condition} {rule.threshold}"
                )
                
                new_alerts.append(alert)
                self._alerts.append(alert)
                self._triggered[rule.name] = datetime.now(timezone.utc)
                
                # Send notification
                if self.notify:
                    self.notify(alert)
        
        return new_alerts
    
    def _get_metric_value(
        self, 
        metric_name: str, 
        metrics: Dict[str, Any]
    ) -> Optional[float]:
        """Get a metric value from the metrics dictionary."""
        # Check counters
        if metric_name in metrics.get("counters", {}):
            return metrics["counters"][metric_name]
        
        # Check gauges
        if metric_name in metrics.get("gauges", {}):
            return metrics["gauges"][metric_name]
        
        # Check histogram stats
        if "_p95" in metric_name:
            base_name = metric_name.replace("_p95", "")
            if base_name in metrics.get("histograms", {}):
                return metrics["histograms"][base_name].get("p95")
        
        if "_avg" in metric_name:
            base_name = metric_name.replace("_avg", "")
            if base_name in metrics.get("histograms", {}):
                return metrics["histograms"][base_name].get("mean")
        
        return None
    
    def _check_condition(
        self, 
        value: float, 
        condition: str, 
        threshold: float
    ) -> bool:
        """Check if a condition is met."""
        conditions = {
            "gt": value > threshold,
            "lt": value < threshold,
            "gte": value >= threshold,
            "lte": value <= threshold,
            "eq": value == threshold,
        }
        return conditions.get(condition, False)
    
    def get_recent_alerts(self, hours: int = 24) -> List[Alert]:
        """
        Get alerts from the last N hours.
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            List of recent alerts
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        return [a for a in self._alerts if a.triggered_at > cutoff]


class HealthChecker:
    """
    Performs health checks on system components.
    
    Returns standardized health status for monitoring dashboards.
    """
    
    def __init__(
        self, 
        metrics_collector: MetricsCollector,
        supabase_client: Optional[Any] = None
    ) -> None:
        """
        Initialize health checker.
        
        Args:
            metrics_collector: MetricsCollector for metrics health
            supabase_client: Supabase client for database health
        """
        self.metrics = metrics_collector
        self.supabase = supabase_client
    
    def check_health(self) -> Dict[str, Any]:
        """
        Perform comprehensive health check.
        
        Returns:
            Health status dictionary with component statuses
        """
        health = {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "components": {},
            "metrics": {}
        }
        
        # Check metrics collector
        health["components"]["metrics"] = self._check_metrics_health()
        
        # Check database
        health["components"]["database"] = self._check_database_health()
        
        # Check rate limiter
        health["components"]["rate_limiter"] = self._check_rate_limiter_health()
        
        # Get key metrics
        all_metrics = self.metrics.get_all_metrics()
        health["metrics"]["uptime_seconds"] = all_metrics.get("uptime_seconds", 0)
        health["metrics"]["counters"] = all_metrics.get("counters", {})
        
        # Determine overall status
        statuses = [c["status"] for c in health["components"].values()]
        if "unhealthy" in statuses:
            health["status"] = "unhealthy"
        elif "degraded" in statuses:
            health["status"] = "degraded"
        
        return health
    
    def _check_metrics_health(self) -> Dict[str, Any]:
        """Check metrics collector health."""
        try:
            metrics = self.metrics.get_all_metrics()
            return {
                "status": "healthy",
                "uptime_seconds": metrics.get("uptime_seconds", 0),
                "counters_count": len(metrics.get("counters", {})),
                "gauges_count": len(metrics.get("gauges", {}))
            }
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}
    
    def _check_database_health(self) -> Dict[str, Any]:
        """Check Supabase database health."""
        if not self.supabase:
            return {"status": "unknown", "message": "No database configured"}
        
        try:
            # Simple query to check connectivity
            result = self.supabase.table("audit_logs").select("count").limit(1).execute()
            return {"status": "healthy", "connected": True}
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)[:100]}
    
    def _check_rate_limiter_health(self) -> Dict[str, Any]:
        """Check rate limiter health."""
        blocked_count = self.metrics._counters.get("rate_limit_blocked", 0)
        
        if blocked_count > 100:
            return {
                "status": "degraded",
                "blocked_requests": blocked_count,
                "message": "High rate limit violations"
            }
        
        return {"status": "healthy", "blocked_requests": blocked_count}


def timed(metric_name: str, tags: Optional[Dict[str, str]] = None):
    """
    Decorator to time function execution.
    
    Args:
        metric_name: Name of the timing metric
        tags: Optional tags for the metric
        
    Usage:
        @timed("scrape_page")
        def scrape_page(url):
            ...
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            # Get metrics collector from kwargs or use global
            collector = kwargs.pop('_metrics', None)
            
            if collector:
                with collector.timer(metric_name, tags):
                    return func(*args, **kwargs)
            else:
                return func(*args, **kwargs)
        
        return wrapper
    return decorator

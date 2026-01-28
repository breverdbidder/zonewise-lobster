# ADR-004: Performance Monitoring and Alerting Architecture

## Status
**Accepted** - January 2026

## Context
Production systems require observability to:
1. Detect issues before users report them
2. Understand system behavior under load
3. Track SLA compliance
4. Enable data-driven optimization

Initial implementation had no monitoring beyond basic logging.

## Decision
We implemented a **Metrics-based Monitoring System** with these components:

### MetricsCollector
Thread-safe collector supporting multiple metric types:

```python
class MetricType(Enum):
    COUNTER = "counter"      # Monotonically increasing
    GAUGE = "gauge"          # Current value
    HISTOGRAM = "histogram"  # Distribution (for percentiles)
    TIMER = "timer"          # Duration measurements
```

### AlertManager
Configurable alerting with rules:

```python
AlertRule(
    name="high_error_rate",
    metric_name="scrape_errors",
    condition="gt",
    threshold=10,
    severity=AlertSeverity.ERROR,
    cooldown_seconds=300
)
```

### HealthChecker
Standardized health endpoint:

```python
{
    "status": "healthy",
    "timestamp": "2026-01-28T15:00:00Z",
    "components": {
        "metrics": {"status": "healthy"},
        "database": {"status": "healthy"},
        "rate_limiter": {"status": "healthy"}
    }
}
```

### Default Alert Rules
| Rule | Metric | Condition | Severity |
|------|--------|-----------|----------|
| high_error_rate | scrape_errors | > 10 | ERROR |
| slow_scrape | scrape_duration_p95 | > 30s | WARNING |
| rate_limit_violations | rate_limit_blocked | > 50 | WARNING |
| low_quality_score | quality_score_avg | < 50 | ERROR |

## Alternatives Considered

### 1. Prometheus + Grafana
**Rejected**: Infrastructure overhead. We don't need push metrics at our scale.

### 2. DataDog / New Relic
**Rejected**: Cost (~$15/host/month). Our Supabase persistence is sufficient.

### 3. StatsD
**Rejected**: Requires additional infrastructure (statsd daemon).

## Consequences

### Positive
- Real-time visibility into system health
- Proactive alerting before failures cascade
- Historical data for optimization
- Low overhead (~0.1ms per metric)

### Negative
- Supabase storage for metrics grows over time
- Need to implement metric retention policy

## Performance
- MetricsCollector: 100K+ ops/sec
- Timer overhead: <0.1ms
- Health check: <50ms

## Usage Example
```python
from monitoring import MetricsCollector, AlertManager, HealthChecker

# Initialize
metrics = MetricsCollector(supabase)
alerts = AlertManager(metrics)
alerts.add_default_rules()
health = HealthChecker(metrics, supabase)

# Record metrics
metrics.increment("scrape_requests")
with metrics.timer("scrape_duration"):
    scrape_page(url)

# Check health
status = health.check_health()
```

## References
- [Google SRE Book - Monitoring](https://sre.google/sre-book/monitoring-distributed-systems/)
- [RED Method](https://www.weave.works/blog/the-red-method-key-metrics-for-microservices-architecture/)

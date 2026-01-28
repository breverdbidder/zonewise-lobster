# ADR-002: Global Rate Limiting Architecture

## Status
**Accepted** - January 2026

## Context
Web scraping Florida county Municode sites requires careful rate limiting to:
1. Avoid overloading external services
2. Prevent IP bans
3. Comply with robots.txt and ToS
4. Maintain good citizenship on the web

Initial implementation used per-workflow rate limits, but this failed when multiple workflows ran concurrently.

## Decision
We implemented a **Global Rate Limiter** with these components:

### Token Bucket Algorithm
- Allows burst traffic while maintaining average rate
- Thread-safe implementation with locking
- Configurable capacity and refill rate

### Per-Domain Limits
```python
DEFAULT_LIMITS = {
    "municode.com": RateLimitConfig(
        requests_per_minute=30,
        requests_per_hour=500,
        requests_per_day=5000,
        burst_limit=10,
        cooldown_seconds=60
    ),
    # ... other domains
}
```

### Cooldown Mechanism
When burst limit is exceeded:
1. Domain enters cooldown period
2. All requests rejected until cooldown expires
3. Security violation logged to audit trail

### State Persistence
- In-memory state for low latency
- Async persistence to Supabase
- Survives process restarts

## Alternatives Considered

### 1. Redis-based Rate Limiting
**Rejected**: Added infrastructure complexity. Supabase sufficient for our scale.

### 2. Per-Workflow Limits Only
**Rejected**: Failed to prevent aggregate abuse across concurrent workflows.

### 3. External Rate Limiting Service
**Rejected**: Added latency and external dependency.

## Consequences

### Positive
- Prevents service abuse
- Consistent behavior across workflows
- Audit trail for all rate limit events
- Configurable per-domain

### Negative
- Slight overhead per request (~0.1ms)
- State loss on crash (recovers from Supabase)

## Performance
- 1000+ acquires/sec throughput
- <1ms latency per acquire

## References
- [Token Bucket Algorithm](https://en.wikipedia.org/wiki/Token_bucket)
- [Rate Limiting Best Practices](https://cloud.google.com/architecture/rate-limiting-strategies-techniques)

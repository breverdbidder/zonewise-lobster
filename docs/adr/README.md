# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) documenting significant architectural decisions made in ZoneWise Lobster.

## Index

| ADR | Title | Status | Date |
|-----|-------|--------|------|
| [ADR-001](ADR-001-security-first-architecture.md) | Security-First Architecture | Accepted | Jan 2026 |
| [ADR-002](ADR-002-global-rate-limiting.md) | Global Rate Limiting | Accepted | Jan 2026 |
| [ADR-003](ADR-003-audit-logging.md) | Audit Logging with Tamper Detection | Accepted | Jan 2026 |
| [ADR-004](ADR-004-monitoring-architecture.md) | Performance Monitoring & Alerting | Accepted | Jan 2026 |

## Summary

These ADRs document the core architectural decisions that make ZoneWise Lobster a **95+ security and code quality** system:

- **ADR-001**: Defense-in-depth security with deterministic execution
- **ADR-002**: Token bucket rate limiting with per-domain configuration
- **ADR-003**: Tamper-proof audit logging with SHA-256 checksums
- **ADR-004**: Metrics-based monitoring with configurable alerting

## Template

New ADRs should follow this template:

```markdown
# ADR-XXX: Title

## Status
Proposed | Accepted | Deprecated | Superseded

## Context
What is the issue that we're seeing that is motivating this decision?

## Decision
What is the change that we're proposing and/or doing?

## Consequences
What becomes easier or more difficult to do because of this change?
```

## References
- [ADR GitHub Organization](https://adr.github.io/)
- [Michael Nygard's ADR Article](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions)

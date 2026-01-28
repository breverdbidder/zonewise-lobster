# ADR-001: Security-First Architecture

## Status
**Accepted** - January 2026

## Context
ZoneWise Lobster was created to address security vulnerabilities in vanilla LLM-based agentic systems (like Moltbot). The Vibe Code Guild analysis identified critical issues:
- Non-deterministic routing allowing prompt injection
- No approval gates for destructive actions
- Missing audit trails
- Exposed credentials

## Decision
We adopted a **Security-First Architecture** with these core principles:

### 1. Deterministic Execution
Replace LLM-based routing with typed YAML pipelines (Lobster workflows). Every execution path is explicit and auditable.

### 2. Defense in Depth
Multiple security layers:
- **Layer 1**: Input sanitization (InputSanitizer)
- **Layer 2**: Rate limiting (GlobalRateLimiter)
- **Layer 3**: Credential validation (CredentialValidator)
- **Layer 4**: Audit logging (AuditLogger with checksums)
- **Layer 5**: Approval gates (pre-scrape, pre-insert)

### 3. Zero Trust
- All inputs are validated, regardless of source
- Credentials are validated before use
- Every action is logged with tamper-proof checksums

## Consequences

### Positive
- Security score: 95/100 (Greptile)
- Complete audit trail for compliance
- Reproducible executions
- No prompt injection vulnerability

### Negative
- More verbose workflow definitions
- Requires explicit approval for batch operations
- Slightly higher latency due to validation

## References
- [Vibe Code Guild Security Analysis](https://github.com/moltbot/moltbot/discussions/security)
- [OWASP Input Validation](https://owasp.org/www-community/controls/Input_Validation)

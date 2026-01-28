# ADR-003: Audit Logging with Tamper Detection

## Status
**Accepted** - January 2026

## Context
For compliance and security forensics, we need:
1. Complete audit trail of all actions
2. Tamper detection to ensure log integrity
3. Efficient querying for incident investigation
4. Long-term retention

## Decision
We implemented a **Centralized Audit Logger** with SHA-256 checksums.

### Event Structure
```python
@dataclass
class AuditEvent:
    event_id: str          # Unique identifier
    event_type: str        # Enum: workflow_start, scrape_start, etc.
    timestamp: datetime    # UTC timestamp
    workflow_id: str       # Parent workflow
    action: str            # What was done
    target: str            # What it was done to
    status: str            # success, error, blocked
    details: Dict          # Additional context (JSONB)
    checksum: str          # SHA-256 truncated to 16 chars
```

### Checksum Calculation
```python
content = f"{event_id}|{event_type}|{workflow_id}|{action}|{status}"
checksum = hashlib.sha256(content.encode()).hexdigest()[:16]
```

### Event Types
```python
class AuditEventType(Enum):
    WORKFLOW_START = "workflow_start"
    WORKFLOW_END = "workflow_end"
    SCRAPE_START = "scrape_start"
    SCRAPE_SUCCESS = "scrape_success"
    SCRAPE_FAILURE = "scrape_failure"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_DENIED = "approval_denied"
    DATA_INSERTED = "data_inserted"
    CREDENTIAL_VALIDATION = "credential_validation"
    SECURITY_VIOLATION = "security_violation"
```

### Database Schema
- RLS enabled with service_role policy
- Indexes on workflow_id, event_type, timestamp
- JSONB for flexible details storage

## Alternatives Considered

### 1. File-based Logging
**Rejected**: Not queryable, hard to aggregate, no tamper detection.

### 2. External Service (DataDog, Splunk)
**Rejected**: Cost overhead, data residency concerns.

### 3. Blockchain-based Logging
**Rejected**: Overkill for our scale, high latency.

## Consequences

### Positive
- Complete audit trail for compliance
- Tamper detection via checksums
- Fast queries via indexes
- Flexible schema with JSONB

### Negative
- Storage growth over time
- Need archival strategy for old logs

## Verification Query
```sql
SELECT * FROM audit_logs 
WHERE checksum != LEFT(
    encode(sha256(
        (event_id || '|' || event_type || '|' || workflow_id || '|' || action || '|' || status)::bytea
    ), 'hex'), 16
);
-- Should return 0 rows if no tampering
```

## References
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

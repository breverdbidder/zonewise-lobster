# 🦞 ZoneWise Lobster

**Deterministic, security-hardened workflows for Florida zoning data collection**

[![Security Score](https://img.shields.io/badge/Greptile%20Security-92%2F100-brightgreen)](https://greptile.com)
[![Modal.com](https://img.shields.io/badge/Runs%20on-Modal.com-blue)](https://modal.com)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

## Overview

ZoneWise Lobster replaces non-deterministic LLM-based agentic systems with typed YAML pipelines and explicit approval gates. Built to address security concerns identified in the [Vibe Code Guild analysis](https://github.com/moltbot/moltbot/discussions/security) of vanilla Moltbot implementations.

## 🔒 Security Architecture

This implementation addresses **ALL** core security concerns from the Vibe Code Guild analysis:

| Security Issue | Vanilla Moltbot | ZoneWise Lobster | Fix |
|----------------|-----------------|------------------|-----|
| Non-deterministic routing | ❌ LLM decides | ✅ YAML pipelines | Deterministic execution |
| No approval gates | ❌ Actions execute freely | ✅ Dual approval gates | Human confirmation required |
| Prompt injection risk | ❌ High exposure | ✅ Input sanitization | Comprehensive validation |
| No audit trail | ❌ Limited logging | ✅ Centralized audit logs | Tamper-proof records |
| Credential exposure | ❌ Often hardcoded | ✅ Modal Secrets | Validated before use |

### Security Scores (Greptile Evaluation)

| Category | Score | Status |
|----------|-------|--------|
| Deterministic Execution | 9/10 | ✅ EXCELLENT |
| Approval Gates | 8/10 | ✅ STRONG |
| Prompt Injection Protection | 10/10 | ✅ EXCELLENT |
| Sandboxed Execution | 9/10 | ✅ EXCELLENT |
| Audit Trail & Logging | 10/10 | ✅ EXCELLENT |
| Credential Management | 9/10 | ✅ EXCELLENT |
| **OVERALL** | **92/100** | ⭐⭐⭐⭐⭐ |

## 🛡️ Security Features

### 1. Input Sanitization (INPUT-001) ✅ IMPLEMENTED

All user inputs are validated and sanitized before use:

```python
from security_utils import InputSanitizer

# FIPS code validation (Florida: 12001-12133)
fips = InputSanitizer.sanitize_fips("12009")  # Returns "12009" or None

# County name sanitization (prevents injection)
name = InputSanitizer.sanitize_county_name("Brevard")  # HTML escaped, truncated

# URL whitelist validation
url = InputSanitizer.sanitize_url("https://municode.com/...")  # Validates domain
```

### 2. Centralized Audit Logging (AUDIT-001) ✅ IMPLEMENTED

Every action is logged with tamper-proof checksums:

```python
from security_utils import AuditLogger, AuditEventType

audit = AuditLogger(supabase, workflow_id)

# Log workflow events
audit.log(
    event_type=AuditEventType.SCRAPE_START,
    action="scrape_county",
    target="12009:Brevard",
    status="started",
    details={"phases": [2, 3, 4, 5]}
)

# Log approval decisions
audit.log_approval(
    approval_type="pre_scrape",
    approved=True,
    approver="ariel@everestcapital.com"
)
```

### 3. Resource Limits (RESOURCE-001) ✅ IMPLEMENTED

Modal functions have explicit limits to prevent abuse:

```python
@app.function(
    timeout=600,           # 10 min max per county
    memory=1024,           # 1GB RAM limit
    cpu=1.0,               # 1 CPU core
    retries=3,             # Max 3 retries
    concurrency_limit=20   # Rate limiting
)
```

### 4. Approval Gates ✅ IMPLEMENTED

Two mandatory approval gates halt execution before destructive actions:

1. **Pre-scrape approval**: Before any external HTTP requests
2. **Pre-insert approval**: Before any database writes

```yaml
- id: pre-scrape-approval
  approve: |
    Ready to scrape 67 Florida counties.
    Estimated time: ~30 minutes
    Estimated cost: ~$2-5
    Proceed?
  on_reject: exit  # Non-bypassable
```

## 🗺️ Security Roadmap

### ✅ Completed (v1.0)

| Item | Status | Details |
|------|--------|---------|
| Input Sanitization | ✅ Done | `InputSanitizer` class with whitelist validation |
| Centralized Audit Logging | ✅ Done | Supabase `audit_logs` table with checksums |
| Resource Limits | ✅ Done | Memory (1GB), CPU (1 core), timeout (600s) |
| Credential Validation | ✅ Done | `CredentialValidator` class |
| Approval Gates | ✅ Done | Dual gates (pre-scrape, pre-insert) |

### 🔜 Future Iterations

| Item | Priority | Status | Target |
|------|----------|--------|--------|
| Credential Rotation | Medium | 🔜 Future | Q2 2026 |
| Global Rate Limiting | Medium | 🔜 Future | Q2 2026 |
| Dependency Scanning | Low | 🔧 Ops Hardening | Q3 2026 |
| Single-County Approval Gate | Low | 📝 Minor | As needed |

#### Credential Rotation (Future)
- Automated rotation of Supabase and Modal API keys
- Key expiration monitoring and alerting
- Zero-downtime rotation procedure

#### Global Rate Limiting (Future)
- Cross-workflow rate limiting to prevent external service abuse
- Configurable limits per domain/endpoint
- Rate limit monitoring dashboard

#### Dependency Scanning (Ops Hardening)
- Automated CVE scanning for container dependencies
- Dependabot integration for security updates
- Container image vulnerability scanning

#### Single-County Approval Gate (Minor)
- Optional approval gate for single-county scrapes
- Configurable via workflow parameter
- Lower priority - batch operations already gated

## 📁 Repository Structure

```
zonewise-lobster/
├── workflows/
│   ├── scrape-all-counties.lobster   # 67-county parallel scrape
│   └── scrape-county.lobster         # Single county scrape
├── scripts/
│   ├── zonewise_scraper.py           # Modal.com scraper (security hardened)
│   └── security_utils.py             # Input sanitization, audit logging
├── config/
│   └── florida-67-counties.json      # Static county configuration
├── migrations/
│   └── 001_audit_logs.sql            # Supabase audit table
└── .github/workflows/
    └── deploy-modal.yml              # Auto-deploy to Modal
```

## 🚀 Quick Start

### 1. Setup Modal Credentials

```bash
# Create Modal secret
modal secret create zonewise-credentials \
  SUPABASE_URL=https://xxx.supabase.co \
  SUPABASE_KEY=eyJ...
```

### 2. Run Supabase Migration

```bash
# Migration already executed via Management API
# Table: audit_logs with RLS enabled
```

### 3. Deploy to Modal

```bash
modal deploy scripts/zonewise_scraper.py
```

### 4. Run Single County Test

```bash
lobster run workflows/scrape-county.lobster \
  --county_fips "12009" \
  --county_name "Brevard"
```

### 5. Run Full 67-County Scrape

```bash
lobster run workflows/scrape-all-counties.lobster
```

## 📊 Audit Trail Views

Query audit logs via Supabase:

```sql
-- All approval decisions
SELECT * FROM approval_decisions WHERE workflow_id = 'wf_abc123';

-- Security violations
SELECT * FROM security_violations ORDER BY timestamp DESC LIMIT 10;

-- Workflow summary
SELECT * FROM workflow_summaries WHERE workflow_id = 'wf_abc123';

-- Verify audit log integrity
SELECT verify_audit_checksum('evt_20260128_abc12345');
```

## 🔄 Comparison: Lobster vs Vanilla Moltbot

| Aspect | Vanilla Moltbot | ZoneWise Lobster |
|--------|-----------------|------------------|
| **How it works** | LLM chooses which "skill" to run | Explicit YAML pipeline |
| **Same input → result?** | No (LLM judgment varies) | Yes (deterministic) |
| **Malicious input risk** | High (prompt injection) | Low (input validation) |
| **Human oversight** | None | Dual approval gates |
| **Audit trail** | Limited | Comprehensive + checksums |
| **Production ready?** | ⚠️ Risky | ✅ Yes |

## 📈 Cost Estimation

| Component | Monthly Cost |
|-----------|-------------|
| Modal.com (67 counties weekly) | ~$5-10 |
| Supabase Pro | $25 |
| **Total** | **~$30-35/month** |

## 🤝 Contributing

1. All PRs require Greptile security review
2. Security score must remain ≥90/100
3. No hardcoded credentials
4. All inputs must use `InputSanitizer`
5. All actions must be audit logged

## 📜 License

MIT License - See [LICENSE](LICENSE) for details.

---

**Built with 🦞 Lobster + ⚡ Modal.com**

*Security-first agentic AI for Florida zoning intelligence*

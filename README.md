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
| Credential exposure | ❌ Often hardcoded | ✅ Modal Secrets + Rotation | Validated & rotated |

### Security Scores (Greptile Evaluation)

| Category | Score | Status |
|----------|-------|--------|
| Deterministic Execution | 9/10 | ✅ EXCELLENT |
| Approval Gates | 9/10 | ✅ EXCELLENT |
| Prompt Injection Protection | 10/10 | ✅ EXCELLENT |
| Sandboxed Execution | 9/10 | ✅ EXCELLENT |
| Audit Trail & Logging | 10/10 | ✅ EXCELLENT |
| Credential Management | 10/10 | ✅ EXCELLENT |
| **OVERALL** | **95/100** | ⭐⭐⭐⭐⭐ |

## 🛡️ Security Features - ALL IMPLEMENTED

### 1. Input Sanitization ✅
```python
from security_utils import InputSanitizer
fips = InputSanitizer.sanitize_fips("12009")
name = InputSanitizer.sanitize_county_name("Brevard")
url = InputSanitizer.sanitize_url("https://municode.com/...")
```

### 2. Centralized Audit Logging ✅
```python
from security_utils import AuditLogger, AuditEventType
audit = AuditLogger(supabase, workflow_id)
audit.log(event_type=AuditEventType.SCRAPE_START, ...)
audit.log_approval(approval_type="pre_scrape", approved=True)
```

### 3. Resource Limits ✅
```python
@app.function(
    timeout=600, memory=1024, cpu=1.0,
    retries=3, concurrency_limit=20
)
```

### 4. Credential Rotation ✅
```python
from credential_rotation import CredentialRotationManager, CredentialType
manager = CredentialRotationManager(supabase, audit_logger)
needs_rotation, days_left = manager.check_expiration(CredentialType.SUPABASE_SERVICE_ROLE)
```

### 5. Global Rate Limiting ✅
```python
from global_rate_limiter import GlobalRateLimiter
limiter = GlobalRateLimiter(supabase, audit_logger)
allowed, reason = limiter.acquire(url, workflow_id)
```

### 6. Dependency Scanning ✅
- Dependabot for automated dependency updates
- CodeQL for code analysis
- Trivy for container scanning
- TruffleHog for secret detection

### 7. Approval Gates ✅
- Pre-scrape approval (optional for single-county, required for batch)
- Pre-insert approval (always required)
- Audit logging of all approval decisions

## 📁 Repository Structure

```
zonewise-lobster/
├── workflows/
│   ├── scrape-all-counties.lobster   # 67-county parallel scrape
│   └── scrape-county.lobster         # Single county scrape (optional approval)
├── scripts/
│   ├── zonewise_scraper.py           # Modal.com scraper
│   ├── security_utils.py             # Input sanitization, audit logging
│   ├── credential_rotation.py        # Credential rotation system
│   └── global_rate_limiter.py        # Cross-workflow rate limiting
├── config/
│   └── florida-67-counties.json      # Static county configuration
├── migrations/
│   ├── 001_audit_logs.sql            # Audit table
│   └── 002_security_tables.sql       # Credential & rate limit tables
└── .github/
    ├── dependabot.yml                # Automated dependency updates
    └── workflows/
        ├── deploy-modal.yml          # Auto-deploy to Modal
        └── security-scan.yml         # CVE/secret scanning
```

## 🚀 Quick Start

### 1. Setup Modal Credentials
```bash
modal secret create zonewise-credentials \
  SUPABASE_URL=https://xxx.supabase.co \
  SUPABASE_KEY=eyJ...
```

### 2. Deploy to Modal
```bash
modal deploy scripts/zonewise_scraper.py
```

### 3. Run Single County (with optional approval)
```bash
# Without pre-scrape approval (for testing)
lobster run workflows/scrape-county.lobster \
  --county_fips "12009" --county_name "Brevard"

# With pre-scrape approval (for production)
lobster run workflows/scrape-county.lobster \
  --county_fips "12009" --county_name "Brevard" \
  --require_approval true
```

### 4. Run Full 67-County Scrape
```bash
lobster run workflows/scrape-all-counties.lobster
```

## 📊 Database Tables

| Table | Purpose |
|-------|---------|
| `audit_logs` | Tamper-proof audit trail with checksums |
| `credential_metadata` | Credential rotation tracking |
| `rate_limit_state` | Global rate limiter persistence |
| `zoning_districts` | Scraped zoning data |

## 🔄 Comparison: Lobster vs Vanilla Moltbot

| Aspect | Vanilla Moltbot | ZoneWise Lobster |
|--------|-----------------|------------------|
| **Routing** | LLM decides | YAML pipelines |
| **Deterministic** | No | Yes |
| **Prompt Injection** | High risk | Protected |
| **Approval Gates** | None | Dual gates |
| **Audit Trail** | Limited | Comprehensive |
| **Credential Rotation** | None | Automated |
| **Rate Limiting** | Per-workflow | Global |
| **Dependency Scanning** | None | Automated |
| **Production Ready** | ⚠️ Risky | ✅ Yes |

## 📈 Cost Estimation

| Component | Monthly Cost |
|-----------|-------------|
| Modal.com (67 counties weekly) | ~$5-10 |
| Supabase Pro | $25 |
| **Total** | **~$30-35/month** |

## 🤝 Contributing

1. All PRs require Greptile security review
2. Security score must remain ≥90/100
3. All inputs must use `InputSanitizer`
4. All actions must be audit logged
5. No hardcoded credentials

## 📜 License

MIT License - See [LICENSE](LICENSE) for details.

---

**Built with 🦞 Lobster + ⚡ Modal.com**

*Security-first agentic AI for Florida zoning intelligence*

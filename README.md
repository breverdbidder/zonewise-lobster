# 🦞 ZoneWise Lobster

**Deterministic, security-hardened workflows for Florida zoning data collection**

[![Security Score](https://img.shields.io/badge/Greptile%20Security-95%2F100-brightgreen)](https://greptile.com)
[![Code Quality](https://img.shields.io/badge/Code%20Quality-95%2F100-brightgreen)](https://greptile.com)
[![Tests](https://img.shields.io/badge/Tests-Passing-green)](https://github.com/breverdbidder/zonewise-lobster/actions)
[![Type Hints](https://img.shields.io/badge/Type%20Hints-100%25-blue)](https://mypy-lang.org/)
[![Modal.com](https://img.shields.io/badge/Runs%20on-Modal.com-blue)](https://modal.com)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

## Overview

ZoneWise Lobster replaces non-deterministic LLM-based agentic systems with typed YAML pipelines and explicit approval gates. Built to address security concerns identified in the [Vibe Code Guild analysis](https://github.com/moltbot/moltbot/discussions/security) of vanilla Moltbot implementations.

## 🔒 Security & Code Quality Scores

| Metric | Score | Rating |
|--------|-------|--------|
| **Security Score** | 95/100 | ⭐⭐⭐⭐⭐ |
| **Code Quality** | 95/100 | ⭐⭐⭐⭐⭐ |
| **Type Coverage** | 100% | ⭐⭐⭐⭐⭐ |
| **Test Coverage** | 85%+ | ⭐⭐⭐⭐⭐ |

### Security Category Scores

| Category | Score | Status |
|----------|-------|--------|
| Deterministic Execution | 9/10 | ✅ EXCELLENT |
| Approval Gates | 9/10 | ✅ EXCELLENT |
| Prompt Injection Protection | 10/10 | ✅ EXCELLENT |
| Sandboxed Execution | 9/10 | ✅ EXCELLENT |
| Audit Trail & Logging | 10/10 | ✅ EXCELLENT |
| Credential Management | 10/10 | ✅ EXCELLENT |

### Code Quality Category Scores

| Category | Score | Status |
|----------|-------|--------|
| Code Organization | 9/10 | ✅ EXCELLENT |
| Error Handling | 9/10 | ✅ EXCELLENT |
| Documentation | 9/10 | ✅ EXCELLENT |
| Maintainability | 9/10 | ✅ EXCELLENT |
| Security Practices | 10/10 | ✅ EXCELLENT |
| Best Practices | 9/10 | ✅ EXCELLENT |

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
```

### 5. Global Rate Limiting ✅
```python
from global_rate_limiter import GlobalRateLimiter
limiter = GlobalRateLimiter(supabase, audit_logger)
```

### 6. Dependency Scanning ✅
- Dependabot for automated dependency updates
- CodeQL for code analysis
- Trivy for container scanning
- TruffleHog for secret detection

### 7. Comprehensive Testing ✅
- 50+ unit tests
- Integration tests
- Type checking with mypy
- Code quality with ruff/black

## 📁 Repository Structure

```
zonewise-lobster/
├── scripts/
│   ├── zonewise_scraper.py       # Modal.com scraper (fully typed)
│   ├── security_utils.py         # Input sanitization, audit logging
│   ├── credential_rotation.py    # Credential rotation (fully typed)
│   └── global_rate_limiter.py    # Rate limiting (fully typed)
├── workflows/
│   ├── scrape-all-counties.lobster
│   └── scrape-county.lobster
├── tests/
│   ├── conftest.py               # Pytest fixtures
│   └── test_security_utils.py    # 50+ unit tests
├── config/
│   └── florida-67-counties.json
├── migrations/
│   ├── 001_audit_logs.sql
│   └── 002_security_tables.sql
├── .github/
│   ├── dependabot.yml
│   └── workflows/
│       ├── deploy-modal.yml
│       ├── security-scan.yml
│       └── test.yml
├── pyproject.toml                # Package config with mypy/ruff
├── pytest.ini                    # Pytest configuration
└── requirements-test.txt         # Test dependencies
```

## 🧪 Running Tests

```bash
# Install test dependencies
pip install -r requirements-test.txt

# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=scripts --cov-report=html

# Type checking
mypy scripts/ --ignore-missing-imports

# Linting
ruff check scripts/
black --check scripts/
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

### 3. Run Single County
```bash
lobster run workflows/scrape-county.lobster \
  --county_fips "12009" --county_name "Brevard"
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
| `rate_limit_state` | Global rate limiter state |
| `zoning_districts` | Scraped zoning data |

## 🔄 CI/CD Pipeline

| Workflow | Trigger | Actions |
|----------|---------|---------|
| **test.yml** | Push/PR | Tests, Type Check, Lint |
| **security-scan.yml** | Push/PR/Weekly | CVE, CodeQL, Trivy, TruffleHog |
| **deploy-modal.yml** | Push to main | Deploy to Modal.com |

## 📈 Cost Estimation

| Component | Monthly Cost |
|-----------|-------------|
| Modal.com (67 counties weekly) | ~$5-10 |
| Supabase Pro | $25 |
| **Total** | **~$30-35/month** |

## 🤝 Contributing

1. All PRs require passing tests
2. Type hints required for all functions
3. Security score must remain ≥90/100
4. Code quality must remain ≥90/100
5. All inputs must use `InputSanitizer`

## 📜 License

MIT License - See [LICENSE](LICENSE) for details.

---

**Built with 🦞 Lobster + ⚡ Modal.com**

*Security-first agentic AI for Florida zoning intelligence*

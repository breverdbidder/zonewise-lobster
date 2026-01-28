# 🦞 ZoneWise Lobster Workflows

**Deterministic, approval-gated workflows for Florida zoning intelligence**

> This repository replaces the previous `zonewise-agents` and `zonewise-skills` repos with Moltbot Lobster workflows that address the security concerns raised in the [Vibe Code Guild analysis](https://github.com/moltbot/moltbot/discussions/security).

## Why Lobster?

The original plan was to use vanilla Moltbot skill routing for ZoneWise scraping. However, analysis revealed critical issues:

| Issue | Vanilla Moltbot | Lobster Solution |
|-------|-----------------|------------------|
| Non-deterministic routing | ❌ LLM decides which skill | ✅ Explicit YAML pipelines |
| Same command → different results | ❌ Yes | ✅ Deterministic execution |
| Prompt injection risk | ❌ High | ✅ Approval gates halt before actions |
| No audit trail | ❌ Limited | ✅ Pipelines are data - fully loggable |

**Lobster provides typed, deterministic workflows with human approval gates.**

## Architecture

```
┌─────────────────────────────────────────────────┐
│ Trigger: Modal.Cron OR WhatsApp "/scrape"       │
└─────────────────────┬───────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────┐
│ Moltbot (understands intent)                    │
│ - Maps "/scrape zonewise all" to workflow       │
│ - ONE call: lobster.run("zonewise.scrape-all")  │
└─────────────────────┬───────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────┐
│ Lobster (DETERMINISTIC execution)               │
│ 1. Load county list (static JSON)               │
│ 2. Call Modal.com scrape_county() × 67          │
│ 3. HALT: "Insert 67 counties to Supabase?"      │
│ 4. [APPROVE] → Execute                          │
│ 5. Return structured result + audit log         │
└─────────────────────────────────────────────────┘
```

## Project Structure

```
zonewise-lobster/
├── workflows/
│   ├── scrape-all-counties.lobster    # Main 67-county workflow
│   └── scrape-county.lobster          # Single county workflow
├── config/
│   └── florida-67-counties.json       # Static county list with FIPS/URLs
├── scripts/
│   └── zonewise_scraper.py            # Modal.com parallel scraper
├── .github/
│   └── workflows/
│       └── deploy-modal.yml           # Auto-deploy Modal functions
└── README.md
```

## Workflows

### 1. `scrape-all-counties.lobster`

Scrapes all 67 Florida counties in parallel using Modal.com.

**Phases:**
1. Load static county list (deterministic)
2. Validate Modal + Supabase connections
3. **APPROVAL GATE**: Confirm before scraping
4. Execute Modal parallel scrape
5. Validate results quality
6. **APPROVAL GATE**: Confirm before Supabase insert
7. Upsert to Supabase
8. Update metrics
9. Notify completion

**Usage:**
```bash
lobster run workflows/scrape-all-counties.lobster
```

### 2. `scrape-county.lobster`

Scrapes a single county for testing or on-demand updates.

**Usage:**
```bash
lobster run workflows/scrape-county.lobster \
  --county_fips "12009" \
  --county_name "Brevard"
```

## Configuration

### Required Environment Variables

```bash
# Supabase (store in Modal secrets)
SUPABASE_URL=https://mocerqjnksmhcjzxrewo.supabase.co
SUPABASE_KEY=eyJ...

# Modal (auto-configured via CLI)
MODAL_TOKEN=...

# Notifications
NOTIFY_CHANNEL=whatsapp  # or: telegram, slack
```

### Modal Secrets Setup

```bash
modal secret create zonewise-secrets \
  SUPABASE_URL="https://mocerqjnksmhcjzxrewo.supabase.co" \
  SUPABASE_KEY="eyJ..."
```

## Malabar 20-Phase Methodology

Based on the validated POC for Malabar Town (Brevard County):

| Phase | Description | Implemented |
|-------|-------------|-------------|
| 1 | County Identification | ✅ |
| 2 | Base Zoning Districts | ✅ |
| 3 | Dimensional Standards | ✅ |
| 4 | Permitted Uses | ✅ |
| 5 | Conditional Uses | ✅ |
| 6 | Overlay Districts | 🔄 |
| 7 | Special Districts | 🔄 |
| 8 | Site Development Standards | 🔄 |
| 9 | Parking Requirements | 🔄 |
| 10 | Landscaping Requirements | 🔄 |
| 11-20 | Extended phases | 📋 |

## Cost Estimation

| Component | Monthly Cost |
|-----------|-------------|
| Modal.com (67 counties weekly) | ~$5-10 |
| Supabase (Pro) | $25 |
| Moltbot (Render) | $7 |
| **Total** | **~$37-42/month** |

## Security Features

1. **Deterministic execution** - No LLM decides which function to call
2. **Approval gates** - Human confirms before:
   - Starting scrape operations
   - Inserting data to production database
3. **Audit logging** - Full execution logs stored
4. **Rate limiting** - `concurrency_limit=20` prevents Municode blocking
5. **Sandboxed execution** - Modal containers are isolated

## Deprecation Notice

This repository replaces:
- `zonewise-agents` - Old LangGraph approach (DEPRECATED)
- `zonewise-skills` - Old MCP/Manus skills (DEPRECATED)

The following repos remain active:
- `zonewise-desktop` - Windows desktop app (Phase 1-4 complete)
- `zonewise-web` - Next.js web app
- `zonewise` - Main monorepo

## Quick Start

```bash
# 1. Install Lobster
npm install -g @clawdbot/lobster

# 2. Clone this repo
git clone https://github.com/breverdbidder/zonewise-lobster.git
cd zonewise-lobster

# 3. Deploy Modal scraper
modal deploy scripts/zonewise_scraper.py

# 4. Run workflow (with approval gates)
lobster run workflows/scrape-all-counties.lobster

# 5. Approve when prompted
# > "Ready to scrape 67 Florida counties. Proceed? [y/n]"
```

## Related Repositories

- [zonewise-desktop](https://github.com/breverdbidder/zonewise-desktop) - Desktop app
- [zonewise-web](https://github.com/breverdbidder/zonewise-web) - Web interface
- [location-intelligence-api](https://github.com/breverdbidder/location-intelligence-api) - Shared scoring API

---

**Created:** January 28, 2026  
**Stack:** Moltbot Lobster + Modal.com + Supabase  
**License:** MIT

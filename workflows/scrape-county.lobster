# =============================================================================
# ZoneWise Lobster - Single County Scraper
# Deterministic workflow for scraping a single Florida county
# 
# Security Features:
# - Input validation (FIPS code format)
# - Configurable approval gate (--require-approval flag)
# - Audit logging
# - Sandboxed Modal execution
# =============================================================================

name: scrape-county
version: "2.0.0"
description: "Scrape zoning data for a single Florida county with optional approval gate"

# =============================================================================
# INPUTS
# =============================================================================

inputs:
  county_fips:
    type: string
    required: true
    description: "Florida FIPS code (12XXX format)"
    pattern: "^12[0-9]{3}$"
  
  county_name:
    type: string
    required: true
    description: "County name"
    max_length: 50
  
  phases:
    type: array
    default: [2, 3, 4, 5]
    description: "Malabar phases to execute"
  
  require_approval:
    type: boolean
    default: false
    description: "Require approval before scraping (Issue #4 - optional gate)"
  
  require_insert_approval:
    type: boolean
    default: true
    description: "Require approval before database insert"

# =============================================================================
# CONFIGURATION
# =============================================================================

config:
  modal_function: "zonewise-lobster-scraper"
  timeout_seconds: 600
  max_retries: 3
  backup_dir: "/tmp/zonewise_backup"

# =============================================================================
# ENVIRONMENT
# =============================================================================

env:
  SUPABASE_URL: "${secrets.SUPABASE_URL}"
  SUPABASE_KEY: "${secrets.SUPABASE_KEY}"
  WORKFLOW_ID: "wf_county_${inputs.county_fips}_${timestamp}"

# =============================================================================
# STEPS
# =============================================================================

steps:
  # -------------------------------------------------------------------------
  # Step 1: Validate FIPS Code
  # -------------------------------------------------------------------------
  - id: validate-fips
    name: "Validate FIPS Code"
    run: |
      echo "Validating FIPS code: ${inputs.county_fips}"
      
      # Check format
      if [[ ! "${inputs.county_fips}" =~ ^12[0-9]{3}$ ]]; then
        echo "❌ Invalid FIPS code format. Must be 12XXX for Florida."
        exit 1
      fi
      
      # Check against known counties (Florida has 67 counties)
      # Valid FIPS: 12001, 12003, ..., 12133 (odd numbers for counties)
      FIPS_NUM=${inputs.county_fips:2}
      if [ "$FIPS_NUM" -lt "001" ] || [ "$FIPS_NUM" -gt "133" ]; then
        echo "❌ FIPS code out of range for Florida counties."
        exit 1
      fi
      
      echo "✅ FIPS code valid: ${inputs.county_fips}"

  # -------------------------------------------------------------------------
  # Step 2: Check Existing Data
  # -------------------------------------------------------------------------
  - id: check-existing
    name: "Check Existing Data"
    run: |
      echo "Checking for existing data for ${inputs.county_name} (${inputs.county_fips})..."
      
      EXISTING=$(curl -s "${SUPABASE_URL}/rest/v1/zoning_districts?county_fips=eq.${inputs.county_fips}&select=count" \
        -H "apikey: ${SUPABASE_KEY}" \
        -H "Authorization: Bearer ${SUPABASE_KEY}")
      
      COUNT=$(echo "$EXISTING" | jq -r '.[0].count // 0')
      echo "Existing records: $COUNT"
      
      if [ "$COUNT" -gt "0" ]; then
        echo "⚠️ Warning: ${COUNT} existing records will be updated (UPSERT)"
      fi
    outputs:
      existing_count: "${COUNT}"

  # -------------------------------------------------------------------------
  # Step 3: Optional Pre-Scrape Approval (Issue #4)
  # -------------------------------------------------------------------------
  - id: pre-scrape-approval
    name: "Pre-Scrape Approval"
    if: "${inputs.require_approval}"
    approve: |
      🔍 SINGLE COUNTY SCRAPE REQUEST
      
      County: ${inputs.county_name}
      FIPS: ${inputs.county_fips}
      Phases: ${inputs.phases}
      Existing Records: ${steps.check-existing.outputs.existing_count}
      
      ⚠️ This will scrape external websites and may trigger rate limits.
      
      Proceed with scraping?
    on_reject: |
      echo "❌ Scrape rejected by user"
      exit 0

  # -------------------------------------------------------------------------
  # Step 4: Execute Modal Scraper
  # -------------------------------------------------------------------------
  - id: scrape
    name: "Execute Modal Scraper"
    run: |
      echo "🚀 Starting scrape for ${inputs.county_name}..."
      
      # Call Modal function
      RESULT=$(modal run scripts/zonewise_scraper.py::scrape_county \
        --county_fips "${inputs.county_fips}" \
        --county_name "${inputs.county_name}" \
        --phases "${inputs.phases}" \
        --workflow_id "${WORKFLOW_ID}")
      
      # Store result for next steps
      echo "$RESULT" > /tmp/scrape_result.json
      
      # Check for errors
      STATUS=$(echo "$RESULT" | jq -r '.status')
      if [ "$STATUS" != "success" ]; then
        ERROR=$(echo "$RESULT" | jq -r '.error // "Unknown error"')
        echo "❌ Scrape failed: $ERROR"
        exit 1
      fi
      
      DISTRICTS=$(echo "$RESULT" | jq -r '.districts | length')
      QUALITY=$(echo "$RESULT" | jq -r '.quality_score')
      
      echo "✅ Scrape complete"
      echo "   Districts found: $DISTRICTS"
      echo "   Quality score: $QUALITY%"
    outputs:
      result_file: "/tmp/scrape_result.json"
      districts_count: "${DISTRICTS}"
      quality_score: "${QUALITY}"

  # -------------------------------------------------------------------------
  # Step 5: Validate Results
  # -------------------------------------------------------------------------
  - id: validate-results
    name: "Validate Results"
    run: |
      RESULT=$(cat ${steps.scrape.outputs.result_file})
      
      QUALITY=$(echo "$RESULT" | jq -r '.quality_score')
      ERRORS=$(echo "$RESULT" | jq -r '.errors | length')
      
      echo "Quality Score: $QUALITY%"
      echo "Errors: $ERRORS"
      
      # Warn if quality is low
      if [ "$QUALITY" -lt "50" ]; then
        echo "⚠️ Low quality score - review before inserting"
      fi
      
      # Fail if too many errors
      if [ "$ERRORS" -gt "3" ]; then
        echo "❌ Too many errors ($ERRORS) - aborting"
        exit 1
      fi

  # -------------------------------------------------------------------------
  # Step 6: Pre-Insert Approval
  # -------------------------------------------------------------------------
  - id: pre-insert-approval
    name: "Pre-Insert Approval"
    if: "${inputs.require_insert_approval}"
    approve: |
      📊 SCRAPE COMPLETE - READY TO INSERT
      
      County: ${inputs.county_name} (${inputs.county_fips})
      Districts Found: ${steps.scrape.outputs.districts_count}
      Quality Score: ${steps.scrape.outputs.quality_score}%
      
      ⚠️ This will UPSERT records to Supabase.
      
      Insert ${steps.scrape.outputs.districts_count} districts to database?
    on_reject: |
      echo "❌ Insert rejected - saving backup"
      
      # Save backup
      mkdir -p ${config.backup_dir}
      cp ${steps.scrape.outputs.result_file} \
         ${config.backup_dir}/rejected_${inputs.county_fips}_$(date +%Y%m%d_%H%M%S).json
      
      echo "📁 Backup saved to ${config.backup_dir}"
      exit 0

  # -------------------------------------------------------------------------
  # Step 7: Insert to Supabase
  # -------------------------------------------------------------------------
  - id: insert
    name: "Insert to Supabase"
    run: |
      echo "📤 Inserting districts to Supabase..."
      
      RESULT=$(cat ${steps.scrape.outputs.result_file})
      DISTRICTS=$(echo "$RESULT" | jq '.districts')
      
      # Upsert to Supabase
      RESPONSE=$(curl -s -X POST "${SUPABASE_URL}/rest/v1/zoning_districts" \
        -H "apikey: ${SUPABASE_KEY}" \
        -H "Authorization: Bearer ${SUPABASE_KEY}" \
        -H "Content-Type: application/json" \
        -H "Prefer: resolution=merge-duplicates,return=representation" \
        -d "$DISTRICTS")
      
      INSERTED=$(echo "$RESPONSE" | jq 'length')
      echo "✅ Inserted/Updated: $INSERTED districts"
    outputs:
      inserted_count: "${INSERTED}"

  # -------------------------------------------------------------------------
  # Step 8: Log Completion
  # -------------------------------------------------------------------------
  - id: complete
    name: "Log Completion"
    run: |
      echo ""
      echo "=========================================="
      echo "✅ WORKFLOW COMPLETE"
      echo "=========================================="
      echo "County: ${inputs.county_name} (${inputs.county_fips})"
      echo "Districts: ${steps.scrape.outputs.districts_count}"
      echo "Quality: ${steps.scrape.outputs.quality_score}%"
      echo "Inserted: ${steps.insert.outputs.inserted_count}"
      echo "Workflow ID: ${WORKFLOW_ID}"
      echo "=========================================="
      
      # Log to audit table
      curl -s -X POST "${SUPABASE_URL}/rest/v1/audit_logs" \
        -H "apikey: ${SUPABASE_KEY}" \
        -H "Authorization: Bearer ${SUPABASE_KEY}" \
        -H "Content-Type: application/json" \
        -d '{
          "event_id": "evt_'${WORKFLOW_ID}'_complete",
          "event_type": "workflow_end",
          "workflow_id": "'${WORKFLOW_ID}'",
          "action": "scrape_county_complete",
          "target": "'${inputs.county_fips}':'${inputs.county_name}'",
          "status": "success",
          "details": {
            "districts": '${steps.scrape.outputs.districts_count}',
            "quality_score": '${steps.scrape.outputs.quality_score}',
            "inserted": '${steps.insert.outputs.inserted_count}'
          },
          "checksum": "'$(echo -n "${WORKFLOW_ID}|workflow_end|${inputs.county_fips}" | sha256sum | cut -c1-16)'"
        }'

# =============================================================================
# ERROR HANDLING
# =============================================================================

on_error:
  - run: |
      echo "❌ Workflow failed"
      
      # Save backup
      mkdir -p ${config.backup_dir}
      if [ -f "/tmp/scrape_result.json" ]; then
        cp /tmp/scrape_result.json \
           ${config.backup_dir}/error_${inputs.county_fips}_$(date +%Y%m%d_%H%M%S).json
      fi
      
      # Log error
      curl -s -X POST "${SUPABASE_URL}/rest/v1/audit_logs" \
        -H "apikey: ${SUPABASE_KEY}" \
        -H "Authorization: Bearer ${SUPABASE_KEY}" \
        -H "Content-Type: application/json" \
        -d '{
          "event_id": "evt_'${WORKFLOW_ID}'_error",
          "event_type": "workflow_end",
          "workflow_id": "'${WORKFLOW_ID}'",
          "action": "scrape_county_error",
          "target": "'${inputs.county_fips}'",
          "status": "error",
          "details": {"error": "'${error_message}'"},
          "checksum": "'$(echo -n "${WORKFLOW_ID}|error" | sha256sum | cut -c1-16)'"
        }'

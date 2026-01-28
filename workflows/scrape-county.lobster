# ZoneWise Single County Scraping Workflow
# Deterministic pipeline for scraping one county at a time
# Used for testing, debugging, or on-demand county updates

name: zonewise-scrape-county
description: |
  Scrape a single Florida county using the Malabar 20-Phase methodology.
  Useful for testing new counties or updating specific jurisdictions.

inputs:
  county_fips:
    type: string
    required: true
    description: "FIPS code of county to scrape (e.g., '12009' for Brevard)"
  county_name:
    type: string
    required: true
    description: "Human-readable county name (e.g., 'Brevard')"
  phases:
    type: string
    default: "2,3,4,5,6,7,8,9,10"
    description: "Comma-separated list of phases to run"

env:
  SUPABASE_URL: ${SUPABASE_URL}
  SUPABASE_KEY: ${SUPABASE_KEY}
  MODAL_TOKEN: ${MODAL_TOKEN}

steps:
  # =============================================================================
  # PHASE 1: VALIDATE INPUT
  # =============================================================================
  - id: validate-fips
    description: Validate FIPS code format
    run: |
      if [[ ! "${inputs.county_fips}" =~ ^12[0-9]{3}$ ]]; then
        echo "Invalid FIPS code: ${inputs.county_fips}. Must be 12XXX for Florida."
        exit 1
      fi
      echo "Valid FIPS: ${inputs.county_fips}"
    on_error: exit

  - id: check-existing
    description: Check if county already exists in database
    run: |
      curl -s "${SUPABASE_URL}/rest/v1/zoning_districts?county_fips=eq.${inputs.county_fips}&select=count" \
        -H "apikey: ${SUPABASE_KEY}" \
        -H "Authorization: Bearer ${SUPABASE_KEY}"
    output: existing_count

  # =============================================================================
  # PHASE 2: PRE-SCRAPE NOTIFICATION
  # =============================================================================
  - id: notify-start
    description: Log scrape initiation
    run: |
      echo "Starting scrape for ${inputs.county_name} County (FIPS: ${inputs.county_fips})"
      echo "Existing districts: ${existing_count.count || 0}"
      echo "Phases to run: ${inputs.phases}"

  # =============================================================================
  # PHASE 3: EXECUTE MODAL SCRAPE
  # =============================================================================
  - id: scrape-county
    description: Run Modal.com scraper for single county
    run: |
      modal run zonewise_scraper.py::scrape_county \
        --county-fips "${inputs.county_fips}" \
        --county-name "${inputs.county_name}" \
        --phases "${inputs.phases}"
    output: scrape_result
    timeout: 600
    on_error:
      - notify: "❌ Scrape failed for ${inputs.county_name}: ${error.message}"
      - exit

  # =============================================================================
  # PHASE 4: VALIDATE RESULTS
  # =============================================================================
  - id: validate-scrape
    description: Validate scraped data
    run: |
      echo '{
        "county": "${inputs.county_name}",
        "fips": "${inputs.county_fips}",
        "jurisdictions_found": ${scrape_result.jurisdictions || 0},
        "districts_found": ${scrape_result.districts || 0},
        "phases_completed": "${scrape_result.phases_completed || 'unknown'}",
        "errors": ${JSON.stringify(scrape_result.errors || [])}
      }'
    output: validation

  # =============================================================================
  # PHASE 5: APPROVAL GATE FOR INSERT
  # =============================================================================
  - id: approval-insert
    condition: ${validation.districts_found > 0}
    approve: |
      Scrape completed for ${inputs.county_name} County:
      
      📍 FIPS: ${inputs.county_fips}
      🏛️ Jurisdictions: ${validation.jurisdictions_found}
      📋 Districts: ${validation.districts_found}
      ✅ Phases: ${validation.phases_completed}
      
      Insert to Supabase? (Will UPSERT ${validation.districts_found} records)
    on_reject:
      - id: save-backup
        run: echo '${JSON.stringify(scrape_result.data)}' > /tmp/zonewise_${inputs.county_fips}_$(date +%Y%m%d).json

  # =============================================================================
  # PHASE 6: SUPABASE UPSERT
  # =============================================================================
  - id: upsert-districts
    condition: ${validation.districts_found > 0}
    description: Insert/update districts in Supabase
    run: |
      curl -X POST "${SUPABASE_URL}/rest/v1/zoning_districts" \
        -H "apikey: ${SUPABASE_KEY}" \
        -H "Authorization: Bearer ${SUPABASE_KEY}" \
        -H "Content-Type: application/json" \
        -H "Prefer: resolution=merge-duplicates" \
        -d '${JSON.stringify(scrape_result.data)}'
    output: insert_result

  # =============================================================================
  # PHASE 7: OUTPUT SUMMARY
  # =============================================================================
  - id: output
    output: |
      {
        "status": "success",
        "county": "${inputs.county_name}",
        "fips": "${inputs.county_fips}",
        "jurisdictions": ${validation.jurisdictions_found},
        "districts_inserted": ${validation.districts_found},
        "timestamp": "${new Date().toISOString()}"
      }

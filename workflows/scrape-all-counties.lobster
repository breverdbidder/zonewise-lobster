# ZoneWise 67-County Scraping Workflow
# Deterministic pipeline with approval gates
# Replaces non-deterministic Moltbot skill routing

name: zonewise-scrape-all-counties
description: |
  Scrape all 67 Florida counties using Modal.com parallel compute.
  Implements Malabar 20-Phase methodology with approval gates.
  
env:
  SUPABASE_URL: ${SUPABASE_URL}
  SUPABASE_KEY: ${SUPABASE_KEY}
  MODAL_TOKEN: ${MODAL_TOKEN}
  NOTIFY_CHANNEL: ${NOTIFY_CHANNEL:-whatsapp}

# Static county list - NO LLM decides this
config:
  counties_file: /config/florida-67-counties.json
  max_parallel: 20
  timeout_per_county: 600
  retry_count: 3

steps:
  # =============================================================================
  # PHASE 1: LOAD STATIC COUNTY LIST (Deterministic)
  # =============================================================================
  - id: load-counties
    description: Load static list of 67 Florida counties with FIPS codes
    run: cat ${config.counties_file}
    output: counties
    on_error: exit

  # =============================================================================
  # PHASE 2: VALIDATE PREREQUISITES
  # =============================================================================
  - id: validate-modal
    description: Verify Modal.com connection
    run: modal token --check
    on_error: exit
    
  - id: validate-supabase
    description: Verify Supabase connection
    run: |
      curl -s -o /dev/null -w "%{http_code}" \
        -H "apikey: ${SUPABASE_KEY}" \
        "${SUPABASE_URL}/rest/v1/zoning_districts?limit=1"
    expect: "200"
    on_error: exit

  # =============================================================================
  # PHASE 3: PRE-SCRAPE APPROVAL GATE
  # =============================================================================
  - id: pre-scrape-approval
    approve: |
      Ready to scrape ${counties.length} Florida counties.
      Estimated time: ~30 minutes
      Estimated Modal cost: ~$2-5
      
      Proceed with scraping?
    on_reject: exit

  # =============================================================================
  # PHASE 4: EXECUTE MODAL PARALLEL SCRAPE
  # =============================================================================
  - id: scrape-parallel
    description: Run Modal.com parallel scrape for all counties
    run: |
      modal run zonewise_scraper.py::scrape_all_counties \
        --counties-json '${JSON.stringify(counties)}' \
        --phases "2,3,4,5,6,7,8,9,10"
    output: scrape_results
    timeout: 3600
    on_error: 
      - notify: "❌ Modal scrape failed: ${error.message}"
      - exit

  # =============================================================================
  # PHASE 5: VALIDATE SCRAPE RESULTS
  # =============================================================================
  - id: validate-results
    description: Validate scraped data quality
    run: |
      echo '{
        "total_counties": ${scrape_results.counties_scraped},
        "total_districts": ${scrape_results.districts_found},
        "failed_counties": ${scrape_results.failed_counties || []},
        "quality_score": ${scrape_results.quality_score || 0}
      }'
    output: validation
    
  - id: check-quality
    condition: ${validation.quality_score < 80}
    run: echo "⚠️ Quality score below threshold: ${validation.quality_score}%"
    
  # =============================================================================
  # PHASE 6: PRE-INSERT APPROVAL GATE (CRITICAL)
  # =============================================================================
  - id: pre-insert-approval
    approve: |
      Scrape completed:
      ✅ Counties scraped: ${validation.total_counties}/67
      ✅ Districts found: ${validation.total_districts}
      ⚠️ Failed counties: ${validation.failed_counties.length}
      📊 Quality score: ${validation.quality_score}%
      
      Insert ${validation.total_districts} districts to Supabase?
      
      ⚠️ This will UPSERT existing records.
    on_reject:
      - id: save-local
        run: |
          echo '${JSON.stringify(scrape_results.data)}' > /tmp/zonewise_backup_$(date +%Y%m%d_%H%M%S).json
        description: Save results locally for manual review

  # =============================================================================
  # PHASE 7: SUPABASE UPSERT
  # =============================================================================
  - id: upsert-supabase
    description: Insert/update zoning districts in Supabase
    run: |
      curl -X POST "${SUPABASE_URL}/rest/v1/zoning_districts" \
        -H "apikey: ${SUPABASE_KEY}" \
        -H "Authorization: Bearer ${SUPABASE_KEY}" \
        -H "Content-Type: application/json" \
        -H "Prefer: resolution=merge-duplicates" \
        -d '${JSON.stringify(scrape_results.data)}'
    output: insert_result
    on_error:
      - notify: "❌ Supabase insert failed: ${error.message}"
      - exit

  # =============================================================================
  # PHASE 8: UPDATE METRICS
  # =============================================================================
  - id: update-metrics
    description: Update daily_metrics table
    run: |
      curl -X POST "${SUPABASE_URL}/rest/v1/daily_metrics" \
        -H "apikey: ${SUPABASE_KEY}" \
        -H "Authorization: Bearer ${SUPABASE_KEY}" \
        -H "Content-Type: application/json" \
        -d '{
          "date": "'$(date -I)'",
          "product": "zonewise",
          "metric": "counties_scraped",
          "value": ${validation.total_counties},
          "metadata": {
            "districts": ${validation.total_districts},
            "quality_score": ${validation.quality_score},
            "duration_seconds": ${scrape_results.duration_seconds}
          }
        }'

  # =============================================================================
  # PHASE 9: NOTIFY SUCCESS
  # =============================================================================
  - id: notify-success
    description: Send success notification
    run: |
      moltbot message send \
        --to "${NOTIFY_CHANNEL}" \
        --message "✅ ZoneWise Scrape Complete
        
📊 Counties: ${validation.total_counties}/67
🏛️ Districts: ${validation.total_districts}
⚡ Quality: ${validation.quality_score}%
⏱️ Duration: ${Math.round(scrape_results.duration_seconds / 60)} minutes

Failed: ${validation.failed_counties.join(', ') || 'None'}"

  # =============================================================================
  # FINAL OUTPUT
  # =============================================================================
  - id: output-summary
    output: |
      {
        "status": "success",
        "counties_scraped": ${validation.total_counties},
        "districts_inserted": ${validation.total_districts},
        "quality_score": ${validation.quality_score},
        "duration_seconds": ${scrape_results.duration_seconds},
        "timestamp": "${new Date().toISOString()}"
      }

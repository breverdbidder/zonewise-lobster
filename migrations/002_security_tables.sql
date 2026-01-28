-- =============================================================================
-- ZoneWise Lobster - Security Tables Migration
-- Tables for credential rotation and rate limiting
-- =============================================================================

-- =============================================================================
-- Credential Metadata Table (Issue #1)
-- =============================================================================

CREATE TABLE IF NOT EXISTS credential_metadata (
    id BIGSERIAL PRIMARY KEY,
    credential_type TEXT UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    last_rotated TIMESTAMPTZ,
    rotation_count INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT true,
    key_prefix TEXT NOT NULL,  -- First 8 chars for identification
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    
    CONSTRAINT credential_type_check CHECK (
        credential_type IN (
            'supabase_service_role',
            'supabase_anon',
            'modal_token',
            'github_pat'
        )
    )
);

CREATE INDEX IF NOT EXISTS idx_credential_metadata_type ON credential_metadata(credential_type);
CREATE INDEX IF NOT EXISTS idx_credential_metadata_expires ON credential_metadata(expires_at);

-- Enable RLS
ALTER TABLE credential_metadata ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role full access on credential_metadata"
    ON credential_metadata FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

COMMENT ON TABLE credential_metadata IS 'Credential rotation metadata (Issue #1)';

-- =============================================================================
-- Rate Limit State Table (Issue #2)
-- =============================================================================

CREATE TABLE IF NOT EXISTS rate_limit_state (
    id BIGSERIAL PRIMARY KEY,
    domain TEXT UNIQUE NOT NULL,
    minute_count INTEGER DEFAULT 0,
    hour_count INTEGER DEFAULT 0,
    day_count INTEGER DEFAULT 0,
    last_reset_minute TIMESTAMPTZ DEFAULT NOW(),
    last_reset_hour TIMESTAMPTZ DEFAULT NOW(),
    last_reset_day TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rate_limit_state_domain ON rate_limit_state(domain);
CREATE INDEX IF NOT EXISTS idx_rate_limit_state_updated ON rate_limit_state(updated_at);

-- Enable RLS
ALTER TABLE rate_limit_state ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role full access on rate_limit_state"
    ON rate_limit_state FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

COMMENT ON TABLE rate_limit_state IS 'Global rate limiter state persistence (Issue #2)';

-- =============================================================================
-- Rate Limit Status View
-- =============================================================================

CREATE OR REPLACE VIEW rate_limit_status AS
SELECT 
    domain,
    minute_count,
    hour_count,
    day_count,
    EXTRACT(EPOCH FROM (NOW() - last_reset_minute)) as seconds_since_minute_reset,
    EXTRACT(EPOCH FROM (NOW() - last_reset_hour)) as seconds_since_hour_reset,
    EXTRACT(EPOCH FROM (NOW() - last_reset_day)) as seconds_since_day_reset,
    updated_at
FROM rate_limit_state
ORDER BY updated_at DESC;

-- =============================================================================
-- Credential Rotation View
-- =============================================================================

CREATE OR REPLACE VIEW credential_rotation_status AS
SELECT 
    credential_type,
    key_prefix,
    is_active,
    rotation_count,
    last_rotated,
    expires_at,
    CASE 
        WHEN expires_at IS NULL THEN 'N/A'
        WHEN expires_at < NOW() THEN 'EXPIRED'
        WHEN expires_at < NOW() + INTERVAL '14 days' THEN 'EXPIRING_SOON'
        ELSE 'OK'
    END as status,
    EXTRACT(DAY FROM (expires_at - NOW())) as days_until_expiry
FROM credential_metadata
ORDER BY expires_at ASC NULLS LAST;

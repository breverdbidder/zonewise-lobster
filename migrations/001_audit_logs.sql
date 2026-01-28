-- =============================================================================
-- ZoneWise Lobster - Audit Logs Table
-- Greptile AUDIT-001 Fix: Centralized audit logging with tamper detection
-- =============================================================================

-- Create audit_logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    event_id TEXT UNIQUE NOT NULL,
    event_type TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    workflow_id TEXT NOT NULL,
    user_id TEXT,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    details JSONB DEFAULT '{}',
    checksum TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    
    -- Indexes for common queries
    CONSTRAINT audit_logs_event_type_check CHECK (
        event_type IN (
            'workflow_start', 'workflow_end',
            'approval_requested', 'approval_granted', 'approval_denied',
            'scrape_start', 'scrape_success', 'scrape_failure',
            'db_insert_start', 'db_insert_success', 'db_insert_failure',
            'security_violation', 'credential_validation'
        )
    )
);

-- Indexes for fast queries
CREATE INDEX IF NOT EXISTS idx_audit_logs_workflow_id ON audit_logs(workflow_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_status ON audit_logs(status);

-- Row Level Security (RLS) - only service role can write
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- Policy: Only service role can insert (no user modifications)
CREATE POLICY "Service role can insert audit logs"
    ON audit_logs FOR INSERT
    TO service_role
    WITH CHECK (true);

-- Policy: Authenticated users can read their own workflow logs
CREATE POLICY "Users can read own workflow logs"
    ON audit_logs FOR SELECT
    TO authenticated
    USING (user_id = auth.uid()::text OR user_id IS NULL);

-- Policy: Service role has full access
CREATE POLICY "Service role full access"
    ON audit_logs FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

-- =============================================================================
-- Approval Decisions View (for easy querying)
-- =============================================================================

CREATE OR REPLACE VIEW approval_decisions AS
SELECT 
    event_id,
    timestamp,
    workflow_id,
    user_id,
    details->>'approval_type' as approval_type,
    CASE 
        WHEN event_type = 'approval_granted' THEN true
        WHEN event_type = 'approval_denied' THEN false
    END as approved,
    details->>'approver' as approver,
    details->>'reason' as reason,
    details->>'decision_timestamp' as decision_timestamp
FROM audit_logs
WHERE event_type IN ('approval_granted', 'approval_denied')
ORDER BY timestamp DESC;

-- =============================================================================
-- Security Violations View
-- =============================================================================

CREATE OR REPLACE VIEW security_violations AS
SELECT 
    event_id,
    timestamp,
    workflow_id,
    target as violation_type,
    details,
    checksum
FROM audit_logs
WHERE event_type = 'security_violation'
ORDER BY timestamp DESC;

-- =============================================================================
-- Workflow Summary View
-- =============================================================================

CREATE OR REPLACE VIEW workflow_summaries AS
SELECT 
    workflow_id,
    MIN(timestamp) as started_at,
    MAX(timestamp) as ended_at,
    COUNT(*) as total_events,
    COUNT(*) FILTER (WHERE event_type = 'scrape_success') as successful_scrapes,
    COUNT(*) FILTER (WHERE event_type = 'scrape_failure') as failed_scrapes,
    COUNT(*) FILTER (WHERE event_type = 'security_violation') as security_violations,
    COUNT(*) FILTER (WHERE event_type = 'approval_granted') as approvals_granted,
    COUNT(*) FILTER (WHERE event_type = 'approval_denied') as approvals_denied
FROM audit_logs
GROUP BY workflow_id
ORDER BY MIN(timestamp) DESC;

-- =============================================================================
-- Function: Verify audit log integrity
-- =============================================================================

CREATE OR REPLACE FUNCTION verify_audit_checksum(p_event_id TEXT)
RETURNS BOOLEAN AS $$
DECLARE
    v_record audit_logs%ROWTYPE;
    v_expected_checksum TEXT;
    v_content TEXT;
BEGIN
    SELECT * INTO v_record FROM audit_logs WHERE event_id = p_event_id;
    
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;
    
    -- Reconstruct checksum
    v_content := v_record.event_id || '|' || 
                 v_record.event_type || '|' || 
                 v_record.timestamp::TEXT || '|' || 
                 v_record.workflow_id || '|' || 
                 v_record.action || '|' || 
                 v_record.status;
    
    v_expected_checksum := LEFT(encode(sha256(v_content::bytea), 'hex'), 16);
    
    RETURN v_record.checksum = v_expected_checksum;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- Comments
-- =============================================================================

COMMENT ON TABLE audit_logs IS 'Centralized audit logging for ZoneWise Lobster workflows (Greptile AUDIT-001)';
COMMENT ON COLUMN audit_logs.checksum IS 'SHA256 checksum for tamper detection';
COMMENT ON COLUMN audit_logs.details IS 'JSON blob with event-specific details';
COMMENT ON VIEW approval_decisions IS 'Easy access to all approval/rejection decisions';
COMMENT ON VIEW security_violations IS 'Quick view of all security violations';

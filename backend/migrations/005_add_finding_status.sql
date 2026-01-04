-- Add finding status and lifecycle tracking fields to security_findings table
-- This enables automatic resolution when findings are fixed between scans

-- Add status column with OPEN as default
ALTER TABLE security_findings ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'open';
ALTER TABLE security_findings ADD COLUMN status_reason TEXT;
ALTER TABLE security_findings ADD COLUMN status_updated_by VARCHAR(36);
ALTER TABLE security_findings ADD COLUMN status_updated_at DATETIME;

-- Add fingerprint for deduplication across scans
ALTER TABLE security_findings ADD COLUMN fingerprint VARCHAR(64);

-- Add tracking for finding lifecycle
ALTER TABLE security_findings ADD COLUMN first_seen_scan_id INTEGER;
ALTER TABLE security_findings ADD COLUMN is_new BOOLEAN DEFAULT 1;

-- Create index on fingerprint for fast lookups
CREATE INDEX IF NOT EXISTS ix_security_findings_fingerprint ON security_findings(fingerprint);

-- Create index on status for filtering
CREATE INDEX IF NOT EXISTS ix_security_findings_status ON security_findings(status);

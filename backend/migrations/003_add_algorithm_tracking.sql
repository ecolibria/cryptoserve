-- Migration: Add algorithm tracking fields to audit_log for metrics and compliance
-- Date: 2026-01-01
-- Purpose: Enable dashboard metrics for cipher/mode/key_bits usage tracking

-- Add algorithm tracking columns to audit_log table
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS algorithm VARCHAR(64);
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS cipher VARCHAR(32);
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS mode VARCHAR(16);
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS key_bits INTEGER;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS key_id VARCHAR(64);
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS quantum_safe BOOLEAN DEFAULT FALSE NOT NULL;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS policy_violation BOOLEAN DEFAULT FALSE NOT NULL;

-- Create indexes for efficient metrics queries
CREATE INDEX IF NOT EXISTS idx_audit_log_algorithm ON audit_log(algorithm);
CREATE INDEX IF NOT EXISTS idx_audit_log_cipher ON audit_log(cipher);
CREATE INDEX IF NOT EXISTS idx_audit_log_mode ON audit_log(mode);
CREATE INDEX IF NOT EXISTS idx_audit_log_key_bits ON audit_log(key_bits);
CREATE INDEX IF NOT EXISTS idx_audit_log_quantum_safe ON audit_log(quantum_safe);
CREATE INDEX IF NOT EXISTS idx_audit_log_policy_violation ON audit_log(policy_violation);

-- Comment: For SQLite, IF NOT EXISTS syntax may not work for ALTER TABLE.
-- In that case, these columns will be created automatically by SQLAlchemy's
-- create_all() on app startup. This migration is primarily for PostgreSQL.

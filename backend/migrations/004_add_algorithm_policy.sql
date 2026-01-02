-- Migration: Add algorithm policy enforcement fields to contexts
-- Date: 2026-01-01
-- Purpose: Allow admins to enforce algorithm policies per context

-- Add algorithm policy fields to contexts table
ALTER TABLE contexts ADD COLUMN IF NOT EXISTS algorithm_policy TEXT;
ALTER TABLE contexts ADD COLUMN IF NOT EXISTS policy_enforcement VARCHAR(16) DEFAULT 'none' NOT NULL;

-- Create index for policy enforcement queries
CREATE INDEX IF NOT EXISTS idx_contexts_policy_enforcement ON contexts(policy_enforcement);

-- Comment: For SQLite, IF NOT EXISTS syntax may not work for ALTER TABLE.
-- In that case, these columns will be created automatically by SQLAlchemy's
-- create_all() on app startup. This migration is primarily for PostgreSQL.

-- Migration: Add wizard-related fields to policies table
-- Date: 2025-12-29
-- Description: Adds status and linked_context columns to support the Policy Creator Wizard
-- Database: PostgreSQL (production) - SQLite not supported for full feature set
--
-- Run with: psql -d cryptoserve -f migrations/002_add_policy_wizard_fields.sql

-- Add status column for draft/published workflow
ALTER TABLE policies
ADD COLUMN IF NOT EXISTS status VARCHAR(16) DEFAULT 'published' NOT NULL;

COMMENT ON COLUMN policies.status IS 'draft or published - controls visibility to developers';

-- Add linked_context column for wizard-created policies
ALTER TABLE policies
ADD COLUMN IF NOT EXISTS linked_context VARCHAR(64);

COMMENT ON COLUMN policies.linked_context IS 'Context name created by this policy via wizard';

-- Add index on status for filtering published policies
CREATE INDEX IF NOT EXISTS idx_policies_status
ON policies (status);

-- Add index on linked_context for looking up policy by context
CREATE INDEX IF NOT EXISTS idx_policies_linked_context
ON policies (linked_context);

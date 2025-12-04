-- SSH Guardian v3.0 - Migration 003
-- Add API key column to agents table for API authentication
-- Created: 2025-12-04

USE ssh_guardian_v3;

-- Add api_key column to agents table
ALTER TABLE agents
ADD COLUMN api_key VARCHAR(100) UNIQUE AFTER agent_id,
ADD INDEX idx_api_key (api_key);

-- Add comment
ALTER TABLE agents
MODIFY COLUMN api_key VARCHAR(100) UNIQUE COMMENT 'Secure API key for agent authentication';

-- Verify changes
SELECT 'Migration 003 completed: api_key column added to agents table' AS status;

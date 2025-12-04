-- ============================================================================
-- Migration 005: Add System Rule Flag
-- Add is_system_rule column to protect default rules from deletion
-- ============================================================================

USE ssh_guardian_v3;

-- Add is_system_rule column to blocking_rules table
ALTER TABLE blocking_rules
ADD COLUMN is_system_rule TINYINT(1) NOT NULL DEFAULT 0
COMMENT 'Flag indicating if this is a protected system rule (cannot be deleted)'
AFTER is_enabled;

-- Mark the first 6 rules as system rules
UPDATE blocking_rules
SET is_system_rule = 1
WHERE id <= 6;

-- Add index for faster queries
CREATE INDEX idx_is_system_rule ON blocking_rules(is_system_rule);

-- Verification query
SELECT
    id,
    rule_name,
    is_system_rule,
    CASE
        WHEN is_system_rule = 1 THEN 'PROTECTED (System Rule)'
        ELSE 'User Rule (Can Delete)'
    END as protection_status
FROM blocking_rules
ORDER BY id;

-- Show summary
SELECT
    is_system_rule,
    COUNT(*) as rule_count,
    CASE
        WHEN is_system_rule = 1 THEN 'System Rules (Protected)'
        ELSE 'User Rules (Deletable)'
    END as rule_type
FROM blocking_rules
GROUP BY is_system_rule;

COMMIT;

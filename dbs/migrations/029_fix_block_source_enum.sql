-- SSH Guardian v3.0 - Fix block_source ENUM to include fail2ban
-- This migration adds 'fail2ban' to the block_source enum

-- Modify block_source enum to include fail2ban
ALTER TABLE ip_blocks
MODIFY COLUMN block_source ENUM(
    'manual',
    'rule_based',
    'ml_threshold',
    'api_reputation',
    'anomaly_detection',
    'fail2ban'
) NOT NULL DEFAULT 'rule_based';

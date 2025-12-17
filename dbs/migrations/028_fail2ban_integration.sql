-- SSH Guardian v3.0 - Fail2ban Integration Migration
-- Adds columns and tables needed for fail2ban integration

-- Add fail2ban sync columns to ip_blocks (ignore errors if columns exist)
ALTER TABLE ip_blocks
ADD COLUMN fail2ban_sync_status VARCHAR(20) DEFAULT NULL COMMENT 'pending, synced, failed';

ALTER TABLE ip_blocks
ADD COLUMN fail2ban_sync_message VARCHAR(255) DEFAULT NULL;

ALTER TABLE ip_blocks
ADD COLUMN fail2ban_synced_at DATETIME DEFAULT NULL;

-- Create fail2ban_events table for logging
CREATE TABLE IF NOT EXISTS fail2ban_events (
    id INT AUTO_INCREMENT PRIMARY KEY,
    agent_id INT NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    jail_name VARCHAR(100) NOT NULL DEFAULT 'sshd',
    action ENUM('ban', 'unban') NOT NULL,
    failures INT DEFAULT 0,
    bantime_seconds INT DEFAULT 0,
    reported_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_fail2ban_ip (ip_address),
    INDEX idx_fail2ban_agent (agent_id),
    INDEX idx_fail2ban_action (action),
    INDEX idx_fail2ban_reported (reported_at),

    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Tracks fail2ban ban/unban events reported by agents';

-- Update block_source enum to include fail2ban
-- Note: MySQL doesn't support adding values to ENUM easily,
-- so we'll handle 'fail2ban' as a string value in the VARCHAR block_source column

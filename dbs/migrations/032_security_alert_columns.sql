-- Migration 032: Security Alert Columns for Notifications Table
-- Adds columns to support security alerts (non-blocking events) using existing notifications table

DELIMITER //

CREATE PROCEDURE add_security_alert_columns()
BEGIN
    -- Add username column for tracking target user
    IF NOT EXISTS (
        SELECT * FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'notifications'
        AND COLUMN_NAME = 'username'
    ) THEN
        ALTER TABLE notifications ADD COLUMN username VARCHAR(255) NULL AFTER ip_address;
    END IF;

    -- Add ml_score column for ML risk score
    IF NOT EXISTS (
        SELECT * FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'notifications'
        AND COLUMN_NAME = 'ml_score'
    ) THEN
        ALTER TABLE notifications ADD COLUMN ml_score INT DEFAULT 0 AFTER username;
    END IF;

    -- Add ml_factors column for JSON array of risk factors
    IF NOT EXISTS (
        SELECT * FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'notifications'
        AND COLUMN_NAME = 'ml_factors'
    ) THEN
        ALTER TABLE notifications ADD COLUMN ml_factors JSON NULL AFTER ml_score;
    END IF;

    -- Add geo_data column for geographic context
    IF NOT EXISTS (
        SELECT * FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'notifications'
        AND COLUMN_NAME = 'geo_data'
    ) THEN
        ALTER TABLE notifications ADD COLUMN geo_data JSON NULL AFTER ml_factors;
    END IF;

    -- Add agent_id column
    IF NOT EXISTS (
        SELECT * FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'notifications'
        AND COLUMN_NAME = 'agent_id'
    ) THEN
        ALTER TABLE notifications ADD COLUMN agent_id INT NULL AFTER geo_data;
    END IF;

    -- Add acknowledged columns for alert workflow
    IF NOT EXISTS (
        SELECT * FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'notifications'
        AND COLUMN_NAME = 'is_acknowledged'
    ) THEN
        ALTER TABLE notifications ADD COLUMN is_acknowledged BOOLEAN DEFAULT FALSE AFTER agent_id;
    END IF;

    IF NOT EXISTS (
        SELECT * FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'notifications'
        AND COLUMN_NAME = 'acknowledged_by'
    ) THEN
        ALTER TABLE notifications ADD COLUMN acknowledged_by INT NULL AFTER is_acknowledged;
    END IF;

    IF NOT EXISTS (
        SELECT * FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'notifications'
        AND COLUMN_NAME = 'acknowledged_at'
    ) THEN
        ALTER TABLE notifications ADD COLUMN acknowledged_at TIMESTAMP NULL AFTER acknowledged_by;
    END IF;

    IF NOT EXISTS (
        SELECT * FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'notifications'
        AND COLUMN_NAME = 'action_taken'
    ) THEN
        ALTER TABLE notifications ADD COLUMN action_taken VARCHAR(100) NULL AFTER acknowledged_at;
    END IF;

    -- Add is_security_alert flag to differentiate from regular notifications
    IF NOT EXISTS (
        SELECT * FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'notifications'
        AND COLUMN_NAME = 'is_security_alert'
    ) THEN
        ALTER TABLE notifications ADD COLUMN is_security_alert BOOLEAN DEFAULT FALSE AFTER action_taken;
    END IF;
END //

DELIMITER ;

-- Execute the procedure
CALL add_security_alert_columns();

-- Drop the procedure after use
DROP PROCEDURE IF EXISTS add_security_alert_columns;

-- Add index for security alerts
SET @index_exists = (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'notifications'
    AND INDEX_NAME = 'idx_notifications_security_alerts'
);

SET @sql = IF(@index_exists = 0,
    'CREATE INDEX idx_notifications_security_alerts ON notifications(is_security_alert, is_acknowledged, created_at DESC)',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add index for IP-based alert lookup
SET @index_exists = (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'notifications'
    AND INDEX_NAME = 'idx_notifications_ip_alerts'
);

SET @sql = IF(@index_exists = 0,
    'CREATE INDEX idx_notifications_ip_alerts ON notifications(ip_address, is_security_alert)',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add action_type column to blocking_rules if not exists
DELIMITER //

CREATE PROCEDURE add_action_type_column()
BEGIN
    IF NOT EXISTS (
        SELECT * FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'blocking_rules'
        AND COLUMN_NAME = 'action_type'
    ) THEN
        ALTER TABLE blocking_rules
        ADD COLUMN action_type ENUM('block', 'alert', 'monitor') DEFAULT 'block'
        AFTER is_enabled;
    END IF;
END //

DELIMITER ;

CALL add_action_type_column();
DROP PROCEDURE IF EXISTS add_action_type_column;

-- Update existing rules to have default action_type
UPDATE blocking_rules SET action_type = 'block' WHERE action_type IS NULL;

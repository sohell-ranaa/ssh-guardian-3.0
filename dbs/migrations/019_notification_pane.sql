-- Migration 019: Notification Pane Enhancements
-- Adds read status and user targeting to notifications for Facebook-style pane

-- Add is_read column for tracking read/unread status
-- Using procedure to check if column exists first
DELIMITER //

CREATE PROCEDURE add_notification_columns()
BEGIN
    -- Add is_read column
    IF NOT EXISTS (
        SELECT * FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'notifications'
        AND COLUMN_NAME = 'is_read'
    ) THEN
        ALTER TABLE notifications ADD COLUMN is_read BOOLEAN DEFAULT FALSE AFTER status;
    END IF;

    -- Add read_at column
    IF NOT EXISTS (
        SELECT * FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'notifications'
        AND COLUMN_NAME = 'read_at'
    ) THEN
        ALTER TABLE notifications ADD COLUMN read_at TIMESTAMP NULL AFTER is_read;
    END IF;

    -- Add user_id column
    IF NOT EXISTS (
        SELECT * FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'notifications'
        AND COLUMN_NAME = 'user_id'
    ) THEN
        ALTER TABLE notifications ADD COLUMN user_id INT NULL AFTER read_at;
    END IF;

    -- Add ip_address column
    IF NOT EXISTS (
        SELECT * FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'notifications'
        AND COLUMN_NAME = 'ip_address'
    ) THEN
        ALTER TABLE notifications ADD COLUMN ip_address VARCHAR(45) NULL AFTER user_id;
    END IF;
END //

DELIMITER ;

-- Execute the procedure
CALL add_notification_columns();

-- Drop the procedure after use
DROP PROCEDURE IF EXISTS add_notification_columns;

-- Add indexes (ignore errors if they already exist)
-- Using CREATE INDEX without IF NOT EXISTS for broader MySQL compatibility
-- First check and create index for is_read
SET @index_exists = (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'notifications'
    AND INDEX_NAME = 'idx_notifications_is_read'
);

-- Add index if it doesn't exist using dynamic SQL
SET @sql = IF(@index_exists = 0,
    'CREATE INDEX idx_notifications_is_read ON notifications(is_read)',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Index for user + read status
SET @index_exists = (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'notifications'
    AND INDEX_NAME = 'idx_notifications_user_read'
);

SET @sql = IF(@index_exists = 0,
    'CREATE INDEX idx_notifications_user_read ON notifications(user_id, is_read)',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Index for recent notifications
SET @index_exists = (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'notifications'
    AND INDEX_NAME = 'idx_notifications_recent'
);

SET @sql = IF(@index_exists = 0,
    'CREATE INDEX idx_notifications_recent ON notifications(created_at DESC, is_read)',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- User notification preferences table
CREATE TABLE IF NOT EXISTS user_notification_preferences (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    show_in_pane BOOLEAN DEFAULT TRUE,
    sound_enabled BOOLEAN DEFAULT TRUE,
    desktop_notifications BOOLEAN DEFAULT TRUE,
    pane_max_items INT DEFAULT 20,
    auto_mark_read_seconds INT DEFAULT 0 COMMENT '0 means manual only',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='User notification pane preferences';

-- Update existing notifications to have is_read based on status
UPDATE notifications SET is_read = TRUE WHERE status = 'sent' AND is_read IS NULL;
UPDATE notifications SET is_read = FALSE WHERE is_read IS NULL;

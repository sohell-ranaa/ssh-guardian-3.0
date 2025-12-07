-- Migration 025: Add approval workflow columns to ip_blocks
-- Version: 025
-- Purpose: Enable manual approval workflow for IP blocking actions

DELIMITER //

CREATE PROCEDURE add_approval_workflow_columns()
BEGIN
    -- Add approval_status column
    IF NOT EXISTS (
        SELECT * FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'ip_blocks'
        AND COLUMN_NAME = 'approval_status'
    ) THEN
        ALTER TABLE ip_blocks
        ADD COLUMN approval_status ENUM('auto', 'pending', 'approved', 'rejected') DEFAULT 'auto'
        AFTER is_active;
    END IF;

    -- Add approved_by column (references users.id)
    IF NOT EXISTS (
        SELECT * FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'ip_blocks'
        AND COLUMN_NAME = 'approved_by'
    ) THEN
        ALTER TABLE ip_blocks
        ADD COLUMN approved_by INT NULL
        AFTER approval_status;
    END IF;

    -- Add approved_at timestamp
    IF NOT EXISTS (
        SELECT * FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'ip_blocks'
        AND COLUMN_NAME = 'approved_at'
    ) THEN
        ALTER TABLE ip_blocks
        ADD COLUMN approved_at TIMESTAMP NULL
        AFTER approved_by;
    END IF;
END //

DELIMITER ;

-- Execute the procedure
CALL add_approval_workflow_columns();

-- Drop the procedure after use
DROP PROCEDURE IF EXISTS add_approval_workflow_columns;

-- Add index for pending approvals (for dashboard query)
-- Check if index exists first
SET @index_exists = (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'ip_blocks'
    AND INDEX_NAME = 'idx_approval_pending'
);

-- Create index if it doesn't exist
SET @sql = IF(@index_exists = 0,
    'CREATE INDEX idx_approval_pending ON ip_blocks(approval_status, is_active)',
    'SELECT "Index idx_approval_pending already exists" AS message'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add composite index for dashboard queries (status + timestamp)
SET @index_exists = (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'ip_blocks'
    AND INDEX_NAME = 'idx_approval_dashboard'
);

SET @sql = IF(@index_exists = 0,
    'CREATE INDEX idx_approval_dashboard ON ip_blocks(approval_status, blocked_at DESC)',
    'SELECT "Index idx_approval_dashboard already exists" AS message'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Optional: Add foreign key for approved_by (if users table exists)
-- Check if users table exists and FK doesn't exist
SET @users_table_exists = (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'users'
);

SET @fk_exists = (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'ip_blocks'
    AND CONSTRAINT_NAME = 'fk_ip_blocks_approver'
);

SET @sql = IF(@users_table_exists > 0 AND @fk_exists = 0,
    'ALTER TABLE ip_blocks ADD CONSTRAINT fk_ip_blocks_approver FOREIGN KEY (approved_by) REFERENCES users(id) ON DELETE SET NULL',
    'SELECT "Users table not found or FK already exists, skipping FK creation" AS message'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Update existing records to have 'auto' approval_status if NULL
UPDATE ip_blocks
SET approval_status = 'auto'
WHERE approval_status IS NULL;

SELECT 'Migration 025 completed successfully' AS status;

-- Migration 025: Add approval workflow columns to ip_blocks
-- Version: 025
-- Purpose: Enable manual approval workflow for IP blocking actions

-- Add approval_status column (check if not exists)
SET @col_exists = (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'ip_blocks'
    AND COLUMN_NAME = 'approval_status'
);

SET @sql_add_approval_status = IF(
    @col_exists = 0,
    'ALTER TABLE ip_blocks ADD COLUMN approval_status ENUM(''auto'', ''pending'', ''approved'', ''rejected'') DEFAULT ''auto'' AFTER is_active',
    'SELECT ''Column approval_status already exists'' AS message'
);

PREPARE stmt FROM @sql_add_approval_status;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add approved_by column (check if not exists)
SET @col_exists = (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'ip_blocks'
    AND COLUMN_NAME = 'approved_by'
);

SET @sql_add_approved_by = IF(
    @col_exists = 0,
    'ALTER TABLE ip_blocks ADD COLUMN approved_by INT NULL AFTER approval_status',
    'SELECT ''Column approved_by already exists'' AS message'
);

PREPARE stmt FROM @sql_add_approved_by;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add approved_at column (check if not exists)
SET @col_exists = (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'ip_blocks'
    AND COLUMN_NAME = 'approved_at'
);

SET @sql_add_approved_at = IF(
    @col_exists = 0,
    'ALTER TABLE ip_blocks ADD COLUMN approved_at TIMESTAMP NULL AFTER approved_by',
    'SELECT ''Column approved_at already exists'' AS message'
);

PREPARE stmt FROM @sql_add_approved_at;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add index for pending approvals
SET @index_exists = (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'ip_blocks'
    AND INDEX_NAME = 'idx_approval_pending'
);

SET @sql_add_index1 = IF(
    @index_exists = 0,
    'CREATE INDEX idx_approval_pending ON ip_blocks(approval_status, is_active)',
    'SELECT ''Index idx_approval_pending already exists'' AS message'
);

PREPARE stmt FROM @sql_add_index1;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add composite index for dashboard queries
SET @index_exists = (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'ip_blocks'
    AND INDEX_NAME = 'idx_approval_dashboard'
);

SET @sql_add_index2 = IF(
    @index_exists = 0,
    'CREATE INDEX idx_approval_dashboard ON ip_blocks(approval_status, blocked_at DESC)',
    'SELECT ''Index idx_approval_dashboard already exists'' AS message'
);

PREPARE stmt FROM @sql_add_index2;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add foreign key for approved_by (if users table exists and FK doesn't exist)
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

SET @sql_add_fk = IF(
    @users_table_exists > 0 AND @fk_exists = 0,
    'ALTER TABLE ip_blocks ADD CONSTRAINT fk_ip_blocks_approver FOREIGN KEY (approved_by) REFERENCES users(id) ON DELETE SET NULL',
    'SELECT ''Users table not found or FK already exists, skipping FK creation'' AS message'
);

PREPARE stmt FROM @sql_add_fk;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Update existing records to have 'auto' approval_status
UPDATE ip_blocks
SET approval_status = 'auto'
WHERE approval_status IS NULL;

SELECT 'Migration 025 completed successfully' AS status;

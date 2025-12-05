-- Migration: 013_event_actions_tables.sql
-- Description: Create tables for Events Live page actionable functions
-- Date: 2025-12-05
-- Author: SSH Guardian v3.0

-- ============================================================================
-- Table: ip_whitelist
-- Purpose: Store trusted IP addresses and ranges that should bypass security checks
-- ============================================================================
CREATE TABLE IF NOT EXISTS ip_whitelist (
    id INT PRIMARY KEY AUTO_INCREMENT,
    ip_address_text VARCHAR(45) NOT NULL COMMENT 'IP address in text format (IPv4 or IPv6)',
    ip_range_cidr VARCHAR(50) NULL COMMENT 'IP range in CIDR notation for subnet whitelisting',
    whitelist_reason VARCHAR(500) NOT NULL COMMENT 'Reason for whitelisting this IP',
    whitelist_source ENUM('manual', 'api', 'rule_based') NOT NULL COMMENT 'Source of the whitelist entry',
    is_active BOOLEAN DEFAULT TRUE COMMENT 'Whether this whitelist entry is currently active',
    expires_at TIMESTAMP NULL COMMENT 'Optional expiration timestamp for temporary whitelisting',
    created_by_user_id INT NULL COMMENT 'User ID who created this entry',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    -- Indexes
    UNIQUE INDEX idx_ip_whitelist_unique (ip_address_text),
    INDEX idx_ip_whitelist_active (is_active),
    INDEX idx_ip_whitelist_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Whitelist of trusted IP addresses that bypass security checks';

-- ============================================================================
-- Table: ip_watchlist
-- Purpose: Monitor suspicious IP addresses with different severity levels
-- ============================================================================
CREATE TABLE IF NOT EXISTS ip_watchlist (
    id INT PRIMARY KEY AUTO_INCREMENT,
    ip_address_text VARCHAR(45) NOT NULL COMMENT 'IP address to monitor',
    watch_reason VARCHAR(500) NOT NULL COMMENT 'Reason for watching this IP',
    watch_level ENUM('low', 'medium', 'high', 'critical') NOT NULL COMMENT 'Severity level of the watch',
    trigger_event_id BIGINT NULL COMMENT 'Event that triggered this watch entry',
    is_active BOOLEAN DEFAULT TRUE COMMENT 'Whether this watch is currently active',
    expires_at TIMESTAMP NULL COMMENT 'Optional expiration timestamp for temporary watches',
    notify_on_activity BOOLEAN DEFAULT TRUE COMMENT 'Send notifications when this IP has activity',
    created_by_user_id INT NULL COMMENT 'User ID who created this entry',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    -- Indexes
    INDEX idx_ip_watchlist_ip (ip_address_text),
    INDEX idx_ip_watchlist_active (is_active),
    INDEX idx_ip_watchlist_level (watch_level),
    INDEX idx_ip_watchlist_expires (expires_at),
    UNIQUE INDEX idx_ip_watchlist_active_unique (ip_address_text, is_active),

    -- Foreign Key
    CONSTRAINT fk_watchlist_event
        FOREIGN KEY (trigger_event_id)
        REFERENCES auth_events(id)
        ON DELETE SET NULL
        ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Watchlist for monitoring suspicious IP addresses';

-- ============================================================================
-- Table: event_notes
-- Purpose: Store notes and annotations for events and IP addresses
-- ============================================================================
CREATE TABLE IF NOT EXISTS event_notes (
    id INT PRIMARY KEY AUTO_INCREMENT,
    note_uuid CHAR(36) NOT NULL COMMENT 'Unique identifier for this note',
    note_type ENUM('event', 'ip', 'general') NOT NULL COMMENT 'Type of note',
    event_id BIGINT NULL COMMENT 'Related event ID (if note_type is event)',
    ip_address_text VARCHAR(45) NULL COMMENT 'Related IP address (if note_type is ip)',
    note_content TEXT NOT NULL COMMENT 'The actual note content',
    is_pinned BOOLEAN DEFAULT FALSE COMMENT 'Whether this note is pinned for visibility',
    created_by_user_id INT NULL COMMENT 'User ID who created this note',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    -- Indexes
    UNIQUE INDEX idx_event_notes_uuid (note_uuid),
    INDEX idx_event_notes_type (note_type),
    INDEX idx_event_notes_event (event_id, created_at),
    INDEX idx_event_notes_ip (ip_address_text, created_at),
    INDEX idx_event_notes_pinned (is_pinned),

    -- Foreign Key
    CONSTRAINT fk_event_notes_event
        FOREIGN KEY (event_id)
        REFERENCES auth_events(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Notes and annotations for events and IP addresses';

-- ============================================================================
-- Table: ip_reports
-- Purpose: Track IP reports sent to external abuse reporting services
-- ============================================================================
CREATE TABLE IF NOT EXISTS ip_reports (
    id INT PRIMARY KEY AUTO_INCREMENT,
    report_uuid CHAR(36) NOT NULL COMMENT 'Unique identifier for this report',
    ip_address_text VARCHAR(45) NOT NULL COMMENT 'IP address being reported',
    report_service ENUM('abuseipdb', 'manual', 'internal') NOT NULL COMMENT 'Service where report was submitted',
    report_categories JSON NULL COMMENT 'Abuse categories for the report',
    report_comment TEXT NULL COMMENT 'Comment/description submitted with the report',
    trigger_event_id BIGINT NULL COMMENT 'Event that triggered this report',
    report_status ENUM('pending', 'submitted', 'acknowledged', 'failed') NOT NULL DEFAULT 'pending' COMMENT 'Current status of the report',
    external_report_id VARCHAR(100) NULL COMMENT 'Report ID from external service',
    response_data JSON NULL COMMENT 'Response data from external service',
    created_by_user_id INT NULL COMMENT 'User ID who created this report',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    -- Indexes
    UNIQUE INDEX idx_ip_reports_uuid (report_uuid),
    INDEX idx_ip_reports_ip (ip_address_text, created_at),
    INDEX idx_ip_reports_status (report_status),
    INDEX idx_ip_reports_service (report_service),
    INDEX idx_ip_reports_external_id (external_report_id),

    -- Foreign Key
    CONSTRAINT fk_ip_reports_event
        FOREIGN KEY (trigger_event_id)
        REFERENCES auth_events(id)
        ON DELETE SET NULL
        ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Track IP reports submitted to external abuse reporting services';

-- ============================================================================
-- End of Migration: 013_event_actions_tables.sql
-- ============================================================================

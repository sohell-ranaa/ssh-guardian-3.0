-- Migration 026: User Login Baselines for Impossible Travel Detection
-- Tracks user login locations for geographic anomaly detection

CREATE TABLE IF NOT EXISTS user_login_baselines (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,

    -- Last known location
    last_latitude DECIMAL(10, 8),
    last_longitude DECIMAL(11, 8),
    last_country_code CHAR(2),
    last_city VARCHAR(100),
    last_ip_text VARCHAR(45),
    last_login_at TIMESTAMP NULL,

    -- Statistics
    login_count INT DEFAULT 0,
    successful_logins INT DEFAULT 0,
    failed_logins INT DEFAULT 0,

    -- Known good locations (JSON array of {country_code, city, lat, lon})
    known_locations JSON,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    -- Indexes
    UNIQUE KEY idx_username (username),
    INDEX idx_last_login (last_login_at),
    INDEX idx_country (last_country_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Add new rule types to blocking_rules enum if not exists
-- Note: MySQL doesn't support easy ENUM modification, so we use a workaround

-- Check and add new rule types
ALTER TABLE blocking_rules
MODIFY COLUMN rule_type ENUM(
    'brute_force',
    'ml_threshold',
    'api_reputation',
    'anomaly_pattern',
    'geo_restriction',
    'geo_anomaly',
    'credential_stuffing',
    'velocity',
    'tor_detection',
    'proxy_detection',
    'threat_combo',
    'repeat_offender',
    'custom'
) NOT NULL;

-- Add block_on_success column if not exists
ALTER TABLE blocking_rules
ADD COLUMN IF NOT EXISTS block_on_success BOOLEAN DEFAULT FALSE
COMMENT 'Block even on successful login (for critical threats)';

-- Add offense_count to ip_blocks for repeat offender tracking
ALTER TABLE ip_blocks
ADD COLUMN IF NOT EXISTS offense_number INT DEFAULT 1
COMMENT 'Which offense number this is for this IP';

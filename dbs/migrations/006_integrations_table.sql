-- Migration 006: Integrations Configuration Table
-- Stores third-party service integration settings
-- Date: 2025-12-04

-- Create integrations table
CREATE TABLE IF NOT EXISTS integrations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    integration_id VARCHAR(50) NOT NULL UNIQUE COMMENT 'Unique identifier (telegram, abuseipdb, etc.)',
    name VARCHAR(100) NOT NULL COMMENT 'Display name',
    description TEXT COMMENT 'Integration description',
    icon VARCHAR(10) DEFAULT NULL COMMENT 'Emoji icon',
    category ENUM('notifications', 'threat_intel', 'email', 'geoip', 'other') DEFAULT 'other',
    is_enabled BOOLEAN DEFAULT FALSE COMMENT 'Whether integration is enabled',
    status ENUM('active', 'configured', 'inactive', 'error') DEFAULT 'inactive',
    last_test_at TIMESTAMP NULL COMMENT 'Last successful test timestamp',
    last_test_result TEXT COMMENT 'Last test result message',
    error_message TEXT COMMENT 'Last error message if any',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_integration_id (integration_id),
    INDEX idx_category (category),
    INDEX idx_status (status),
    INDEX idx_enabled (is_enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create integration config table for key-value settings
CREATE TABLE IF NOT EXISTS integration_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    integration_id VARCHAR(50) NOT NULL COMMENT 'References integrations.integration_id',
    config_key VARCHAR(100) NOT NULL COMMENT 'Configuration key',
    config_value TEXT COMMENT 'Configuration value (encrypted if sensitive)',
    value_type ENUM('string', 'number', 'boolean', 'json') DEFAULT 'string',
    is_sensitive BOOLEAN DEFAULT FALSE COMMENT 'Whether value should be masked in UI',
    is_required BOOLEAN DEFAULT FALSE COMMENT 'Whether this config is required',
    display_name VARCHAR(100) COMMENT 'Label for UI display',
    description TEXT COMMENT 'Help text for UI',
    display_order INT DEFAULT 0 COMMENT 'Order in configuration form',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_integration_config (integration_id, config_key),
    INDEX idx_integration_id (integration_id),
    CONSTRAINT fk_integration_config_integration
        FOREIGN KEY (integration_id) REFERENCES integrations(integration_id)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert default integrations (using hex for emoji to avoid encoding issues)
INSERT INTO integrations (integration_id, name, description, icon, category, is_enabled, status) VALUES
('telegram', 'Telegram Bot', 'Send notifications and alerts via Telegram', 0xF09F93B1, 'notifications', FALSE, 'inactive'),
('abuseipdb', 'AbuseIPDB', 'Check IP reputation using AbuseIPDB database', 0xF09F9BA1EFB88F, 'threat_intel', FALSE, 'inactive'),
('virustotal', 'VirusTotal', 'Scan IPs for malware and security threats', 0xF09F94AC, 'threat_intel', FALSE, 'inactive'),
('shodan', 'Shodan', 'Discover open ports and vulnerabilities', 0xF09F948D, 'threat_intel', FALSE, 'inactive'),
('smtp', 'Email (SMTP)', 'Send email notifications and OTP codes', 0xF09F93A7, 'email', FALSE, 'inactive'),
('ipapi', 'IP-API', 'GeoIP lookup for IP geolocation (free tier)', 0xF09F8C8D, 'geoip', TRUE, 'active')
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP;

-- Insert Telegram configuration keys
INSERT INTO integration_config (integration_id, config_key, config_value, value_type, is_sensitive, is_required, display_name, description, display_order) VALUES
('telegram', 'bot_token', '', 'string', TRUE, TRUE, 'Bot Token', 'Telegram bot token from @BotFather', 1),
('telegram', 'chat_id', '', 'string', FALSE, TRUE, 'Chat ID', 'Telegram chat/group ID for notifications', 2),
('telegram', 'enabled', 'false', 'boolean', FALSE, FALSE, 'Enabled', 'Enable Telegram notifications', 3)
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP;

-- Insert AbuseIPDB configuration keys
INSERT INTO integration_config (integration_id, config_key, config_value, value_type, is_sensitive, is_required, display_name, description, display_order) VALUES
('abuseipdb', 'api_key', '', 'string', TRUE, TRUE, 'API Key', 'AbuseIPDB API key', 1),
('abuseipdb', 'enabled', 'false', 'boolean', FALSE, FALSE, 'Enabled', 'Enable AbuseIPDB lookups', 2),
('abuseipdb', 'rate_limit_day', '1000', 'number', FALSE, FALSE, 'Daily Rate Limit', 'Maximum requests per day', 3),
('abuseipdb', 'rate_limit_minute', '30', 'number', FALSE, FALSE, 'Minute Rate Limit', 'Maximum requests per minute', 4)
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP;

-- Insert VirusTotal configuration keys
INSERT INTO integration_config (integration_id, config_key, config_value, value_type, is_sensitive, is_required, display_name, description, display_order) VALUES
('virustotal', 'api_key', '', 'string', TRUE, TRUE, 'API Key', 'VirusTotal API key', 1),
('virustotal', 'enabled', 'false', 'boolean', FALSE, FALSE, 'Enabled', 'Enable VirusTotal lookups', 2),
('virustotal', 'rate_limit_day', '250', 'number', FALSE, FALSE, 'Daily Rate Limit', 'Maximum requests per day', 3),
('virustotal', 'rate_limit_minute', '4', 'number', FALSE, FALSE, 'Minute Rate Limit', 'Maximum requests per minute', 4)
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP;

-- Insert Shodan configuration keys
INSERT INTO integration_config (integration_id, config_key, config_value, value_type, is_sensitive, is_required, display_name, description, display_order) VALUES
('shodan', 'api_key', '', 'string', TRUE, TRUE, 'API Key', 'Shodan API key', 1),
('shodan', 'enabled', 'false', 'boolean', FALSE, FALSE, 'Enabled', 'Enable Shodan lookups', 2),
('shodan', 'high_risk_only', 'true', 'boolean', FALSE, FALSE, 'High Risk Only', 'Only query Shodan for high-risk IPs', 3),
('shodan', 'rate_limit_month', '100', 'number', FALSE, FALSE, 'Monthly Rate Limit', 'Maximum requests per month', 4),
('shodan', 'rate_limit_day', '3', 'number', FALSE, FALSE, 'Daily Rate Limit', 'Maximum requests per day', 5)
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP;

-- Insert SMTP configuration keys
INSERT INTO integration_config (integration_id, config_key, config_value, value_type, is_sensitive, is_required, display_name, description, display_order) VALUES
('smtp', 'host', '', 'string', FALSE, TRUE, 'SMTP Host', 'SMTP server hostname', 1),
('smtp', 'port', '587', 'number', FALSE, TRUE, 'SMTP Port', 'SMTP server port (25, 465, or 587)', 2),
('smtp', 'user', '', 'string', FALSE, TRUE, 'Username', 'SMTP authentication username', 3),
('smtp', 'password', '', 'string', TRUE, TRUE, 'Password', 'SMTP authentication password', 4),
('smtp', 'from_email', '', 'string', FALSE, TRUE, 'From Email', 'Sender email address', 5),
('smtp', 'from_name', 'SSH Guardian', 'string', FALSE, FALSE, 'From Name', 'Sender display name', 6),
('smtp', 'use_tls', 'true', 'boolean', FALSE, FALSE, 'Use TLS', 'Use TLS encryption', 7)
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP;

-- Insert IP-API configuration keys (no API key required for free tier)
INSERT INTO integration_config (integration_id, config_key, config_value, value_type, is_sensitive, is_required, display_name, description, display_order) VALUES
('ipapi', 'enabled', 'true', 'boolean', FALSE, FALSE, 'Enabled', 'Enable GeoIP lookups', 1),
('ipapi', 'rate_limit_minute', '45', 'number', FALSE, FALSE, 'Rate Limit', 'Maximum requests per minute (free tier)', 2)
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP;

-- Settings Table Migration
-- Stores key-value configuration settings for the application

CREATE TABLE IF NOT EXISTS system_settings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    setting_key VARCHAR(100) NOT NULL UNIQUE,
    setting_value TEXT,
    setting_type ENUM('string', 'number', 'boolean', 'json') DEFAULT 'string',
    category VARCHAR(50) DEFAULT 'general',
    description TEXT,
    is_sensitive BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_category (category),
    INDEX idx_key (setting_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert default settings
INSERT INTO system_settings (setting_key, setting_value, setting_type, category, description) VALUES
('system_name', 'SSH Guardian v3.0', 'string', 'general', 'System display name'),
('max_login_attempts', '5', 'number', 'security', 'Maximum failed login attempts before blocking'),
('block_duration_minutes', '60', 'number', 'security', 'Default block duration in minutes'),
('enable_auto_blocking', 'true', 'boolean', 'security', 'Automatically block suspicious IPs'),
('risk_score_threshold', '70', 'number', 'security', 'Risk score threshold for auto-blocking'),
('enable_notifications', 'true', 'boolean', 'notifications', 'Enable email/webhook notifications'),
('notification_email', '', 'string', 'notifications', 'Email address for notifications'),
('data_retention_days', '90', 'number', 'general', 'Number of days to retain event data'),
('enable_geolocation', 'true', 'boolean', 'general', 'Enable IP geolocation lookup'),
('dashboard_refresh_interval', '30', 'number', 'general', 'Dashboard auto-refresh interval in seconds')
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP;

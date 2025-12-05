-- Cache Settings Table Migration
-- Stores configurable cache TTL and auto-refresh settings for each endpoint

CREATE TABLE IF NOT EXISTS cache_settings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    endpoint_key VARCHAR(100) NOT NULL UNIQUE,
    endpoint_name VARCHAR(150) NOT NULL,
    endpoint_description TEXT,
    category VARCHAR(50) NOT NULL DEFAULT 'general',

    -- Cache Configuration
    ttl_seconds INT NOT NULL DEFAULT 300,
    default_ttl_seconds INT NOT NULL DEFAULT 300,
    min_ttl_seconds INT NOT NULL DEFAULT 30,
    max_ttl_seconds INT NOT NULL DEFAULT 86400,

    -- Auto-refresh settings
    auto_refresh_enabled BOOLEAN DEFAULT FALSE,
    auto_refresh_interval_seconds INT DEFAULT 60,
    incremental_update_enabled BOOLEAN DEFAULT FALSE,

    -- Cache behavior
    is_enabled BOOLEAN DEFAULT TRUE,
    priority ENUM('low', 'normal', 'high', 'critical') DEFAULT 'normal',

    -- Statistics (updated by cache system)
    hit_count BIGINT UNSIGNED DEFAULT 0,
    miss_count BIGINT UNSIGNED DEFAULT 0,
    last_hit_at TIMESTAMP NULL,
    last_refresh_at TIMESTAMP NULL,
    avg_load_time_ms DECIMAL(10,2) DEFAULT 0,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_category (category),
    INDEX idx_enabled (is_enabled),
    INDEX idx_priority (priority)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert default cache settings for all endpoints
INSERT INTO cache_settings (endpoint_key, endpoint_name, endpoint_description, category, ttl_seconds, default_ttl_seconds, min_ttl_seconds, max_ttl_seconds, auto_refresh_enabled, auto_refresh_interval_seconds, priority) VALUES

-- Events (Dynamic data - shorter TTL)
('events_list', 'Events List', 'Live authentication events with pagination', 'events', 120, 120, 30, 600, TRUE, 30, 'high'),
('events_count', 'Events Count', 'Total event count for pagination', 'events', 300, 300, 60, 900, FALSE, 0, 'normal'),
('events_analysis', 'Event Analysis', 'Event statistics and patterns', 'events', 300, 300, 60, 900, FALSE, 0, 'normal'),
('events_timeline', 'Events Timeline', 'Time-based event distribution', 'events', 300, 300, 60, 900, FALSE, 0, 'normal'),

-- IP Statistics
('ip_stats_list', 'IP Stats List', 'IP address statistics listing', 'ip_stats', 300, 300, 60, 1800, FALSE, 0, 'normal'),
('ip_stats_summary', 'IP Stats Summary', 'Aggregate IP statistics', 'ip_stats', 600, 600, 120, 1800, FALSE, 0, 'normal'),
('ip_stats_detail', 'IP Detail', 'Individual IP details', 'ip_stats', 600, 600, 120, 3600, FALSE, 0, 'normal'),

-- Blocking
('blocking_list', 'Block List', 'Active IP blocks', 'blocking', 300, 300, 60, 900, TRUE, 60, 'high'),
('blocking_stats', 'Block Stats', 'Blocking statistics', 'blocking', 600, 600, 120, 1800, FALSE, 0, 'normal'),
('blocking_rules', 'Block Rules', 'Blocking rules configuration', 'blocking', 1800, 1800, 300, 3600, FALSE, 0, 'low'),

-- GeoIP (Static data - long TTL)
('geoip_lookup', 'GeoIP Lookup', 'IP to location mapping', 'geoip', 7200, 7200, 3600, 86400, FALSE, 0, 'low'),
('geoip_stats', 'GeoIP Stats', 'Geographic distribution stats', 'geoip', 1800, 1800, 600, 7200, FALSE, 0, 'low'),
('geoip_recent', 'Recent GeoIP', 'Recently looked up locations', 'geoip', 600, 600, 120, 1800, FALSE, 0, 'normal'),

-- Threat Intel (Semi-static - medium TTL)
('threat_intel_lookup', 'Threat Intel Lookup', 'IP threat intelligence data', 'threat_intel', 3600, 3600, 1800, 86400, FALSE, 0, 'low'),
('threat_intel_stats', 'Threat Intel Stats', 'Threat intelligence statistics', 'threat_intel', 1800, 1800, 600, 7200, FALSE, 0, 'low'),
('threat_intel_recent', 'Recent Threats', 'Recently analyzed threats', 'threat_intel', 600, 600, 120, 1800, FALSE, 0, 'normal'),

-- ML (Predictions cache)
('ml_predictions', 'ML Predictions', 'Machine learning predictions', 'ml', 600, 600, 120, 1800, FALSE, 0, 'normal'),
('ml_models', 'ML Models', 'Model information and status', 'ml', 3600, 3600, 600, 7200, FALSE, 0, 'low'),
('ml_overview', 'ML Overview', 'ML dashboard overview', 'ml', 300, 300, 60, 900, FALSE, 0, 'normal'),

-- Audit Logs
('audit_list', 'Audit List', 'Audit log entries', 'audit', 300, 300, 60, 1800, FALSE, 0, 'normal'),
('audit_stats', 'Audit Stats', 'Audit log statistics', 'audit', 600, 600, 120, 1800, FALSE, 0, 'normal'),
('audit_actions', 'Audit Actions', 'Available audit action types', 'audit', 1800, 1800, 600, 7200, FALSE, 0, 'low'),

-- Notifications
('notifications_list', 'Notifications List', 'Notification history', 'notifications', 300, 300, 60, 900, TRUE, 60, 'normal'),
('notifications_stats', 'Notification Stats', 'Notification statistics', 'notifications', 600, 600, 120, 1800, FALSE, 0, 'normal'),

-- Trends & Reports (Historical - long TTL)
('trends_overview', 'Trends Overview', 'Trend analysis overview', 'reports', 1800, 1800, 600, 7200, FALSE, 0, 'low'),
('trends_daily', 'Daily Trends', 'Daily activity trends', 'reports', 1800, 1800, 600, 7200, FALSE, 0, 'low'),
('trends_geographic', 'Geographic Trends', 'Geographic distribution trends', 'reports', 1800, 1800, 600, 7200, FALSE, 0, 'low'),
('daily_reports', 'Daily Reports', 'Generated daily reports', 'reports', 3600, 3600, 1800, 86400, FALSE, 0, 'low'),

-- Dashboard Summary
('dashboard_summary', 'Dashboard Summary', 'Main dashboard statistics', 'dashboard', 300, 300, 60, 900, TRUE, 30, 'critical')

ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP;

-- Global cache configuration (stored in system_settings)
INSERT INTO system_settings (setting_key, setting_value, setting_type, category, description) VALUES
('cache_enabled', 'true', 'boolean', 'cache', 'Enable/disable Redis caching globally'),
('cache_default_ttl', '300', 'number', 'cache', 'Default cache TTL in seconds'),
('cache_auto_refresh_global', 'true', 'boolean', 'cache', 'Enable auto-refresh for configured endpoints'),
('cache_stale_threshold_percent', '80', 'number', 'cache', 'Percentage of TTL after which cache is considered stale'),
('cache_preload_on_startup', 'false', 'boolean', 'cache', 'Preload critical caches on server startup'),
('cache_stats_retention_days', '7', 'number', 'cache', 'Days to retain cache statistics')
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP;

-- Migration 014: FreeIPAPI Integration
-- Adds FreeIPAPI as an alternative GeoIP provider
-- Date: 2025-12-05

-- Insert FreeIPAPI integration
INSERT INTO integrations (integration_id, name, description, icon, category, is_enabled, status) VALUES
('freeipapi', 'FreeIPAPI', 'IP geolocation lookup with detailed information (free tier, no API key required)', 0xF09F8C90, 'geoip', TRUE, 'active')
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP;

-- Insert FreeIPAPI configuration keys
INSERT INTO integration_config (integration_id, config_key, config_value, value_type, is_sensitive, is_required, display_name, description, display_order) VALUES
('freeipapi', 'enabled', 'true', 'boolean', FALSE, FALSE, 'Enabled', 'Enable FreeIPAPI for IP geolocation lookups', 1),
('freeipapi', 'cache_ttl_hours', '24', 'number', FALSE, FALSE, 'Cache TTL (Hours)', 'How long to cache IP geolocation results', 2),
('freeipapi', 'rate_limit_minute', '60', 'number', FALSE, FALSE, 'Rate Limit', 'Maximum requests per minute (free tier)', 3),
('freeipapi', 'use_as_primary', 'true', 'boolean', FALSE, FALSE, 'Primary Provider', 'Use FreeIPAPI as the primary GeoIP provider', 4)
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP;

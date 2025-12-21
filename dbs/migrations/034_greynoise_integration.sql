-- SSH Guardian v3.1 - Migration 034: GreyNoise Integration
-- Adds GreyNoise API support for distinguishing internet noise from targeted attacks
-- Created: 2024-12-21

-- Add GreyNoise columns to ip_geolocation table
ALTER TABLE ip_geolocation
ADD COLUMN greynoise_noise BOOLEAN DEFAULT NULL COMMENT 'True if IP is known internet scanner',
ADD COLUMN greynoise_riot BOOLEAN DEFAULT NULL COMMENT 'True if IP is known benign service (CDN, search engine)',
ADD COLUMN greynoise_classification VARCHAR(20) DEFAULT NULL COMMENT 'benign, malicious, or unknown',
ADD COLUMN greynoise_checked_at TIMESTAMP NULL COMMENT 'When GreyNoise was last checked';

-- Add index for GreyNoise noise filtering
CREATE INDEX idx_ip_geolocation_greynoise ON ip_geolocation (greynoise_noise, greynoise_riot);

-- Insert GreyNoise integration into integrations table
INSERT INTO integrations (integration_type, name, is_enabled, config, credentials, created_at, updated_at)
VALUES (
    'greynoise',
    'GreyNoise',
    FALSE,
    '{"enabled": "false", "use_community_api": "true"}',
    '{"api_key": ""}',
    NOW(),
    NOW()
)
ON DUPLICATE KEY UPDATE updated_at = NOW();

-- Migration completed

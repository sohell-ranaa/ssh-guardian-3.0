-- ============================================================================
-- SSH Guardian v3.0 - Authentication & System Tables
-- Part 2 of Schema
-- ============================================================================

SET FOREIGN_KEY_CHECKS = 0;

-- ============================================================================
-- AUTHENTICATION & USER MANAGEMENT
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 15. Roles (RBAC Roles)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS roles (
    id INT AUTO_INCREMENT PRIMARY KEY,

    name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT NULL,
    permissions JSON NOT NULL COMMENT 'Permission flags',

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='RBAC roles with JSON permissions';

-- ----------------------------------------------------------------------------
-- 16. Users (User Accounts)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,

    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    role_id INT NOT NULL,

    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    is_email_verified BOOLEAN DEFAULT FALSE,

    -- Security
    last_login TIMESTAMP NULL,
    failed_login_attempts INT DEFAULT 0,
    locked_until TIMESTAMP NULL,

    -- Metadata
    created_by INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    KEY idx_role_id (role_id),
    KEY idx_is_active (is_active),
    KEY idx_created_by (created_by),
    KEY idx_email_verified (is_email_verified),

    FOREIGN KEY (role_id) REFERENCES roles(id),
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='User accounts with RBAC';

-- Add FKs to other tables referencing users
ALTER TABLE agents ADD CONSTRAINT fk_agents_approved_by
    FOREIGN KEY (approved_by_user_id) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE blocking_rules ADD CONSTRAINT fk_blocking_rules_creator
    FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE ip_blocks ADD CONSTRAINT fk_ip_blocks_creator
    FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE ip_blocks ADD CONSTRAINT fk_ip_blocks_unblocker
    FOREIGN KEY (unblocked_by_user_id) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE blocking_actions ADD CONSTRAINT fk_blocking_actions_user
    FOREIGN KEY (performed_by_user_id) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE simulation_runs ADD CONSTRAINT fk_simulation_runs_user
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;

-- ----------------------------------------------------------------------------
-- 17. User Sessions (Active Sessions)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,

    user_id INT NOT NULL,
    session_token VARCHAR(255) NOT NULL UNIQUE,

    -- Connection Info
    ip_address VARCHAR(45) NULL,
    user_agent TEXT NULL,

    -- Session Management
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    KEY idx_user_id (user_id),
    KEY idx_expires_at (expires_at),
    KEY idx_last_activity (last_activity),

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Active user sessions for authentication';

-- ----------------------------------------------------------------------------
-- 18. User OTPs (One-Time Passwords)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_otps (
    id INT AUTO_INCREMENT PRIMARY KEY,

    user_id INT NOT NULL,
    otp_code VARCHAR(6) NOT NULL,
    purpose ENUM('login', 'password_reset', 'email_verification') DEFAULT 'login',

    -- Validity
    expires_at TIMESTAMP NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMP NULL,

    -- Context
    ip_address VARCHAR(45) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    KEY idx_user_id (user_id),
    KEY idx_purpose (purpose),
    KEY idx_expires_at (expires_at),
    KEY idx_otp_lookup (user_id, otp_code, purpose, is_used),

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='OTP codes for two-factor authentication';

-- ----------------------------------------------------------------------------
-- 19. Audit Logs (Security Audit Trail)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    user_id INT NULL,
    action VARCHAR(100) NOT NULL,

    -- Resource
    resource_type VARCHAR(50) NULL,
    resource_id VARCHAR(100) NULL,

    -- Details
    details JSON NULL,

    -- Context
    ip_address VARCHAR(45) NULL,
    user_agent TEXT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    KEY idx_user_id (user_id),
    KEY idx_action (action),
    KEY idx_created_at (created_at),
    KEY idx_resource (resource_type, resource_id),

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Comprehensive audit trail for security events';

-- ============================================================================
-- SIMULATION TABLES
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 20. Simulation Templates (Predefined Attack Scenarios)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS simulation_templates (
    id INT AUTO_INCREMENT PRIMARY KEY,

    template_name VARCHAR(100) NOT NULL UNIQUE,
    display_name VARCHAR(255) NOT NULL,
    description TEXT NULL,

    -- Template Configuration
    template_type ENUM('brute_force', 'credential_stuffing', 'distributed_attack',
                       'slow_attack', 'targeted_attack', 'custom') NOT NULL,
    default_config JSON NOT NULL,

    -- Characteristics
    difficulty_level ENUM('easy', 'medium', 'hard', 'expert') DEFAULT 'medium',
    estimated_duration_minutes INT NULL,
    estimated_events INT NULL,

    -- Visibility
    is_visible BOOLEAN DEFAULT TRUE,
    is_system BOOLEAN DEFAULT FALSE COMMENT 'System templates cannot be deleted',

    -- Statistics
    times_used INT DEFAULT 0,
    last_used_at TIMESTAMP NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    KEY idx_template_type (template_type),
    KEY idx_is_visible (is_visible),
    KEY idx_difficulty (difficulty_level)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Predefined simulation templates';

-- ----------------------------------------------------------------------------
-- 21. Simulation Logs (Detailed Simulation Logs)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS simulation_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    simulation_run_id INT NOT NULL,
    log_uuid CHAR(36) NOT NULL UNIQUE,
    log_timestamp TIMESTAMP(6) NOT NULL COMMENT 'Microsecond precision',
    sequence_number INT NOT NULL,

    -- Log Details
    stage VARCHAR(50) NOT NULL COMMENT 'init, generate, process, cleanup',
    level ENUM('TRACE', 'DEBUG', 'INFO', 'SUCCESS', 'WARNING', 'ERROR', 'CRITICAL') DEFAULT 'INFO',
    category VARCHAR(50) NULL COMMENT 'Type of operation',
    message TEXT NOT NULL,

    -- Context
    ip_address VARCHAR(45) NULL,
    username VARCHAR(255) NULL,
    event_count INT NULL,

    -- Structured Data
    metadata JSON NULL,
    stack_trace TEXT NULL COMMENT 'For errors',

    -- Performance
    execution_time_ms INT NULL,
    memory_usage_mb DECIMAL(10,2) NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    KEY idx_simulation_run (simulation_run_id),
    KEY idx_timestamp (log_timestamp),
    KEY idx_sequence (simulation_run_id, sequence_number),
    KEY idx_level (level),
    KEY idx_stage (stage),

    FOREIGN KEY (simulation_run_id) REFERENCES simulation_runs(id) ON DELETE CASCADE

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Detailed simulation execution logs';

-- ----------------------------------------------------------------------------
-- 22. Simulation IP Pool (IP Pool for Simulations)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS simulation_ip_pool (
    id INT AUTO_INCREMENT PRIMARY KEY,

    ip_address VARCHAR(45) NOT NULL UNIQUE,
    pool_type ENUM('malicious', 'trusted', 'random', 'geo_specific') NOT NULL,

    -- Geographic Data
    country_code CHAR(2) NULL,
    city VARCHAR(100) NULL,

    -- Characteristics
    reputation_score INT NULL COMMENT '0-100',
    is_vpn BOOLEAN DEFAULT FALSE,
    is_proxy BOOLEAN DEFAULT FALSE,
    is_tor BOOLEAN DEFAULT FALSE,

    -- Source
    source VARCHAR(100) NULL COMMENT 'Where IP was sourced from',
    notes TEXT NULL,

    -- Usage Tracking
    times_used INT DEFAULT 0,
    last_used_at TIMESTAMP NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    KEY idx_pool_type (pool_type),
    KEY idx_country_code (country_code),
    KEY idx_reputation_score (reputation_score),
    KEY idx_times_used (times_used)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='IP address pool for simulation scenarios';

-- ============================================================================
-- SYSTEM CONFIGURATION & ALERTS
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 23. System Config (System-wide Configuration)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS system_config (
    id INT AUTO_INCREMENT PRIMARY KEY,

    config_key VARCHAR(100) NOT NULL UNIQUE,
    config_value TEXT NOT NULL,
    value_type ENUM('string', 'int', 'float', 'boolean', 'json') DEFAULT 'string',

    description TEXT NULL,
    is_encrypted BOOLEAN DEFAULT FALSE,
    is_public BOOLEAN DEFAULT FALSE COMMENT 'Can be accessed by non-admin users',

    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    updated_by_user_id INT NULL,

    KEY idx_config_key (config_key),
    KEY idx_is_public (is_public),

    FOREIGN KEY (updated_by_user_id) REFERENCES users(id) ON DELETE SET NULL

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='System-wide configuration key-value store';

-- ----------------------------------------------------------------------------
-- 24. System Alerts (System-wide Alerts)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS system_alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,

    alert_uuid CHAR(36) NOT NULL UNIQUE,
    alert_type ENUM('security', 'performance', 'agent_health',
                    'system_error', 'threshold_breach', 'database') NOT NULL,
    severity ENUM('info', 'warning', 'error', 'critical') NOT NULL,

    -- Alert Details
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    source VARCHAR(100) NULL COMMENT 'Component that triggered alert',

    -- Related Entities
    agent_id INT NULL,
    simulation_run_id INT NULL,
    ip_address VARCHAR(45) NULL,

    -- Status
    status ENUM('active', 'acknowledged', 'resolved', 'dismissed') DEFAULT 'active',
    acknowledged_at TIMESTAMP NULL,
    acknowledged_by_user_id INT NULL,
    resolved_at TIMESTAMP NULL,
    resolved_by_user_id INT NULL,
    resolution_notes TEXT NULL,

    -- Notifications
    notification_sent BOOLEAN DEFAULT FALSE,
    notification_sent_at TIMESTAMP NULL,

    -- Metadata
    alert_data JSON NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    KEY idx_alert_type (alert_type),
    KEY idx_severity (severity),
    KEY idx_status (status),
    KEY idx_created_at (created_at),
    KEY idx_agent (agent_id),
    KEY idx_simulation_run (simulation_run_id),
    KEY idx_active_alerts (status, severity),

    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE SET NULL,
    FOREIGN KEY (simulation_run_id) REFERENCES simulation_runs(id) ON DELETE SET NULL,
    FOREIGN KEY (acknowledged_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (resolved_by_user_id) REFERENCES users(id) ON DELETE SET NULL

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='System-wide alerts and notifications';

-- ============================================================================
-- INSERT DEFAULT DATA
-- ============================================================================

-- Insert default roles
INSERT INTO roles (id, name, description, permissions) VALUES
(1, 'Super Admin', 'Full system access with all permissions', JSON_OBJECT(
    'dashboard_access', true,
    'user_management', true,
    'simulation_management', true,
    'system_settings', true,
    'audit_logs', true,
    'ip_management', true,
    'agent_management', true,
    'notification_management', true,
    'blocking_rules', true
)),
(2, 'Admin', 'Administrative access without user management', JSON_OBJECT(
    'dashboard_access', true,
    'simulation_management', true,
    'ip_management', true,
    'agent_management', true,
    'notification_management', true,
    'blocking_rules', true
)),
(3, 'Analyst', 'Read access with basic simulation capabilities', JSON_OBJECT(
    'dashboard_access', true,
    'simulation_management', true
)),
(4, 'Viewer', 'Read-only dashboard access', JSON_OBJECT(
    'dashboard_access', true
));

-- Insert default system configuration
INSERT INTO system_config (config_key, config_value, value_type, description, is_public) VALUES
('system_name', 'SSH Guardian v3.0', 'string', 'System name', true),
('max_session_duration_days', '30', 'int', 'Maximum session duration', false),
('otp_validity_minutes', '5', 'int', 'OTP validity period', false),
('max_failed_attempts', '5', 'int', 'Max failed login attempts before lockout', false),
('lockout_duration_minutes', '30', 'int', 'Account lockout duration', false),
('default_block_duration_minutes', '1440', 'int', 'Default IP block duration (24 hours)', false),
('enable_ml_processing', 'true', 'boolean', 'Enable ML risk analysis', false),
('enable_geoip_lookup', 'true', 'boolean', 'Enable GeoIP lookups', false),
('enable_threat_intel', 'true', 'boolean', 'Enable 3rd party threat intel APIs', false),
('enable_auto_blocking', 'true', 'boolean', 'Enable automatic IP blocking', false),
('enable_telegram_notifications', 'false', 'boolean', 'Enable Telegram notifications', false),
('data_retention_days', '90', 'int', 'Number of days to keep auth events', false),
('simulation_retention_days', '7', 'int', 'Number of days to keep simulation data', false);

-- Insert default blocking rules
INSERT INTO blocking_rules (rule_name, rule_type, is_enabled, priority, conditions, block_duration_minutes, auto_unblock, notify_on_trigger, description) VALUES
('Brute Force Protection', 'brute_force', true, 90,
 JSON_OBJECT('failed_attempts', 5, 'time_window_minutes', 10, 'unique_usernames', 3),
 1440, true, true,
 'Block IPs with 5+ failed attempts in 10 minutes across 3+ usernames'),

('High ML Risk Score', 'ml_threshold', true, 80,
 JSON_OBJECT('min_risk_score', 85, 'min_confidence', 0.80),
 2880, true, true,
 'Block IPs with ML risk score >= 85 and confidence >= 80%'),

('Critical API Reputation', 'api_reputation', true, 70,
 JSON_OBJECT('abuseipdb_min_score', 80, 'virustotal_min_positives', 3),
 4320, true, true,
 'Block IPs with poor reputation from threat intelligence APIs'),

('Anomaly Detection', 'anomaly_pattern', true, 60,
 JSON_OBJECT('anomaly_types', JSON_ARRAY('geo_anomaly', 'time_anomaly', 'volume_anomaly')),
 720, true, true,
 'Block IPs showing multiple anomaly patterns');

-- Insert default notification rule
INSERT INTO notification_rules (rule_name, is_enabled, trigger_on, conditions, channels, message_template, message_format) VALUES
('Critical IP Block Alert', true, 'ip_blocked',
 JSON_OBJECT('min_risk_score', 80),
 JSON_ARRAY('telegram'),
 '🚨 **Critical IP Blocked**\n\nIP: {ip_address}\nRisk Score: {risk_score}\nReason: {reason}\n\nTime: {timestamp}',
 'markdown');

-- Insert default log sources
INSERT INTO log_sources (source_type, source_name, source_description, is_active) VALUES
('agent', 'primary_agents', 'Real SSH logs from production agents', true),
('synthetic', 'dashboard_generator', 'Synthetic logs generated from dashboard', true),
('simulation', 'simulation_engine', 'Simulated attack scenarios', true);

-- Insert default simulation templates
INSERT INTO simulation_templates (template_name, display_name, description, template_type, default_config, difficulty_level, estimated_duration_minutes, estimated_events) VALUES
('basic_brute_force', 'Basic Brute Force Attack', 'Simple brute force attack from single IP', 'brute_force',
 JSON_OBJECT('total_events', 100, 'failed_attempts', 95, 'unique_ips', 1, 'time_distribution', 'constant'),
 'easy', 5, 100),

('distributed_brute_force', 'Distributed Brute Force', 'Brute force attack from multiple IPs', 'brute_force',
 JSON_OBJECT('total_events', 500, 'failed_attempts', 450, 'unique_ips', 50, 'time_distribution', 'random'),
 'medium', 15, 500),

('credential_stuffing', 'Credential Stuffing Attack', 'Automated login attempts with leaked credentials', 'credential_stuffing',
 JSON_OBJECT('total_events', 1000, 'failed_attempts', 900, 'unique_ips', 100, 'username_list_size', 50),
 'medium', 20, 1000),

('slow_attack', 'Slow Persistent Attack', 'Low-volume attack over extended period', 'slow_attack',
 JSON_OBJECT('total_events', 200, 'failed_attempts', 180, 'unique_ips', 10, 'attack_duration_hours', 24),
 'hard', 60, 200);

-- Add circular foreign key constraints now that all tables exist
ALTER TABLE auth_events ADD CONSTRAINT fk_auth_events_block
    FOREIGN KEY (block_id) REFERENCES ip_blocks(id) ON DELETE SET NULL;

ALTER TABLE ip_blocks ADD CONSTRAINT fk_ip_blocks_trigger_event
    FOREIGN KEY (trigger_event_id) REFERENCES auth_events(id) ON DELETE SET NULL;

ALTER TABLE blocking_actions ADD CONSTRAINT fk_blocking_actions_trigger_event
    FOREIGN KEY (triggered_by_event_id) REFERENCES auth_events(id) ON DELETE SET NULL;

SET FOREIGN_KEY_CHECKS = 1;

-- ============================================================================
-- SCHEMA CREATION COMPLETE
-- ============================================================================

-- ============================================================================
-- SSH Guardian v3.0 - Initial Database Schema
-- Version: 3.0.0
-- Date: 2025-12-04
-- Purpose: Complete database schema for SSH Guardian v3.0
-- ============================================================================

-- This schema implements the complete data pipeline:
-- Log Reception → Parsing → DB → ML → API Check → Action → Notify → Report

SET FOREIGN_KEY_CHECKS = 0;

-- ============================================================================
-- CORE TABLES: Authentication Events & IP Management
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. IP Geolocation Cache (Normalized)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ip_geolocation (
    id INT AUTO_INCREMENT PRIMARY KEY,

    -- IP Address (Binary + Text for performance)
    ip_address VARBINARY(16) NOT NULL UNIQUE COMMENT 'Binary IPv4/IPv6',
    ip_address_text VARCHAR(45) NOT NULL UNIQUE COMMENT 'Text representation',
    ip_version TINYINT NOT NULL COMMENT '4 or 6',

    -- Geographic Information
    country_code CHAR(2) NULL COMMENT 'ISO 3166-1 alpha-2',
    country_name VARCHAR(100) NULL,
    region VARCHAR(100) NULL,
    city VARCHAR(100) NULL,
    postal_code VARCHAR(20) NULL,
    latitude DECIMAL(10,8) NULL,
    longitude DECIMAL(11,8) NULL,
    timezone VARCHAR(50) NULL,

    -- Network Information
    asn INT NULL COMMENT 'Autonomous System Number',
    asn_org VARCHAR(255) NULL COMMENT 'AS Organization',
    isp VARCHAR(255) NULL,
    connection_type VARCHAR(50) NULL COMMENT 'cable, dsl, cellular, etc',

    -- Threat Indicators (from GeoIP database)
    is_proxy BOOLEAN DEFAULT FALSE,
    is_vpn BOOLEAN DEFAULT FALSE,
    is_tor BOOLEAN DEFAULT FALSE,
    is_datacenter BOOLEAN DEFAULT FALSE,
    is_hosting BOOLEAN DEFAULT FALSE,

    -- Cache Management
    lookup_count INT DEFAULT 1 COMMENT 'Number of times looked up',
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    cache_expires_at TIMESTAMP NULL COMMENT 'When to refresh GeoIP data',

    -- Indexes for fast lookups
    KEY idx_country (country_code),
    KEY idx_asn (asn),
    KEY idx_proxy_flags (is_proxy, is_vpn, is_tor),
    KEY idx_cache_expires (cache_expires_at),
    KEY idx_last_seen (last_seen)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Normalized GeoIP cache - prevents duplication across events';

-- ----------------------------------------------------------------------------
-- 2. Log Sources (Tracks where logs come from)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS log_sources (
    id INT AUTO_INCREMENT PRIMARY KEY,

    source_type ENUM('agent', 'synthetic', 'simulation') NOT NULL,
    source_name VARCHAR(100) NOT NULL UNIQUE,
    source_description TEXT NULL,

    -- Configuration
    is_active BOOLEAN DEFAULT TRUE,
    config JSON NULL COMMENT 'Source-specific configuration',

    -- Statistics
    total_events_received BIGINT DEFAULT 0,
    last_event_at TIMESTAMP NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    KEY idx_source_type (source_type),
    KEY idx_is_active (is_active)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Tracking of all log sources (agents, synthetic generators, simulations)';

-- ----------------------------------------------------------------------------
-- 3. Agents (Connected SSH Guardian Agents)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS agents (
    id INT AUTO_INCREMENT PRIMARY KEY,

    agent_uuid CHAR(36) NOT NULL UNIQUE,
    agent_id VARCHAR(100) NOT NULL UNIQUE COMMENT 'Human-readable ID',

    -- Agent Information
    hostname VARCHAR(255) NOT NULL,
    display_name VARCHAR(255) NULL,
    agent_type ENUM('primary', 'secondary', 'monitor_only') DEFAULT 'secondary',

    -- Network Information
    ip_address_primary VARCHAR(45) NULL,
    ip_address_internal VARCHAR(45) NULL,
    mac_address VARCHAR(17) NULL,

    -- Location & Environment
    location VARCHAR(255) NULL,
    datacenter VARCHAR(100) NULL,
    environment ENUM('production', 'staging', 'development', 'testing') DEFAULT 'production',

    -- Status
    status ENUM('online', 'offline', 'maintenance', 'error', 'unknown') DEFAULT 'unknown',
    health_status ENUM('healthy', 'degraded', 'critical') DEFAULT 'healthy',
    last_heartbeat TIMESTAMP NULL,
    heartbeat_interval_sec INT DEFAULT 30,
    consecutive_missed_heartbeats INT DEFAULT 0,

    -- Version & Configuration
    version VARCHAR(50) NULL,
    config_version VARCHAR(50) NULL,
    supported_features JSON NULL COMMENT 'Array of feature flags',

    -- Statistics
    total_events_sent BIGINT DEFAULT 0,
    total_uptime_seconds BIGINT DEFAULT 0,
    last_restart_at TIMESTAMP NULL,
    restart_count INT DEFAULT 0,

    -- Management
    is_active BOOLEAN DEFAULT TRUE,
    is_approved BOOLEAN DEFAULT FALSE COMMENT 'Manual approval required',
    notes TEXT NULL,

    -- System Information
    system_info JSON NULL COMMENT 'OS, CPU, RAM, Disk details',
    custom_metadata JSON NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    approved_at TIMESTAMP NULL,
    approved_by_user_id INT NULL,

    KEY idx_hostname (hostname),
    KEY idx_status (status),
    KEY idx_health_status (health_status),
    KEY idx_last_heartbeat (last_heartbeat),
    KEY idx_is_active (is_active),
    KEY idx_environment (environment),
    KEY idx_agent_type (agent_type)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='SSH Guardian monitoring agents';

-- ----------------------------------------------------------------------------
-- 4. Simulation Runs (Simulation Tracking)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS simulation_runs (
    id INT AUTO_INCREMENT PRIMARY KEY,

    run_uuid CHAR(36) NOT NULL UNIQUE,

    -- User Information
    user_id INT NULL,
    user_email VARCHAR(255) NULL,

    -- Template Information
    template_name VARCHAR(100) NOT NULL,
    template_display_name VARCHAR(255) NULL,

    -- Configuration
    config JSON NOT NULL COMMENT 'Simulation parameters',

    -- Status & Progress
    status ENUM('pending', 'initializing', 'running', 'paused',
                'completed', 'failed', 'cancelled') DEFAULT 'pending',
    progress_percent TINYINT UNSIGNED DEFAULT 0,

    -- Statistics
    total_events_planned INT DEFAULT 0,
    events_generated INT DEFAULT 0,
    ips_blocked INT DEFAULT 0,
    anomalies_detected INT DEFAULT 0,
    notifications_sent INT DEFAULT 0,

    -- Timing
    started_at TIMESTAMP NULL,
    completed_at TIMESTAMP NULL,
    duration_seconds INT NULL,

    -- Error Handling
    error_message TEXT NULL,

    -- Cleanup
    data_retention_days INT DEFAULT 7,
    auto_cleanup_enabled BOOLEAN DEFAULT TRUE,
    cleaned_up_at TIMESTAMP NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    KEY idx_status (status),
    KEY idx_created_at (created_at),
    KEY idx_user_id (user_id),
    KEY idx_cleanup (auto_cleanup_enabled, cleaned_up_at)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Simulation run tracking';

-- ----------------------------------------------------------------------------
-- 5. Auth Events (Unified SSH Authentication Events)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS auth_events (
    -- Primary Key
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_uuid CHAR(36) NOT NULL UNIQUE,

    -- Timing
    timestamp DATETIME(3) NOT NULL COMMENT 'Event occurrence time',
    processed_at DATETIME(3) NULL COMMENT 'When pipeline completed',

    -- Source Information
    source_type ENUM('agent', 'synthetic', 'simulation') NOT NULL,
    agent_id INT NULL,
    log_source_id INT NULL,
    simulation_run_id INT NULL,

    -- Event Classification
    event_type ENUM('failed', 'successful', 'invalid') NOT NULL,
    auth_method ENUM('password', 'publickey', 'keyboard-interactive', 'none', 'other') NULL,

    -- IP Information (Binary + Text)
    source_ip VARBINARY(16) NOT NULL,
    source_ip_text VARCHAR(45) NOT NULL,
    source_port INT UNSIGNED NULL,
    geo_id INT NULL COMMENT 'FK to ip_geolocation',

    -- Target Information
    target_server VARCHAR(255) NOT NULL,
    target_port INT UNSIGNED DEFAULT 22,
    target_username VARCHAR(255) NOT NULL,

    -- Event Details
    failure_reason ENUM('invalid_password', 'invalid_user', 'connection_refused',
                        'key_rejected', 'timeout', 'max_attempts', 'other') NULL,
    session_id VARCHAR(100) NULL,
    session_duration_sec INT UNSIGNED NULL COMMENT 'For successful logins',

    -- Processing Pipeline Status
    processing_status ENUM('pending', 'geoip_complete', 'ml_complete',
                          'intel_complete', 'completed', 'error') DEFAULT 'pending',
    processing_error TEXT NULL,

    -- ML Analysis Results
    ml_risk_score TINYINT UNSIGNED DEFAULT 0 COMMENT '0-100',
    ml_threat_type VARCHAR(100) NULL,
    ml_confidence DECIMAL(5,4) NULL COMMENT '0.0000-1.0000',
    is_anomaly BOOLEAN DEFAULT FALSE,
    anomaly_reasons JSON NULL,

    -- Action Taken
    was_blocked BOOLEAN DEFAULT FALSE,
    block_id INT NULL COMMENT 'FK to ip_blocks if blocked',

    -- Raw Data
    raw_log_line TEXT NULL,
    additional_metadata JSON NULL,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    -- Indexes for performance
    KEY idx_timestamp (timestamp),
    KEY idx_event_type (event_type),
    KEY idx_source_ip (source_ip),
    KEY idx_source_ip_text (source_ip_text),
    KEY idx_target_server (target_server),
    KEY idx_target_username (target_username),
    KEY idx_is_anomaly (is_anomaly),
    KEY idx_source_type (source_type),
    KEY idx_processing_status (processing_status),
    KEY idx_agent (agent_id),
    KEY idx_geo (geo_id),

    -- Composite indexes for common query patterns
    KEY idx_ip_time (source_ip, timestamp),
    KEY idx_server_time (target_server, timestamp),
    KEY idx_pipeline (processing_status, created_at),
    KEY idx_source_processing (source_type, processing_status)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Unified SSH authentication events from all sources';
-- Note: Partitioning removed for simplicity and to allow foreign keys
-- Can be added later if needed for very large datasets

-- Note: Some FK constraints will be added in part 2 after all tables are created

-- ============================================================================
-- THREAT INTELLIGENCE & BLOCKING
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 6. IP Threat Intelligence (3rd Party API Results)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ip_threat_intelligence (
    id INT AUTO_INCREMENT PRIMARY KEY,

    -- IP Reference
    ip_address_text VARCHAR(45) NOT NULL UNIQUE,
    geo_id INT NULL,

    -- AbuseIPDB Data
    abuseipdb_score INT NULL COMMENT '0-100 confidence of abuse',
    abuseipdb_confidence INT NULL,
    abuseipdb_reports INT NULL COMMENT 'Number of abuse reports',
    abuseipdb_last_reported TIMESTAMP NULL,
    abuseipdb_categories JSON NULL COMMENT 'Array of abuse categories',
    abuseipdb_checked_at TIMESTAMP NULL,

    -- Shodan Data
    shodan_ports JSON NULL COMMENT 'Open ports detected',
    shodan_tags JSON NULL COMMENT 'Tags like "honeypot", "vpn", etc',
    shodan_vulns JSON NULL COMMENT 'Known vulnerabilities',
    shodan_last_update TIMESTAMP NULL,
    shodan_checked_at TIMESTAMP NULL,

    -- VirusTotal Data
    virustotal_positives INT NULL COMMENT 'Detection count',
    virustotal_total INT NULL COMMENT 'Total engines checked',
    virustotal_detected_urls JSON NULL,
    virustotal_checked_at TIMESTAMP NULL,

    -- Aggregated Threat Assessment
    overall_threat_level ENUM('clean', 'low', 'medium', 'high', 'critical') DEFAULT 'clean',
    threat_confidence DECIMAL(5,4) NULL COMMENT 'Confidence in assessment',
    threat_categories JSON NULL COMMENT 'Combined threat categories',

    -- Cache Management
    needs_refresh BOOLEAN DEFAULT FALSE,
    refresh_after TIMESTAMP NULL,
    last_error TEXT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    -- Indexes
    KEY idx_geo (geo_id),
    KEY idx_threat_level (overall_threat_level),
    KEY idx_abuseipdb_score (abuseipdb_score),
    KEY idx_refresh (needs_refresh, refresh_after),
    KEY idx_updated (updated_at),

    FOREIGN KEY (geo_id) REFERENCES ip_geolocation(id) ON DELETE SET NULL

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Threat intelligence from AbuseIPDB, Shodan, VirusTotal';

-- ----------------------------------------------------------------------------
-- 7. Blocking Rules (Auto-blocking Configuration)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS blocking_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,

    -- Rule Identification
    rule_name VARCHAR(100) NOT NULL UNIQUE,
    rule_type ENUM('brute_force', 'ml_threshold', 'api_reputation',
                   'anomaly_pattern', 'geo_restriction', 'custom') NOT NULL,
    is_enabled BOOLEAN DEFAULT TRUE,
    priority INT DEFAULT 50 COMMENT '1-100, higher evaluated first',

    -- Rule Conditions (JSON for flexibility)
    conditions JSON NOT NULL,
    /*
    Examples:
    brute_force: {
        "failed_attempts": 5,
        "time_window_minutes": 10,
        "unique_usernames": 3
    }
    ml_threshold: {
        "min_risk_score": 80,
        "min_confidence": 0.75,
        "threat_types": ["brute_force", "credential_stuffing"]
    }
    api_reputation: {
        "abuseipdb_min_score": 80,
        "virustotal_min_positives": 3
    }
    anomaly_pattern: {
        "anomaly_types": ["geo_anomaly", "time_anomaly", "volume_anomaly"]
    }
    geo_restriction: {
        "blocked_countries": ["CN", "RU", "KP"],
        "whitelist_ips": ["1.2.3.4"]
    }
    */

    -- Actions
    block_duration_minutes INT DEFAULT 1440 COMMENT '1440 = 24 hours',
    auto_unblock BOOLEAN DEFAULT TRUE,

    -- Notifications
    notify_on_trigger BOOLEAN DEFAULT TRUE,
    notification_channels JSON NULL COMMENT '["telegram", "email", "webhook"]',
    notification_message_template TEXT NULL,

    -- Statistics
    times_triggered INT DEFAULT 0,
    last_triggered_at TIMESTAMP NULL,
    ips_blocked_total INT DEFAULT 0,

    -- Metadata
    description TEXT NULL,
    created_by_user_id INT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    KEY idx_rule_type (rule_type),
    KEY idx_enabled_priority (is_enabled, priority),
    KEY idx_last_triggered (last_triggered_at)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Configurable rules for automatic IP blocking';

-- ----------------------------------------------------------------------------
-- 8. IP Blocks (Active IP Blocks)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ip_blocks (
    id INT AUTO_INCREMENT PRIMARY KEY,

    -- IP Information
    ip_address VARBINARY(16) NOT NULL,
    ip_address_text VARCHAR(45) NOT NULL,
    ip_range_cidr VARCHAR(50) NULL COMMENT 'For CIDR range blocks (e.g., 192.168.1.0/24)',

    -- Block Details
    block_reason VARCHAR(500) NOT NULL,
    block_source ENUM('manual', 'rule_based', 'ml_threshold',
                     'api_reputation', 'anomaly_detection') NOT NULL,
    blocking_rule_id INT NULL COMMENT 'FK to blocking_rules',

    -- Trigger Information
    trigger_event_id BIGINT NULL COMMENT 'Event that triggered block',
    failed_attempts INT DEFAULT 0,
    risk_score TINYINT UNSIGNED NULL,
    threat_level VARCHAR(50) NULL,

    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    unblock_at TIMESTAMP NULL,
    auto_unblock BOOLEAN DEFAULT TRUE,

    -- Manual Management
    manually_unblocked_at TIMESTAMP NULL,
    unblocked_by_user_id INT NULL,
    unblock_reason VARCHAR(500) NULL,

    -- Simulation
    is_simulation BOOLEAN DEFAULT FALSE,
    simulation_run_id INT NULL,

    -- Metadata
    block_metadata JSON NULL,
    created_by_user_id INT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    -- Indexes
    KEY idx_ip_binary (ip_address),
    KEY idx_ip_text (ip_address_text),
    KEY idx_is_active (is_active),
    KEY idx_unblock_at (unblock_at),
    KEY idx_block_source (block_source),
    KEY idx_is_simulation (is_simulation),
    KEY idx_active_ip (is_active, ip_address),
    KEY idx_trigger_event (trigger_event_id),

    FOREIGN KEY (blocking_rule_id) REFERENCES blocking_rules(id) ON DELETE SET NULL,
    FOREIGN KEY (simulation_run_id) REFERENCES simulation_runs(id) ON DELETE CASCADE

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Active IP blocks with rule-based and manual blocking';

-- ----------------------------------------------------------------------------
-- 9. Blocking Actions (Audit Trail of Block/Unblock Events)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS blocking_actions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    action_uuid CHAR(36) NOT NULL UNIQUE,
    ip_block_id INT NOT NULL,
    ip_address_text VARCHAR(45) NOT NULL,

    action_type ENUM('blocked', 'unblocked', 'modified') NOT NULL,
    action_source ENUM('system', 'manual', 'rule', 'api') NOT NULL,

    -- Details
    reason TEXT NULL,
    performed_by_user_id INT NULL,
    triggered_by_rule_id INT NULL,
    triggered_by_event_id BIGINT NULL,

    -- Metadata
    action_metadata JSON NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    KEY idx_ip_block (ip_block_id),
    KEY idx_action_type (action_type),
    KEY idx_created_at (created_at),
    KEY idx_ip_address (ip_address_text),

    FOREIGN KEY (ip_block_id) REFERENCES ip_blocks(id) ON DELETE CASCADE,
    FOREIGN KEY (triggered_by_rule_id) REFERENCES blocking_rules(id) ON DELETE SET NULL,
    FOREIGN KEY (triggered_by_event_id) REFERENCES auth_events(id) ON DELETE SET NULL

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Audit trail of all blocking actions';

-- ============================================================================
-- NOTIFICATIONS & ALERTING
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 10. Notification Rules
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notification_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,

    rule_name VARCHAR(100) NOT NULL UNIQUE,
    is_enabled BOOLEAN DEFAULT TRUE,

    -- Trigger Conditions
    trigger_on ENUM('ip_blocked', 'high_risk_detected', 'anomaly_detected',
                    'brute_force_detected', 'agent_offline', 'system_error') NOT NULL,
    conditions JSON NULL,

    -- Notification Channels
    channels JSON NOT NULL COMMENT '["telegram", "email", "webhook", "slack"]',

    -- Telegram Configuration
    telegram_bot_token VARCHAR(255) NULL,
    telegram_chat_id VARCHAR(255) NULL,

    -- Email Configuration
    email_recipients JSON NULL,

    -- Webhook Configuration
    webhook_url VARCHAR(500) NULL,
    webhook_headers JSON NULL,

    -- Message Template
    message_template TEXT NOT NULL,
    message_format ENUM('text', 'html', 'markdown') DEFAULT 'markdown',

    -- Rate Limiting
    rate_limit_minutes INT DEFAULT 5 COMMENT 'Min minutes between same notifications',

    -- Statistics
    times_triggered INT DEFAULT 0,
    last_triggered_at TIMESTAMP NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    KEY idx_trigger_on (trigger_on),
    KEY idx_is_enabled (is_enabled)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Notification rules and channel configuration';

-- ----------------------------------------------------------------------------
-- 11. Notifications (Notification Queue & History)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notifications (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    notification_uuid CHAR(36) NOT NULL UNIQUE,

    -- Rule & Trigger
    notification_rule_id INT NULL,
    trigger_type VARCHAR(100) NOT NULL,
    trigger_event_id BIGINT NULL COMMENT 'FK to auth_events if triggered by event',
    trigger_block_id INT NULL COMMENT 'FK to ip_blocks if triggered by block',

    -- Channels
    channels JSON NOT NULL COMMENT 'Channels to send to',

    -- Message
    message_title VARCHAR(500) NOT NULL,
    message_body TEXT NOT NULL,
    message_format ENUM('text', 'html', 'markdown') DEFAULT 'text',

    -- Priority
    priority ENUM('low', 'normal', 'high', 'critical') DEFAULT 'normal',

    -- Status
    status ENUM('pending', 'sent', 'failed', 'cancelled') DEFAULT 'pending',
    sent_at TIMESTAMP NULL,
    failed_reason TEXT NULL,
    retry_count INT DEFAULT 0,

    -- Delivery Status per Channel
    delivery_status JSON NULL COMMENT 'Status per channel',

    -- Metadata
    notification_metadata JSON NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    KEY idx_status (status),
    KEY idx_created_at (created_at),
    KEY idx_priority (priority),
    KEY idx_trigger_type (trigger_type),
    KEY idx_pending (status, created_at),

    FOREIGN KEY (notification_rule_id) REFERENCES notification_rules(id) ON DELETE SET NULL,
    FOREIGN KEY (trigger_event_id) REFERENCES auth_events(id) ON DELETE CASCADE,
    FOREIGN KEY (trigger_block_id) REFERENCES ip_blocks(id) ON DELETE CASCADE

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Notification queue and delivery history';

-- ============================================================================
-- STATISTICS & REPORTING
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 12. IP Statistics (Aggregated per-IP statistics)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ip_statistics (
    id INT AUTO_INCREMENT PRIMARY KEY,

    ip_address_text VARCHAR(45) NOT NULL UNIQUE,
    geo_id INT NULL,

    -- Event Counts
    total_events INT DEFAULT 0,
    failed_events INT DEFAULT 0,
    successful_events INT DEFAULT 0,
    invalid_events INT DEFAULT 0,

    -- Unique Targets
    unique_servers INT DEFAULT 0,
    unique_usernames INT DEFAULT 0,

    -- Risk Assessment
    avg_risk_score DECIMAL(5,2) NULL,
    max_risk_score TINYINT UNSIGNED NULL,
    anomaly_count INT DEFAULT 0,

    -- Blocking History
    times_blocked INT DEFAULT 0,
    currently_blocked BOOLEAN DEFAULT FALSE,
    last_blocked_at TIMESTAMP NULL,

    -- Timeline
    first_seen TIMESTAMP NULL,
    last_seen TIMESTAMP NULL,

    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    KEY idx_total_events (total_events),
    KEY idx_failed_events (failed_events),
    KEY idx_currently_blocked (currently_blocked),
    KEY idx_last_seen (last_seen),

    FOREIGN KEY (geo_id) REFERENCES ip_geolocation(id) ON DELETE SET NULL

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Aggregated statistics per IP address';

-- ----------------------------------------------------------------------------
-- 13. Daily Statistics (System-wide daily aggregates)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS daily_statistics (
    id INT AUTO_INCREMENT PRIMARY KEY,

    stat_date DATE NOT NULL UNIQUE,

    -- Event Counts
    total_events INT DEFAULT 0,
    failed_events INT DEFAULT 0,
    successful_events INT DEFAULT 0,
    invalid_events INT DEFAULT 0,

    -- Source Breakdown
    events_from_agents INT DEFAULT 0,
    events_from_synthetic INT DEFAULT 0,
    events_from_simulation INT DEFAULT 0,

    -- Unique Counts
    unique_ips INT DEFAULT 0,
    unique_servers INT DEFAULT 0,
    unique_usernames INT DEFAULT 0,

    -- Threat Detection
    anomalies_detected INT DEFAULT 0,
    high_risk_events INT DEFAULT 0,

    -- Blocking
    ips_blocked INT DEFAULT 0,
    ips_unblocked INT DEFAULT 0,

    -- Notifications
    notifications_sent INT DEFAULT 0,

    -- Agents
    active_agents INT DEFAULT 0,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    KEY idx_stat_date (stat_date)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Daily aggregated statistics for reporting';

-- ----------------------------------------------------------------------------
-- 14. Agent Heartbeats (Agent Health Metrics)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS agent_heartbeats (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    agent_id INT NOT NULL,
    heartbeat_timestamp TIMESTAMP(3) NOT NULL,

    -- System Metrics
    cpu_usage_percent DECIMAL(5,2) NULL,
    memory_usage_percent DECIMAL(5,2) NULL,
    disk_usage_percent DECIMAL(5,2) NULL,
    load_average DECIMAL(5,2) NULL,

    -- Application Metrics
    events_in_queue INT NULL,
    events_processed_last_minute INT NULL,
    processing_lag_seconds INT NULL,

    -- Network Metrics
    network_latency_ms INT NULL,
    connection_status ENUM('connected', 'degraded', 'disconnected') DEFAULT 'connected',

    -- Health Status
    health_status ENUM('healthy', 'warning', 'critical') DEFAULT 'healthy',
    health_issues JSON NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    KEY idx_agent (agent_id),
    KEY idx_timestamp (heartbeat_timestamp),
    KEY idx_health (health_status),

    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Agent health monitoring time-series data';

-- Continued in next part due to length...
SET FOREIGN_KEY_CHECKS = 1;

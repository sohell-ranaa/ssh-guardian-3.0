-- ============================================================================
-- SSH Guardian v3.1 - Clean Database Schema
-- ============================================================================
-- Designed for clarity, proper normalization, and clean data types
-- ============================================================================

-- Drop and create fresh database
DROP DATABASE IF EXISTS ssh_guardian_v3_1;
CREATE DATABASE ssh_guardian_v3_1 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE ssh_guardian_v3_1;

-- ============================================================================
-- DOMAIN 1: USER MANAGEMENT
-- ============================================================================

-- 1.1 Roles
CREATE TABLE roles (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT,
    permissions JSON,
    is_system_role BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 1.2 Users
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(100),
    role_id INT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    email_verified_at TIMESTAMP NULL,
    last_login_at TIMESTAMP NULL,
    last_login_ip VARCHAR(45),
    failed_login_attempts INT DEFAULT 0,
    locked_until TIMESTAMP NULL,
    preferences JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_email (email),
    INDEX idx_role (role_id),
    FOREIGN KEY (role_id) REFERENCES roles(id)
) ENGINE=InnoDB;

-- 1.3 User Sessions
CREATE TABLE user_sessions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    session_token VARCHAR(255) NOT NULL UNIQUE,
    ip_address VARCHAR(45),
    user_agent TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP NOT NULL,
    last_activity_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_user (user_id),
    INDEX idx_token (session_token),
    INDEX idx_expires (expires_at),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 1.4 User OTPs
CREATE TABLE user_otps (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    otp_code VARCHAR(10) NOT NULL,
    purpose VARCHAR(50) NOT NULL, -- 'login', 'password_reset', 'email_verification'
    is_used BOOLEAN DEFAULT FALSE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_user (user_id),
    INDEX idx_expires (expires_at),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ============================================================================
-- DOMAIN 2: AGENT MANAGEMENT
-- ============================================================================

-- 2.1 Agents
CREATE TABLE agents (
    id INT PRIMARY KEY AUTO_INCREMENT,
    agent_uuid CHAR(36) NOT NULL UNIQUE,
    agent_id VARCHAR(100) NOT NULL UNIQUE,
    api_key VARCHAR(255) NOT NULL,
    hostname VARCHAR(255),
    display_name VARCHAR(100),
    agent_type VARCHAR(20) DEFAULT 'secondary', -- 'primary', 'secondary'
    ip_address VARCHAR(45),
    ip_address_internal VARCHAR(45),
    mac_address VARCHAR(17),
    location VARCHAR(100),
    environment VARCHAR(20) DEFAULT 'production', -- 'production', 'staging', 'development'
    status VARCHAR(20) DEFAULT 'pending', -- 'pending', 'active', 'inactive', 'disconnected'
    health_status VARCHAR(20) DEFAULT 'unknown', -- 'healthy', 'degraded', 'unhealthy', 'unknown'
    last_heartbeat TIMESTAMP NULL,
    heartbeat_interval_sec INT DEFAULT 30,
    version VARCHAR(20),
    supported_features JSON,
    total_events_sent BIGINT DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    is_approved BOOLEAN DEFAULT FALSE,
    approved_by_user_id INT NULL,
    approved_at TIMESTAMP NULL,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_uuid (agent_uuid),
    INDEX idx_agent_id (agent_id),
    INDEX idx_status (status),
    INDEX idx_health (health_status),
    FOREIGN KEY (approved_by_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- 2.2 Agent Heartbeats (7-day retention)
CREATE TABLE agent_heartbeats (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    agent_id INT NOT NULL,
    heartbeat_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    cpu_usage DECIMAL(5,2),
    memory_usage DECIMAL(5,2),
    disk_usage DECIMAL(5,2),
    load_average VARCHAR(50),
    uptime_seconds BIGINT,
    network_stats JSON,
    process_count INT,
    agent_version VARCHAR(20),
    metadata JSON,

    INDEX idx_agent (agent_id),
    INDEX idx_timestamp (heartbeat_timestamp),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 2.3 Agent Log Batches (30-day retention)
CREATE TABLE agent_log_batches (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    batch_uuid CHAR(36) NOT NULL UNIQUE,
    agent_id INT NOT NULL,
    log_source VARCHAR(100) DEFAULT 'auth.log',
    events_count INT DEFAULT 0,
    events_processed INT DEFAULT 0,
    events_failed INT DEFAULT 0,
    status VARCHAR(20) DEFAULT 'received', -- 'received', 'processing', 'completed', 'failed'
    processing_started_at TIMESTAMP NULL,
    processing_completed_at TIMESTAMP NULL,
    processing_duration_ms INT,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_agent (agent_id),
    INDEX idx_uuid (batch_uuid),
    INDEX idx_status (status),
    INDEX idx_created (created_at),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 2.4 Agent UFW State
CREATE TABLE agent_ufw_state (
    id INT PRIMARY KEY AUTO_INCREMENT,
    agent_id INT NOT NULL UNIQUE,
    is_enabled BOOLEAN DEFAULT FALSE,
    ufw_status VARCHAR(20) DEFAULT 'inactive', -- 'active', 'inactive', 'not_installed'
    default_incoming VARCHAR(20) DEFAULT 'deny',
    default_outgoing VARCHAR(20) DEFAULT 'allow',
    default_routed VARCHAR(20) DEFAULT 'disabled',
    logging_level VARCHAR(20) DEFAULT 'low',
    ipv6_enabled BOOLEAN DEFAULT TRUE,
    rules_count INT DEFAULT 0,
    ufw_version VARCHAR(20),
    last_sync TIMESTAMP NULL,
    raw_status TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 2.5 Agent UFW Rules
CREATE TABLE agent_ufw_rules (
    id INT PRIMARY KEY AUTO_INCREMENT,
    agent_id INT NOT NULL,
    rule_index INT NOT NULL,
    action VARCHAR(20) NOT NULL, -- 'allow', 'deny', 'reject', 'limit'
    direction VARCHAR(10) DEFAULT 'in', -- 'in', 'out'
    protocol VARCHAR(20), -- 'tcp', 'udp', 'any', 'tcp (v6)', etc.
    from_ip VARCHAR(50) DEFAULT 'Anywhere',
    from_port VARCHAR(20),
    to_ip VARCHAR(50) DEFAULT 'Anywhere',
    to_port VARCHAR(20),
    interface VARCHAR(50),
    comment VARCHAR(255),
    is_v6 BOOLEAN DEFAULT FALSE,
    raw_rule TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_agent (agent_id),
    INDEX idx_action (action),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 2.6 Agent UFW Commands
CREATE TABLE agent_ufw_commands (
    id INT PRIMARY KEY AUTO_INCREMENT,
    agent_id INT NOT NULL,
    command_uuid CHAR(36) NOT NULL UNIQUE,
    command_type VARCHAR(50) NOT NULL,
    params JSON,
    ufw_command TEXT,
    status VARCHAR(20) DEFAULT 'pending', -- 'pending', 'sent', 'completed', 'failed'
    result_message TEXT,
    created_by INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent_at TIMESTAMP NULL,
    executed_at TIMESTAMP NULL,

    INDEX idx_agent (agent_id),
    INDEX idx_uuid (command_uuid),
    INDEX idx_status (status),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ============================================================================
-- DOMAIN 3: IP INTELLIGENCE
-- ============================================================================

-- 3.1 IP Geolocation (merged with threat intelligence)
CREATE TABLE ip_geolocation (
    id INT PRIMARY KEY AUTO_INCREMENT,
    ip_address VARBINARY(16) NOT NULL UNIQUE,
    ip_address_text VARCHAR(45) NOT NULL UNIQUE,
    ip_version TINYINT DEFAULT 4,
    -- Geolocation
    country_code CHAR(2),
    country_name VARCHAR(100),
    region VARCHAR(100),
    city VARCHAR(100),
    postal_code VARCHAR(20),
    latitude DECIMAL(10,8),
    longitude DECIMAL(11,8),
    timezone VARCHAR(50),
    -- Network info
    asn INT,
    asn_org VARCHAR(255),
    isp VARCHAR(255),
    connection_type VARCHAR(50),
    -- Proxy/VPN detection
    is_proxy BOOLEAN DEFAULT FALSE,
    is_vpn BOOLEAN DEFAULT FALSE,
    is_tor BOOLEAN DEFAULT FALSE,
    is_datacenter BOOLEAN DEFAULT FALSE,
    is_hosting BOOLEAN DEFAULT FALSE,
    -- Threat intelligence (merged from ip_threat_intelligence)
    abuseipdb_score INT,
    abuseipdb_reports INT,
    abuseipdb_last_reported TIMESTAMP NULL,
    abuseipdb_checked_at TIMESTAMP NULL,
    virustotal_positives INT,
    virustotal_total INT,
    virustotal_checked_at TIMESTAMP NULL,
    threat_level VARCHAR(20) DEFAULT 'unknown', -- 'clean', 'low', 'medium', 'high', 'critical'
    threat_categories JSON,
    -- Metadata
    lookup_count INT DEFAULT 1,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    cache_expires_at TIMESTAMP NULL,

    INDEX idx_ip_text (ip_address_text),
    INDEX idx_country (country_code),
    INDEX idx_threat (threat_level),
    INDEX idx_asn (asn)
) ENGINE=InnoDB;

-- 3.2 IP Blocks
CREATE TABLE ip_blocks (
    id INT PRIMARY KEY AUTO_INCREMENT,
    ip_address VARBINARY(16) NOT NULL,
    ip_address_text VARCHAR(45) NOT NULL,
    ip_range_cidr VARCHAR(50),
    block_reason TEXT NOT NULL,
    block_source VARCHAR(30) NOT NULL, -- 'manual', 'rule', 'ml', 'api', 'fail2ban'
    blocking_rule_id INT NULL,
    trigger_event_id BIGINT NULL,
    agent_id INT NULL,
    geo_id INT NULL,
    failed_attempts INT DEFAULT 0,
    risk_score TINYINT UNSIGNED,
    threat_level VARCHAR(20),
    is_active BOOLEAN DEFAULT TRUE,
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    unblock_at TIMESTAMP NULL,
    auto_unblock BOOLEAN DEFAULT TRUE,
    unblocked_at TIMESTAMP NULL,
    unblocked_by_user_id INT NULL,
    unblock_reason TEXT,
    is_simulation BOOLEAN DEFAULT FALSE,
    simulation_run_id INT NULL,
    metadata JSON,
    created_by_user_id INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_ip (ip_address_text),
    INDEX idx_active (is_active),
    INDEX idx_source (block_source),
    INDEX idx_agent (agent_id),
    INDEX idx_blocked_at (blocked_at),
    INDEX idx_unblock_at (unblock_at),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE SET NULL,
    FOREIGN KEY (geo_id) REFERENCES ip_geolocation(id) ON DELETE SET NULL,
    FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (unblocked_by_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ============================================================================
-- DOMAIN 4: AUTH EVENTS
-- ============================================================================

-- 4.1 Auth Events
CREATE TABLE auth_events (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    event_uuid CHAR(36) NOT NULL UNIQUE,
    timestamp TIMESTAMP NOT NULL,
    source_type VARCHAR(20) DEFAULT 'agent', -- 'agent', 'simulation'
    agent_id INT NULL,
    simulation_run_id INT NULL,
    event_type VARCHAR(20) NOT NULL, -- 'success', 'failed', 'invalid_user', 'key_auth', etc.
    auth_method VARCHAR(20), -- 'password', 'publickey', 'keyboard-interactive'
    source_ip VARBINARY(16),
    source_ip_text VARCHAR(45),
    source_port INT,
    target_server VARCHAR(255),
    target_port INT DEFAULT 22,
    target_username VARCHAR(100),
    failure_reason TEXT,
    geo_id INT NULL,
    block_id INT NULL,
    raw_log_line TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_uuid (event_uuid),
    INDEX idx_timestamp (timestamp),
    INDEX idx_agent (agent_id),
    INDEX idx_type (event_type),
    INDEX idx_source_ip (source_ip_text),
    INDEX idx_username (target_username),
    INDEX idx_simulation (simulation_run_id),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE SET NULL,
    FOREIGN KEY (geo_id) REFERENCES ip_geolocation(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- 4.2 Auth Events ML (predictions)
CREATE TABLE auth_events_ml (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    event_id BIGINT NOT NULL,
    model_id INT NULL,
    risk_score DECIMAL(5,4) DEFAULT 0,
    threat_type VARCHAR(50),
    confidence DECIMAL(5,4) DEFAULT 0,
    is_anomaly BOOLEAN DEFAULT FALSE,
    features_snapshot JSON,
    inference_time_ms INT,
    manual_feedback VARCHAR(20), -- 'confirmed_threat', 'false_positive', 'unclear'
    feedback_at TIMESTAMP NULL,
    feedback_by_user_id INT NULL,
    feedback_notes TEXT,
    was_blocked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_event (event_id),
    INDEX idx_risk (risk_score),
    INDEX idx_anomaly (is_anomaly),
    FOREIGN KEY (event_id) REFERENCES auth_events(id) ON DELETE CASCADE,
    FOREIGN KEY (feedback_by_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- 4.3 Auth Events Daily Summary
CREATE TABLE auth_events_daily (
    id INT PRIMARY KEY AUTO_INCREMENT,
    summary_date DATE NOT NULL,
    agent_id INT NULL,
    total_events INT DEFAULT 0,
    failed_events INT DEFAULT 0,
    successful_events INT DEFAULT 0,
    invalid_user_events INT DEFAULT 0,
    unique_ips INT DEFAULT 0,
    unique_usernames INT DEFAULT 0,
    unique_countries INT DEFAULT 0,
    ips_blocked INT DEFAULT 0,
    top_ips JSON,
    top_usernames JSON,
    top_countries JSON,
    hourly_distribution JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE KEY unique_date_agent (summary_date, agent_id),
    INDEX idx_date (summary_date),
    INDEX idx_agent (agent_id),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ============================================================================
-- DOMAIN 5: BLOCKING SYSTEM
-- ============================================================================

-- 5.1 Blocking Rules
CREATE TABLE blocking_rules (
    id INT PRIMARY KEY AUTO_INCREMENT,
    rule_name VARCHAR(100) NOT NULL,
    rule_type VARCHAR(30) NOT NULL, -- 'threshold', 'pattern', 'geo', 'time_based', 'ml'
    is_enabled BOOLEAN DEFAULT TRUE,
    is_system_rule BOOLEAN DEFAULT FALSE,
    priority INT DEFAULT 50,
    conditions JSON NOT NULL,
    block_duration_minutes INT DEFAULT 1440,
    auto_unblock BOOLEAN DEFAULT TRUE,
    notify_on_trigger BOOLEAN DEFAULT TRUE,
    notification_channels JSON,
    times_triggered INT DEFAULT 0,
    last_triggered_at TIMESTAMP NULL,
    ips_blocked_total INT DEFAULT 0,
    description TEXT,
    created_by_user_id INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_enabled (is_enabled),
    INDEX idx_type (rule_type),
    INDEX idx_priority (priority),
    FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- 5.2 Blocking Actions (history of all block/unblock actions)
CREATE TABLE blocking_actions (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    action_uuid CHAR(36) NOT NULL UNIQUE,
    ip_block_id INT NULL,
    ip_address_text VARCHAR(45) NOT NULL,
    action_type VARCHAR(20) NOT NULL, -- 'block', 'unblock', 'extend', 'modify'
    action_source VARCHAR(30) NOT NULL, -- 'system', 'manual', 'rule', 'api', 'expiry', 'fail2ban'
    reason TEXT,
    performed_by_user_id INT NULL,
    triggered_by_rule_id INT NULL,
    triggered_by_event_id BIGINT NULL,
    agent_id INT NULL,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_uuid (action_uuid),
    INDEX idx_ip (ip_address_text),
    INDEX idx_block (ip_block_id),
    INDEX idx_type (action_type),
    INDEX idx_created (created_at),
    FOREIGN KEY (performed_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ============================================================================
-- DOMAIN 6: FAIL2BAN
-- ============================================================================

-- 6.1 Fail2ban State (current bans per agent)
CREATE TABLE fail2ban_state (
    id INT PRIMARY KEY AUTO_INCREMENT,
    agent_id INT NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    jail_name VARCHAR(100) DEFAULT 'sshd',
    banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    bantime_seconds INT DEFAULT 0,
    failures INT DEFAULT 0,
    last_sync TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY unique_agent_ip_jail (agent_id, ip_address, jail_name),
    INDEX idx_agent (agent_id),
    INDEX idx_ip (ip_address),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 6.2 Fail2ban Events (history)
CREATE TABLE fail2ban_events (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    agent_id INT NOT NULL,
    event_type VARCHAR(20) NOT NULL, -- 'ban', 'unban'
    ip_address VARCHAR(45) NOT NULL,
    jail_name VARCHAR(100) DEFAULT 'sshd',
    failures INT DEFAULT 0,
    bantime_seconds INT DEFAULT 0,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    raw_log TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_agent (agent_id),
    INDEX idx_ip (ip_address),
    INDEX idx_type (event_type),
    INDEX idx_timestamp (timestamp),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ============================================================================
-- DOMAIN 7: ML SYSTEM
-- ============================================================================

-- 7.1 ML Models
CREATE TABLE ml_models (
    id INT PRIMARY KEY AUTO_INCREMENT,
    model_uuid CHAR(36) NOT NULL UNIQUE,
    model_name VARCHAR(100) NOT NULL,
    algorithm VARCHAR(50) NOT NULL,
    version VARCHAR(20) NOT NULL,
    status VARCHAR(20) DEFAULT 'training', -- 'training', 'ready', 'active', 'deprecated'
    is_active BOOLEAN DEFAULT FALSE,
    model_path VARCHAR(500),
    model_size_bytes BIGINT,
    hyperparameters JSON,
    feature_config JSON,
    training_run_id INT NULL,
    -- Metrics
    accuracy DECIMAL(5,4),
    precision_score DECIMAL(5,4),
    recall_score DECIMAL(5,4),
    f1_score DECIMAL(5,4),
    auc_roc DECIMAL(5,4),
    predictions_count BIGINT DEFAULT 0,
    avg_inference_time_ms INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    promoted_at TIMESTAMP NULL,
    deprecated_at TIMESTAMP NULL,

    INDEX idx_uuid (model_uuid),
    INDEX idx_status (status),
    INDEX idx_active (is_active)
) ENGINE=InnoDB;

-- 7.2 ML Training Runs
CREATE TABLE ml_training_runs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    run_uuid CHAR(36) NOT NULL UNIQUE,
    model_name VARCHAR(100),
    algorithm VARCHAR(50),
    status VARCHAR(20) DEFAULT 'running', -- 'running', 'completed', 'failed', 'cancelled'
    training_data_start DATE,
    training_data_end DATE,
    total_samples INT,
    training_samples INT,
    validation_samples INT,
    test_samples INT,
    hyperparameters JSON,
    final_metrics JSON,
    error_message TEXT,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    duration_seconds INT,
    triggered_by_user_id INT NULL,

    INDEX idx_uuid (run_uuid),
    INDEX idx_status (status),
    FOREIGN KEY (triggered_by_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ============================================================================
-- DOMAIN 8: SIMULATION
-- ============================================================================

-- 8.1 Simulation Templates
CREATE TABLE simulation_templates (
    id INT PRIMARY KEY AUTO_INCREMENT,
    template_name VARCHAR(100) NOT NULL,
    description TEXT,
    attack_type VARCHAR(50) NOT NULL,
    parameters JSON NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_by_user_id INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- 8.2 Simulation Runs
CREATE TABLE simulation_runs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    run_uuid CHAR(36) NOT NULL UNIQUE,
    template_id INT NULL,
    run_name VARCHAR(100),
    status VARCHAR(20) DEFAULT 'pending', -- 'pending', 'running', 'completed', 'failed', 'cancelled'
    attack_type VARCHAR(50),
    parameters JSON,
    target_agent_id INT NULL,
    events_generated INT DEFAULT 0,
    events_blocked INT DEFAULT 0,
    detection_rate DECIMAL(5,4),
    false_positive_rate DECIMAL(5,4),
    started_at TIMESTAMP NULL,
    completed_at TIMESTAMP NULL,
    duration_seconds INT,
    results JSON,
    triggered_by_user_id INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_uuid (run_uuid),
    INDEX idx_status (status),
    FOREIGN KEY (template_id) REFERENCES simulation_templates(id) ON DELETE SET NULL,
    FOREIGN KEY (target_agent_id) REFERENCES agents(id) ON DELETE SET NULL,
    FOREIGN KEY (triggered_by_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- 8.3 Simulation IP Pool
CREATE TABLE simulation_ip_pool (
    id INT PRIMARY KEY AUTO_INCREMENT,
    ip_address VARCHAR(45) NOT NULL,
    ip_type VARCHAR(20) DEFAULT 'malicious', -- 'malicious', 'suspicious', 'benign'
    country_code CHAR(2),
    threat_score INT,
    attack_patterns JSON,
    times_used INT DEFAULT 0,
    last_used_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY unique_ip (ip_address),
    INDEX idx_type (ip_type),
    INDEX idx_country (country_code)
) ENGINE=InnoDB;

-- 8.4 Live Simulation Runs
CREATE TABLE live_simulation_runs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    run_uuid CHAR(36) NOT NULL UNIQUE,
    simulation_run_id INT NULL,
    agent_id INT NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    events_sent INT DEFAULT 0,
    events_detected INT DEFAULT 0,
    started_at TIMESTAMP NULL,
    completed_at TIMESTAMP NULL,
    results JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_uuid (run_uuid),
    INDEX idx_status (status),
    FOREIGN KEY (simulation_run_id) REFERENCES simulation_runs(id) ON DELETE CASCADE,
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ============================================================================
-- DOMAIN 9: SYSTEM CONFIG
-- ============================================================================

-- 9.1 System Settings (consolidated)
CREATE TABLE system_settings (
    id INT PRIMARY KEY AUTO_INCREMENT,
    setting_key VARCHAR(100) NOT NULL UNIQUE,
    setting_value TEXT,
    value_type VARCHAR(20) DEFAULT 'string', -- 'string', 'number', 'boolean', 'json'
    category VARCHAR(50) DEFAULT 'general', -- 'general', 'security', 'cache', 'ml', 'notification', etc.
    description TEXT,
    is_sensitive BOOLEAN DEFAULT FALSE,
    is_public BOOLEAN DEFAULT FALSE,
    updated_by_user_id INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_category (category),
    FOREIGN KEY (updated_by_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- 9.2 Integrations
CREATE TABLE integrations (
    id INT PRIMARY KEY AUTO_INCREMENT,
    integration_type VARCHAR(50) NOT NULL, -- 'abuseipdb', 'virustotal', 'slack', 'email', 'telegram', etc.
    name VARCHAR(100) NOT NULL,
    is_enabled BOOLEAN DEFAULT FALSE,
    config JSON,
    credentials JSON, -- Encrypted
    last_used_at TIMESTAMP NULL,
    last_error TEXT,
    error_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE KEY unique_type (integration_type),
    INDEX idx_enabled (is_enabled)
) ENGINE=InnoDB;

-- 9.3 Notification Rules
CREATE TABLE notification_rules (
    id INT PRIMARY KEY AUTO_INCREMENT,
    rule_name VARCHAR(100) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    conditions JSON,
    channels JSON NOT NULL, -- ['email', 'slack', 'telegram']
    message_template TEXT,
    is_enabled BOOLEAN DEFAULT TRUE,
    cooldown_minutes INT DEFAULT 5,
    last_triggered_at TIMESTAMP NULL,
    times_triggered INT DEFAULT 0,
    created_by_user_id INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_event (event_type),
    INDEX idx_enabled (is_enabled),
    FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- 9.4 Notifications (sent)
CREATE TABLE notifications (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    notification_rule_id INT NULL,
    channel VARCHAR(30) NOT NULL,
    recipient VARCHAR(255),
    subject VARCHAR(255),
    message TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'pending', -- 'pending', 'sent', 'failed'
    error_message TEXT,
    sent_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_rule (notification_rule_id),
    INDEX idx_status (status),
    INDEX idx_created (created_at),
    FOREIGN KEY (notification_rule_id) REFERENCES notification_rules(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ============================================================================
-- DOMAIN 10: AUDIT & LOGS
-- ============================================================================

-- 10.1 Audit Logs
CREATE TABLE audit_logs (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NULL,
    action VARCHAR(50) NOT NULL,
    entity_type VARCHAR(50) NOT NULL,
    entity_id VARCHAR(50),
    old_values JSON,
    new_values JSON,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_user (user_id),
    INDEX idx_action (action),
    INDEX idx_entity (entity_type, entity_id),
    INDEX idx_created (created_at),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- 10.2 UFW Audit Log
CREATE TABLE ufw_audit_log (
    id INT PRIMARY KEY AUTO_INCREMENT,
    agent_id INT NOT NULL,
    command_id INT NULL,
    action VARCHAR(50) NOT NULL,
    rule_before TEXT,
    rule_after TEXT,
    performed_by_user_id INT NULL,
    ip_address VARCHAR(45),
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_agent (agent_id),
    INDEX idx_action (action),
    INDEX idx_created (created_at),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE,
    FOREIGN KEY (performed_by_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- 10.3 Log Sources
CREATE TABLE log_sources (
    id INT PRIMARY KEY AUTO_INCREMENT,
    source_name VARCHAR(100) NOT NULL,
    source_type VARCHAR(30) NOT NULL, -- 'file', 'syslog', 'journald'
    file_path VARCHAR(500),
    pattern_regex TEXT,
    is_enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE KEY unique_name (source_name)
) ENGINE=InnoDB;

-- ============================================================================
-- DOMAIN 11: UI SUPPORT
-- ============================================================================

-- 11.1 Guide Steps (onboarding)
CREATE TABLE guide_steps (
    id INT PRIMARY KEY AUTO_INCREMENT,
    step_key VARCHAR(50) NOT NULL UNIQUE,
    title VARCHAR(100) NOT NULL,
    description TEXT,
    step_order INT NOT NULL,
    is_required BOOLEAN DEFAULT FALSE,
    icon VARCHAR(50),
    action_url VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 11.2 UFW Rule Templates
CREATE TABLE ufw_rule_templates (
    id INT PRIMARY KEY AUTO_INCREMENT,
    template_name VARCHAR(100) NOT NULL,
    description TEXT,
    category VARCHAR(50),
    action VARCHAR(20) NOT NULL,
    direction VARCHAR(10) DEFAULT 'in',
    protocol VARCHAR(20),
    port VARCHAR(20),
    from_ip VARCHAR(50),
    to_ip VARCHAR(50),
    is_common BOOLEAN DEFAULT FALSE,
    display_order INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_category (category),
    INDEX idx_common (is_common)
) ENGINE=InnoDB;

-- ============================================================================
-- MIGRATION TRACKING
-- ============================================================================

CREATE TABLE _migration_log (
    id INT PRIMARY KEY AUTO_INCREMENT,
    migration_name VARCHAR(100) NOT NULL,
    source_table VARCHAR(100),
    target_table VARCHAR(100),
    records_migrated INT DEFAULT 0,
    records_skipped INT DEFAULT 0,
    notes TEXT,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL
) ENGINE=InnoDB;

-- ============================================================================
-- DATA RETENTION EVENTS
-- ============================================================================

-- Auto-cleanup old heartbeats (keep 7 days)
CREATE EVENT IF NOT EXISTS cleanup_old_heartbeats
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP
DO
    DELETE FROM agent_heartbeats WHERE heartbeat_timestamp < DATE_SUB(NOW(), INTERVAL 7 DAY);

-- Auto-cleanup old log batches (keep 30 days)
CREATE EVENT IF NOT EXISTS cleanup_old_log_batches
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP
DO
    DELETE FROM agent_log_batches WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY);

-- ============================================================================
-- SCHEMA COMPLETE: 33 tables
-- ============================================================================

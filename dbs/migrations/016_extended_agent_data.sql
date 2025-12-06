-- ============================================================================
-- SSH Guardian v3.0 - Extended Agent Data Tables
-- Migration: 016_extended_agent_data.sql
-- Description: Tables for listening ports, system users, and firewall suggestions
-- ============================================================================

-- ============================================================================
-- TABLE: agent_listening_ports
-- Stores listening ports/services on each agent
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_listening_ports (
    id INT PRIMARY KEY AUTO_INCREMENT,
    agent_id INT NOT NULL,
    port INT NOT NULL,
    protocol VARCHAR(10) NOT NULL DEFAULT 'tcp',
    address VARCHAR(100) NOT NULL DEFAULT '0.0.0.0',
    state VARCHAR(20) DEFAULT 'LISTEN',
    pid INT DEFAULT 0,
    process_name VARCHAR(100) DEFAULT '',
    user VARCHAR(100) DEFAULT '',
    is_protected BOOLEAN DEFAULT FALSE,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE KEY uk_agent_port (agent_id, port, protocol),
    INDEX idx_agent_ports (agent_id),
    INDEX idx_protected (agent_id, is_protected),
    INDEX idx_process (agent_id, process_name),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ============================================================================
-- TABLE: agent_system_users
-- Stores system users on each agent
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_system_users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    agent_id INT NOT NULL,
    username VARCHAR(100) NOT NULL,
    uid INT NOT NULL,
    gid INT NOT NULL,
    home_dir VARCHAR(255) DEFAULT '',
    shell VARCHAR(100) DEFAULT '',
    is_system_user BOOLEAN DEFAULT FALSE,
    is_login_enabled BOOLEAN DEFAULT TRUE,
    last_login DATETIME,
    groups_json JSON COMMENT 'List of groups',
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE KEY uk_agent_user (agent_id, username),
    INDEX idx_agent_users (agent_id),
    INDEX idx_login_enabled (agent_id, is_login_enabled),
    INDEX idx_system_user (agent_id, is_system_user),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ============================================================================
-- TABLE: agent_active_connections
-- Stores active network connections on agents
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_active_connections (
    id INT PRIMARY KEY AUTO_INCREMENT,
    agent_id INT NOT NULL,
    protocol VARCHAR(10) NOT NULL DEFAULT 'tcp',
    state VARCHAR(20) DEFAULT 'ESTAB',
    local_address VARCHAR(100),
    local_port INT,
    remote_address VARCHAR(100),
    remote_port INT,
    process_name VARCHAR(100) DEFAULT '',
    pid INT DEFAULT 0,
    recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_agent_conns (agent_id),
    INDEX idx_remote_ip (agent_id, remote_address),
    INDEX idx_recorded (agent_id, recorded_at),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ============================================================================
-- TABLE: agent_command_history
-- Stores command history from agents
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_command_history (
    id INT PRIMARY KEY AUTO_INCREMENT,
    agent_id INT NOT NULL,
    command TEXT NOT NULL,
    user VARCHAR(100) DEFAULT 'unknown',
    working_dir VARCHAR(255) DEFAULT '~',
    exit_code INT,
    command_timestamp DATETIME,
    recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_agent_history (agent_id),
    INDEX idx_user_history (agent_id, user),
    INDEX idx_timestamp (agent_id, command_timestamp),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ============================================================================
-- TABLE: firewall_suggestions
-- Stores smart firewall rule suggestions for agents
-- ============================================================================

CREATE TABLE IF NOT EXISTS firewall_suggestions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    agent_id INT NOT NULL,
    suggestion_type VARCHAR(50) NOT NULL COMMENT 'allow_service, block_ip, rate_limit, ssh_hardening, policy',
    priority ENUM('low', 'medium', 'high') DEFAULT 'medium',
    title VARCHAR(255) NOT NULL,
    description TEXT,
    rule_json JSON COMMENT 'Suggested rule parameters',
    iptables_cmd TEXT COMMENT 'Full iptables command',
    recommendation TEXT,
    status ENUM('pending', 'applied', 'dismissed', 'expired') DEFAULT 'pending',
    auto_apply BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    applied_at DATETIME,
    dismissed_at DATETIME,
    dismissed_by INT,

    INDEX idx_agent_suggestions (agent_id),
    INDEX idx_status (agent_id, status),
    INDEX idx_priority (agent_id, priority),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ============================================================================
-- TABLE: protected_ports
-- Stores protected ports configuration per agent
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_protected_ports (
    id INT PRIMARY KEY AUTO_INCREMENT,
    agent_id INT NOT NULL,
    port INT NOT NULL,
    service_name VARCHAR(100) NOT NULL,
    reason VARCHAR(255) DEFAULT 'Critical service',
    is_listening BOOLEAN DEFAULT FALSE,
    is_custom BOOLEAN DEFAULT FALSE COMMENT 'True if manually added',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY uk_agent_protected_port (agent_id, port),
    INDEX idx_agent_protected (agent_id),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ============================================================================
-- Update agent_firewall_state with extended data columns
-- ============================================================================

-- Add columns if they don't exist (using procedure for compatibility)
DROP PROCEDURE IF EXISTS add_extended_columns;

DELIMITER //

CREATE PROCEDURE add_extended_columns()
BEGIN
    -- Check and add listening_ports_count
    IF NOT EXISTS (
        SELECT * FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'agent_firewall_state'
        AND COLUMN_NAME = 'listening_ports_count'
    ) THEN
        ALTER TABLE agent_firewall_state ADD COLUMN listening_ports_count INT DEFAULT 0;
    END IF;

    -- Check and add users_count
    IF NOT EXISTS (
        SELECT * FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'agent_firewall_state'
        AND COLUMN_NAME = 'users_count'
    ) THEN
        ALTER TABLE agent_firewall_state ADD COLUMN users_count INT DEFAULT 0;
    END IF;

    -- Check and add active_connections_count
    IF NOT EXISTS (
        SELECT * FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'agent_firewall_state'
        AND COLUMN_NAME = 'active_connections_count'
    ) THEN
        ALTER TABLE agent_firewall_state ADD COLUMN active_connections_count INT DEFAULT 0;
    END IF;

    -- Check and add suggestions_count
    IF NOT EXISTS (
        SELECT * FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'agent_firewall_state'
        AND COLUMN_NAME = 'suggestions_count'
    ) THEN
        ALTER TABLE agent_firewall_state ADD COLUMN suggestions_count INT DEFAULT 0;
    END IF;

    -- Check and add extended_data_json
    IF NOT EXISTS (
        SELECT * FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'agent_firewall_state'
        AND COLUMN_NAME = 'extended_data_json'
    ) THEN
        ALTER TABLE agent_firewall_state ADD COLUMN extended_data_json JSON COMMENT 'Extended collected data';
    END IF;
END //

DELIMITER ;

CALL add_extended_columns();
DROP PROCEDURE IF EXISTS add_extended_columns;


-- ============================================================================
-- VIEWS
-- ============================================================================

-- View: Agent security overview
CREATE OR REPLACE VIEW v_agent_security_overview AS
SELECT
    a.id AS agent_id,
    a.hostname,
    a.agent_id AS agent_uuid,
    fs.rules_count,
    fs.port_forwards_count,
    fs.listening_ports_count,
    fs.users_count,
    fs.active_connections_count,
    fs.suggestions_count,
    fs.last_sync,
    (SELECT COUNT(*) FROM firewall_suggestions
     WHERE agent_id = a.id AND status = 'pending') AS pending_suggestions,
    (SELECT COUNT(*) FROM firewall_suggestions
     WHERE agent_id = a.id AND status = 'pending' AND priority = 'high') AS high_priority_suggestions,
    (SELECT COUNT(*) FROM agent_listening_ports
     WHERE agent_id = a.id AND is_protected = TRUE) AS protected_ports_count
FROM agents a
LEFT JOIN agent_firewall_state fs ON a.id = fs.agent_id
WHERE a.is_active = TRUE;


-- View: Login-enabled users per agent
CREATE OR REPLACE VIEW v_agent_login_users AS
SELECT
    asu.agent_id,
    a.hostname,
    asu.username,
    asu.uid,
    asu.shell,
    asu.last_login,
    asu.groups_json
FROM agent_system_users asu
JOIN agents a ON asu.agent_id = a.id
WHERE asu.is_login_enabled = TRUE
  AND a.is_active = TRUE
ORDER BY a.hostname, asu.username;


-- View: High-priority pending suggestions
CREATE OR REPLACE VIEW v_pending_high_priority_suggestions AS
SELECT
    fs.*,
    a.hostname,
    a.agent_id AS agent_uuid
FROM firewall_suggestions fs
JOIN agents a ON fs.agent_id = a.id
WHERE fs.status = 'pending'
  AND fs.priority = 'high'
  AND a.is_active = TRUE
ORDER BY fs.created_at DESC;


-- ============================================================================
-- SHOW COMPLETION MESSAGE
-- ============================================================================

SELECT 'Extended agent data tables created successfully!' AS status;

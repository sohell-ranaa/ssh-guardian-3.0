-- ============================================================================
-- SSH Guardian v3.0 - UFW Firewall Management Tables
-- Migration: 017_ufw_firewall_tables.sql
-- Description: Tables for storing and managing UFW rules from agents
-- ============================================================================

-- ============================================================================
-- TABLE: agent_ufw_state
-- Stores the overall UFW state for each agent
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_ufw_state (
    id INT PRIMARY KEY AUTO_INCREMENT,
    agent_id INT NOT NULL,
    ufw_status ENUM('active', 'inactive', 'not_installed') DEFAULT 'inactive',
    default_incoming VARCHAR(20) DEFAULT 'deny',
    default_outgoing VARCHAR(20) DEFAULT 'allow',
    default_routed VARCHAR(20) DEFAULT 'disabled',
    logging_level VARCHAR(20) DEFAULT 'low',
    ipv6_enabled BOOLEAN DEFAULT TRUE,
    rules_count INT DEFAULT 0,
    last_sync DATETIME,
    ufw_version VARCHAR(20),
    raw_status TEXT COMMENT 'Full ufw status verbose output',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE KEY uk_agent_ufw_state (agent_id),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ============================================================================
-- TABLE: agent_ufw_rules
-- Stores individual UFW rules
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_ufw_rules (
    id INT PRIMARY KEY AUTO_INCREMENT,
    agent_id INT NOT NULL,
    rule_index INT NOT NULL COMMENT 'UFW rule number',
    action VARCHAR(20) NOT NULL COMMENT 'ALLOW, DENY, REJECT, LIMIT',
    direction VARCHAR(10) DEFAULT 'IN' COMMENT 'IN, OUT',
    from_ip VARCHAR(50) DEFAULT 'Anywhere',
    from_port VARCHAR(20) DEFAULT '',
    to_ip VARCHAR(50) DEFAULT 'Anywhere',
    to_port VARCHAR(20) DEFAULT '',
    protocol VARCHAR(10) DEFAULT '' COMMENT 'tcp, udp, or empty for both',
    interface VARCHAR(50) DEFAULT '' COMMENT 'on eth0, etc.',
    comment TEXT DEFAULT '',
    is_v6 BOOLEAN DEFAULT FALSE COMMENT 'IPv6 rule',
    raw_rule TEXT COMMENT 'Original rule text from ufw status',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_agent_rules (agent_id),
    INDEX idx_action (agent_id, action),
    INDEX idx_port (agent_id, to_port),
    INDEX idx_direction (agent_id, direction),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ============================================================================
-- TABLE: agent_ufw_commands
-- Stores UFW commands to be executed by agents
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_ufw_commands (
    id INT PRIMARY KEY AUTO_INCREMENT,
    agent_id INT NOT NULL,
    command_uuid VARCHAR(36) NOT NULL UNIQUE,
    command_type VARCHAR(50) NOT NULL COMMENT 'allow, deny, reject, delete, enable, disable, reset, etc.',
    params_json JSON COMMENT 'Command parameters',
    ufw_command TEXT COMMENT 'The actual ufw command to execute',
    status ENUM('pending', 'sent', 'completed', 'failed') DEFAULT 'pending',
    result_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent_at DATETIME,
    executed_at DATETIME,
    created_by INT COMMENT 'User ID who created the command',

    INDEX idx_agent_commands (agent_id),
    INDEX idx_status (agent_id, status),
    INDEX idx_command_uuid (command_uuid),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ============================================================================
-- TABLE: ufw_rule_templates
-- Predefined UFW rule templates for easy rule creation
-- ============================================================================

CREATE TABLE IF NOT EXISTS ufw_rule_templates (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    category VARCHAR(50) DEFAULT 'general',
    ufw_command TEXT NOT NULL COMMENT 'UFW command template',
    params_schema JSON COMMENT 'Expected parameters for the template',
    is_system BOOLEAN DEFAULT FALSE,
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_category (category)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ============================================================================
-- INSERT DEFAULT UFW RULE TEMPLATES
-- ============================================================================

INSERT INTO ufw_rule_templates (name, description, category, ufw_command, params_schema, is_system) VALUES
('Allow SSH', 'Allow incoming SSH connections on port 22', 'security',
 'ufw allow 22/tcp', '{}', TRUE),

('Allow HTTP', 'Allow incoming HTTP connections on port 80', 'web',
 'ufw allow 80/tcp', '{}', TRUE),

('Allow HTTPS', 'Allow incoming HTTPS connections on port 443', 'web',
 'ufw allow 443/tcp', '{}', TRUE),

('Allow HTTP and HTTPS', 'Allow both HTTP and HTTPS', 'web',
 'ufw allow proto tcp from any to any port 80,443', '{}', TRUE),

('Allow Custom Port', 'Allow a specific port', 'general',
 'ufw allow {{port}}/{{protocol}}', '{"port": "number", "protocol": "tcp|udp"}', TRUE),

('Block IP', 'Block all traffic from a specific IP address', 'security',
 'ufw deny from {{ip}}', '{"ip": "IP address to block"}', TRUE),

('Allow IP', 'Allow all traffic from a specific IP address', 'security',
 'ufw allow from {{ip}}', '{"ip": "IP address to allow"}', TRUE),

('Allow Port from IP', 'Allow a port from a specific IP only', 'security',
 'ufw allow from {{ip}} to any port {{port}}', '{"ip": "Source IP", "port": "Port number"}', TRUE),

('Allow SSH from IP', 'Allow SSH only from a specific IP', 'security',
 'ufw allow from {{ip}} to any port 22', '{"ip": "Source IP to allow SSH from"}', TRUE),

('Limit SSH', 'Rate limit SSH connections (brute force protection)', 'security',
 'ufw limit 22/tcp', '{}', TRUE),

('Allow MySQL', 'Allow MySQL connections on port 3306', 'database',
 'ufw allow 3306/tcp', '{}', TRUE),

('Allow PostgreSQL', 'Allow PostgreSQL connections on port 5432', 'database',
 'ufw allow 5432/tcp', '{}', TRUE),

('Allow Redis', 'Allow Redis connections on port 6379', 'database',
 'ufw allow 6379/tcp', '{}', TRUE),

('Allow MongoDB', 'Allow MongoDB connections on port 27017', 'database',
 'ufw allow 27017/tcp', '{}', TRUE),

('Allow SMTP', 'Allow SMTP on port 25', 'mail',
 'ufw allow 25/tcp', '{}', TRUE),

('Allow IMAP', 'Allow IMAP on port 143', 'mail',
 'ufw allow 143/tcp', '{}', TRUE),

('Allow IMAPS', 'Allow IMAPS on port 993', 'mail',
 'ufw allow 993/tcp', '{}', TRUE),

('Allow FTP', 'Allow FTP on ports 20,21', 'file',
 'ufw allow 20:21/tcp', '{}', TRUE),

('Allow DNS', 'Allow DNS on port 53', 'network',
 'ufw allow 53', '{}', TRUE),

('Allow OpenVPN', 'Allow OpenVPN on port 1194', 'vpn',
 'ufw allow 1194/udp', '{}', TRUE),

('Allow WireGuard', 'Allow WireGuard on port 51820', 'vpn',
 'ufw allow 51820/udp', '{}', TRUE),

('SSH Guardian Dashboard', 'Allow SSH Guardian Dashboard on port 8081', 'system',
 'ufw allow 8081/tcp', '{}', TRUE),

('Allow Subnet', 'Allow all traffic from a subnet', 'network',
 'ufw allow from {{subnet}}', '{"subnet": "Subnet CIDR e.g. 192.168.1.0/24"}', TRUE),

('Deny Port', 'Deny incoming connections on a port', 'general',
 'ufw deny {{port}}/{{protocol}}', '{"port": "number", "protocol": "tcp|udp"}', TRUE);


-- ============================================================================
-- TABLE: ufw_audit_log
-- Audit log for UFW changes
-- ============================================================================

CREATE TABLE IF NOT EXISTS ufw_audit_log (
    id INT PRIMARY KEY AUTO_INCREMENT,
    agent_id INT NOT NULL,
    command_type VARCHAR(50) NOT NULL,
    ufw_command TEXT,
    params_json JSON,
    command_uuid VARCHAR(36),
    status VARCHAR(20),
    result_message TEXT,
    performed_by INT COMMENT 'User ID who performed the action',
    performed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_agent_audit (agent_id),
    INDEX idx_performed_at (performed_at),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ============================================================================
-- Add UFW-related columns to agent_firewall_state for backward compatibility
-- ============================================================================

ALTER TABLE agent_firewall_state
ADD COLUMN IF NOT EXISTS ufw_active BOOLEAN DEFAULT FALSE AFTER port_forwards_count,
ADD COLUMN IF NOT EXISTS ufw_default_incoming VARCHAR(20) DEFAULT 'deny' AFTER ufw_active,
ADD COLUMN IF NOT EXISTS ufw_default_outgoing VARCHAR(20) DEFAULT 'allow' AFTER ufw_default_incoming,
ADD COLUMN IF NOT EXISTS ufw_rules_count INT DEFAULT 0 AFTER ufw_default_outgoing;


-- ============================================================================
-- VIEWS
-- ============================================================================

-- View: UFW summary per agent
CREATE OR REPLACE VIEW v_agent_ufw_summary AS
SELECT
    a.id AS agent_id,
    a.hostname,
    a.agent_id AS agent_uuid,
    us.ufw_status,
    us.default_incoming,
    us.default_outgoing,
    us.rules_count,
    us.last_sync,
    (SELECT COUNT(*) FROM agent_ufw_commands
     WHERE agent_id = a.id AND status = 'pending') AS pending_commands
FROM agents a
LEFT JOIN agent_ufw_state us ON a.id = us.agent_id
WHERE a.is_active = TRUE;


-- View: All UFW rules across agents
CREATE OR REPLACE VIEW v_all_ufw_rules AS
SELECT
    r.*,
    a.hostname,
    a.agent_id AS agent_uuid,
    a.ip_address_primary AS agent_ip
FROM agent_ufw_rules r
JOIN agents a ON r.agent_id = a.id
WHERE a.is_active = TRUE
ORDER BY a.hostname, r.rule_index;


-- ============================================================================
-- SHOW COMPLETION MESSAGE
-- ============================================================================

SELECT 'UFW firewall management tables created successfully!' AS status;

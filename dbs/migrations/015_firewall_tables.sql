-- ============================================================================
-- SSH Guardian v3.0 - Firewall Management Tables
-- Migration: 015_firewall_tables.sql
-- Description: Tables for storing and managing iptables rules from agents
-- ============================================================================

-- ============================================================================
-- TABLE: agent_firewall_state
-- Stores the overall firewall state for each agent
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_firewall_state (
    id INT PRIMARY KEY AUTO_INCREMENT,
    agent_id INT NOT NULL,
    firewall_data JSON COMMENT 'Full firewall rules data as JSON',
    status_json JSON COMMENT 'Firewall status summary',
    rules_count INT DEFAULT 0,
    port_forwards_count INT DEFAULT 0,
    last_sync DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE KEY uk_agent_firewall_state (agent_id),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ============================================================================
-- TABLE: agent_firewall_rules
-- Stores individual parsed iptables rules for querying
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_firewall_rules (
    id INT PRIMARY KEY AUTO_INCREMENT,
    agent_id INT NOT NULL,
    table_name VARCHAR(20) NOT NULL COMMENT 'filter, nat, mangle, raw',
    chain VARCHAR(50) NOT NULL COMMENT 'INPUT, OUTPUT, FORWARD, custom chains',
    rule_num INT NOT NULL,
    target VARCHAR(50) NOT NULL COMMENT 'ACCEPT, DROP, REJECT, DNAT, SNAT, etc.',
    protocol VARCHAR(20) DEFAULT 'all',
    source_ip VARCHAR(50) DEFAULT '0.0.0.0/0',
    destination_ip VARCHAR(50) DEFAULT '0.0.0.0/0',
    in_interface VARCHAR(50) DEFAULT '',
    out_interface VARCHAR(50) DEFAULT '',
    ports VARCHAR(100) DEFAULT '' COMMENT 'dport:22, sport:1024:65535, etc.',
    options TEXT COMMENT 'Additional rule options',
    raw_rule TEXT COMMENT 'Original rule text from iptables',
    packets_count BIGINT DEFAULT 0,
    bytes_count BIGINT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_agent_rules (agent_id),
    INDEX idx_table_chain (agent_id, table_name, chain),
    INDEX idx_target (agent_id, target),
    INDEX idx_source (agent_id, source_ip),
    INDEX idx_destination (agent_id, destination_ip),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ============================================================================
-- TABLE: agent_port_forwards
-- Stores detected port forwarding rules
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_port_forwards (
    id INT PRIMARY KEY AUTO_INCREMENT,
    agent_id INT NOT NULL,
    external_port INT NOT NULL,
    internal_ip VARCHAR(45) NOT NULL,
    internal_port INT NOT NULL,
    protocol VARCHAR(10) DEFAULT 'tcp',
    interface VARCHAR(50) DEFAULT '',
    is_enabled BOOLEAN DEFAULT TRUE,
    description VARCHAR(255) DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_agent_pf (agent_id),
    INDEX idx_external_port (agent_id, external_port),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ============================================================================
-- TABLE: agent_network_interfaces
-- Stores network interface information from agents
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_network_interfaces (
    id INT PRIMARY KEY AUTO_INCREMENT,
    agent_id INT NOT NULL,
    interface_name VARCHAR(50) NOT NULL,
    state VARCHAR(20) DEFAULT 'unknown',
    mac_address VARCHAR(20) DEFAULT '',
    addresses_json JSON COMMENT 'IP addresses with CIDR',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_agent_iface (agent_id),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ============================================================================
-- TABLE: agent_firewall_commands
-- Stores firewall commands to be executed by agents
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_firewall_commands (
    id INT PRIMARY KEY AUTO_INCREMENT,
    agent_id INT NOT NULL,
    command_uuid VARCHAR(36) NOT NULL UNIQUE,
    action VARCHAR(50) NOT NULL COMMENT 'add_rule, delete_rule, add_port_forward, etc.',
    params_json JSON COMMENT 'Command parameters',
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
-- TABLE: firewall_rule_templates
-- Predefined firewall rule templates for easy rule creation
-- ============================================================================

CREATE TABLE IF NOT EXISTS firewall_rule_templates (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    category VARCHAR(50) DEFAULT 'general',
    rule_spec JSON NOT NULL COMMENT 'Rule specification template',
    is_system BOOLEAN DEFAULT FALSE COMMENT 'System-provided template',
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_category (category)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ============================================================================
-- INSERT DEFAULT RULE TEMPLATES
-- ============================================================================

INSERT INTO firewall_rule_templates (name, description, category, rule_spec, is_system) VALUES
('Allow SSH', 'Allow incoming SSH connections on port 22', 'security',
 '{"table": "filter", "chain": "INPUT", "protocol": "tcp", "dport": 22, "target": "ACCEPT"}', TRUE),

('Allow HTTP', 'Allow incoming HTTP connections on port 80', 'web',
 '{"table": "filter", "chain": "INPUT", "protocol": "tcp", "dport": 80, "target": "ACCEPT"}', TRUE),

('Allow HTTPS', 'Allow incoming HTTPS connections on port 443', 'web',
 '{"table": "filter", "chain": "INPUT", "protocol": "tcp", "dport": 443, "target": "ACCEPT"}', TRUE),

('Block IP', 'Block all traffic from a specific IP address', 'security',
 '{"table": "filter", "chain": "INPUT", "source": "{{ip}}", "target": "DROP"}', TRUE),

('Allow Established', 'Allow established and related connections', 'security',
 '{"table": "filter", "chain": "INPUT", "state": "ESTABLISHED,RELATED", "target": "ACCEPT"}', TRUE),

('Allow Loopback', 'Allow all traffic on loopback interface', 'system',
 '{"table": "filter", "chain": "INPUT", "in_interface": "lo", "target": "ACCEPT"}', TRUE),

('Allow ICMP/Ping', 'Allow ICMP ping requests', 'network',
 '{"table": "filter", "chain": "INPUT", "protocol": "icmp", "target": "ACCEPT"}', TRUE),

('Allow DNS', 'Allow outgoing DNS queries', 'network',
 '{"table": "filter", "chain": "OUTPUT", "protocol": "udp", "dport": 53, "target": "ACCEPT"}', TRUE),

('Allow MySQL', 'Allow MySQL connections on port 3306', 'database',
 '{"table": "filter", "chain": "INPUT", "protocol": "tcp", "dport": 3306, "target": "ACCEPT"}', TRUE),

('Allow PostgreSQL', 'Allow PostgreSQL connections on port 5432', 'database',
 '{"table": "filter", "chain": "INPUT", "protocol": "tcp", "dport": 5432, "target": "ACCEPT"}', TRUE),

('Allow Redis', 'Allow Redis connections on port 6379', 'database',
 '{"table": "filter", "chain": "INPUT", "protocol": "tcp", "dport": 6379, "target": "ACCEPT"}', TRUE),

('Log Dropped Packets', 'Log packets before dropping', 'logging',
 '{"table": "filter", "chain": "INPUT", "target": "LOG", "log_prefix": "DROPPED: "}', TRUE),

('Port Forward Template', 'Template for port forwarding', 'nat',
 '{"table": "nat", "chain": "PREROUTING", "protocol": "tcp", "dport": "{{external_port}}", "target": "DNAT", "to_destination": "{{internal_ip}}:{{internal_port}}"}', TRUE),

('Masquerade Outgoing', 'NAT masquerade for outgoing traffic', 'nat',
 '{"table": "nat", "chain": "POSTROUTING", "out_interface": "{{interface}}", "target": "MASQUERADE"}', TRUE);


-- ============================================================================
-- TABLE: firewall_audit_log
-- Audit log for firewall changes
-- ============================================================================

CREATE TABLE IF NOT EXISTS firewall_audit_log (
    id INT PRIMARY KEY AUTO_INCREMENT,
    agent_id INT NOT NULL,
    action VARCHAR(50) NOT NULL,
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
-- VIEWS
-- ============================================================================

-- View: Firewall summary per agent
CREATE OR REPLACE VIEW v_agent_firewall_summary AS
SELECT
    a.id AS agent_id,
    a.hostname,
    a.agent_id AS agent_uuid,
    fs.rules_count,
    fs.port_forwards_count,
    fs.last_sync,
    fs.status_json,
    (SELECT COUNT(*) FROM agent_firewall_commands
     WHERE agent_id = a.id AND status = 'pending') AS pending_commands
FROM agents a
LEFT JOIN agent_firewall_state fs ON a.id = fs.agent_id
WHERE a.is_active = TRUE;


-- View: Port forwards across all agents
CREATE OR REPLACE VIEW v_all_port_forwards AS
SELECT
    pf.*,
    a.hostname,
    a.agent_id AS agent_uuid,
    a.ip_address_primary AS agent_ip
FROM agent_port_forwards pf
JOIN agents a ON pf.agent_id = a.id
WHERE a.is_active = TRUE
ORDER BY a.hostname, pf.external_port;


-- ============================================================================
-- SHOW COMPLETION MESSAGE
-- ============================================================================

SELECT 'Firewall management tables created successfully!' AS status;

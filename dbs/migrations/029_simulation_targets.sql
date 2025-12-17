-- SSH Guardian v3.0 - Live Attack Simulation Migration
-- Adds tables for managing simulation targets and tracking live simulation runs

-- Table for registered simulation target servers
CREATE TABLE IF NOT EXISTS simulation_targets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    ip_address VARCHAR(45) NOT NULL,
    port INT DEFAULT 5001 COMMENT 'Port where simulation receiver listens',
    api_key VARCHAR(64) NOT NULL COMMENT 'API key for authenticating with receiver',
    agent_id INT DEFAULT NULL COMMENT 'Link to agents table if also registered as SSH Guardian agent',
    is_active BOOLEAN DEFAULT TRUE,
    last_tested_at DATETIME DEFAULT NULL,
    test_status VARCHAR(20) DEFAULT NULL COMMENT 'success, failed, pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_sim_targets_active (is_active),
    INDEX idx_sim_targets_ip (ip_address),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Registered servers that can receive live attack simulations';

-- Table for tracking LIVE attack simulation run history
-- Named differently from simulation_runs (which is for pipeline simulation)
CREATE TABLE IF NOT EXISTS live_simulation_runs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    target_id INT NOT NULL,
    scenario_id VARCHAR(50) NOT NULL COMMENT 'ID from DEMO_SCENARIOS',
    scenario_name VARCHAR(100) DEFAULT NULL,
    source_ip VARCHAR(45) NOT NULL COMMENT 'IP used in simulation (from scenario)',
    event_count INT NOT NULL DEFAULT 15,
    status ENUM('pending', 'injected', 'detected', 'blocked', 'completed', 'failed') DEFAULT 'pending',
    error_message TEXT DEFAULT NULL,

    -- Timeline tracking
    injected_at DATETIME DEFAULT NULL COMMENT 'When events were written to auth.log',
    detected_at DATETIME DEFAULT NULL COMMENT 'When first auth_event appeared in dashboard',
    blocked_at DATETIME DEFAULT NULL COMMENT 'When IP was blocked (fail2ban or ML)',
    completed_at DATETIME DEFAULT NULL,

    -- Results
    fail2ban_block_id INT DEFAULT NULL COMMENT 'ID of fail2ban block if triggered',
    ml_block_id INT DEFAULT NULL COMMENT 'ID of ML-triggered block if triggered',
    events_detected INT DEFAULT 0 COMMENT 'Count of events received from agent',
    result_json TEXT DEFAULT NULL COMMENT 'Full result details as JSON',

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_live_sim_runs_target (target_id),
    INDEX idx_live_sim_runs_status (status),
    INDEX idx_live_sim_runs_scenario (scenario_id),
    INDEX idx_live_sim_runs_created (created_at),
    INDEX idx_live_sim_runs_source_ip (source_ip),
    FOREIGN KEY (target_id) REFERENCES simulation_targets(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Tracks live attack simulation runs and their results';

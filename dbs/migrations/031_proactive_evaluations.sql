-- SSH Guardian v3.0 - Proactive Evaluations Table
-- Logs real-time ML evaluations of auth events

CREATE TABLE IF NOT EXISTS proactive_evaluations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    username VARCHAR(100),
    event_type VARCHAR(50),
    threat_score TINYINT UNSIGNED NOT NULL DEFAULT 0,
    risk_level ENUM('low', 'medium', 'high', 'critical') NOT NULL DEFAULT 'low',
    action_taken VARCHAR(100),
    factors_json TEXT,
    evaluated_at DATETIME NOT NULL,

    INDEX idx_proactive_ip (ip_address),
    INDEX idx_proactive_score (threat_score),
    INDEX idx_proactive_level (risk_level),
    INDEX idx_proactive_time (evaluated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Real-time ML evaluations of incoming auth events';

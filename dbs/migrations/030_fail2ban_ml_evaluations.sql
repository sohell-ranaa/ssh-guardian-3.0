-- SSH Guardian v3.0 - Fail2ban ML Evaluations Table
-- Stores ML threat evaluations for fail2ban bans

CREATE TABLE IF NOT EXISTS fail2ban_ml_evaluations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    threat_score TINYINT UNSIGNED NOT NULL DEFAULT 0,
    risk_level ENUM('low', 'medium', 'high', 'critical') NOT NULL DEFAULT 'low',
    recommended_action VARCHAR(50) NOT NULL,
    auto_escalated BOOLEAN DEFAULT FALSE,
    factors_json TEXT,
    evaluated_at DATETIME NOT NULL,

    INDEX idx_f2b_eval_ip (ip_address),
    INDEX idx_f2b_eval_score (threat_score),
    INDEX idx_f2b_eval_escalated (auto_escalated),
    INDEX idx_f2b_eval_time (evaluated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='ML threat evaluations for fail2ban bans';

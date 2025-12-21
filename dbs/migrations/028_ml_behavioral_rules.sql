-- Migration 028: ML Behavioral Analysis Rules
-- Adds advanced behavioral pattern detection rules with HIGHEST priority
-- These rules use the BehavioralAnalyzer for ML-based threat detection

-- ML Behavioral Analysis Rule (HIGHEST PRIORITY - detects what rule-based can't)
-- This rule uses BehavioralAnalyzer to detect:
-- - Impossible travel
-- - Unusual login times
-- - New locations/IPs for users
-- - Credential stuffing patterns
-- - Success after brute force
INSERT INTO blocking_rules (rule_name, rule_type, priority, conditions, block_duration_minutes, is_enabled, is_system_rule, auto_unblock, description) VALUES
(
    'ml_behavioral_critical',
    'behavioral_analysis',
    150,  -- HIGHEST priority (above all other rules)
    '{
        "min_risk_score": 60,
        "min_confidence": 0.5,
        "priority_factors": ["impossible_travel", "credential_stuffing", "brute_force"],
        "requires_approval": false
    }',
    0,    -- 0 = permanent block for critical threats (handled by rule logic)
    1,
    1,
    0,    -- auto_unblock = false for ML critical detections
    'ML Behavioral Analysis: Detects impossible travel, credential stuffing, and advanced attack patterns that rule-based systems cannot detect.'
),
(
    'ml_behavioral_high',
    'behavioral_analysis',
    145,
    '{
        "min_risk_score": 40,
        "min_confidence": 0.5,
        "priority_factors": ["new_location", "unusual_time", "success_after_failures"],
        "requires_approval": false
    }',
    2880,  -- 48 hours
    1,
    1,
    1,
    'ML Behavioral Analysis: Detects new login locations, unusual times, and success after failures patterns.'
)
ON DUPLICATE KEY UPDATE
    priority = VALUES(priority),
    conditions = VALUES(conditions),
    block_duration_minutes = VALUES(block_duration_minutes),
    is_enabled = VALUES(is_enabled),
    description = VALUES(description);

-- Distributed Brute Force Rule (many IPs, many users, slow attack)
INSERT INTO blocking_rules (rule_name, rule_type, priority, conditions, block_duration_minutes, is_enabled, is_system_rule, auto_unblock, description) VALUES
(
    'distributed_brute_force',
    'distributed_brute_force',
    120,
    '{
        "unique_ips_threshold": 5,
        "unique_usernames_threshold": 10,
        "time_window_minutes": 60,
        "max_attempts_per_ip": 3
    }',
    2880,
    1,
    1,
    1,
    'Detects coordinated attacks from multiple IPs trying many usernames with slow frequency to evade detection.'
)
ON DUPLICATE KEY UPDATE
    priority = VALUES(priority),
    conditions = VALUES(conditions),
    block_duration_minutes = VALUES(block_duration_minutes),
    is_enabled = VALUES(is_enabled),
    description = VALUES(description);

-- Account Takeover Detection Rule
INSERT INTO blocking_rules (rule_name, rule_type, priority, conditions, block_duration_minutes, is_enabled, is_system_rule, auto_unblock, description) VALUES
(
    'account_takeover_detection',
    'account_takeover',
    125,
    '{
        "unique_ips_threshold": 3,
        "unique_countries_threshold": 2,
        "time_window_minutes": 30,
        "check_threat_intel": true
    }',
    1440,
    1,
    1,
    1,
    'Detects when a username is targeted from multiple IPs/countries in a short time - indicates credential testing or compromised credentials.'
)
ON DUPLICATE KEY UPDATE
    priority = VALUES(priority),
    conditions = VALUES(conditions),
    block_duration_minutes = VALUES(block_duration_minutes),
    is_enabled = VALUES(is_enabled),
    description = VALUES(description);

-- Off-Hours Anomaly Rule
INSERT INTO blocking_rules (rule_name, rule_type, priority, conditions, block_duration_minutes, is_enabled, is_system_rule, auto_unblock, description) VALUES
(
    'off_hours_anomaly',
    'off_hours_anomaly',
    80,
    '{
        "work_start_hour": 8,
        "work_end_hour": 18,
        "work_days": [0, 1, 2, 3, 4],
        "min_off_hours_attempts": 3,
        "check_user_baseline": true
    }',
    720,
    1,
    1,
    1,
    'Detects login attempts outside business hours when combined with other risk factors.'
)
ON DUPLICATE KEY UPDATE
    priority = VALUES(priority),
    conditions = VALUES(conditions),
    block_duration_minutes = VALUES(block_duration_minutes),
    is_enabled = VALUES(is_enabled),
    description = VALUES(description);

-- Summary of ML rules
SELECT
    rule_type,
    rule_name,
    priority,
    is_enabled,
    block_duration_minutes as block_mins
FROM blocking_rules
WHERE rule_type IN ('behavioral_analysis', 'distributed_brute_force', 'account_takeover', 'off_hours_anomaly')
ORDER BY priority DESC;

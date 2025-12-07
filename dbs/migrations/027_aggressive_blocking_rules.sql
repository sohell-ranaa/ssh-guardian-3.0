-- Migration 027: Aggressive Blocking Rules
-- Implements tiered, aggressive blocking for practical security scenarios

-- First, disable old default rules (if any exist)
UPDATE blocking_rules SET is_enabled = 0 WHERE is_system_rule = 1;

-- AbuseIPDB Tier Rules
INSERT INTO blocking_rules (rule_name, rule_type, priority, conditions, block_duration_minutes, is_enabled, is_system_rule, auto_unblock) VALUES
('abuseipdb_critical_90', 'api_reputation', 100, '{"min_abuseipdb_score": 90, "block_on_success": true}', 10080, 1, 1, 1),
('abuseipdb_high_70', 'api_reputation', 95, '{"min_abuseipdb_score": 70}', 1440, 1, 1, 1),
('abuseipdb_medium_50', 'api_reputation', 90, '{"min_abuseipdb_score": 50, "require_failed_login": true}', 720, 1, 1, 1),
('abuseipdb_low_25', 'api_reputation', 85, '{"min_abuseipdb_score": 25, "min_failed_attempts": 2}', 360, 1, 1, 1)
ON DUPLICATE KEY UPDATE
    priority = VALUES(priority),
    conditions = VALUES(conditions),
    block_duration_minutes = VALUES(block_duration_minutes),
    is_enabled = VALUES(is_enabled);

-- Brute Force Rules (5 fails minimum as per user requirement)
INSERT INTO blocking_rules (rule_name, rule_type, priority, conditions, block_duration_minutes, is_enabled, is_system_rule, auto_unblock) VALUES
('brute_force_5_in_10min', 'brute_force', 88, '{"failed_attempts": 5, "time_window_minutes": 10}', 1440, 1, 1, 1),
('brute_force_10_in_30min', 'brute_force', 82, '{"failed_attempts": 10, "time_window_minutes": 30}', 720, 1, 1, 1),
('brute_force_20_in_1hr', 'brute_force', 78, '{"failed_attempts": 20, "time_window_minutes": 60}', 360, 1, 1, 1)
ON DUPLICATE KEY UPDATE
    priority = VALUES(priority),
    conditions = VALUES(conditions),
    block_duration_minutes = VALUES(block_duration_minutes),
    is_enabled = VALUES(is_enabled);

-- Credential Stuffing Rules (5 unique users as per user requirement)
INSERT INTO blocking_rules (rule_name, rule_type, priority, conditions, block_duration_minutes, is_enabled, is_system_rule, auto_unblock) VALUES
('cred_stuff_5_users_15min', 'credential_stuffing', 92, '{"unique_usernames": 5, "time_window_minutes": 15}', 2880, 1, 1, 1),
('cred_stuff_10_users_1hr', 'credential_stuffing', 86, '{"unique_usernames": 10, "time_window_minutes": 60}', 1440, 1, 1, 1)
ON DUPLICATE KEY UPDATE
    priority = VALUES(priority),
    conditions = VALUES(conditions),
    block_duration_minutes = VALUES(block_duration_minutes),
    is_enabled = VALUES(is_enabled);

-- Velocity / DDoS Rules (20 events/min as per user requirement - aggressive)
INSERT INTO blocking_rules (rule_name, rule_type, priority, conditions, block_duration_minutes, is_enabled, is_system_rule, auto_unblock) VALUES
('ddos_20_per_min', 'velocity', 99, '{"max_events": 20, "time_window_seconds": 60}', 10080, 1, 1, 1),
('ddos_50_per_2min', 'velocity', 96, '{"max_events": 50, "time_window_seconds": 120}', 2880, 1, 1, 1),
('ddos_100_per_5min', 'velocity', 93, '{"max_events": 100, "time_window_seconds": 300}', 1440, 1, 1, 1)
ON DUPLICATE KEY UPDATE
    priority = VALUES(priority),
    conditions = VALUES(conditions),
    block_duration_minutes = VALUES(block_duration_minutes),
    is_enabled = VALUES(is_enabled);

-- Tor Detection Rule (block on fail only as per user requirement)
INSERT INTO blocking_rules (rule_name, rule_type, priority, conditions, block_duration_minutes, is_enabled, is_system_rule, auto_unblock) VALUES
('tor_failed_login', 'tor_detection', 91, '{"is_tor": true, "require_failed_login": true}', 1440, 1, 1, 1)
ON DUPLICATE KEY UPDATE
    priority = VALUES(priority),
    conditions = VALUES(conditions),
    block_duration_minutes = VALUES(block_duration_minutes),
    is_enabled = VALUES(is_enabled);

-- VPN/Proxy Detection Rule (block if score >= 30 as per user requirement)
INSERT INTO blocking_rules (rule_name, rule_type, priority, conditions, block_duration_minutes, is_enabled, is_system_rule, auto_unblock) VALUES
('vpn_proxy_score_30', 'proxy_detection', 87, '{"is_proxy_or_vpn": true, "min_abuseipdb_score": 30}', 720, 1, 1, 1)
ON DUPLICATE KEY UPDATE
    priority = VALUES(priority),
    conditions = VALUES(conditions),
    block_duration_minutes = VALUES(block_duration_minutes),
    is_enabled = VALUES(is_enabled);

-- High-Risk Country Rules (2 fails = block as per user requirement)
INSERT INTO blocking_rules (rule_name, rule_type, priority, conditions, block_duration_minutes, is_enabled, is_system_rule, auto_unblock) VALUES
('high_risk_country_2_fails', 'geo_restriction', 84, '{"countries": ["CN","RU","KP","IR","BY"], "min_failed_attempts": 2}', 1440, 1, 1, 1)
ON DUPLICATE KEY UPDATE
    priority = VALUES(priority),
    conditions = VALUES(conditions),
    block_duration_minutes = VALUES(block_duration_minutes),
    is_enabled = VALUES(is_enabled);

-- Impossible Travel Rule (1000km / 2hr as per user requirement)
INSERT INTO blocking_rules (rule_name, rule_type, priority, conditions, block_duration_minutes, is_enabled, is_system_rule, auto_unblock) VALUES
('impossible_travel_1000km_2hr', 'geo_anomaly', 94, '{"max_distance_km": 1000, "time_window_hours": 2}', 1440, 1, 1, 1)
ON DUPLICATE KEY UPDATE
    priority = VALUES(priority),
    conditions = VALUES(conditions),
    block_duration_minutes = VALUES(block_duration_minutes),
    is_enabled = VALUES(is_enabled);

-- Threat Combo Rules
INSERT INTO blocking_rules (rule_name, rule_type, priority, conditions, block_duration_minutes, is_enabled, is_system_rule, auto_unblock) VALUES
('combo_abuse50_tor_fail', 'threat_combo', 97, '{"min_abuseipdb_score": 50, "is_tor": true, "require_failed_login": true}', 2880, 1, 1, 1),
('combo_abuse50_proxy_fail', 'threat_combo', 95, '{"min_abuseipdb_score": 50, "is_proxy": true, "require_failed_login": true}', 1440, 1, 1, 1),
('combo_vt_5_positives', 'threat_combo', 98, '{"min_virustotal_positives": 5}', 1440, 1, 1, 1),
('combo_shodan_3_vulns_fail', 'threat_combo', 89, '{"min_shodan_vulns": 3, "require_failed_login": true}', 720, 1, 1, 1)
ON DUPLICATE KEY UPDATE
    priority = VALUES(priority),
    conditions = VALUES(conditions),
    block_duration_minutes = VALUES(block_duration_minutes),
    is_enabled = VALUES(is_enabled);

-- Repeat Offender Rule (escalating blocks as per user requirement)
INSERT INTO blocking_rules (rule_name, rule_type, priority, conditions, block_duration_minutes, is_enabled, is_system_rule, auto_unblock) VALUES
('repeat_offender_escalation', 'repeat_offender', 75, '{"escalation": {"2": 2, "3": 10080, "4": 43200}}', 1440, 1, 1, 1)
ON DUPLICATE KEY UPDATE
    priority = VALUES(priority),
    conditions = VALUES(conditions),
    block_duration_minutes = VALUES(block_duration_minutes),
    is_enabled = VALUES(is_enabled);

-- Summary of rules inserted
SELECT
    rule_type,
    COUNT(*) as rule_count,
    GROUP_CONCAT(rule_name) as rules
FROM blocking_rules
WHERE is_enabled = 1
GROUP BY rule_type
ORDER BY rule_type;

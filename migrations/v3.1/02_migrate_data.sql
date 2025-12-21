-- ============================================================================
-- SSH Guardian v3.1 - Data Migration Script
-- ============================================================================
-- Transforms data from ssh_guardian_v3 to fit the clean v3.1 schema
-- OLD DATABASE REMAINS UNTOUCHED
-- ============================================================================

USE ssh_guardian_v3_1;

-- Disable FK checks during migration
SET FOREIGN_KEY_CHECKS = 0;
SET SQL_MODE = 'NO_AUTO_VALUE_ON_ZERO';

-- ============================================================================
-- DOMAIN 1: USER MANAGEMENT
-- ============================================================================

-- 1.1 Roles
INSERT INTO roles (id, name, description, permissions, is_system_role, created_at, updated_at)
SELECT id, name, description, permissions, 0, COALESCE(created_at, NOW()), COALESCE(updated_at, NOW())
FROM ssh_guardian_v3.roles;

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated)
SELECT 'roles', 'roles', 'roles', COUNT(*) FROM ssh_guardian_v3.roles;

-- 1.2 Users (map is_email_verified -> email_verified_at, last_login -> last_login_at)
INSERT INTO users (id, email, password_hash, full_name, role_id, is_active, email_verified_at,
    last_login_at, last_login_ip, failed_login_attempts, locked_until, preferences, created_at, updated_at)
SELECT id, email, password_hash, full_name, role_id, COALESCE(is_active, 1),
    IF(is_email_verified = 1, created_at, NULL),
    last_login, NULL, COALESCE(failed_login_attempts, 0), locked_until, NULL,
    COALESCE(created_at, NOW()), COALESCE(updated_at, NOW())
FROM ssh_guardian_v3.users;

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated)
SELECT 'users', 'users', 'users', COUNT(*) FROM ssh_guardian_v3.users;

-- 1.3 User Sessions (map last_activity -> last_activity_at)
INSERT INTO user_sessions (id, user_id, session_token, ip_address, user_agent, is_active,
    expires_at, last_activity_at, created_at)
SELECT id, user_id, session_token, ip_address, user_agent, 1, expires_at,
    COALESCE(last_activity, NOW()), COALESCE(created_at, NOW())
FROM ssh_guardian_v3.user_sessions
WHERE user_id IN (SELECT id FROM users);

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated)
SELECT 'user_sessions', 'user_sessions', 'user_sessions', COUNT(*) FROM ssh_guardian_v3.user_sessions;

-- 1.4 User OTPs (map purpose -> purpose directly since we use VARCHAR now)
INSERT INTO user_otps (id, user_id, otp_code, purpose, is_used, expires_at, created_at)
SELECT id, user_id, otp_code, purpose, COALESCE(is_used, 0), expires_at, COALESCE(created_at, NOW())
FROM ssh_guardian_v3.user_otps
WHERE user_id IN (SELECT id FROM users);

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated)
SELECT 'user_otps', 'user_otps', 'user_otps', COUNT(*) FROM ssh_guardian_v3.user_otps;

-- ============================================================================
-- DOMAIN 2: AGENT MANAGEMENT
-- ============================================================================

-- 2.1 Agents
INSERT INTO agents (id, agent_uuid, agent_id, api_key, hostname, display_name, agent_type,
    ip_address, ip_address_internal, mac_address, location, environment, status, health_status,
    last_heartbeat, heartbeat_interval_sec, version, supported_features, total_events_sent,
    is_active, is_approved, approved_by_user_id, approved_at, notes, created_at, updated_at)
SELECT id, agent_uuid, agent_id, api_key, hostname, display_name,
    COALESCE(agent_type, 'secondary'),
    ip_address_primary, ip_address_internal, mac_address, location,
    COALESCE(environment, 'production'),
    COALESCE(status, 'pending'),
    COALESCE(health_status, 'unknown'),
    last_heartbeat, COALESCE(heartbeat_interval_sec, 30), version, supported_features,
    COALESCE(total_events_sent, 0), COALESCE(is_active, 1), COALESCE(is_approved, 0),
    approved_by_user_id, approved_at, notes, COALESCE(created_at, NOW()), COALESCE(updated_at, NOW())
FROM ssh_guardian_v3.agents;

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated)
SELECT 'agents', 'agents', 'agents', COUNT(*) FROM ssh_guardian_v3.agents;

-- 2.2 Agent Heartbeats (last 7 days only)
INSERT INTO agent_heartbeats (id, agent_id, heartbeat_timestamp, cpu_usage, memory_usage,
    disk_usage, load_average, uptime_seconds, network_stats, process_count, agent_version, metadata)
SELECT id, agent_id, heartbeat_timestamp, cpu_usage, memory_usage, disk_usage, load_average,
    uptime_seconds, network_stats, process_count, agent_version, metadata
FROM ssh_guardian_v3.agent_heartbeats
WHERE heartbeat_timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
AND agent_id IN (SELECT id FROM agents);

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated, notes)
SELECT 'agent_heartbeats', 'agent_heartbeats', 'agent_heartbeats',
    (SELECT COUNT(*) FROM ssh_guardian_v3.agent_heartbeats WHERE heartbeat_timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)),
    'Only last 7 days migrated';

-- 2.3 Agent Log Batches (last 30 days, map column names)
INSERT INTO agent_log_batches (id, batch_uuid, agent_id, log_source, events_count, events_processed,
    events_failed, status, processing_started_at, processing_completed_at, processing_duration_ms,
    error_message, created_at)
SELECT id, batch_uuid, agent_id,
    COALESCE(source_filename, 'auth.log'),
    COALESCE(batch_size, 0),
    COALESCE(events_created, 0),
    COALESCE(events_failed, 0),
    COALESCE(processing_status, 'received'),
    processing_started_at, processing_completed_at, processing_duration_ms,
    error_message, COALESCE(created_at, NOW())
FROM ssh_guardian_v3.agent_log_batches
WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
AND agent_id IN (SELECT id FROM agents);

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated, notes)
SELECT 'agent_log_batches', 'agent_log_batches', 'agent_log_batches',
    (SELECT COUNT(*) FROM ssh_guardian_v3.agent_log_batches WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)),
    'Only last 30 days migrated';

-- 2.4 Agent UFW State (map ufw_status -> is_enabled + ufw_status)
INSERT INTO agent_ufw_state (id, agent_id, is_enabled, ufw_status, default_incoming, default_outgoing,
    default_routed, logging_level, ipv6_enabled, rules_count, ufw_version, last_sync, raw_status,
    created_at, updated_at)
SELECT id, agent_id,
    IF(ufw_status = 'active', 1, 0),
    COALESCE(ufw_status, 'inactive'),
    COALESCE(default_incoming, 'deny'),
    COALESCE(default_outgoing, 'allow'),
    COALESCE(default_routed, 'disabled'),
    COALESCE(logging_level, 'low'),
    COALESCE(ipv6_enabled, 1),
    COALESCE(rules_count, 0),
    ufw_version, last_sync, raw_status,
    COALESCE(created_at, NOW()), COALESCE(updated_at, NOW())
FROM ssh_guardian_v3.agent_ufw_state
WHERE agent_id IN (SELECT id FROM agents);

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated)
SELECT 'agent_ufw_state', 'agent_ufw_state', 'agent_ufw_state', COUNT(*) FROM ssh_guardian_v3.agent_ufw_state;

-- 2.5 Agent UFW Rules (ipv6 -> is_v6, keep protocol as-is since VARCHAR now)
INSERT INTO agent_ufw_rules (id, agent_id, rule_index, action, direction, protocol, from_ip,
    from_port, to_ip, to_port, interface, comment, is_v6, raw_rule, created_at, updated_at)
SELECT id, agent_id, rule_index, action,
    COALESCE(direction, 'in'),
    protocol, -- Now VARCHAR, accepts 'tcp (v6)' etc.
    COALESCE(from_ip, 'Anywhere'),
    from_port,
    COALESCE(to_ip, 'Anywhere'),
    to_port, interface, comment,
    COALESCE(ipv6, 0),
    raw_rule, COALESCE(created_at, NOW()), COALESCE(updated_at, NOW())
FROM ssh_guardian_v3.agent_ufw_rules
WHERE agent_id IN (SELECT id FROM agents);

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated)
SELECT 'agent_ufw_rules', 'agent_ufw_rules', 'agent_ufw_rules', COUNT(*) FROM ssh_guardian_v3.agent_ufw_rules;

-- 2.6 Agent UFW Commands (params_json -> params)
INSERT INTO agent_ufw_commands (id, agent_id, command_uuid, command_type, params, ufw_command,
    status, result_message, created_by, created_at, sent_at, executed_at)
SELECT id, agent_id, command_uuid, command_type, params_json, ufw_command,
    COALESCE(status, 'pending'), result_message, created_by,
    COALESCE(created_at, NOW()), sent_at, executed_at
FROM ssh_guardian_v3.agent_ufw_commands
WHERE agent_id IN (SELECT id FROM agents);

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated)
SELECT 'agent_ufw_commands', 'agent_ufw_commands', 'agent_ufw_commands', COUNT(*) FROM ssh_guardian_v3.agent_ufw_commands;

-- ============================================================================
-- DOMAIN 3: IP INTELLIGENCE
-- ============================================================================

-- 3.1 IP Geolocation (merge with ip_threat_intelligence)
INSERT INTO ip_geolocation (id, ip_address, ip_address_text, ip_version, country_code, country_name,
    region, city, postal_code, latitude, longitude, timezone, asn, asn_org, isp, connection_type,
    is_proxy, is_vpn, is_tor, is_datacenter, is_hosting,
    abuseipdb_score, abuseipdb_reports, abuseipdb_last_reported, abuseipdb_checked_at,
    virustotal_positives, virustotal_total, virustotal_checked_at,
    threat_level, threat_categories, lookup_count, first_seen, last_seen, cache_expires_at)
SELECT g.id, g.ip_address, g.ip_address_text, COALESCE(g.ip_version, 4),
    g.country_code, g.country_name, g.region, g.city, g.postal_code,
    g.latitude, g.longitude, g.timezone, g.asn, g.asn_org, g.isp, g.connection_type,
    COALESCE(g.is_proxy, 0), COALESCE(g.is_vpn, 0), COALESCE(g.is_tor, 0),
    COALESCE(g.is_datacenter, 0), COALESCE(g.is_hosting, 0),
    t.abuseipdb_score, t.abuseipdb_reports, t.abuseipdb_last_reported, t.abuseipdb_checked_at,
    t.virustotal_positives, t.virustotal_total, t.virustotal_checked_at,
    COALESCE(t.overall_threat_level, 'unknown'), t.threat_categories,
    COALESCE(g.lookup_count, 1), COALESCE(g.first_seen, NOW()), COALESCE(g.last_seen, NOW()), g.cache_expires_at
FROM ssh_guardian_v3.ip_geolocation g
LEFT JOIN ssh_guardian_v3.ip_threat_intelligence t ON g.ip_address_text = t.ip_address_text;

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated, notes)
SELECT 'ip_geolocation', 'ip_geolocation + ip_threat_intelligence', 'ip_geolocation', COUNT(*), 'Merged with threat intelligence'
FROM ssh_guardian_v3.ip_geolocation;

-- 3.2 IP Blocks (map block_source values, geo_id may not exist)
INSERT INTO ip_blocks (id, ip_address, ip_address_text, ip_range_cidr, block_reason, block_source,
    blocking_rule_id, trigger_event_id, agent_id, geo_id, failed_attempts, risk_score, threat_level,
    is_active, blocked_at, unblock_at, auto_unblock, unblocked_at, unblocked_by_user_id,
    unblock_reason, is_simulation, simulation_run_id, metadata, created_by_user_id, created_at, updated_at)
SELECT id, ip_address, ip_address_text, ip_range_cidr, block_reason,
    CASE block_source
        WHEN 'rule_based' THEN 'rule'
        WHEN 'ml_threshold' THEN 'ml'
        WHEN 'api_reputation' THEN 'api'
        WHEN 'anomaly_detection' THEN 'ml'
        ELSE COALESCE(block_source, 'manual')
    END,
    blocking_rule_id, trigger_event_id, agent_id,
    (SELECT id FROM ip_geolocation WHERE ip_address_text = ssh_guardian_v3.ip_blocks.ip_address_text LIMIT 1),
    COALESCE(failed_attempts, 0), risk_score, threat_level,
    COALESCE(is_active, 1), COALESCE(blocked_at, NOW()), unblock_at, COALESCE(auto_unblock, 1),
    manually_unblocked_at, unblocked_by_user_id, unblock_reason,
    COALESCE(is_simulation, 0), simulation_run_id, block_metadata, created_by_user_id,
    COALESCE(created_at, NOW()), COALESCE(updated_at, NOW())
FROM ssh_guardian_v3.ip_blocks;

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated)
SELECT 'ip_blocks', 'ip_blocks', 'ip_blocks', COUNT(*) FROM ssh_guardian_v3.ip_blocks;

-- ============================================================================
-- DOMAIN 4: AUTH EVENTS
-- ============================================================================

-- 4.1 Auth Events (map source_type 'synthetic' -> 'simulation')
INSERT INTO auth_events (id, event_uuid, timestamp, source_type, agent_id, simulation_run_id,
    event_type, auth_method, source_ip, source_ip_text, source_port, target_server, target_port,
    target_username, failure_reason, geo_id, block_id, raw_log_line, created_at)
SELECT id, event_uuid, timestamp,
    CASE WHEN source_type = 'synthetic' THEN 'simulation' ELSE COALESCE(source_type, 'agent') END,
    agent_id, simulation_run_id,
    COALESCE(event_type, 'failed'), auth_method, source_ip, source_ip_text, source_port,
    target_server, COALESCE(target_port, 22), target_username, failure_reason,
    geo_id, block_id, raw_log_line, COALESCE(created_at, NOW())
FROM ssh_guardian_v3.auth_events;

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated)
SELECT 'auth_events', 'auth_events', 'auth_events', COUNT(*) FROM ssh_guardian_v3.auth_events;

-- 4.2 Auth Events ML (from ml_predictions)
INSERT INTO auth_events_ml (event_id, model_id, risk_score, threat_type, confidence, is_anomaly,
    features_snapshot, inference_time_ms, manual_feedback, feedback_at, feedback_by_user_id,
    feedback_notes, was_blocked, created_at)
SELECT event_id, model_id, COALESCE(risk_score, 0), threat_type, COALESCE(confidence, 0),
    COALESCE(is_anomaly, 0), features_snapshot, inference_time_ms, manual_feedback,
    feedback_at, feedback_by_user_id, feedback_notes, COALESCE(was_blocked, 0),
    COALESCE(created_at, NOW())
FROM ssh_guardian_v3.ml_predictions
WHERE event_id IN (SELECT id FROM auth_events);

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated)
SELECT 'auth_events_ml', 'ml_predictions', 'auth_events_ml', COUNT(*) FROM ssh_guardian_v3.ml_predictions;

-- 4.3 Auth Events Daily (rename invalid_events -> invalid_user_events)
INSERT INTO auth_events_daily (id, summary_date, agent_id, total_events, failed_events,
    successful_events, invalid_user_events, unique_ips, unique_usernames, unique_countries,
    ips_blocked, top_ips, top_usernames, top_countries, hourly_distribution, created_at, updated_at)
SELECT id, summary_date, agent_id, COALESCE(total_events, 0), COALESCE(failed_events, 0),
    COALESCE(successful_events, 0), COALESCE(invalid_events, 0), COALESCE(unique_ips, 0),
    COALESCE(unique_usernames, 0), COALESCE(unique_countries, 0), COALESCE(ips_blocked, 0),
    top_ips, top_usernames, top_countries, hourly_distribution,
    COALESCE(created_at, NOW()), COALESCE(updated_at, NOW())
FROM ssh_guardian_v3.auth_events_daily_summary;

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated)
SELECT 'auth_events_daily', 'auth_events_daily_summary', 'auth_events_daily', COUNT(*) FROM ssh_guardian_v3.auth_events_daily_summary;

-- ============================================================================
-- DOMAIN 5: BLOCKING SYSTEM
-- ============================================================================

-- 5.1 Blocking Rules
INSERT INTO blocking_rules (id, rule_name, rule_type, is_enabled, is_system_rule, priority,
    conditions, block_duration_minutes, auto_unblock, notify_on_trigger, notification_channels,
    times_triggered, last_triggered_at, ips_blocked_total, description, created_by_user_id,
    created_at, updated_at)
SELECT id, rule_name, rule_type, COALESCE(is_enabled, 1), COALESCE(is_system_rule, 0),
    COALESCE(priority, 50), conditions, COALESCE(block_duration_minutes, 1440),
    COALESCE(auto_unblock, 1), COALESCE(notify_on_trigger, 1), notification_channels,
    COALESCE(times_triggered, 0), last_triggered_at, COALESCE(ips_blocked_total, 0),
    description, created_by_user_id, COALESCE(created_at, NOW()), COALESCE(updated_at, NOW())
FROM ssh_guardian_v3.blocking_rules;

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated)
SELECT 'blocking_rules', 'blocking_rules', 'blocking_rules', COUNT(*) FROM ssh_guardian_v3.blocking_rules;

-- 5.2 Blocking Actions
INSERT INTO blocking_actions (id, action_uuid, ip_block_id, ip_address_text, action_type,
    action_source, reason, performed_by_user_id, triggered_by_rule_id, triggered_by_event_id,
    agent_id, metadata, created_at)
SELECT id, action_uuid, ip_block_id, ip_address_text, action_type,
    COALESCE(action_source, 'system'), reason, performed_by_user_id,
    triggered_by_rule_id, triggered_by_event_id, NULL, action_metadata, COALESCE(created_at, NOW())
FROM ssh_guardian_v3.blocking_actions;

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated)
SELECT 'blocking_actions', 'blocking_actions', 'blocking_actions', COUNT(*) FROM ssh_guardian_v3.blocking_actions;

-- Also migrate ip_block_events into blocking_actions (consolidated)
INSERT INTO blocking_actions (action_uuid, ip_block_id, ip_address_text, action_type,
    action_source, reason, performed_by_user_id, agent_id, created_at)
SELECT UUID(), NULL, ip_address,
    CASE event_type WHEN 'block' THEN 'block' WHEN 'unblock' THEN 'unblock' ELSE 'block' END,
    CASE block_source
        WHEN 'fail2ban' THEN 'fail2ban'
        WHEN 'manual' THEN 'manual'
        WHEN 'ml' THEN 'system'
        WHEN 'api' THEN 'api'
        ELSE 'system'
    END,
    reason, user_id, agent_id, COALESCE(created_at, NOW())
FROM ssh_guardian_v3.ip_block_events
WHERE ip_address NOT IN (SELECT ip_address_text FROM blocking_actions);

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated, notes)
SELECT 'ip_block_events_merge', 'ip_block_events', 'blocking_actions', COUNT(*), 'Merged into blocking_actions'
FROM ssh_guardian_v3.ip_block_events;

-- ============================================================================
-- DOMAIN 6: FAIL2BAN
-- ============================================================================

-- 6.1 Fail2ban State
INSERT INTO fail2ban_state (id, agent_id, ip_address, jail_name, banned_at, bantime_seconds,
    failures, last_sync)
SELECT id, agent_id, ip_address, COALESCE(jail_name, 'sshd'), banned_at,
    COALESCE(bantime_seconds, 0), COALESCE(failures, 0), COALESCE(last_sync, NOW())
FROM ssh_guardian_v3.agent_fail2ban_state
WHERE agent_id IN (SELECT id FROM agents);

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated)
SELECT 'fail2ban_state', 'agent_fail2ban_state', 'fail2ban_state', COUNT(*) FROM ssh_guardian_v3.agent_fail2ban_state;

-- 6.2 Fail2ban Events
INSERT INTO fail2ban_events (id, agent_id, event_type, ip_address, jail_name, failures,
    bantime_seconds, timestamp, raw_log, created_at)
SELECT id, agent_id, event_type, ip_address, COALESCE(jail_name, 'sshd'),
    COALESCE(failures, 0), COALESCE(bantime_seconds, 0), timestamp, raw_log,
    COALESCE(created_at, NOW())
FROM ssh_guardian_v3.fail2ban_events
WHERE agent_id IN (SELECT id FROM agents);

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated)
SELECT 'fail2ban_events', 'fail2ban_events', 'fail2ban_events', COUNT(*) FROM ssh_guardian_v3.fail2ban_events;

-- ============================================================================
-- DOMAIN 7: ML SYSTEM
-- ============================================================================

-- 7.1 ML Models (recall -> recall_score)
INSERT INTO ml_models (id, model_uuid, model_name, algorithm, version, status, is_active,
    model_path, model_size_bytes, hyperparameters, feature_config, training_run_id,
    accuracy, precision_score, recall_score, f1_score, auc_roc, predictions_count,
    avg_inference_time_ms, created_at, updated_at, promoted_at, deprecated_at)
SELECT id, model_uuid, model_name, algorithm, version, COALESCE(status, 'training'),
    COALESCE(is_active, 0), model_path, model_size_bytes, hyperparameters, feature_config,
    training_run_id, accuracy, precision_score, `recall`, f1_score, auc_roc,
    COALESCE(predictions_count, 0), avg_inference_time_ms,
    COALESCE(created_at, NOW()), COALESCE(updated_at, NOW()), promoted_at, deprecated_at
FROM ssh_guardian_v3.ml_models;

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated)
SELECT 'ml_models', 'ml_models', 'ml_models', COUNT(*) FROM ssh_guardian_v3.ml_models;

-- 7.2 ML Training Runs
INSERT INTO ml_training_runs (id, run_uuid, model_name, algorithm, status, training_data_start,
    training_data_end, total_samples, training_samples, validation_samples, test_samples,
    hyperparameters, final_metrics, error_message, started_at, completed_at, duration_seconds,
    triggered_by_user_id)
SELECT id, run_uuid, model_name, algorithm, COALESCE(status, 'running'),
    training_data_start, training_data_end, total_samples, training_samples, validation_samples,
    test_samples, hyperparameters, final_metrics, error_message,
    COALESCE(started_at, NOW()), completed_at, duration_seconds, triggered_by_user_id
FROM ssh_guardian_v3.ml_training_runs;

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated)
SELECT 'ml_training_runs', 'ml_training_runs', 'ml_training_runs', COUNT(*) FROM ssh_guardian_v3.ml_training_runs;

-- ============================================================================
-- DOMAIN 8: SIMULATION
-- ============================================================================

-- 8.1 Simulation Templates
INSERT INTO simulation_templates (id, template_name, description, attack_type, parameters,
    is_active, created_by_user_id, created_at, updated_at)
SELECT id, template_name, description, attack_type, parameters,
    COALESCE(is_active, 1), created_by_user_id, COALESCE(created_at, NOW()), COALESCE(updated_at, NOW())
FROM ssh_guardian_v3.simulation_templates;

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated)
SELECT 'simulation_templates', 'simulation_templates', 'simulation_templates', COUNT(*) FROM ssh_guardian_v3.simulation_templates;

-- 8.2 Simulation Runs
INSERT INTO simulation_runs (id, run_uuid, template_id, run_name, status, attack_type, parameters,
    target_agent_id, events_generated, events_blocked, detection_rate, false_positive_rate,
    started_at, completed_at, duration_seconds, results, triggered_by_user_id, created_at)
SELECT id, run_uuid, template_id, run_name, COALESCE(status, 'pending'), attack_type, parameters,
    target_agent_id, COALESCE(events_generated, 0), COALESCE(events_blocked, 0),
    detection_rate, false_positive_rate, started_at, completed_at, duration_seconds,
    results, triggered_by_user_id, COALESCE(created_at, NOW())
FROM ssh_guardian_v3.simulation_runs;

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated)
SELECT 'simulation_runs', 'simulation_runs', 'simulation_runs', COUNT(*) FROM ssh_guardian_v3.simulation_runs;

-- 8.3 Simulation IP Pool
INSERT INTO simulation_ip_pool (id, ip_address, ip_type, country_code, threat_score,
    attack_patterns, times_used, last_used_at, created_at)
SELECT id, ip_address, COALESCE(ip_type, 'malicious'), country_code, threat_score,
    attack_patterns, COALESCE(times_used, 0), last_used_at, COALESCE(created_at, NOW())
FROM ssh_guardian_v3.simulation_ip_pool;

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated)
SELECT 'simulation_ip_pool', 'simulation_ip_pool', 'simulation_ip_pool', COUNT(*) FROM ssh_guardian_v3.simulation_ip_pool;

-- 8.4 Live Simulation Runs
INSERT INTO live_simulation_runs (id, run_uuid, simulation_run_id, agent_id, status,
    events_sent, events_detected, started_at, completed_at, results, created_at)
SELECT id, run_uuid, simulation_run_id, agent_id, COALESCE(status, 'pending'),
    COALESCE(events_sent, 0), COALESCE(events_detected, 0), started_at, completed_at,
    results, COALESCE(created_at, NOW())
FROM ssh_guardian_v3.live_simulation_runs
WHERE agent_id IN (SELECT id FROM agents);

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated)
SELECT 'live_simulation_runs', 'live_simulation_runs', 'live_simulation_runs', COUNT(*) FROM ssh_guardian_v3.live_simulation_runs;

-- ============================================================================
-- DOMAIN 9: SYSTEM CONFIG
-- ============================================================================

-- 9.1 System Settings (consolidate from 3 tables)
-- From system_settings
INSERT INTO system_settings (setting_key, setting_value, value_type, category, description,
    is_sensitive, is_public, created_at, updated_at)
SELECT setting_key, setting_value, COALESCE(setting_type, 'string'),
    COALESCE(category, 'general'), description, COALESCE(is_sensitive, 0), 0,
    COALESCE(created_at, NOW()), COALESCE(updated_at, NOW())
FROM ssh_guardian_v3.system_settings;

-- From system_config (map int/float -> number)
INSERT INTO system_settings (setting_key, setting_value, value_type, category, description,
    is_sensitive, is_public, updated_by_user_id, created_at, updated_at)
SELECT config_key, config_value,
    CASE value_type
        WHEN 'int' THEN 'number'
        WHEN 'float' THEN 'number'
        ELSE COALESCE(value_type, 'string')
    END,
    'system', description, COALESCE(is_encrypted, 0), COALESCE(is_public, 0),
    updated_by_user_id, NOW(), COALESCE(updated_at, NOW())
FROM ssh_guardian_v3.system_config
WHERE config_key NOT IN (SELECT setting_key FROM system_settings);

-- Note: cache_settings is no longer migrated - caching now uses hardcoded values in code

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated, notes)
VALUES ('system_settings', 'system_settings + system_config', 'system_settings',
    (SELECT COUNT(*) FROM system_settings), 'Consolidated from 2 tables (cache_settings removed)');

-- 9.2 Integrations (merge with integration_config)
INSERT INTO integrations (id, integration_type, name, is_enabled, config, credentials,
    last_used_at, last_error, error_count, created_at, updated_at)
SELECT i.id, i.integration_type, i.name, COALESCE(i.is_enabled, 0),
    (SELECT JSON_OBJECTAGG(config_key, config_value)
     FROM ssh_guardian_v3.integration_config
     WHERE integration_id = i.id),
    i.credentials, i.last_used_at, i.last_error, COALESCE(i.error_count, 0),
    COALESCE(i.created_at, NOW()), COALESCE(i.updated_at, NOW())
FROM ssh_guardian_v3.integrations i;

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated, notes)
SELECT 'integrations', 'integrations + integration_config', 'integrations', COUNT(*), 'Merged with config'
FROM ssh_guardian_v3.integrations;

-- 9.3 Notification Rules
INSERT INTO notification_rules (id, rule_name, event_type, conditions, channels, message_template,
    is_enabled, cooldown_minutes, last_triggered_at, times_triggered, created_by_user_id,
    created_at, updated_at)
SELECT id, rule_name, event_type, conditions, channels, message_template,
    COALESCE(is_enabled, 1), COALESCE(cooldown_minutes, 5), last_triggered_at,
    COALESCE(times_triggered, 0), created_by_user_id,
    COALESCE(created_at, NOW()), COALESCE(updated_at, NOW())
FROM ssh_guardian_v3.notification_rules;

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated)
SELECT 'notification_rules', 'notification_rules', 'notification_rules', COUNT(*) FROM ssh_guardian_v3.notification_rules;

-- 9.4 Notifications
INSERT INTO notifications (id, notification_rule_id, channel, recipient, subject, message,
    status, error_message, sent_at, created_at)
SELECT id, notification_rule_id, channel, recipient, subject, message,
    COALESCE(status, 'pending'), error_message, sent_at, COALESCE(created_at, NOW())
FROM ssh_guardian_v3.notifications;

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated)
SELECT 'notifications', 'notifications', 'notifications', COUNT(*) FROM ssh_guardian_v3.notifications;

-- ============================================================================
-- DOMAIN 10: AUDIT & LOGS
-- ============================================================================

-- 10.1 Audit Logs
INSERT INTO audit_logs (id, user_id, action, entity_type, entity_id, old_values, new_values,
    ip_address, user_agent, created_at)
SELECT id, user_id, action, entity_type, entity_id, old_values, new_values,
    ip_address, user_agent, COALESCE(created_at, NOW())
FROM ssh_guardian_v3.audit_logs;

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated)
SELECT 'audit_logs', 'audit_logs', 'audit_logs', COUNT(*) FROM ssh_guardian_v3.audit_logs;

-- 10.2 UFW Audit Log
INSERT INTO ufw_audit_log (id, agent_id, command_id, action, rule_before, rule_after,
    performed_by_user_id, ip_address, success, error_message, created_at)
SELECT id, agent_id, command_id, action, rule_before, rule_after,
    performed_by_user_id, ip_address, COALESCE(success, 1), error_message,
    COALESCE(created_at, NOW())
FROM ssh_guardian_v3.ufw_audit_log
WHERE agent_id IN (SELECT id FROM agents);

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated)
SELECT 'ufw_audit_log', 'ufw_audit_log', 'ufw_audit_log', COUNT(*) FROM ssh_guardian_v3.ufw_audit_log;

-- 10.3 Log Sources
INSERT INTO log_sources (id, source_name, source_type, file_path, pattern_regex, is_enabled,
    created_at, updated_at)
SELECT id, source_name, source_type, file_path, pattern_regex, COALESCE(is_enabled, 1),
    COALESCE(created_at, NOW()), COALESCE(updated_at, NOW())
FROM ssh_guardian_v3.log_sources;

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated)
SELECT 'log_sources', 'log_sources', 'log_sources', COUNT(*) FROM ssh_guardian_v3.log_sources;

-- ============================================================================
-- DOMAIN 11: UI SUPPORT
-- ============================================================================

-- 11.1 Guide Steps
INSERT INTO guide_steps (id, step_key, title, description, step_order, is_required, icon,
    action_url, created_at)
SELECT id, step_key, title, description, step_order, COALESCE(is_required, 0), icon,
    action_url, COALESCE(created_at, NOW())
FROM ssh_guardian_v3.guide_steps;

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated)
SELECT 'guide_steps', 'guide_steps', 'guide_steps', COUNT(*) FROM ssh_guardian_v3.guide_steps;

-- 11.2 UFW Rule Templates
INSERT INTO ufw_rule_templates (id, template_name, description, category, action, direction,
    protocol, port, from_ip, to_ip, is_common, display_order, created_at)
SELECT id, template_name, description, category, action, direction, protocol, port,
    from_ip, to_ip, COALESCE(is_common, 0), COALESCE(display_order, 0),
    COALESCE(created_at, NOW())
FROM ssh_guardian_v3.ufw_rule_templates;

INSERT INTO _migration_log (migration_name, source_table, target_table, records_migrated)
SELECT 'ufw_rule_templates', 'ufw_rule_templates', 'ufw_rule_templates', COUNT(*) FROM ssh_guardian_v3.ufw_rule_templates;

-- ============================================================================
-- RE-ENABLE FOREIGN KEY CHECKS
-- ============================================================================

SET FOREIGN_KEY_CHECKS = 1;

-- ============================================================================
-- MIGRATION COMPLETE
-- ============================================================================
SELECT '=== MIGRATION COMPLETE ===' AS status;
SELECT migration_name, source_table, target_table, records_migrated, notes
FROM _migration_log ORDER BY id;

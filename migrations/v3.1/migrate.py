#!/usr/bin/env python3
"""
SSH Guardian v3.1 - Database Migration API
Migrates data from ssh_guardian_v3 to ssh_guardian_v3_1
"""

import mysql.connector
from mysql.connector import Error
from datetime import datetime
import json
import uuid

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '123123',
    'buffered': True
}

SOURCE_DB = 'ssh_guardian_v3'
TARGET_DB = 'ssh_guardian_v3_1'


class MigrationAPI:
    def __init__(self):
        self.source_conn = None
        self.target_conn = None
        self.results = {}

    def connect(self):
        """Connect to both databases"""
        self.source_conn = mysql.connector.connect(**DB_CONFIG, database=SOURCE_DB)
        self.target_conn = mysql.connector.connect(**DB_CONFIG, database=TARGET_DB)
        print(f"Connected to {SOURCE_DB} and {TARGET_DB}")

    def close(self):
        """Close connections"""
        if self.source_conn:
            self.source_conn.close()
        if self.target_conn:
            self.target_conn.close()

    def get_cursor(self, source=True):
        """Get cursor for source or target database"""
        conn = self.source_conn if source else self.target_conn
        return conn.cursor(dictionary=True)

    def execute_target(self, query, params=None):
        """Execute query on target database"""
        cursor = self.get_cursor(source=False)
        cursor.execute(query, params or ())
        self.target_conn.commit()
        return cursor

    def log(self, msg, level='INFO'):
        """Print log message"""
        symbols = {'INFO': '→', 'OK': '✓', 'ERR': '✗', 'WARN': '⚠'}
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {symbols.get(level, '→')} {msg}")

    def migrate_all(self):
        """Run all migrations"""
        self.connect()

        # Disable FK checks
        self.execute_target("SET FOREIGN_KEY_CHECKS = 0")

        try:
            # Core tables first
            self.migrate_roles()
            self.migrate_users()
            self.migrate_user_sessions()
            self.migrate_user_otps()
            self.migrate_agents()

            # Agent related
            self.migrate_agent_heartbeats()
            self.migrate_agent_log_batches()
            self.migrate_agent_ufw_state()
            self.migrate_agent_ufw_rules()
            self.migrate_agent_ufw_commands()

            # IP related
            self.migrate_ip_geolocation()
            self.migrate_ip_blocks()

            # Events
            self.migrate_auth_events()
            self.migrate_auth_events_ml()
            self.migrate_auth_events_daily()

            # Blocking
            self.migrate_blocking_rules()
            self.migrate_blocking_actions()

            # Fail2ban
            self.migrate_fail2ban_state()
            self.migrate_fail2ban_events()

            # ML
            self.migrate_ml_models()
            self.migrate_ml_training_runs()

            # Simulation
            self.migrate_simulation_templates()
            self.migrate_simulation_runs()
            self.migrate_simulation_ip_pool()
            self.migrate_live_simulation_runs()

            # System
            self.migrate_system_settings()
            self.migrate_integrations()
            self.migrate_notification_rules()
            self.migrate_notifications()

            # Audit/Logs
            self.migrate_audit_logs()
            self.migrate_ufw_audit_log()
            self.migrate_log_sources()

            # UI
            self.migrate_guide_steps()
            self.migrate_ufw_rule_templates()

            # Re-enable FK checks
            self.execute_target("SET FOREIGN_KEY_CHECKS = 1")

            self.print_summary()

        finally:
            self.close()

    def print_summary(self):
        """Print migration summary"""
        print("\n" + "="*50)
        print("MIGRATION SUMMARY")
        print("="*50)
        total = 0
        for table, count in self.results.items():
            print(f"  {table:30} {count:>6}")
            total += count
        print("-"*50)
        print(f"  {'TOTAL':30} {total:>6}")
        print("="*50)

    # =========================================================================
    # MIGRATION METHODS
    # =========================================================================

    def migrate_roles(self):
        """Migrate roles table"""
        self.log("Migrating roles...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM roles")
        count = 0
        for row in src.fetchall():
            try:
                tgt.execute("""
                    INSERT INTO roles (id, name, description, permissions, is_system_role, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row['name'], row.get('description'), row.get('permissions'),
                      0, row.get('created_at') or datetime.now(), row.get('updated_at') or datetime.now()))
                count += 1
            except Error as e:
                if 'Duplicate' not in str(e):
                    self.log(f"Error: {e}", 'ERR')

        self.target_conn.commit()
        self.results['roles'] = count
        self.log(f"Roles: {count}", 'OK')

    def migrate_users(self):
        """Migrate users table"""
        self.log("Migrating users...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM users")
        count = 0
        for row in src.fetchall():
            try:
                email_verified = row.get('created_at') if row.get('is_email_verified') else None
                tgt.execute("""
                    INSERT INTO users (id, email, password_hash, full_name, role_id, is_active,
                        email_verified_at, last_login_at, failed_login_attempts, locked_until, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row['email'], row['password_hash'], row['full_name'], row['role_id'],
                      row.get('is_active', 1), email_verified, row.get('last_login'),
                      row.get('failed_login_attempts', 0), row.get('locked_until'),
                      row.get('created_at') or datetime.now(), row.get('updated_at') or datetime.now()))
                count += 1
            except Error as e:
                if 'Duplicate' not in str(e):
                    self.log(f"Error: {e}", 'ERR')

        self.target_conn.commit()
        self.results['users'] = count
        self.log(f"Users: {count}", 'OK')

    def migrate_user_sessions(self):
        """Migrate user_sessions table"""
        self.log("Migrating user_sessions...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM user_sessions")
        count = 0
        for row in src.fetchall():
            try:
                tgt.execute("""
                    INSERT INTO user_sessions (id, user_id, session_token, ip_address, user_agent,
                        is_active, expires_at, last_activity_at, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row['user_id'], row['session_token'], row.get('ip_address'),
                      row.get('user_agent'), 1, row.get('expires_at'),
                      row.get('last_activity') or datetime.now(), row.get('created_at') or datetime.now()))
                count += 1
            except Error as e:
                if 'Duplicate' not in str(e):
                    self.log(f"Error: {e}", 'ERR')

        self.target_conn.commit()
        self.results['user_sessions'] = count
        self.log(f"User sessions: {count}", 'OK')

    def migrate_user_otps(self):
        """Migrate user_otps table"""
        self.log("Migrating user_otps...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM user_otps")
        count = 0
        for row in src.fetchall():
            try:
                tgt.execute("""
                    INSERT INTO user_otps (id, user_id, otp_code, purpose, is_used, expires_at, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row['user_id'], row['otp_code'], row.get('purpose', 'login'),
                      row.get('is_used', 0), row['expires_at'], row.get('created_at') or datetime.now()))
                count += 1
            except Error as e:
                if 'Duplicate' not in str(e):
                    self.log(f"Error: {e}", 'ERR')

        self.target_conn.commit()
        self.results['user_otps'] = count
        self.log(f"User OTPs: {count}", 'OK')

    def migrate_agents(self):
        """Migrate agents table"""
        self.log("Migrating agents...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM agents")
        count = 0
        for row in src.fetchall():
            try:
                tgt.execute("""
                    INSERT INTO agents (id, agent_uuid, agent_id, api_key, hostname, display_name,
                        agent_type, ip_address, ip_address_internal, mac_address, location, environment,
                        status, health_status, last_heartbeat, heartbeat_interval_sec, version,
                        supported_features, total_events_sent, is_active, is_approved, approved_by_user_id,
                        approved_at, notes, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row['agent_uuid'], row['agent_id'], row['api_key'],
                      row.get('hostname'), row.get('display_name'), row.get('agent_type', 'secondary'),
                      row.get('ip_address_primary'), row.get('ip_address_internal'), row.get('mac_address'),
                      row.get('location'), row.get('environment', 'production'), row.get('status', 'pending'),
                      row.get('health_status', 'unknown'), row.get('last_heartbeat'),
                      row.get('heartbeat_interval_sec', 30), row.get('version'), row.get('supported_features'),
                      row.get('total_events_sent', 0), row.get('is_active', 1), row.get('is_approved', 0),
                      row.get('approved_by_user_id'), row.get('approved_at'), row.get('notes'),
                      row.get('created_at') or datetime.now(), row.get('updated_at') or datetime.now()))
                count += 1
            except Error as e:
                if 'Duplicate' not in str(e):
                    self.log(f"Error: {e}", 'ERR')

        self.target_conn.commit()
        self.results['agents'] = count
        self.log(f"Agents: {count}", 'OK')

    def migrate_agent_heartbeats(self):
        """Migrate agent_heartbeats (all records)"""
        self.log("Migrating agent_heartbeats...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM agent_heartbeats")
        count = 0
        for row in src.fetchall():
            try:
                tgt.execute("""
                    INSERT INTO agent_heartbeats (id, agent_id, heartbeat_timestamp, cpu_usage, memory_usage,
                        disk_usage, load_average, uptime_seconds, network_stats, process_count, agent_version, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row['agent_id'], row['heartbeat_timestamp'],
                      row.get('cpu_percent'), row.get('memory_percent'), row.get('disk_percent'),
                      json.dumps(row.get('load_average')) if row.get('load_average') else None,
                      row.get('uptime_seconds'),
                      json.dumps(row.get('network_stats')) if row.get('network_stats') else None,
                      row.get('process_count'), row.get('agent_version'),
                      json.dumps(row.get('extra_data')) if row.get('extra_data') else None))
                count += 1
            except Error as e:
                pass  # Skip errors silently for bulk data

        self.target_conn.commit()
        self.results['agent_heartbeats'] = count
        self.log(f"Agent heartbeats: {count}", 'OK')

    def migrate_agent_log_batches(self):
        """Migrate agent_log_batches"""
        self.log("Migrating agent_log_batches...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM agent_log_batches")
        count = 0
        for row in src.fetchall():
            try:
                tgt.execute("""
                    INSERT INTO agent_log_batches (id, batch_uuid, agent_id, log_source, events_count,
                        events_processed, events_failed, status, processing_started_at, processing_completed_at,
                        processing_duration_ms, error_message, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row['batch_uuid'], row['agent_id'],
                      row.get('source_filename', 'auth.log'), row.get('batch_size', 0),
                      row.get('events_created', 0), row.get('events_failed', 0),
                      row.get('processing_status', 'received'), row.get('processing_started_at'),
                      row.get('processing_completed_at'), row.get('processing_duration_ms'),
                      row.get('error_message'), row.get('created_at') or datetime.now()))
                count += 1
            except Error as e:
                pass

        self.target_conn.commit()
        self.results['agent_log_batches'] = count
        self.log(f"Agent log batches: {count}", 'OK')

    def migrate_agent_ufw_state(self):
        """Migrate agent_ufw_state"""
        self.log("Migrating agent_ufw_state...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM agent_ufw_state")
        count = 0
        for row in src.fetchall():
            try:
                is_enabled = 1 if row.get('ufw_status') == 'active' else 0
                tgt.execute("""
                    INSERT INTO agent_ufw_state (id, agent_id, is_enabled, ufw_status, default_incoming,
                        default_outgoing, default_routed, logging_level, ipv6_enabled, rules_count,
                        ufw_version, last_sync, raw_status, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row['agent_id'], is_enabled, row.get('ufw_status', 'inactive'),
                      row.get('default_incoming', 'deny'), row.get('default_outgoing', 'allow'),
                      row.get('default_routed', 'disabled'), row.get('logging_level', 'low'),
                      row.get('ipv6_enabled', 1), row.get('rules_count', 0), row.get('ufw_version'),
                      row.get('last_sync'), row.get('raw_status'),
                      row.get('created_at') or datetime.now(), row.get('updated_at') or datetime.now()))
                count += 1
            except Error as e:
                if 'Duplicate' not in str(e):
                    self.log(f"Error: {e}", 'ERR')

        self.target_conn.commit()
        self.results['agent_ufw_state'] = count
        self.log(f"Agent UFW state: {count}", 'OK')

    def migrate_agent_ufw_rules(self):
        """Migrate agent_ufw_rules"""
        self.log("Migrating agent_ufw_rules...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM agent_ufw_rules")
        count = 0
        for row in src.fetchall():
            try:
                tgt.execute("""
                    INSERT INTO agent_ufw_rules (id, agent_id, rule_index, action, direction, protocol,
                        from_ip, from_port, to_ip, to_port, interface, comment, is_v6, raw_rule, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row['agent_id'], row['rule_index'], row['action'],
                      row.get('direction', 'in'), row.get('protocol'), row.get('from_ip', 'Anywhere'),
                      row.get('from_port'), row.get('to_ip', 'Anywhere'), row.get('to_port'),
                      row.get('interface'), row.get('comment'), row.get('ipv6', 0), row.get('raw_rule'),
                      row.get('created_at') or datetime.now(), row.get('updated_at') or datetime.now()))
                count += 1
            except Error as e:
                pass

        self.target_conn.commit()
        self.results['agent_ufw_rules'] = count
        self.log(f"Agent UFW rules: {count}", 'OK')

    def migrate_agent_ufw_commands(self):
        """Migrate agent_ufw_commands"""
        self.log("Migrating agent_ufw_commands...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM agent_ufw_commands")
        count = 0
        for row in src.fetchall():
            try:
                tgt.execute("""
                    INSERT INTO agent_ufw_commands (id, agent_id, command_uuid, command_type, params,
                        ufw_command, status, result_message, created_by, created_at, sent_at, executed_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row['agent_id'], row['command_uuid'], row['command_type'],
                      row.get('params_json'), row.get('ufw_command'), row.get('status', 'pending'),
                      row.get('result_message'), row.get('created_by'),
                      row.get('created_at') or datetime.now(), row.get('sent_at'), row.get('executed_at')))
                count += 1
            except Error as e:
                pass

        self.target_conn.commit()
        self.results['agent_ufw_commands'] = count
        self.log(f"Agent UFW commands: {count}", 'OK')

    def migrate_ip_geolocation(self):
        """Migrate ip_geolocation merged with ip_threat_intelligence"""
        self.log("Migrating ip_geolocation (merged)...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("""
            SELECT g.*, t.abuseipdb_score, t.abuseipdb_reports, t.abuseipdb_last_reported,
                   t.abuseipdb_checked_at, t.virustotal_positives, t.virustotal_total,
                   t.virustotal_checked_at, t.overall_threat_level, t.threat_categories
            FROM ip_geolocation g
            LEFT JOIN ip_threat_intelligence t ON g.ip_address_text = t.ip_address_text
        """)
        count = 0
        for row in src.fetchall():
            try:
                tgt.execute("""
                    INSERT INTO ip_geolocation (id, ip_address, ip_address_text, ip_version, country_code,
                        country_name, region, city, postal_code, latitude, longitude, timezone, asn, asn_org,
                        isp, connection_type, is_proxy, is_vpn, is_tor, is_datacenter, is_hosting,
                        abuseipdb_score, abuseipdb_reports, abuseipdb_last_reported, abuseipdb_checked_at,
                        virustotal_positives, virustotal_total, virustotal_checked_at, threat_level,
                        threat_categories, lookup_count, first_seen, last_seen, cache_expires_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row['ip_address'], row['ip_address_text'], row.get('ip_version', 4),
                      row.get('country_code'), row.get('country_name'), row.get('region'), row.get('city'),
                      row.get('postal_code'), row.get('latitude'), row.get('longitude'), row.get('timezone'),
                      row.get('asn'), row.get('asn_org'), row.get('isp'), row.get('connection_type'),
                      row.get('is_proxy', 0), row.get('is_vpn', 0), row.get('is_tor', 0),
                      row.get('is_datacenter', 0), row.get('is_hosting', 0),
                      row.get('abuseipdb_score'), row.get('abuseipdb_reports'),
                      row.get('abuseipdb_last_reported'), row.get('abuseipdb_checked_at'),
                      row.get('virustotal_positives'), row.get('virustotal_total'),
                      row.get('virustotal_checked_at'), row.get('overall_threat_level', 'unknown'),
                      row.get('threat_categories'), row.get('lookup_count', 1),
                      row.get('first_seen') or datetime.now(), row.get('last_seen') or datetime.now(),
                      row.get('cache_expires_at')))
                count += 1
            except Error as e:
                if 'Duplicate' not in str(e):
                    self.log(f"Error: {e}", 'ERR')

        self.target_conn.commit()
        self.results['ip_geolocation'] = count
        self.log(f"IP geolocation: {count}", 'OK')

    def migrate_ip_blocks(self):
        """Migrate ip_blocks"""
        self.log("Migrating ip_blocks...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        # Map old block_source values to new
        source_map = {'rule_based': 'rule', 'ml_threshold': 'ml', 'api_reputation': 'api', 'anomaly_detection': 'ml'}

        src.execute("SELECT * FROM ip_blocks")
        count = 0
        for row in src.fetchall():
            try:
                block_source = row.get('block_source', 'manual')
                block_source = source_map.get(block_source, block_source)

                tgt.execute("""
                    INSERT INTO ip_blocks (id, ip_address, ip_address_text, ip_range_cidr, block_reason,
                        block_source, blocking_rule_id, trigger_event_id, agent_id, failed_attempts,
                        risk_score, threat_level, is_active, blocked_at, unblock_at, auto_unblock,
                        unblocked_at, unblocked_by_user_id, unblock_reason, is_simulation, simulation_run_id,
                        metadata, created_by_user_id, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row['ip_address'], row['ip_address_text'], row.get('ip_range_cidr'),
                      row['block_reason'], block_source, row.get('blocking_rule_id'),
                      row.get('trigger_event_id'), row.get('agent_id'), row.get('failed_attempts', 0),
                      row.get('risk_score'), row.get('threat_level'), row.get('is_active', 1),
                      row.get('blocked_at') or datetime.now(), row.get('unblock_at'),
                      row.get('auto_unblock', 1), row.get('manually_unblocked_at'),
                      row.get('unblocked_by_user_id'), row.get('unblock_reason'),
                      row.get('is_simulation', 0), row.get('simulation_run_id'),
                      row.get('block_metadata'), row.get('created_by_user_id'),
                      row.get('created_at') or datetime.now(), row.get('updated_at') or datetime.now()))
                count += 1
            except Error as e:
                pass

        self.target_conn.commit()
        self.results['ip_blocks'] = count
        self.log(f"IP blocks: {count}", 'OK')

    def migrate_auth_events(self):
        """Migrate auth_events"""
        self.log("Migrating auth_events...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM auth_events")
        count = 0
        for row in src.fetchall():
            try:
                source_type = row.get('source_type', 'agent')
                if source_type == 'synthetic':
                    source_type = 'simulation'

                tgt.execute("""
                    INSERT INTO auth_events (id, event_uuid, timestamp, source_type, agent_id,
                        simulation_run_id, event_type, auth_method, source_ip, source_ip_text, source_port,
                        target_server, target_port, target_username, failure_reason, geo_id, block_id,
                        raw_log_line, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row['event_uuid'], row['timestamp'], source_type,
                      row.get('agent_id'), row.get('simulation_run_id'),
                      row.get('event_type', 'failed'), row.get('auth_method'),
                      row.get('source_ip'), row.get('source_ip_text'), row.get('source_port'),
                      row.get('target_server'), row.get('target_port', 22), row.get('target_username'),
                      row.get('failure_reason'), row.get('geo_id'), row.get('block_id'),
                      row.get('raw_log_line'), row.get('created_at') or datetime.now()))
                count += 1
            except Error as e:
                pass

        self.target_conn.commit()
        self.results['auth_events'] = count
        self.log(f"Auth events: {count}", 'OK')

    def migrate_auth_events_ml(self):
        """Migrate ml_predictions to auth_events_ml"""
        self.log("Migrating auth_events_ml (from ml_predictions)...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM ml_predictions")
        count = 0
        for row in src.fetchall():
            try:
                tgt.execute("""
                    INSERT INTO auth_events_ml (event_id, model_id, risk_score, threat_type, confidence,
                        is_anomaly, features_snapshot, inference_time_ms, manual_feedback, feedback_at,
                        feedback_by_user_id, feedback_notes, was_blocked, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['event_id'], row.get('model_id'), row.get('risk_score', 0),
                      row.get('threat_type'), row.get('confidence', 0), row.get('is_anomaly', 0),
                      row.get('features_snapshot'), row.get('inference_time_ms'),
                      row.get('manual_feedback'), row.get('feedback_at'),
                      row.get('feedback_by_user_id'), row.get('feedback_notes'),
                      row.get('was_blocked', 0), row.get('created_at') or datetime.now()))
                count += 1
            except Error as e:
                pass

        self.target_conn.commit()
        self.results['auth_events_ml'] = count
        self.log(f"Auth events ML: {count}", 'OK')

    def migrate_auth_events_daily(self):
        """Migrate auth_events_daily_summary to auth_events_daily"""
        self.log("Migrating auth_events_daily...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM auth_events_daily_summary")
        count = 0
        for row in src.fetchall():
            try:
                tgt.execute("""
                    INSERT INTO auth_events_daily (summary_date, total_events, failed_events,
                        successful_events, invalid_user_events, unique_ips, unique_usernames,
                        created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['summary_date'], row.get('total_events', 0), row.get('failed_count', 0),
                      row.get('successful_count', 0), row.get('invalid_count', 0),
                      row.get('unique_ips', 0), row.get('unique_usernames', 0),
                      row.get('created_at') or datetime.now(), row.get('updated_at') or datetime.now()))
                count += 1
            except Error as e:
                pass

        self.target_conn.commit()
        self.results['auth_events_daily'] = count
        self.log(f"Auth events daily: {count}", 'OK')

    def migrate_blocking_rules(self):
        """Migrate blocking_rules"""
        self.log("Migrating blocking_rules...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM blocking_rules")
        count = 0
        for row in src.fetchall():
            try:
                tgt.execute("""
                    INSERT INTO blocking_rules (id, rule_name, rule_type, is_enabled, is_system_rule,
                        priority, conditions, block_duration_minutes, auto_unblock, notify_on_trigger,
                        notification_channels, times_triggered, last_triggered_at, ips_blocked_total,
                        description, created_by_user_id, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row['rule_name'], row['rule_type'], row.get('is_enabled', 1),
                      row.get('is_system_rule', 0), row.get('priority', 50), row.get('conditions'),
                      row.get('block_duration_minutes', 1440), row.get('auto_unblock', 1),
                      row.get('notify_on_trigger', 1), row.get('notification_channels'),
                      row.get('times_triggered', 0), row.get('last_triggered_at'),
                      row.get('ips_blocked_total', 0), row.get('description'),
                      row.get('created_by_user_id'),
                      row.get('created_at') or datetime.now(), row.get('updated_at') or datetime.now()))
                count += 1
            except Error as e:
                if 'Duplicate' not in str(e):
                    self.log(f"Error: {e}", 'ERR')

        self.target_conn.commit()
        self.results['blocking_rules'] = count
        self.log(f"Blocking rules: {count}", 'OK')

    def migrate_blocking_actions(self):
        """Migrate blocking_actions"""
        self.log("Migrating blocking_actions...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM blocking_actions")
        count = 0
        for row in src.fetchall():
            try:
                tgt.execute("""
                    INSERT INTO blocking_actions (id, action_uuid, ip_block_id, ip_address_text,
                        action_type, action_source, reason, performed_by_user_id, triggered_by_rule_id,
                        triggered_by_event_id, metadata, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row['action_uuid'], row.get('ip_block_id'), row['ip_address_text'],
                      row['action_type'], row.get('action_source', 'system'), row.get('reason'),
                      row.get('performed_by_user_id'), row.get('triggered_by_rule_id'),
                      row.get('triggered_by_event_id'), row.get('action_metadata'),
                      row.get('created_at') or datetime.now()))
                count += 1
            except Error as e:
                pass

        self.target_conn.commit()
        self.results['blocking_actions'] = count
        self.log(f"Blocking actions: {count}", 'OK')

    def migrate_fail2ban_state(self):
        """Migrate agent_fail2ban_state to fail2ban_state"""
        self.log("Migrating fail2ban_state...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM agent_fail2ban_state")
        count = 0
        for row in src.fetchall():
            try:
                tgt.execute("""
                    INSERT INTO fail2ban_state (id, agent_id, ip_address, jail_name, banned_at,
                        bantime_seconds, failures, last_sync)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row['agent_id'], row['ip_address'], row.get('jail_name', 'sshd'),
                      row.get('banned_at'), row.get('bantime_seconds', 0), row.get('failures', 0),
                      row.get('last_sync') or datetime.now()))
                count += 1
            except Error as e:
                pass

        self.target_conn.commit()
        self.results['fail2ban_state'] = count
        self.log(f"Fail2ban state: {count}", 'OK')

    def migrate_fail2ban_events(self):
        """Migrate fail2ban_events"""
        self.log("Migrating fail2ban_events...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM fail2ban_events")
        count = 0
        for row in src.fetchall():
            try:
                tgt.execute("""
                    INSERT INTO fail2ban_events (id, agent_id, event_type, ip_address, jail_name,
                        failures, bantime_seconds, timestamp, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row['agent_id'], row.get('action', 'ban'), row['ip_address'],
                      row.get('jail_name', 'sshd'), row.get('failures', 0),
                      row.get('bantime_seconds', 0), row.get('reported_at'),
                      row.get('created_at') or datetime.now()))
                count += 1
            except Error as e:
                pass

        self.target_conn.commit()
        self.results['fail2ban_events'] = count
        self.log(f"Fail2ban events: {count}", 'OK')

    def migrate_ml_models(self):
        """Migrate ml_models"""
        self.log("Migrating ml_models...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM ml_models")
        count = 0
        for row in src.fetchall():
            try:
                tgt.execute("""
                    INSERT INTO ml_models (id, model_uuid, model_name, algorithm, version, status,
                        is_active, model_path, model_size_bytes, hyperparameters, feature_config,
                        training_run_id, accuracy, precision_score, recall_score, f1_score, auc_roc,
                        predictions_count, avg_inference_time_ms, created_at, updated_at, promoted_at, deprecated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row['model_uuid'], row['model_name'], row['algorithm'], row['version'],
                      row.get('status', 'training'), row.get('is_active', 0), row.get('model_path'),
                      row.get('model_size_bytes'), row.get('hyperparameters'), row.get('feature_config'),
                      row.get('training_run_id'), row.get('accuracy'), row.get('precision_score'),
                      row.get('recall'), row.get('f1_score'), row.get('auc_roc'),
                      row.get('predictions_count', 0), row.get('avg_inference_time_ms'),
                      row.get('created_at') or datetime.now(), row.get('updated_at') or datetime.now(),
                      row.get('promoted_at'), row.get('deprecated_at')))
                count += 1
            except Error as e:
                if 'Duplicate' not in str(e):
                    self.log(f"Error: {e}", 'ERR')

        self.target_conn.commit()
        self.results['ml_models'] = count
        self.log(f"ML models: {count}", 'OK')

    def migrate_ml_training_runs(self):
        """Migrate ml_training_runs"""
        self.log("Migrating ml_training_runs...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM ml_training_runs")
        count = 0
        for row in src.fetchall():
            try:
                tgt.execute("""
                    INSERT INTO ml_training_runs (id, run_uuid, model_name, algorithm, status,
                        training_data_start, training_data_end, total_samples, training_samples,
                        validation_samples, test_samples, hyperparameters, final_metrics, error_message,
                        started_at, completed_at, duration_seconds, triggered_by_user_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row['run_uuid'], row.get('model_name'), row.get('algorithm'),
                      row.get('status', 'running'), row.get('training_data_start'),
                      row.get('training_data_end'), row.get('total_samples'), row.get('training_samples'),
                      row.get('validation_samples'), row.get('test_samples'), row.get('hyperparameters'),
                      row.get('final_metrics'), row.get('error_message'),
                      row.get('started_at') or datetime.now(), row.get('completed_at'),
                      row.get('duration_seconds'), row.get('triggered_by_user_id')))
                count += 1
            except Error as e:
                pass

        self.target_conn.commit()
        self.results['ml_training_runs'] = count
        self.log(f"ML training runs: {count}", 'OK')

    def migrate_simulation_templates(self):
        """Migrate simulation_templates"""
        self.log("Migrating simulation_templates...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM simulation_templates")
        count = 0
        for row in src.fetchall():
            try:
                tgt.execute("""
                    INSERT INTO simulation_templates (id, template_name, description, attack_type,
                        parameters, is_active, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row['template_name'], row.get('description'),
                      row.get('template_type', 'brute_force'), row.get('default_config'),
                      row.get('is_visible', 1),
                      row.get('created_at') or datetime.now(), row.get('updated_at') or datetime.now()))
                count += 1
            except Error as e:
                if 'Duplicate' not in str(e):
                    self.log(f"Error: {e}", 'ERR')

        self.target_conn.commit()
        self.results['simulation_templates'] = count
        self.log(f"Simulation templates: {count}", 'OK')

    def migrate_simulation_runs(self):
        """Migrate simulation_runs"""
        self.log("Migrating simulation_runs...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM simulation_runs")
        count = 0
        for row in src.fetchall():
            try:
                tgt.execute("""
                    INSERT INTO simulation_runs (id, run_uuid, template_id, run_name, status, attack_type,
                        parameters, target_agent_id, events_generated, events_blocked, detection_rate,
                        false_positive_rate, started_at, completed_at, duration_seconds, results,
                        triggered_by_user_id, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row['run_uuid'], row.get('template_id'), row.get('run_name'),
                      row.get('status', 'pending'), row.get('attack_type'), row.get('parameters'),
                      row.get('target_agent_id'), row.get('events_generated', 0),
                      row.get('events_blocked', 0), row.get('detection_rate'),
                      row.get('false_positive_rate'), row.get('started_at'), row.get('completed_at'),
                      row.get('duration_seconds'), row.get('results'), row.get('triggered_by_user_id'),
                      row.get('created_at') or datetime.now()))
                count += 1
            except Error as e:
                pass

        self.target_conn.commit()
        self.results['simulation_runs'] = count
        self.log(f"Simulation runs: {count}", 'OK')

    def migrate_simulation_ip_pool(self):
        """Migrate simulation_ip_pool"""
        self.log("Migrating simulation_ip_pool...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM simulation_ip_pool")
        count = 0
        for row in src.fetchall():
            try:
                tgt.execute("""
                    INSERT INTO simulation_ip_pool (id, ip_address, ip_type, country_code, threat_score,
                        attack_patterns, times_used, last_used_at, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row['ip_address'], row.get('ip_type', 'malicious'),
                      row.get('country_code'), row.get('threat_score'), row.get('attack_patterns'),
                      row.get('times_used', 0), row.get('last_used_at'),
                      row.get('created_at') or datetime.now()))
                count += 1
            except Error as e:
                pass

        self.target_conn.commit()
        self.results['simulation_ip_pool'] = count
        self.log(f"Simulation IP pool: {count}", 'OK')

    def migrate_live_simulation_runs(self):
        """Migrate live_simulation_runs"""
        self.log("Migrating live_simulation_runs...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM live_simulation_runs")
        count = 0
        for row in src.fetchall():
            try:
                tgt.execute("""
                    INSERT INTO live_simulation_runs (id, run_uuid, agent_id, status, events_sent,
                        events_detected, started_at, completed_at, results, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], str(uuid.uuid4()), row.get('target_id'), row.get('status', 'pending'),
                      row.get('event_count', 0), row.get('events_detected', 0),
                      row.get('injected_at'), row.get('completed_at'), row.get('result_json'),
                      row.get('created_at') or datetime.now()))
                count += 1
            except Error as e:
                pass

        self.target_conn.commit()
        self.results['live_simulation_runs'] = count
        self.log(f"Live simulation runs: {count}", 'OK')

    def migrate_system_settings(self):
        """Migrate system_settings + system_config (cache_settings removed)"""
        self.log("Migrating system_settings (consolidated)...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)
        count = 0

        # From system_settings
        src.execute("SELECT * FROM system_settings")
        for row in src.fetchall():
            try:
                tgt.execute("""
                    INSERT INTO system_settings (setting_key, setting_value, value_type, category,
                        description, is_sensitive, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['setting_key'], row.get('setting_value'), row.get('setting_type', 'string'),
                      row.get('category', 'general'), row.get('description'), row.get('is_sensitive', 0),
                      row.get('created_at') or datetime.now(), row.get('updated_at') or datetime.now()))
                count += 1
            except Error as e:
                pass

        # From system_config
        type_map = {'int': 'number', 'float': 'number'}
        src.execute("SELECT * FROM system_config")
        for row in src.fetchall():
            try:
                value_type = row.get('value_type', 'string')
                value_type = type_map.get(value_type, value_type)
                tgt.execute("""
                    INSERT INTO system_settings (setting_key, setting_value, value_type, category,
                        description, is_sensitive, is_public, updated_by_user_id, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['config_key'], row.get('config_value'), value_type, 'system',
                      row.get('description'), row.get('is_encrypted', 0), row.get('is_public', 0),
                      row.get('updated_by_user_id'), datetime.now(),
                      row.get('updated_at') or datetime.now()))
                count += 1
            except Error as e:
                pass

        # Note: cache_settings is no longer migrated - caching now uses hardcoded values in code

        self.target_conn.commit()
        self.results['system_settings'] = count
        self.log(f"System settings: {count}", 'OK')

    def migrate_integrations(self):
        """Migrate integrations + integration_config"""
        self.log("Migrating integrations (with config)...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM integrations")
        count = 0
        for row in src.fetchall():
            try:
                # Get config for this integration
                src2 = self.get_cursor(source=True)
                src2.execute("""
                    SELECT config_key, config_value, is_sensitive
                    FROM integration_config WHERE integration_id = %s
                """, (row['integration_id'],))
                config_rows = src2.fetchall()

                # Build config and credentials
                config = {}
                credentials = {}
                for cfg in config_rows:
                    if cfg.get('is_sensitive'):
                        credentials[cfg['config_key']] = cfg['config_value']
                    else:
                        config[cfg['config_key']] = cfg['config_value']

                tgt.execute("""
                    INSERT INTO integrations (id, integration_type, name, is_enabled, config, credentials,
                        last_used_at, last_error, error_count, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row['integration_id'], row['name'], row.get('is_enabled', 0),
                      json.dumps(config) if config else None,
                      json.dumps(credentials) if credentials else None,
                      row.get('last_test_at'), row.get('error_message'), 0,
                      row.get('created_at') or datetime.now(), row.get('updated_at') or datetime.now()))
                count += 1
            except Error as e:
                if 'Duplicate' not in str(e):
                    self.log(f"Error: {e}", 'ERR')

        self.target_conn.commit()
        self.results['integrations'] = count
        self.log(f"Integrations: {count}", 'OK')

    def migrate_notification_rules(self):
        """Migrate notification_rules"""
        self.log("Migrating notification_rules...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM notification_rules")
        count = 0
        for row in src.fetchall():
            try:
                # Map old columns to new:
                # trigger_on -> event_type
                # rate_limit_minutes -> cooldown_minutes
                tgt.execute("""
                    INSERT INTO notification_rules (id, rule_name, event_type, conditions, channels,
                        message_template, is_enabled, cooldown_minutes, last_triggered_at, times_triggered,
                        created_by_user_id, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row['rule_name'], row['trigger_on'], row.get('conditions'),
                      row.get('channels'), row.get('message_template'), row.get('is_enabled', 1),
                      row.get('rate_limit_minutes', 5), row.get('last_triggered_at'),
                      row.get('times_triggered', 0), row.get('created_by_user_id'),
                      row.get('created_at') or datetime.now(), row.get('updated_at') or datetime.now()))
                count += 1
            except Error as e:
                if 'Duplicate' not in str(e):
                    self.log(f"notification_rules error: {e}", 'ERR')

        self.target_conn.commit()
        self.results['notification_rules'] = count
        self.log(f"Notification rules: {count}", 'OK')

    def migrate_notifications(self):
        """Migrate notifications"""
        self.log("Migrating notifications...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM notifications")
        count = 0
        for row in src.fetchall():
            try:
                # Map old columns to new:
                # channels (JSON) -> channel (first channel from array)
                # message_title -> subject
                # message_body -> message
                # failed_reason -> error_message
                channels = row.get('channels')
                if isinstance(channels, str):
                    try:
                        channels = json.loads(channels)
                    except:
                        channels = []
                channel = channels[0] if channels else 'system'

                tgt.execute("""
                    INSERT INTO notifications (id, notification_rule_id, channel, recipient, subject,
                        message, status, error_message, sent_at, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row.get('notification_rule_id'), channel, row.get('ip_address'),
                      row.get('message_title'), row.get('message_body'), row.get('status', 'pending'),
                      row.get('failed_reason'), row.get('sent_at'),
                      row.get('created_at') or datetime.now()))
                count += 1
            except Error as e:
                if 'Duplicate' not in str(e):
                    self.log(f"notifications error: {e}", 'ERR')

        self.target_conn.commit()
        self.results['notifications'] = count
        self.log(f"Notifications: {count}", 'OK')

    def migrate_audit_logs(self):
        """Migrate audit_logs"""
        self.log("Migrating audit_logs...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM audit_logs")
        count = 0
        for row in src.fetchall():
            try:
                # Map old columns to new:
                # resource_type -> entity_type
                # resource_id -> entity_id
                # details -> new_values (old_values is null since not tracked before)
                tgt.execute("""
                    INSERT INTO audit_logs (id, user_id, action, entity_type, entity_id, old_values,
                        new_values, ip_address, user_agent, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row.get('user_id'), row['action'], row.get('resource_type'),
                      row.get('resource_id'), None, row.get('details'),
                      row.get('ip_address'), row.get('user_agent'),
                      row.get('created_at') or datetime.now()))
                count += 1
            except Error as e:
                if 'Duplicate' not in str(e):
                    self.log(f"audit_logs error: {e}", 'ERR')

        self.target_conn.commit()
        self.results['audit_logs'] = count
        self.log(f"Audit logs: {count}", 'OK')

    def migrate_ufw_audit_log(self):
        """Migrate firewall_audit_log -> ufw_audit_log"""
        self.log("Migrating ufw_audit_log (from firewall_audit_log)...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        # Old table is firewall_audit_log
        src.execute("SELECT * FROM firewall_audit_log")
        count = 0
        for row in src.fetchall():
            try:
                # Map old columns to new:
                # command_type -> action
                # params_json -> rule_before (store original params)
                # ufw_command -> rule_after (store actual command)
                # performed_by -> performed_by_user_id
                # performed_at -> created_at
                success = 1 if row.get('status') in ('completed', 'success') else 0

                tgt.execute("""
                    INSERT INTO ufw_audit_log (id, agent_id, command_id, action, rule_before, rule_after,
                        performed_by_user_id, ip_address, success, error_message, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row['agent_id'], None, row.get('command_type'),
                      row.get('params_json'), row.get('ufw_command'), row.get('performed_by'),
                      None, success, row.get('result_message'),
                      row.get('performed_at') or datetime.now()))
                count += 1
            except Error as e:
                if 'Duplicate' not in str(e):
                    self.log(f"ufw_audit_log error: {e}", 'ERR')

        self.target_conn.commit()
        self.results['ufw_audit_log'] = count
        self.log(f"UFW audit log: {count}", 'OK')

    def migrate_log_sources(self):
        """Migrate log_sources"""
        self.log("Migrating log_sources...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM log_sources")
        count = 0
        for row in src.fetchall():
            try:
                # Map old columns to new:
                # source_description -> not mapped (removed)
                # config -> pattern_regex (extract if present)
                # is_active -> is_enabled
                config = row.get('config')
                pattern = None
                file_path = None
                if config:
                    if isinstance(config, str):
                        try:
                            config = json.loads(config)
                        except:
                            config = {}
                    pattern = config.get('pattern_regex')
                    file_path = config.get('file_path')

                tgt.execute("""
                    INSERT INTO log_sources (id, source_name, source_type, file_path, pattern_regex,
                        is_enabled, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row['source_name'], row['source_type'], file_path,
                      pattern, row.get('is_active', 1),
                      row.get('created_at') or datetime.now(), row.get('updated_at') or datetime.now()))
                count += 1
            except Error as e:
                if 'Duplicate' not in str(e):
                    self.log(f"log_sources error: {e}", 'ERR')

        self.target_conn.commit()
        self.results['log_sources'] = count
        self.log(f"Log sources: {count}", 'OK')

    def migrate_guide_steps(self):
        """Migrate guide_steps"""
        self.log("Migrating guide_steps...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM guide_steps")
        count = 0
        for row in src.fetchall():
            try:
                # Map old columns to new:
                # step_number -> step_order
                # subtitle -> description
                # content_html -> not mapped (too large, can be re-added manually)
                # display_order -> step_order (backup)
                # is_active -> is_required (inverse meaning but similar purpose)
                step_order = row.get('step_number') or row.get('display_order', 0)

                tgt.execute("""
                    INSERT INTO guide_steps (id, step_key, title, description, step_order, is_required,
                        icon, action_url, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row['step_key'], row['title'], row.get('subtitle'),
                      step_order, row.get('is_active', 0), row.get('icon'),
                      row.get('image_url'), row.get('created_at') or datetime.now()))
                count += 1
            except Error as e:
                if 'Duplicate' not in str(e):
                    self.log(f"guide_steps error: {e}", 'ERR')

        self.target_conn.commit()
        self.results['guide_steps'] = count
        self.log(f"Guide steps: {count}", 'OK')

    def migrate_ufw_rule_templates(self):
        """Migrate ufw_rule_templates"""
        self.log("Migrating ufw_rule_templates...")
        src = self.get_cursor(source=True)
        tgt = self.get_cursor(source=False)

        src.execute("SELECT * FROM ufw_rule_templates")
        count = 0
        for row in src.fetchall():
            try:
                # Map old columns to new:
                # name -> template_name
                # ufw_command -> extract action, protocol, port from params_schema
                # is_system -> is_common
                params = row.get('params_schema')
                action = 'allow'
                direction = 'in'
                protocol = None
                port = None
                from_ip = None
                to_ip = None

                if params:
                    if isinstance(params, str):
                        try:
                            params = json.loads(params)
                        except:
                            params = {}
                    action = params.get('action', 'allow')
                    direction = params.get('direction', 'in')
                    protocol = params.get('protocol')
                    port = params.get('port')
                    from_ip = params.get('from_ip')
                    to_ip = params.get('to_ip')

                tgt.execute("""
                    INSERT INTO ufw_rule_templates (id, template_name, description, category, action,
                        direction, protocol, port, from_ip, to_ip, is_common, display_order, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (row['id'], row['name'], row.get('description'), row.get('category'),
                      action, direction, protocol, port,
                      from_ip, to_ip, row.get('is_system', 0),
                      0, row.get('created_at') or datetime.now()))
                count += 1
            except Error as e:
                if 'Duplicate' not in str(e):
                    self.log(f"ufw_rule_templates error: {e}", 'ERR')

        self.target_conn.commit()
        self.results['ufw_rule_templates'] = count
        self.log(f"UFW rule templates: {count}", 'OK')


if __name__ == '__main__':
    print("="*50)
    print("SSH Guardian Database Migration")
    print("From: ssh_guardian_v3 -> ssh_guardian_v3_1")
    print("="*50)
    print()

    api = MigrationAPI()
    api.migrate_all()

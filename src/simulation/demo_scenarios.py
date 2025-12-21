"""
SSH Guardian v3.0 - Demo Scenarios
Simplified attack simulations organized by blocking mechanism

CATEGORIES:
1. UFW BLOCKING - Triggers SSH Guardian rules → adds UFW deny rules
2. FAIL2BAN BLOCKING - Generates auth.log entries → fail2ban detects & bans

Each scenario clearly shows:
- What triggers the block
- Expected outcome
- Block duration
"""

import sys
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
import random

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src"))


# =============================================================================
# CATEGORY 1: UFW AUTO-BLOCK SCENARIOS
# These trigger SSH Guardian blocking rules → UFW deny commands sent to agent
# =============================================================================

UFW_BLOCKING_SCENARIOS = {
    # -------------------------------------------------------------------------
    # REPUTATION-BASED BLOCKING (AbuseIPDB Score)
    # -------------------------------------------------------------------------
    "bad_reputation_critical": {
        "id": "bad_reputation_critical",
        "name": "Bad Reputation (Critical)",
        "category": "ufw_block",
        "description": "IP with very bad reputation (AbuseIPDB 90+). Blocked immediately, even on successful login.",
        "trigger": "AbuseIPDB score >= 90",
        "block_duration": "7 days",
        "rule_name": "abuseipdb_critical_90",
        "severity": "critical",
        "ip": "185.220.101.1",
        "alternate_ips": ["185.220.101.2", "185.220.101.54"],
        "why_blocked": "This IP has been reported by many users as malicious. Score 90+ means confirmed bad actor.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"
    },

    "bad_reputation_high": {
        "id": "bad_reputation_high",
        "name": "Bad Reputation (High)",
        "category": "ufw_block",
        "description": "IP with bad reputation (AbuseIPDB 70+). Blocked on any failed login.",
        "trigger": "AbuseIPDB score >= 70 + failed login",
        "block_duration": "24 hours",
        "rule_name": "abuseipdb_high_70",
        "severity": "high",
        "ip": "45.142.212.61",
        "alternate_ips": ["193.56.28.103"],
        "why_blocked": "Known attacker IP. High abuse reports from the security community.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Failed password for admin from {ip} port {port} ssh2"
    },

    # -------------------------------------------------------------------------
    # BEHAVIOR-BASED BLOCKING (Attack Patterns)
    # -------------------------------------------------------------------------
    "brute_force_attack": {
        "id": "brute_force_attack",
        "name": "Brute Force Attack",
        "category": "ufw_block",
        "description": "5 failed login attempts in 10 minutes from same IP.",
        "trigger": "5 failed logins in 10 minutes",
        "block_duration": "24 hours",
        "rule_name": "brute_force_5_in_10min",
        "severity": "high",
        "ip": "91.240.118.172",
        "alternate_ips": ["45.142.212.61"],
        "why_blocked": "Too many failed attempts. This is password guessing - a common attack method.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Failed password for root from {ip} port {port} ssh2",
        "event_count": 5
    },

    "credential_stuffing": {
        "id": "credential_stuffing",
        "name": "Credential Stuffing",
        "category": "ufw_block",
        "description": "Trying 5+ different usernames in 15 minutes.",
        "trigger": "5 different usernames in 15 minutes",
        "block_duration": "48 hours",
        "rule_name": "cred_stuff_5_users_15min",
        "severity": "high",
        "ip": "45.227.254.0",
        "alternate_ips": ["193.56.28.103"],
        "why_blocked": "Testing stolen credentials from data breaches. Different from brute force.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Failed password for {username} from {ip} port {port} ssh2",
        "usernames": ["admin", "root", "user", "postgres", "mysql", "oracle", "test"]
    },

    "rapid_attack": {
        "id": "rapid_attack",
        "name": "Rapid Attack (DDoS-like)",
        "category": "ufw_block",
        "description": "20+ connection attempts in 1 minute. Could be automated attack.",
        "trigger": "20+ events per minute",
        "block_duration": "7 days",
        "rule_name": "ddos_20_per_min",
        "severity": "critical",
        "ip": "185.156.73.0",
        "alternate_ips": ["91.240.118.172"],
        "why_blocked": "Attack velocity too high. Either automated tool or botnet.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Failed password for root from {ip} port {port} ssh2",
        "event_count": 20
    },

    # -------------------------------------------------------------------------
    # ANONYMIZATION NETWORK BLOCKING (Tor/VPN/Proxy)
    # -------------------------------------------------------------------------
    "tor_exit_node": {
        "id": "tor_exit_node",
        "name": "Tor Exit Node Attack",
        "category": "ufw_block",
        "description": "Attack from Tor network. Attacker hiding their identity.",
        "trigger": "Tor exit node + failed login",
        "block_duration": "24 hours",
        "rule_name": "tor_failed_login",
        "severity": "high",
        "ip": "185.220.101.1",
        "alternate_ips": ["185.220.101.2", "185.220.102.1"],
        "why_blocked": "Tor is used for anonymity. Legitimate users rarely SSH via Tor.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"
    },

    "vpn_proxy_attack": {
        "id": "vpn_proxy_attack",
        "name": "VPN/Proxy Attack",
        "category": "ufw_block",
        "description": "Attack via VPN/Proxy with moderate bad reputation.",
        "trigger": "VPN/Proxy + AbuseIPDB score >= 30",
        "block_duration": "12 hours",
        "rule_name": "vpn_proxy_score_30",
        "severity": "medium",
        "ip": "103.216.221.19",
        "alternate_ips": ["45.142.212.61"],
        "why_blocked": "Commercial VPN/proxy with suspicious activity. Could be attacker hiding location.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Failed password for admin from {ip} port {port} ssh2"
    },

    # -------------------------------------------------------------------------
    # GEOGRAPHIC BLOCKING (High-Risk Countries)
    # -------------------------------------------------------------------------
    "high_risk_country": {
        "id": "high_risk_country",
        "name": "High-Risk Country Attack",
        "category": "ufw_block",
        "description": "Attack from country known for cyber attacks (CN, RU, KP, IR, BY).",
        "trigger": "High-risk country + 2 failed logins",
        "block_duration": "24 hours",
        "rule_name": "high_risk_country_2_fails",
        "severity": "high",
        "ip": "218.92.0.107",
        "alternate_ips": ["39.96.0.0"],
        "why_blocked": "Most attacks originate from these countries. 2 fails triggers block.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Failed password for root from {ip} port {port} ssh2",
        "event_count": 1
    },

    # -------------------------------------------------------------------------
    # MALWARE/THREAT INTEL BLOCKING
    # -------------------------------------------------------------------------
    "malware_source": {
        "id": "malware_source",
        "name": "Known Malware Source",
        "category": "ufw_block",
        "description": "IP flagged by 5+ antivirus vendors on VirusTotal.",
        "trigger": "VirusTotal: 5+ vendor detections",
        "block_duration": "24 hours",
        "rule_name": "combo_vt_5_positives",
        "severity": "critical",
        "ip": "193.56.28.103",
        "alternate_ips": ["45.142.212.61", "185.156.73.0"],
        "why_blocked": "Multiple security companies flagged this IP for malware distribution.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Failed password for oracle from {ip} port {port} ssh2"
    },
}


# =============================================================================
# CATEGORY 2: FAIL2BAN SCENARIOS
# These generate auth.log entries that fail2ban will detect and ban
# Fail2ban watches auth.log directly - no SSH Guardian rules involved
# =============================================================================

FAIL2BAN_SCENARIOS = {
    "f2b_brute_force": {
        "id": "f2b_brute_force",
        "name": "Fail2ban: Brute Force",
        "category": "fail2ban",
        "description": "5 failed SSH attempts. Fail2ban watches auth.log and bans automatically.",
        "trigger": "5 failed SSH logins (fail2ban maxretry)",
        "block_duration": "10 minutes (fail2ban default)",
        "mechanism": "fail2ban",
        "severity": "high",
        "ip": "10.99.99.1",
        "why_blocked": "Fail2ban detects repeated failures in auth.log. No ML or API needed.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Failed password for root from {ip} port {port} ssh2",
        "event_count": 5
    },

    "f2b_invalid_user": {
        "id": "f2b_invalid_user",
        "name": "Fail2ban: Invalid Users",
        "category": "fail2ban",
        "description": "Attempting to login with usernames that don't exist.",
        "trigger": "5 invalid user attempts (fail2ban)",
        "block_duration": "10 minutes (fail2ban default)",
        "mechanism": "fail2ban",
        "severity": "medium",
        "ip": "10.99.99.2",
        "why_blocked": "Trying non-existent usernames like 'test', 'guest', 'ftpuser'.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Failed password for invalid user {username} from {ip} port {port} ssh2",
        "usernames": ["test", "guest", "ftpuser", "backup", "scan"],
        "event_count": 5
    },
}


# =============================================================================
# BASELINE/COMPARISON SCENARIOS
# =============================================================================

BASELINE_SCENARIOS = {
    "clean_ip": {
        "id": "clean_ip",
        "name": "Clean IP (No Block)",
        "category": "baseline",
        "description": "Clean IP with zero threat reputation. Tests that system does NOT create false positives.",
        "trigger": "None - clean successful login",
        "block_duration": "N/A",
        "severity": "low",
        "ip": "8.8.8.8",
        "username": "testuser",
        "alternate_ips": ["1.1.1.1"],
        "why_not_blocked": "AbuseIPDB score=0, no suspicious patterns, legitimate Google DNS IP.",
        "log_template": "sshd[{pid}]: Accepted password for testuser from {ip} port {port} ssh2",
        "event_count": 1,
        "expected_outcome": {
            "block": False,
            "alert": False,
            "ml_score_max": 20
        }
    },
}


# =============================================================================
# CATEGORY 3: ML BEHAVIORAL ANALYSIS SCENARIOS
# These demonstrate behavioral anomaly detection by the ML engine
# Focus on patterns that rule-based systems miss but ML can detect
# =============================================================================

ML_BEHAVIORAL_SCENARIOS = {
    # -------------------------------------------------------------------------
    # IMPOSSIBLE TRAVEL DETECTION
    # -------------------------------------------------------------------------
    "ml_impossible_travel": {
        "id": "ml_impossible_travel",
        "name": "Impossible Travel",
        "category": "ml_behavioral",
        "description": "User logs in from Boston, then Moscow 2 hours later. Distance requires 3,750 km/h - physically impossible.",
        "trigger": "ML: Location change faster than possible travel speed",
        "block_duration": "Session terminated + 24h IP block",
        "rule_name": "ml_impossible_travel",
        "severity": "critical",
        "ip": "185.220.101.1",  # Moscow Tor exit
        "alternate_ips": ["77.88.8.8"],  # Other RU IP
        "why_blocked": "Account likely compromised. Legitimate user cannot travel 7,500km in 2 hours.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Accepted password for john.smith from {ip} port {port} ssh2",
        "ml_factors": [
            {"type": "impossible_travel", "score": 40, "description": "Boston → Moscow in 2h = 3,750 km/h"},
            {"type": "new_location", "score": 20, "description": "First login from Russia"},
            {"type": "tor_exit", "score": 25, "description": "Connection via Tor network"}
        ],
        "tooltip": {
            "what_it_tests": "ML behavioral analysis detecting physically impossible location changes",
            "expected_outcome": "Block IP immediately + flag for security review",
            "why_ml_needed": "Rule-based systems don't track user location history or calculate travel velocity",
            "real_world": "Common in account takeover attacks where credentials are stolen and used from different country"
        },
        "creates_baseline": True,
        "baseline_user": "john.smith",
        "baseline_location": {"city": "Boston", "country": "US", "lat": 42.36, "lon": -71.06}
    },

    # -------------------------------------------------------------------------
    # UNUSUAL LOGIN TIME DETECTION
    # -------------------------------------------------------------------------
    "ml_time_anomaly": {
        "id": "ml_time_anomaly",
        "name": "Unusual Login Time",
        "category": "ml_behavioral",
        "description": "User typically logs in 9am-5pm, but suddenly logs in at 3:17 AM. Could indicate compromised credentials.",
        "trigger": "ML: Login time 6+ hours outside normal pattern",
        "block_duration": "Alert + require MFA verification",
        "rule_name": "ml_time_anomaly",
        "severity": "medium",
        "ip": "24.48.0.1",  # Normal ISP
        "alternate_ips": ["73.162.0.1"],
        "why_blocked": "Unusual activity time. May be legitimate (travel/emergency) but warrants verification.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Accepted password for alice.johnson from {ip} port {port} ssh2",
        "ml_factors": [
            {"type": "unusual_time", "score": 15, "description": "Login at 3:17 AM, typical hours 9am-5pm"},
            {"type": "new_ip_for_user", "score": 10, "description": "First time from this IP"}
        ],
        "tooltip": {
            "what_it_tests": "ML pattern analysis of user's typical login schedule",
            "expected_outcome": "Risk score elevated, MFA challenge triggered",
            "why_ml_needed": "Requires learning each user's normal behavior pattern over time",
            "real_world": "Attackers often operate in different timezones or outside business hours"
        },
        "creates_baseline": True,
        "baseline_user": "alice.johnson",
        "baseline_hours": [9, 10, 11, 12, 13, 14, 15, 16, 17]
    },

    # -------------------------------------------------------------------------
    # NEW LOCATION FOR USER
    # -------------------------------------------------------------------------
    "ml_new_location": {
        "id": "ml_new_location",
        "name": "Login from New Country",
        "category": "ml_behavioral",
        "description": "Developer always logs in from US, suddenly logs in from Brazil. First time from this country in 60 days.",
        "trigger": "ML: First login from country not in user's baseline",
        "block_duration": "Alert + step-up authentication",
        "rule_name": "ml_new_location",
        "severity": "high",
        "ip": "200.160.2.3",  # Brazil
        "alternate_ips": ["177.71.0.1"],
        "why_blocked": "New geographic location. Could be legitimate travel or account compromise.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Accepted password for developer from {ip} port {port} ssh2",
        "ml_factors": [
            {"type": "new_location", "score": 20, "description": "First login from Brazil (60-day baseline: US only)"},
            {"type": "geo_mismatch", "score": 10, "description": "User logs in from US 98% of the time"}
        ],
        "tooltip": {
            "what_it_tests": "ML geo-behavioral analysis tracking user's location patterns",
            "expected_outcome": "Elevated risk score, email verification sent to user",
            "why_ml_needed": "Must maintain per-user location history and detect anomalies",
            "real_world": "Either legitimate business travel or stolen credentials used abroad"
        },
        "creates_baseline": True,
        "baseline_user": "developer",
        "baseline_countries": ["US"]
    },

    # -------------------------------------------------------------------------
    # SUCCESS AFTER MULTIPLE FAILURES
    # -------------------------------------------------------------------------
    "ml_success_after_failures": {
        "id": "ml_success_after_failures",
        "name": "Brute Force Success",
        "category": "ml_behavioral",
        "description": "15 failed login attempts followed by successful login. Classic brute force attack that finally succeeded.",
        "trigger": "ML: Successful login after 10+ failures from same IP",
        "block_duration": "Session terminated + password reset required",
        "rule_name": "ml_brute_success",
        "severity": "critical",
        "ip": "103.21.244.1",  # India hosting
        "alternate_ips": ["103.21.244.5"],
        "why_blocked": "Password was likely guessed/cracked. Immediate action required to secure account.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Accepted password for sarah.wilson from {ip} port {port} ssh2",
        "ml_factors": [
            {"type": "success_after_failures", "score": 15, "description": "15 failed attempts before success"},
            {"type": "rapid_attempts", "score": 20, "description": "All attempts within 30 minutes"},
            {"type": "new_ip_for_user", "score": 15, "description": "User never logged in from this IP"}
        ],
        "tooltip": {
            "what_it_tests": "ML correlation of failed attempts with eventual success",
            "expected_outcome": "Block IP, terminate session, force password reset, alert security team",
            "why_ml_needed": "Correlates failed attempts with success across time window",
            "real_world": "Attacker successfully guessed/cracked weak password after multiple tries"
        },
        "pre_inject_failures": 15,
        "creates_baseline": True,
        "baseline_user": "sarah.wilson"
    },

    # -------------------------------------------------------------------------
    # CREDENTIAL STUFFING PATTERN
    # -------------------------------------------------------------------------
    "ml_credential_stuffing": {
        "id": "ml_credential_stuffing",
        "name": "Credential Stuffing (ML)",
        "category": "ml_behavioral",
        "description": "IP tries 50 different usernames in 1 hour with 4% success. Using stolen credential lists from data breaches.",
        "trigger": "ML: 10+ unique usernames + <20% success rate",
        "block_duration": "Immediate permanent block",
        "rule_name": "ml_cred_stuffing",
        "severity": "critical",
        "ip": "116.31.127.1",  # China datacenter
        "alternate_ips": ["218.92.0.107"],
        "why_blocked": "Automated attack testing stolen username/password combinations.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Failed password for {username} from {ip} port {port} ssh2",
        "usernames": ["admin", "root", "user", "test", "guest", "postgres", "mysql", "oracle",
                     "backup", "ftp", "mail", "info", "support", "sales", "dev", "jenkins"],
        "ml_factors": [
            {"type": "credential_stuffing", "score": 25, "description": "50 usernames tried, 4% success rate"},
            {"type": "rapid_attempts", "score": 20, "description": "All attempts within 1 hour"},
            {"type": "datacenter_ip", "score": 10, "description": "Source is cloud/hosting provider"}
        ],
        "tooltip": {
            "what_it_tests": "ML pattern recognition for credential stuffing attacks",
            "expected_outcome": "Immediate block + report to AbuseIPDB + alert on any successful logins",
            "why_ml_needed": "Recognizes low success rate across many users as attack pattern",
            "real_world": "Attackers use breach databases to test credentials across many services"
        },
        "event_count": 50
    },

    # -------------------------------------------------------------------------
    # MULTIPLE ANOMALIES COMBINED (HIGHEST RISK)
    # -------------------------------------------------------------------------
    "ml_combined_anomalies": {
        "id": "ml_combined_anomalies",
        "name": "Multiple Anomalies (Critical)",
        "category": "ml_behavioral",
        "description": "Admin account: New IP + New Country (Russia) + Tor exit + 2:33 AM login. Every signal is suspicious.",
        "trigger": "ML: 3+ behavioral anomalies on privileged account",
        "block_duration": "Immediate block + account lockout + security incident",
        "rule_name": "ml_multi_anomaly_critical",
        "severity": "critical",
        "ip": "185.220.101.2",  # Tor exit
        "alternate_ips": ["185.220.102.1"],
        "why_blocked": "Multiple high-risk signals on privileged account. Almost certainly an attack.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Accepted password for admin from {ip} port {port} ssh2",
        "ml_factors": [
            {"type": "new_ip_for_user", "score": 15, "description": "First time from this IP"},
            {"type": "new_location", "score": 20, "description": "First login from Russia"},
            {"type": "unusual_time", "score": 15, "description": "Login at 2:33 AM (typical: 10am-4pm)"},
            {"type": "tor_exit", "score": 25, "description": "Connection via Tor network"},
            {"type": "privileged_account", "score": 10, "description": "Attempted access to 'admin' account"}
        ],
        "tooltip": {
            "what_it_tests": "ML composite scoring combining multiple anomaly signals",
            "expected_outcome": "Immediate block, session termination, account lockout, security incident created",
            "why_ml_needed": "Weighs and combines multiple weak signals into strong attack indicator",
            "real_world": "Sophisticated attackers using Tor from foreign country at odd hours"
        },
        "creates_baseline": True,
        "baseline_user": "admin",
        "baseline_countries": ["US"],
        "baseline_hours": [10, 11, 12, 13, 14, 15, 16]
    },

    # -------------------------------------------------------------------------
    # LATERAL MOVEMENT DETECTION
    # -------------------------------------------------------------------------
    "ml_lateral_movement": {
        "id": "ml_lateral_movement",
        "name": "Lateral Movement Pattern",
        "category": "ml_behavioral",
        "description": "Same IP successfully logs into 5 different servers in 10 minutes. Could indicate stolen credentials or compromised host.",
        "trigger": "ML: Same IP accessing multiple servers in short window",
        "block_duration": "Block on all servers + security incident",
        "rule_name": "ml_lateral_movement",
        "severity": "critical",
        "ip": "10.0.1.50",  # Internal or VPN
        "alternate_ips": ["192.168.1.100"],
        "why_blocked": "Unusual access pattern. Either insider threat or compromised machine.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Accepted password for deploy from {ip} port {port} ssh2",
        "ml_factors": [
            {"type": "multi_server_access", "score": 30, "description": "5 different servers in 10 minutes"},
            {"type": "service_account", "score": 10, "description": "Using deploy/service account"},
            {"type": "unusual_pattern", "score": 15, "description": "Not matching normal automation patterns"}
        ],
        "tooltip": {
            "what_it_tests": "ML cross-server correlation detecting lateral movement",
            "expected_outcome": "Block on all servers, investigate source, check for malware",
            "why_ml_needed": "Requires correlating events across multiple servers in real-time",
            "real_world": "Attacker moving through network after initial compromise"
        },
        "multi_server": True,
        "server_count": 5
    },
}


# =============================================================================
# CATEGORY 4: ALERT-ONLY SCENARIOS (NON-BLOCKING)
# These generate security alerts but DO NOT block the IP
# Used for monitoring suspicious but not necessarily malicious activity
# Successful logins with anomalies that warrant attention but not immediate block
# =============================================================================

ALERT_ONLY_SCENARIOS = {
    # -------------------------------------------------------------------------
    # SUCCESSFUL LOGIN AT UNUSUAL TIME (ALERT ONLY)
    # -------------------------------------------------------------------------
    "alert_unusual_time": {
        "id": "alert_unusual_time",
        "name": "Alert: Unusual Login Time",
        "category": "alert_only",
        "action_type": "alert",  # This scenario creates ALERT, not BLOCK
        "description": "ML detects login at 3:30 AM for user who normally works 9am-5pm. Triggers behavioral anomaly alert.",
        "trigger": "ML Behavioral: Login time outside learned pattern",
        "block_duration": "NO BLOCK - Alert Only",
        "rule_name": "alert_unusual_time",
        "severity": "medium",
        "ip": "73.162.0.1",  # Normal residential ISP
        "alternate_ips": ["24.48.0.1", "98.217.0.1"],
        "why_alerted": "ML learned this user's typical hours (9am-5pm). 3:30 AM login deviates from baseline - triggers alert notification.",
        "custom_time": "03:30:00",  # Force 3:30 AM timestamp for ML detection
        "log_template": "Dec {day} {time} server sshd[{pid}]: Accepted password for dev.user from {ip} port {port} ssh2",
        "ml_factors": [
            {"type": "unusual_time", "score": 31, "description": "3:30 AM login vs learned 9am-5pm pattern"}
        ],
        "tooltip": {
            "what_it_tests": "ML Behavioral Analysis - detects logins outside user's learned schedule",
            "expected_outcome": "Behavioral anomaly alert sent via Telegram. No IP block.",
            "why_not_blocked": "Alert-only scenario. ML detects deviation but allows login.",
            "real_world": "Employee working late, traveling, or attacker using stolen credentials"
        },
        "creates_baseline": True,
        "baseline_user": "dev.user",
        "baseline_hours": [9, 10, 11, 12, 13, 14, 15, 16, 17],
        "event_count": 1
    },

    # -------------------------------------------------------------------------
    # SUCCESSFUL LOGIN FROM NEW LOCATION (ALERT ONLY)
    # -------------------------------------------------------------------------
    "alert_new_location": {
        "id": "alert_new_location",
        "name": "Alert: New Location",
        "category": "alert_only",
        "action_type": "alert",
        "description": "ML detects first login from UK. User's learned profile shows US-only logins. Triggers location anomaly alert.",
        "trigger": "ML Behavioral: New country not in learned profile",
        "block_duration": "NO BLOCK - Alert Only",
        "rule_name": "alert_new_location",
        "severity": "medium",
        "ip": "82.132.234.1",  # UK residential IP
        "alternate_ips": ["86.158.0.1", "90.252.0.1"],
        "why_alerted": "ML learned user's locations (US only). UK login is 100% novel - triggers behavioral alert.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Accepted password for engineer from {ip} port {port} ssh2",
        "ml_factors": [
            {"type": "new_location", "score": 38, "description": "First login from UK + new IP (baseline: US only)"}
        ],
        "tooltip": {
            "what_it_tests": "ML Behavioral Analysis - detects logins from locations not in user's profile",
            "expected_outcome": "Behavioral anomaly alert sent via Telegram. No IP block.",
            "why_not_blocked": "Alert-only scenario. User may be traveling legitimately.",
            "real_world": "Business travel, vacation, or attacker in different country"
        },
        "creates_baseline": True,
        "baseline_user": "engineer",
        "baseline_countries": ["US"],
        "event_count": 1
    },

    # -------------------------------------------------------------------------
    # SUCCESSFUL LOGIN FROM NEW IP (ALERT ONLY)
    # -------------------------------------------------------------------------
    "alert_new_ip": {
        "id": "alert_new_ip",
        "name": "Alert: First Time IP",
        "category": "alert_only",
        "action_type": "alert",
        "description": "User successfully logs in from an IP they've never used before. Normal time, same country.",
        "trigger": "First login from this IP address for user",
        "block_duration": "NO BLOCK - Alert Only",
        "rule_name": "alert_new_ip_for_user",
        "severity": "low",
        "ip": "98.217.55.12",  # Different residential IP, same ISP
        "alternate_ips": ["73.162.88.100", "24.48.200.50"],
        "why_alerted": "New IP but same geographic area. User may have changed ISP or working from new location.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Accepted password for analyst from {ip} port {port} ssh2",
        "ml_factors": [
            {"type": "new_ip_for_user", "score": 10, "description": "First time from this IP, same country"}
        ],
        "tooltip": {
            "what_it_tests": "Tracking per-user IP patterns",
            "expected_outcome": "ALERT created - no block. Pattern recorded for future analysis.",
            "why_not_blocked": "Low risk - same country, normal hours, just new IP.",
            "real_world": "User at coffee shop, new home internet, or traveling within country"
        },
        "creates_baseline": True,
        "baseline_user": "analyst",
        "baseline_ips": ["98.217.50.1", "98.217.50.2"],
        "event_count": 1
    },

    # -------------------------------------------------------------------------
    # SUCCESSFUL LOGIN OUTSIDE BUSINESS HOURS (ALERT ONLY)
    # -------------------------------------------------------------------------
    "alert_weekend_login": {
        "id": "alert_weekend_login",
        "name": "Alert: Weekend Login",
        "category": "alert_only",
        "action_type": "alert",
        "description": "User logs in on Saturday at 2pm. User normally only works weekdays. Login successful from known IP.",
        "trigger": "Weekend login when user has weekday-only pattern",
        "block_duration": "NO BLOCK - Alert Only",
        "rule_name": "alert_off_hours",
        "severity": "low",
        "ip": "73.162.50.1",  # Known user IP
        "alternate_ips": ["24.48.100.1"],
        "why_alerted": "Weekend access from user who typically only works weekdays. Could be catching up on work.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Accepted password for pm_lead from {ip} port {port} ssh2",
        "ml_factors": [
            {"type": "unusual_time", "score": 8, "description": "Weekend login, user has weekday-only pattern"}
        ],
        "tooltip": {
            "what_it_tests": "Detecting weekend/holiday logins for weekday workers",
            "expected_outcome": "ALERT created - no block. Manager may be notified.",
            "why_not_blocked": "Known IP, successful auth, just unusual day of week.",
            "real_world": "Employee catching up on work, or investigating potential incident"
        },
        "creates_baseline": True,
        "baseline_user": "pm_lead",
        "baseline_days": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"],
        "event_count": 1
    },

    # -------------------------------------------------------------------------
    # SUCCESSFUL LOGIN WITH SLIGHTLY ELEVATED ML SCORE (ALERT ONLY)
    # -------------------------------------------------------------------------
    "alert_elevated_risk": {
        "id": "alert_elevated_risk",
        "name": "Alert: Elevated Risk Score",
        "category": "alert_only",
        "action_type": "alert",
        "description": "Successful login with ML score between 30-50. Multiple minor anomalies but nothing critical.",
        "trigger": "ML risk score 30-50 on successful login",
        "block_duration": "NO BLOCK - Alert Only",
        "rule_name": "alert_elevated_ml",
        "severity": "medium",
        "ip": "104.28.5.100",  # CDN/cloud IP
        "alternate_ips": ["172.67.0.1"],
        "why_alerted": "Multiple minor risk factors combined. Not enough for block but warrants monitoring.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Accepted publickey for sysadmin from {ip} port {port} ssh2",
        "ml_factors": [
            {"type": "new_ip_for_user", "score": 10, "description": "First time from this IP"},
            {"type": "unusual_time", "score": 10, "description": "Login at 6:45 PM, typical hours 9am-5pm"},
            {"type": "cloud_provider_ip", "score": 15, "description": "IP belongs to cloud provider"}
        ],
        "tooltip": {
            "what_it_tests": "Alerting on moderate risk scores without blocking",
            "expected_outcome": "ALERT created - patterns logged for analysis. No block.",
            "why_not_blocked": "Score below blocking threshold. User authenticated successfully.",
            "real_world": "Sysadmin accessing from cloud shell or working late"
        },
        "creates_baseline": True,
        "baseline_user": "sysadmin",
        "event_count": 1
    },

    # -------------------------------------------------------------------------
    # SUCCESSFUL ROOT LOGIN FROM NEW LOCATION (ALERT)
    # -------------------------------------------------------------------------
    "alert_root_new_location": {
        "id": "alert_root_new_location",
        "name": "Alert: Root from New Location",
        "category": "alert_only",
        "action_type": "alert",
        "description": "Root login succeeds from Canada. Root usually logs in from US office IPs only.",
        "trigger": "Privileged account + new location",
        "block_duration": "NO BLOCK - High Priority Alert",
        "rule_name": "alert_privileged_new_location",
        "severity": "high",
        "ip": "206.47.0.1",  # Canada residential
        "alternate_ips": ["142.161.0.1"],
        "why_alerted": "Privileged account from new location. High priority but successful auth suggests valid credentials.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Accepted publickey for root from {ip} port {port} ssh2",
        "ml_factors": [
            {"type": "privileged_account", "score": 15, "description": "Root account access"},
            {"type": "new_location", "score": 20, "description": "First login from Canada"}
        ],
        "tooltip": {
            "what_it_tests": "High-priority alerting for privileged accounts",
            "expected_outcome": "HIGH priority alert - security team notified immediately. No block.",
            "why_not_blocked": "Successful key-based auth. Admin may be traveling.",
            "real_world": "Sysadmin on vacation or attacker with stolen SSH key"
        },
        "creates_baseline": True,
        "baseline_user": "root",
        "baseline_countries": ["US"],
        "event_count": 1
    }
}


# Combine all scenarios for backward compatibility
DEMO_SCENARIOS = {
    **UFW_BLOCKING_SCENARIOS,
    **FAIL2BAN_SCENARIOS,
    **BASELINE_SCENARIOS,
    **ML_BEHAVIORAL_SCENARIOS,
    **ALERT_ONLY_SCENARIOS
}


def get_scenarios_by_category() -> Dict[str, List[Dict]]:
    """Get scenarios organized by blocking category"""
    return {
        "ufw_blocking": [
            {
                "id": s["id"],
                "name": s["name"],
                "description": s["description"],
                "trigger": s["trigger"],
                "block_duration": s["block_duration"],
                "severity": s["severity"],
                "ip": s["ip"],
                "why_blocked": s.get("why_blocked", ""),
                "rule_name": s.get("rule_name", "")
            }
            for s in UFW_BLOCKING_SCENARIOS.values()
        ],
        "fail2ban": [
            {
                "id": s["id"],
                "name": s["name"],
                "description": s["description"],
                "trigger": s["trigger"],
                "block_duration": s["block_duration"],
                "severity": s["severity"],
                "ip": s["ip"],
                "why_blocked": s.get("why_blocked", "")
            }
            for s in FAIL2BAN_SCENARIOS.values()
        ],
        "ml_behavioral": [
            {
                "id": s["id"],
                "name": s["name"],
                "description": s["description"],
                "trigger": s["trigger"],
                "block_duration": s["block_duration"],
                "severity": s["severity"],
                "ip": s["ip"],
                "why_blocked": s.get("why_blocked", ""),
                "rule_name": s.get("rule_name", ""),
                "ml_factors": s.get("ml_factors", []),
                "tooltip": s.get("tooltip", {})
            }
            for s in ML_BEHAVIORAL_SCENARIOS.values()
        ],
        "alert_only": [
            {
                "id": s["id"],
                "name": s["name"],
                "description": s["description"],
                "trigger": s["trigger"],
                "block_duration": s["block_duration"],
                "severity": s["severity"],
                "ip": s["ip"],
                "why_alerted": s.get("why_alerted", ""),
                "rule_name": s.get("rule_name", ""),
                "action_type": "alert",
                "ml_factors": s.get("ml_factors", []),
                "tooltip": s.get("tooltip", {})
            }
            for s in ALERT_ONLY_SCENARIOS.values()
        ],
        "baseline": [
            {
                "id": s["id"],
                "name": s["name"],
                "description": s["description"],
                "severity": s["severity"],
                "ip": s["ip"],
                "why_not_blocked": s.get("why_not_blocked", "")
            }
            for s in BASELINE_SCENARIOS.values()
        ]
    }


def get_demo_scenarios(use_fresh_ips: bool = True) -> List[Dict]:
    """Get list of all demo scenarios for UI"""
    scenarios = []
    for scenario_id, scenario in DEMO_SCENARIOS.items():
        ip = get_rotated_ip(scenario_id) if use_fresh_ips else scenario["ip"]
        scenario_data = {
            "id": scenario["id"],
            "name": scenario["name"],
            "description": scenario["description"],
            "severity": scenario["severity"],
            "category": scenario.get("category", "unknown"),
            "ip": ip or scenario["ip"],
            "trigger": scenario.get("trigger", ""),
            "block_duration": scenario.get("block_duration", ""),
            "why_blocked": scenario.get("why_blocked", scenario.get("why_not_blocked", scenario.get("why_alerted", ""))),
            "rule_name": scenario.get("rule_name", ""),
            "action_type": scenario.get("action_type", "block"),  # block or alert
            "expected_results": {
                "rule_triggered": scenario.get("rule_name", ""),
                "block_action": scenario.get("block_duration", "NO BLOCK"),
                "threat_level": scenario.get("severity", "unknown").upper(),
                "action_type": scenario.get("action_type", "block")
            }
        }

        # Add ML-specific fields for behavioral scenarios
        if scenario.get("category") == "ml_behavioral":
            scenario_data["ml_factors"] = scenario.get("ml_factors", [])
            scenario_data["tooltip"] = scenario.get("tooltip", {})
            scenario_data["creates_baseline"] = scenario.get("creates_baseline", False)
            scenario_data["baseline_user"] = scenario.get("baseline_user", "")

        # Add alert-specific fields for alert_only scenarios
        if scenario.get("category") == "alert_only":
            scenario_data["ml_factors"] = scenario.get("ml_factors", [])
            scenario_data["tooltip"] = scenario.get("tooltip", {})
            scenario_data["creates_baseline"] = scenario.get("creates_baseline", False)
            scenario_data["baseline_user"] = scenario.get("baseline_user", "")
            scenario_data["why_alerted"] = scenario.get("why_alerted", "")

        scenarios.append(scenario_data)
    return scenarios


def get_demo_scenario(scenario_id: str) -> Optional[Dict]:
    """Get a specific demo scenario"""
    return DEMO_SCENARIOS.get(scenario_id)


def get_rotated_ip(scenario_id: str) -> str:
    """Get IP for scenario with optional rotation"""
    scenario = DEMO_SCENARIOS.get(scenario_id)
    if not scenario:
        return None

    # IMPORTANT: For baseline/clean scenarios, always use the scenario's defined IP
    # These are known-safe IPs (Google DNS, Cloudflare, etc.) that should NOT be blocked
    if scenario.get('category') == 'baseline':
        return scenario['ip']  # Return clean IP as-is (8.8.8.8, 1.1.1.1, etc.)

    # For alert-only scenarios, use scenario IP (no rotation needed)
    if scenario.get('action_type') == 'alert':
        return scenario['ip']

    # Try fresh IP pool for attack scenarios
    try:
        from simulation.ip_fetcher import get_fresh_ip
        category_map = {
            'bad_reputation_critical': 'brute_force',
            'bad_reputation_high': 'brute_force',
            'brute_force_attack': 'brute_force',
            'credential_stuffing': 'brute_force',
            'rapid_attack': 'ddos_botnet',
            'tor_exit_node': 'tor_exit',
            'vpn_proxy_attack': 'brute_force',
            'high_risk_country': 'brute_force',
            'malware_source': 'botnet',
        }
        pool_category = category_map.get(scenario_id, 'brute_force')
        fresh_ip = get_fresh_ip(pool_category)
        if fresh_ip:
            return fresh_ip
    except Exception:
        pass

    # Fallback to hardcoded rotation
    if scenario.get('alternate_ips'):
        all_ips = [scenario['ip']] + scenario['alternate_ips']
        return random.choice(all_ips)

    return scenario['ip']


def generate_demo_log(scenario_id: str, custom_ip: str = None) -> Optional[str]:
    """Generate a log line for a demo scenario"""
    # Check both DEMO_SCENARIOS and ALERT_ONLY_SCENARIOS
    scenario = DEMO_SCENARIOS.get(scenario_id) or ALERT_ONLY_SCENARIOS.get(scenario_id)
    if not scenario:
        return None

    now = datetime.now()
    ip_to_use = custom_ip if custom_ip else get_rotated_ip(scenario_id)

    template = scenario.get("log_template", "")
    if not template:
        return None

    # Random username for credential stuffing scenarios
    usernames = scenario.get('usernames', ['root', 'admin', 'user'])

    # Use custom_time if specified in scenario (for ML time-based scenarios)
    time_str = scenario.get('custom_time', now.strftime("%H:%M:%S"))

    log = template.format(
        day=now.day,
        time=time_str,
        pid=random.randint(10000, 99999),
        ip=ip_to_use,
        port=random.randint(40000, 65000),
        username=random.choice(usernames) if '{username}' in template else ''
    )
    return log


def run_demo_scenario(scenario_id: str, verbose: bool = False,
                      agent_id: int = None, run_full_pipeline: bool = False) -> Dict:
    """Execute a single demo scenario with full enrichment pipeline."""
    from core.log_processor import process_log_line

    # Check both DEMO_SCENARIOS and ALERT_ONLY_SCENARIOS
    scenario = DEMO_SCENARIOS.get(scenario_id) or ALERT_ONLY_SCENARIOS.get(scenario_id)
    if not scenario:
        return {"success": False, "error": f"Unknown scenario: {scenario_id}"}

    # Auto-seed user profile for alert scenarios that require baselines
    if scenario.get('creates_baseline') and scenario.get('baseline_user'):
        try:
            from core.ml_behavioral_learner import seed_simulation_profiles
            if verbose:
                print(f"[Baseline] Seeding profile for user: {scenario['baseline_user']}")
            seed_simulation_profiles()
        except Exception as e:
            if verbose:
                print(f"[Baseline] Warning: Could not seed profile: {e}")

    if verbose:
        print(f"\n{'='*60}")
        print(f"SCENARIO: {scenario['name']}")
        print(f"{'='*60}")
        print(f"Description: {scenario['description']}")
        print(f"Trigger: {scenario.get('trigger', 'N/A')}")
        print(f"Expected: {scenario.get('block_duration', 'No block')}")
        print(f"{'='*60}")

    # Generate log entries (some scenarios need multiple)
    event_count = scenario.get('event_count', 1)
    rotated_ip = get_rotated_ip(scenario_id)

    if verbose:
        print(f"\nUsing IP: {rotated_ip}")
        print(f"Generating {event_count} log entries...")

    # FAIL2BAN SCENARIOS: Inject logs into auth.log, let fail2ban handle blocking
    # Do NOT process through ML/blocking engine - fail2ban will detect and block locally
    if scenario.get('category') == 'fail2ban' or scenario.get('mechanism') == 'fail2ban':
        import subprocess
        from datetime import datetime

        logs_injected = []
        for i in range(event_count):
            log_line = generate_demo_log(scenario_id, custom_ip=rotated_ip)
            if verbose:
                print(f"  [{i+1}] Injecting: {log_line}")

            # Inject into auth.log with proper timestamp for fail2ban
            timestamp = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f%z') or datetime.now().isoformat()
            # Replace the template timestamp with current ISO timestamp
            import re
            log_line = re.sub(r'^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}', timestamp[:19], log_line)

            try:
                # Append to auth.log
                with open('/var/log/auth.log', 'a') as f:
                    f.write(log_line + '\n')
                logs_injected.append(log_line)
            except PermissionError:
                # Try with logger command as fallback
                try:
                    subprocess.run(['logger', '-p', 'auth.info', '-t', 'sshd', log_line], check=True)
                    logs_injected.append(log_line)
                except Exception as e:
                    if verbose:
                        print(f"  Warning: Could not inject log: {e}")

        return {
            "success": True,
            "scenario_id": scenario_id,
            "scenario_name": scenario["name"],
            "ip": rotated_ip,
            "event_count": event_count,
            "mechanism": "fail2ban",
            "logs_injected": len(logs_injected),
            "expected": {
                "trigger": scenario.get("trigger"),
                "block_duration": scenario.get("block_duration"),
                "why_blocked": scenario.get("why_blocked", "")
            },
            "message": f"Injected {len(logs_injected)} log entries into auth.log. Fail2ban will detect and block locally. Agent will sync ban to dashboard.",
            "blocking": {
                "blocked": False,
                "mechanism": "fail2ban",
                "note": "Fail2ban handles blocking locally - check fail2ban status after ~30 seconds"
            }
        }

    # UFW/ML SCENARIOS: Process through normal pipeline
    result = None
    for i in range(event_count):
        log_line = generate_demo_log(scenario_id, custom_ip=rotated_ip)
        if verbose:
            print(f"  [{i+1}] {log_line}")

        result = process_log_line(
            log_line,
            source_type='agent' if agent_id else 'simulation',
            agent_id=agent_id,
            skip_blocking=False,  # Always run blocking evaluation for simulations
            skip_learning=True    # Skip behavioral learning to prevent profile contamination
        )

    if result and result.get('success'):
        enrichment = result.get('enrichment', {})
        blocking_result = enrichment.get('blocking', {})

        # Pipeline tracking
        pipeline_steps = {
            'event_created': {'status': 'success', 'event_id': result.get('event_id')},
            'enrichment': {'status': 'success' if enrichment else 'skipped'},
            'ip_blocked': {
                'status': 'success' if blocking_result.get('blocked') else 'skipped',
                'is_blocked': blocking_result.get('blocked', False),
                'triggered_rules': blocking_result.get('triggered_rules', []),
                'duration': blocking_result.get('adjusted_duration')
            },
            'ufw_command': {'status': 'skipped'},
            'notification': {'status': 'skipped'}
        }

        if run_full_pipeline and agent_id:
            try:
                from simulation.pipeline_executor import execute_pipeline
                pipeline_steps = execute_pipeline(
                    event_id=result.get('event_id'),
                    source_ip=rotated_ip,
                    agent_id=agent_id,
                    enrichment=enrichment
                )
            except Exception as e:
                print(f"Pipeline error: {e}")

        return {
            "success": True,
            "scenario_id": scenario_id,
            "scenario_name": scenario["name"],
            "ip": rotated_ip,
            "event_count": event_count,
            "event_id": result.get('event_id'),
            "event_type": result.get('event_type'),
            "expected": {
                "trigger": scenario.get("trigger"),
                "block_duration": scenario.get("block_duration"),
                "rule_name": scenario.get("rule_name"),
                "why_blocked": scenario.get("why_blocked", scenario.get("why_not_blocked", ""))
            },
            "agent_id": agent_id,
            "run_full_pipeline": run_full_pipeline,
            "pipeline_steps": pipeline_steps,
            "blocking": blocking_result,
            "actual_results": {
                "geoip": enrichment.get('geoip'),
                "ml": enrichment.get('ml'),
                "threat_intel": enrichment.get('threat_intel'),
                "blocking": blocking_result,
                "enrichment": enrichment,  # Full enrichment including behavioral_ml
                "behavioral_ml": enrichment.get('behavioral_ml')  # Behavioral ML analysis
            }
        }
    else:
        return {"success": False, "error": result.get('error') if result else "No result"}


def run_full_demo(verbose: bool = True) -> Dict:
    """Run all demo scenarios and return results."""
    results = []
    summary = {
        "total_scenarios": len(DEMO_SCENARIOS),
        "successful": 0,
        "blocked": 0,
        "categories": {
            "ufw_block": 0,
            "fail2ban": 0,
            "baseline": 0
        }
    }

    if verbose:
        print("\n" + "=" * 70)
        print("SSH GUARDIAN v3.0 - FULL DEMONSTRATION")
        print("=" * 70)

    for scenario_id in DEMO_SCENARIOS:
        result = run_demo_scenario(scenario_id, verbose=verbose)
        results.append(result)

        if result.get('success'):
            summary['successful'] += 1

            category = DEMO_SCENARIOS[scenario_id].get('category', 'unknown')
            if category in summary['categories']:
                summary['categories'][category] += 1

            if result.get('blocking', {}).get('blocked'):
                summary['blocked'] += 1

    if verbose:
        print("\n" + "=" * 70)
        print("SUMMARY")
        print(f"Total: {summary['total_scenarios']}")
        print(f"Successful: {summary['successful']}")
        print(f"Blocked: {summary['blocked']}")
        print("=" * 70)

    return {
        "success": True,
        "summary": summary,
        "results": results,
        "timestamp": datetime.now().isoformat()
    }

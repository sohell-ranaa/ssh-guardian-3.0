"""
SSH Guardian v3.0 - Demo Scenarios (Aligned with Blocking Rules)
9 test scenarios covering core blocking rules

BLOCKING RULES TESTED:
ID | Rule Name                          | Type              | Action | Priority
---|------------------------------------|--------------------|--------|----------
19 | Off-Hours Successful Login Alert   | off_hours_anomaly  | alert  | 20
14 | Multi-User Same IP Alert           | credential_stuffing| alert  | 25
11 | Failed Login Alert (3 attempts)    | brute_force        | alert  | 30
12 | Failed Login Block (5 attempts)    | brute_force        | block  | 40
13 | Persistent Attacker UFW Block      | brute_force        | block  | 50
17 | Bad IP Failed Attempts Block       | api_reputation     | block  | 60
18 | High Risk IP Immediate Block       | api_reputation     | block  | 70

CATEGORIES:
1. CLEAN IP SCENARIOS (6) - Tests for clean IPs (AbuseIPDB < 20)
2. BAD IP SCENARIOS (2) - Tests for bad IPs (AbuseIPDB >= 25)
3. BASELINE (1) - Control scenario (no action)

NOTE: Impossible travel scenarios removed - require complex baseline setup
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
# CATEGORY 1: CLEAN IP SCENARIOS (AbuseIPDB score < 20)
# =============================================================================

CLEAN_IP_SCENARIOS = {
    # SCENARIO 1: Clean IP + Daytime Success = NO ACTION
    "clean_daytime_success": {
        "id": "clean_daytime_success",
        "name": "Clean IP - Daytime Success",
        "category": "baseline",
        "action_type": "none",
        "description": "Clean IP (AbuseIPDB 0) with successful daytime login. Should trigger NO rules.",
        "trigger": "None - normal login during business hours",
        "block_duration": "N/A - NO ACTION",
        "rule_id": None,
        "rule_name": "None (no rule matches)",
        "severity": "low",
        "ip": "8.8.8.8",
        "alternate_ips": ["1.1.1.1", "208.67.222.222"],
        "abuseipdb_score": 0,
        "why_not_blocked": "Clean IP, daytime login, no suspicious patterns. Expected: NO ACTION.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Accepted password for {username} from {ip} port {port} ssh2",
        "usernames": ["john.smith", "alice.johnson"],
        "custom_time": "10:30:00",
        "event_count": 1,
        "expected_outcome": {
            "block": False,
            "alert": False,
            "rule_triggered": None
        }
    },

    # SCENARIO 2: Clean IP + Midnight Success = ALERT
    "clean_midnight_success": {
        "id": "clean_midnight_success",
        "name": "Clean IP - Midnight Success",
        "category": "alert_only",
        "action_type": "alert",
        "description": "Clean IP (AbuseIPDB 0) with successful login at 3 AM. Triggers off-hours alert.",
        "trigger": "Successful login outside 6AM-10PM from clean IP",
        "block_duration": "NO BLOCK - Alert Only",
        "rule_id": 19,
        "rule_name": "Off-Hours Successful Login Alert",
        "severity": "medium",
        "ip": "8.8.8.8",
        "alternate_ips": ["1.1.1.1"],
        "abuseipdb_score": 0,
        "why_alerted": "Off-hours login from clean IP warrants monitoring but not blocking.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Accepted password for {username} from {ip} port {port} ssh2",
        "usernames": ["john.smith", "dev.user"],
        "custom_time": "03:00:00",
        "event_count": 1,
        "expected_outcome": {
            "block": False,
            "alert": True,
            "rule_triggered": "Off-Hours Successful Login Alert"
        }
    },

    # SCENARIO 3a: Clean IP + 3 Failed = ALERT
    "clean_3_failed": {
        "id": "clean_3_failed",
        "name": "Clean IP - 3 Failed Logins",
        "category": "alert_only",
        "action_type": "alert",
        "description": "Clean IP (AbuseIPDB 0) with 3 failed login attempts in 10 minutes. Alert only.",
        "trigger": "3 failed attempts in 10 minutes from clean IP",
        "block_duration": "NO BLOCK - Alert Only",
        "rule_id": 11,
        "rule_name": "Failed Login Alert (3 attempts)",
        "severity": "medium",
        "ip": "91.240.118.172",
        "alternate_ips": ["45.227.254.0"],
        "abuseipdb_score": 0,
        "why_alerted": "Early warning for potential brute force. 3 fails = alert, 5 fails = block.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Failed password for {username} from {ip} port {port} ssh2",
        "usernames": ["root", "admin", "user"],
        "event_count": 3,
        "expected_outcome": {
            "block": False,
            "alert": True,
            "rule_triggered": "Failed Login Alert (3 attempts)"
        }
    },

    # SCENARIO 3b: Clean IP + 5 Failed = FAIL2BAN BLOCK
    "clean_5_failed": {
        "id": "clean_5_failed",
        "name": "Clean IP - 5 Failed Logins",
        "category": "fail2ban_block",
        "action_type": "block",
        "description": "Clean IP (AbuseIPDB 0) with 5 failed login attempts in 10 minutes. Fail2ban block.",
        "trigger": "5 failed attempts in 10 minutes from clean IP",
        "block_duration": "24 hours (fail2ban)",
        "rule_id": 12,
        "rule_name": "Failed Login Block (5 attempts)",
        "severity": "high",
        "ip": "91.240.118.172",
        "alternate_ips": ["45.227.254.0", "193.56.28.103"],
        "abuseipdb_score": 0,
        "why_blocked": "Classic brute force pattern. 5 failed attempts = temporary block.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Failed password for {username} from {ip} port {port} ssh2",
        "usernames": ["root", "admin", "user", "postgres", "mysql"],
        "event_count": 5,
        "expected_outcome": {
            "block": True,
            "alert": False,
            "rule_triggered": "Failed Login Block (5 attempts)",
            "block_method": "fail2ban",
            "auto_unblock": True
        }
    },

    # SCENARIO 4: Clean IP + 10 Failed in 24h = UFW BLOCK
    # Uses different IPs from clean_5_failed to avoid conflicts
    "clean_10_failed_24h": {
        "id": "clean_10_failed_24h",
        "name": "Clean IP - Persistent Attacker",
        "category": "ufw_block",
        "action_type": "block",
        "description": "Clean IP (AbuseIPDB 0) with 10+ failed logins in 24 hours. UFW permanent block.",
        "trigger": "10 failed attempts in 24 hours from clean IP",
        "block_duration": "30 days (UFW permanent)",
        "rule_id": 13,
        "rule_name": "Persistent Attacker UFW Block",
        "severity": "critical",
        "ip": "9.9.9.9",
        "alternate_ips": ["8.8.9.9", "8.8.9.8"],
        "abuseipdb_score": 0,
        "why_blocked": "Persistent attack pattern over 24h indicates determined attacker.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Failed password for {username} from {ip} port {port} ssh2",
        "usernames": ["root", "admin", "user", "postgres", "mysql", "oracle", "test", "ftp", "www", "nginx"],
        "event_count": 10,
        "expected_outcome": {
            "block": True,
            "alert": False,
            "rule_triggered": "Persistent Attacker UFW Block",
            "block_method": "ufw",
            "auto_unblock": False
        }
    },

    # SCENARIO 5: Clean IP + Multiple Users Success = ALERT
    "clean_multi_user": {
        "id": "clean_multi_user",
        "name": "Clean IP - Multi-User Success",
        "category": "alert_only",
        "action_type": "alert",
        "description": "Clean IP (AbuseIPDB 0) with successful logins from 2+ different users. Alert only.",
        "trigger": "2+ unique usernames succeed from same clean IP in 60 minutes",
        "block_duration": "NO BLOCK - Alert Only",
        "rule_id": 14,
        "rule_name": "Multi-User Same IP Alert",
        "severity": "medium",
        "ip": "73.162.0.1",
        "alternate_ips": ["24.48.0.1"],
        "abuseipdb_score": 0,
        "why_alerted": "Multiple users from same IP may indicate shared VPN or credential stuffing success.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Accepted password for {username} from {ip} port {port} ssh2",
        "usernames": ["john.smith", "alice.johnson", "bob.wilson"],
        "event_count": 2,
        "expected_outcome": {
            "block": False,
            "alert": True,
            "rule_triggered": "Multi-User Same IP Alert"
        }
    },
}


# =============================================================================
# CATEGORY 2: BAD IP SCENARIOS (AbuseIPDB score >= 25)
# =============================================================================

BAD_IP_SCENARIOS = {
    # SCENARIO 8: Bad IP (25+) + 5 Failed = FAIL2BAN BLOCK
    "bad_ip_5_failed": {
        "id": "bad_ip_5_failed",
        "name": "Bad IP - 5 Failed Block",
        "category": "fail2ban_block",
        "action_type": "block",
        "description": "Bad IP (AbuseIPDB 25+) with 5 failed logins in 24h. Fail2ban block.",
        "trigger": "5 failed attempts from bad IP (AbuseIPDB 25+)",
        "block_duration": "24 hours (fail2ban)",
        "rule_id": 17,
        "rule_name": "Bad IP Failed Attempts Block",
        "severity": "high",
        "ip": "185.220.101.1",
        "alternate_ips": ["45.142.212.61"],
        "abuseipdb_score": 30,
        "why_blocked": "Bad reputation IP + multiple failed attempts = confirmed attack.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Failed password for {username} from {ip} port {port} ssh2",
        "usernames": ["root", "admin", "user", "postgres", "mysql"],
        "event_count": 5,
        "expected_outcome": {
            "block": True,
            "alert": False,
            "rule_triggered": "Bad IP Failed Attempts Block",
            "block_method": "fail2ban",
            "auto_unblock": True
        }
    },

    # SCENARIO 9: High Risk IP (50+) + 3 Failed = UFW BLOCK
    "high_risk_3_failed": {
        "id": "high_risk_3_failed",
        "name": "High Risk IP - Immediate Block",
        "category": "ufw_block",
        "action_type": "block",
        "description": "High risk IP (AbuseIPDB 50+) with just 3 failed logins. UFW permanent block.",
        "trigger": "3 failed attempts from high-risk IP (AbuseIPDB 50+)",
        "block_duration": "30 days (UFW permanent)",
        "rule_id": 18,
        "rule_name": "High Risk IP Immediate Block",
        "severity": "critical",
        "ip": "45.142.212.61",
        "alternate_ips": ["185.220.101.1"],
        "abuseipdb_score": 70,
        "why_blocked": "Very bad reputation + failed attempts = aggressive block immediately.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Failed password for {username} from {ip} port {port} ssh2",
        "usernames": ["root", "admin", "oracle"],
        "event_count": 3,
        "expected_outcome": {
            "block": True,
            "alert": False,
            "rule_triggered": "High Risk IP Immediate Block",
            "block_method": "ufw",
            "auto_unblock": False
        }
    },
}


# =============================================================================
# CATEGORY 3: ML BEHAVIORAL SCENARIOS
# =============================================================================

# NOTE: Impossible travel scenarios removed - require complex baseline setup
# with prior login history from different geolocations
ML_BEHAVIORAL_SCENARIOS = {}


# =============================================================================
# CATEGORY 4: BASELINE (CONTROL SCENARIO)
# =============================================================================

BASELINE_SCENARIOS = {
    "clean_baseline": {
        "id": "clean_baseline",
        "name": "Clean Baseline (Control)",
        "category": "baseline",
        "action_type": "none",
        "description": "Control test: Clean IP, daytime, single user. Must NOT trigger any rules.",
        "trigger": "None - this is the control scenario",
        "block_duration": "N/A - NO ACTION expected",
        "rule_id": None,
        "rule_name": "None",
        "severity": "low",
        "ip": "8.8.8.8",
        "alternate_ips": ["1.1.1.1"],
        "abuseipdb_score": 0,
        "why_not_blocked": "False positive test. This scenario must NOT trigger any rule.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Accepted password for testuser from {ip} port {port} ssh2",
        "usernames": ["testuser"],
        "custom_time": "14:30:00",
        "event_count": 1,
        "expected_outcome": {
            "block": False,
            "alert": False,
            "rule_triggered": None,
            "ml_score_max": 20
        }
    },
}


# =============================================================================
# COMBINED SCENARIOS
# =============================================================================

DEMO_SCENARIOS = {
    **CLEAN_IP_SCENARIOS,
    **BAD_IP_SCENARIOS,
    **ML_BEHAVIORAL_SCENARIOS,
    **BASELINE_SCENARIOS
}

# Legacy compatibility aliases
UFW_BLOCKING_SCENARIOS = {
    "bad_reputation": BAD_IP_SCENARIOS["high_risk_3_failed"],
    "brute_force": CLEAN_IP_SCENARIOS["clean_5_failed"],
    "anonymizer": BAD_IP_SCENARIOS["bad_ip_5_failed"],  # Was bad_ip_alert (removed)
}

FAIL2BAN_SCENARIOS = {
    "fail2ban_trigger": CLEAN_IP_SCENARIOS["clean_5_failed"],
}

ALERT_ONLY_SCENARIOS = {
    "alert_anomaly": CLEAN_IP_SCENARIOS["clean_midnight_success"],
}

PRIVATE_IP_SCENARIOS = {
    "private_ip_insider": {
        "id": "private_ip_insider",
        "name": "Private IP: Insider Threat",
        "category": "private_ip",
        "description": "Internal network login at 3 AM with brute force pattern.",
        "trigger": "Behavioral: Unusual time + brute force from private IP",
        "block_duration": "Alert + elevated risk",
        "rule_name": "private_ip_behavioral",
        "severity": "high",
        "ip": "192.168.1.100",
        "alternate_ips": ["10.0.0.50", "172.16.0.25"],
        "log_template": "Dec {day} {time} server sshd[{pid}]: Failed password for {username} from {ip} port {port} ssh2",
        "usernames": ["root", "admin", "deploy"],
        "custom_time": "03:00:00",
        "is_private_ip": True,
        "event_count": 5,
        "expected_outcome": {
            "block": False,
            "alert": True,
            "rule_triggered": None
        }
    },
}


def get_scenarios_by_category() -> Dict[str, List[Dict]]:
    """Get scenarios organized by blocking category"""
    return {
        "clean_ip": list(CLEAN_IP_SCENARIOS.values()),
        "bad_ip": list(BAD_IP_SCENARIOS.values()),
        "ml_behavioral": list(ML_BEHAVIORAL_SCENARIOS.values()),
        "baseline": list(BASELINE_SCENARIOS.values()),
        # Legacy compatibility
        "ufw_blocking": list(UFW_BLOCKING_SCENARIOS.values()),
        "fail2ban": list(FAIL2BAN_SCENARIOS.values()),
        "alert_only": list(ALERT_ONLY_SCENARIOS.values()),
        "private_ip": list(PRIVATE_IP_SCENARIOS.values()),
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
            "action_type": scenario.get("action_type", "block"),
            "is_private_ip": scenario.get("is_private_ip", False),
            "event_count": scenario.get("event_count", 1),
            "usernames": scenario.get("usernames", ["root"]),
            "baseline_user": scenario.get("baseline_user", ""),
            "log_template": scenario.get("log_template", ""),
            "expected_results": {
                "rule_triggered": scenario.get("rule_name", ""),
                "block_action": scenario.get("block_duration", "NO BLOCK"),
                "threat_level": scenario.get("severity", "unknown").upper(),
                "action_type": scenario.get("action_type", "block")
            }
        }

        # Add ML-specific fields
        if scenario.get("ml_factors"):
            scenario_data["ml_factors"] = scenario.get("ml_factors", [])
            scenario_data["tooltip"] = scenario.get("tooltip", {})
            scenario_data["creates_baseline"] = scenario.get("creates_baseline", False)
            scenario_data["baseline_user"] = scenario.get("baseline_user", "")

        # Add behavioral factors for private IP scenarios
        if scenario.get("behavioral_factors"):
            scenario_data["behavioral_factors"] = scenario.get("behavioral_factors", [])

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

    # Baseline and alert scenarios use fixed IPs
    if scenario.get('category') in ['baseline', 'alert_only', 'private_ip']:
        return scenario['ip']

    # IMPORTANT: Clean IP scenarios (abuseipdb_score = 0) must use fixed IPs
    # to ensure the max_abuseipdb_score filters work correctly
    if scenario.get('abuseipdb_score', 100) <= 20:
        # Clean IP scenario - use fixed IP or alternates only
        if scenario.get('alternate_ips'):
            all_ips = [scenario['ip']] + scenario['alternate_ips']
            return random.choice(all_ips)
        return scenario['ip']

    # Try fresh IP pool for BAD IP attack scenarios only
    try:
        from simulation.ip_fetcher import get_fresh_ip
        category_map = {
            'bad_reputation': 'brute_force',
            'brute_force': 'brute_force',
            'anonymizer': 'tor_exit',
        }
        pool_category = category_map.get(scenario_id, 'brute_force')
        fresh_ip = get_fresh_ip(pool_category)
        if fresh_ip:
            return fresh_ip
    except Exception:
        pass

    # Fallback to random alternate
    if scenario.get('alternate_ips'):
        all_ips = [scenario['ip']] + scenario['alternate_ips']
        return random.choice(all_ips)

    return scenario['ip']


def generate_demo_log(scenario_id: str, custom_ip: str = None) -> Optional[str]:
    """Generate a log line for a demo scenario"""
    scenario = DEMO_SCENARIOS.get(scenario_id)
    if not scenario:
        return None

    now = datetime.now()
    ip_to_use = custom_ip if custom_ip else get_rotated_ip(scenario_id)

    template = scenario.get("log_template", "")
    if not template:
        return None

    usernames = scenario.get('usernames', ['root', 'admin', 'user'])
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

    scenario = DEMO_SCENARIOS.get(scenario_id)
    if not scenario:
        return {"success": False, "error": f"Unknown scenario: {scenario_id}"}

    # Default to first active agent for UFW/fail2ban integration
    if agent_id is None:
        try:
            from connection import get_connection
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT id FROM agents WHERE is_active = TRUE LIMIT 1")
            agent_row = cursor.fetchone()
            if agent_row:
                agent_id = agent_row['id']
            cursor.close()
            conn.close()
        except Exception:
            pass  # Continue without agent_id if lookup fails

    # Auto-seed user profile for scenarios that require baselines
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

    event_count = scenario.get('event_count', 1)
    rotated_ip = get_rotated_ip(scenario_id)

    if verbose:
        print(f"\nUsing IP: {rotated_ip}")
        print(f"Generating {event_count} log entries...")

    # FAIL2BAN: Inject logs, let fail2ban handle
    if scenario.get('category') == 'fail2ban' or scenario.get('mechanism') == 'fail2ban':
        logs_injected = []
        for i in range(event_count):
            log_line = generate_demo_log(scenario_id, custom_ip=rotated_ip)
            if verbose:
                print(f"  [{i+1}] Injecting: {log_line}")

            try:
                with open('/var/log/auth.log', 'a') as f:
                    f.write(log_line + '\n')
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
            "message": f"Injected {len(logs_injected)} logs. Fail2ban will detect and block."
        }

    # Other scenarios: Process through pipeline
    # Track if IP was blocked at ANY point during the scenario
    result = None
    cumulative_blocking = {'blocked': False, 'triggered_rules': [], 'alerts_created': 0}
    cumulative_proactive = {}

    for i in range(event_count):
        log_line = generate_demo_log(scenario_id, custom_ip=rotated_ip)
        if verbose:
            print(f"  [{i+1}] {log_line}")

        result = process_log_line(
            log_line,
            source_type='agent' if agent_id else 'simulation',
            agent_id=agent_id,
            skip_blocking=False,
            skip_learning=True
        )

        # Accumulate blocking results across all events
        if result and result.get('success'):
            enrichment = result.get('enrichment', {})
            blocking_result = enrichment.get('blocking', {})
            proactive_block = result.get('proactive_block', {})

            # Track if blocked at ANY point
            if blocking_result.get('blocked'):
                cumulative_blocking['blocked'] = True
                if blocking_result.get('triggered_rules'):
                    for rule in blocking_result['triggered_rules']:
                        if rule not in cumulative_blocking['triggered_rules']:
                            cumulative_blocking['triggered_rules'].append(rule)
            if blocking_result.get('alerts_created', 0) > 0:
                cumulative_blocking['alerts_created'] += blocking_result.get('alerts_created', 0)
            if blocking_result.get('triggered_rules') and not cumulative_blocking['triggered_rules']:
                cumulative_blocking['triggered_rules'] = blocking_result['triggered_rules']

            # Track proactive blocks
            if proactive_block and proactive_block.get('should_block'):
                cumulative_blocking['blocked'] = True
                cumulative_proactive = proactive_block
                if not cumulative_blocking['triggered_rules']:
                    cumulative_blocking['triggered_rules'] = [f"Proactive: {proactive_block.get('action_taken', 'blocked')}"]
                cumulative_blocking['proactive'] = True

    if result and result.get('success'):
        enrichment = result.get('enrichment', {})

        return {
            "success": True,
            "scenario_id": scenario_id,
            "scenario_name": scenario["name"],
            "ip": rotated_ip,
            "event_count": event_count,
            "event_id": result.get('event_id'),
            "is_private_ip": enrichment.get('is_private_ip', False),
            "blocking": cumulative_blocking,
            "proactive_block": cumulative_proactive,
            "actual_results": {
                "geoip": enrichment.get('geoip'),
                "ml": enrichment.get('ml'),
                "threat_intel": enrichment.get('threat_intel'),
                "behavioral": enrichment.get('behavioral')
            }
        }
    else:
        return {"success": False, "error": result.get('error') if result else "No result"}


def run_full_demo(verbose: bool = True) -> Dict:
    """Run all demo scenarios and return results."""
    results = []
    summary = {"total": len(DEMO_SCENARIOS), "successful": 0, "blocked": 0}

    if verbose:
        print("\n" + "=" * 60)
        print("SSH GUARDIAN v3.0 - FULL DEMO (10 SCENARIOS)")
        print("=" * 60)

    for scenario_id in DEMO_SCENARIOS:
        result = run_demo_scenario(scenario_id, verbose=verbose)
        results.append(result)

        if result.get('success'):
            summary['successful'] += 1
            if result.get('blocking', {}).get('blocked'):
                summary['blocked'] += 1

    if verbose:
        print("\n" + "=" * 60)
        print(f"SUMMARY: {summary['successful']}/{summary['total']} successful, {summary['blocked']} blocked")
        print("=" * 60)

    return {"success": True, "summary": summary, "results": results}

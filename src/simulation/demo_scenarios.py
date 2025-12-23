"""
SSH Guardian v3.0 - Demo Scenarios (Minimal Set)
10 essential attack simulations covering all detection mechanisms

CATEGORIES:
1. UFW BLOCKING (3) - Triggers SSH Guardian rules → UFW deny
2. FAIL2BAN (1) - Generates auth.log entries → fail2ban bans
3. ML BEHAVIORAL (3) - Advanced pattern detection using ML
4. ALERT ONLY (1) - Monitoring without blocking
5. PRIVATE IP (1) - Internal network threat detection
6. BASELINE (1) - Control scenario (no action)
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
# CATEGORY 1: UFW AUTO-BLOCK SCENARIOS (3)
# =============================================================================

UFW_BLOCKING_SCENARIOS = {
    "bad_reputation": {
        "id": "bad_reputation",
        "name": "Bad Reputation",
        "category": "ufw_block",
        "description": "IP with bad reputation (AbuseIPDB 70+). Blocked on failed login. Critical IPs (90+) blocked immediately.",
        "trigger": "AbuseIPDB score >= 70",
        "block_duration": "24 hours (critical: 7 days)",
        "rule_name": "abuseipdb_high_70",
        "severity": "high",
        "ip": "185.220.101.1",
        "alternate_ips": ["45.142.212.61", "185.220.101.2"],
        "why_blocked": "Known attacker IP reported by security community. High abuse score triggers automatic block.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Failed password for root from {ip} port {port} ssh2",
        "event_count": 1
    },

    "brute_force": {
        "id": "brute_force",
        "name": "Brute Force Attack",
        "category": "ufw_block",
        "description": "5+ failed login attempts in 10 minutes. Classic password guessing attack.",
        "trigger": "5 failed logins in 10 minutes",
        "block_duration": "24 hours",
        "rule_name": "brute_force_5_in_10min",
        "severity": "high",
        "ip": "91.240.118.172",
        "alternate_ips": ["45.227.254.0", "193.56.28.103"],
        "why_blocked": "Too many failed attempts indicates password guessing or credential stuffing attack.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Failed password for {username} from {ip} port {port} ssh2",
        "usernames": ["root", "admin", "user", "postgres", "mysql", "oracle", "test"],
        "event_count": 5
    },

    "anonymizer": {
        "id": "anonymizer",
        "name": "Anonymizer Attack (Tor/VPN)",
        "category": "ufw_block",
        "description": "Attack via Tor exit node, VPN, or proxy. Attacker hiding identity.",
        "trigger": "Tor/VPN/Proxy + failed login",
        "block_duration": "24 hours",
        "rule_name": "anonymizer_failed_login",
        "severity": "high",
        "ip": "185.220.101.1",
        "alternate_ips": ["185.220.102.1", "103.216.221.19"],
        "why_blocked": "Anonymization networks are commonly used by attackers. Legitimate users rarely SSH via Tor.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Failed password for root from {ip} port {port} ssh2",
        "event_count": 1
    },
}


# =============================================================================
# CATEGORY 2: FAIL2BAN SCENARIOS (1)
# =============================================================================

FAIL2BAN_SCENARIOS = {
    "fail2ban_trigger": {
        "id": "fail2ban_trigger",
        "name": "Fail2ban Trigger",
        "category": "fail2ban",
        "description": "5 failed SSH attempts. Fail2ban watches auth.log and bans automatically.",
        "trigger": "5 failed SSH logins (fail2ban maxretry)",
        "block_duration": "10 minutes (fail2ban default)",
        "mechanism": "fail2ban",
        "severity": "high",
        "ip": "10.99.99.1",
        "alternate_ips": ["10.99.99.2"],
        "why_blocked": "Fail2ban detects repeated failures in auth.log. No ML or API needed.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Failed password for {username} from {ip} port {port} ssh2",
        "usernames": ["root", "admin", "test", "guest", "ftpuser"],
        "event_count": 5
    },
}


# =============================================================================
# CATEGORY 3: ML BEHAVIORAL SCENARIOS (3)
# =============================================================================

ML_BEHAVIORAL_SCENARIOS = {
    "ml_impossible_travel": {
        "id": "ml_impossible_travel",
        "name": "Impossible Travel",
        "category": "ml_behavioral",
        "description": "User logs in from Boston, then Moscow 2 hours later. Physically impossible travel speed.",
        "trigger": "ML: Location change faster than possible travel",
        "block_duration": "24h IP block + session terminated",
        "rule_name": "ml_impossible_travel",
        "severity": "critical",
        "ip": "185.220.101.1",
        "alternate_ips": ["77.88.8.8", "200.160.2.3"],
        "why_blocked": "Account likely compromised. Legitimate user cannot travel 7,500km in 2 hours.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Accepted password for {username} from {ip} port {port} ssh2",
        "usernames": ["john.smith", "admin", "deploy"],
        "ml_factors": [
            {"type": "impossible_travel", "score": 40, "description": "Boston → Moscow in 2h = 3,750 km/h"},
            {"type": "new_location", "score": 20, "description": "First login from Russia"},
            {"type": "tor_exit", "score": 25, "description": "Connection via Tor network"}
        ],
        "tooltip": {
            "what_it_tests": "ML detecting physically impossible location changes",
            "expected_outcome": "Block IP + flag for security review",
            "why_ml_needed": "Rule-based systems don't track location history or calculate travel velocity"
        },
        "creates_baseline": True,
        "baseline_user": "john.smith",
        "baseline_location": {"city": "Boston", "country": "US", "lat": 42.36, "lon": -71.06},
        "event_count": 1
    },

    "ml_time_anomaly": {
        "id": "ml_time_anomaly",
        "name": "Time Anomaly",
        "category": "ml_behavioral",
        "description": "User typically logs in 9am-5pm, but suddenly logs in at 3:00 AM.",
        "trigger": "ML: Login time 6+ hours outside normal pattern",
        "block_duration": "Alert + elevated risk",
        "rule_name": "ml_time_anomaly",
        "severity": "medium",
        "ip": "24.48.0.1",
        "alternate_ips": ["73.162.0.1", "98.217.0.1"],
        "why_blocked": "Unusual activity time. May be legitimate but warrants verification.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Accepted password for {username} from {ip} port {port} ssh2",
        "usernames": ["alice.johnson", "dev.user"],
        "custom_time": "03:00:00",
        "ml_factors": [
            {"type": "unusual_time", "score": 25, "description": "Login at 3:00 AM, typical hours 9am-5pm"},
            {"type": "new_ip_for_user", "score": 15, "description": "First time from this IP"}
        ],
        "tooltip": {
            "what_it_tests": "ML pattern analysis of user's typical login schedule",
            "expected_outcome": "Risk score elevated, potential MFA challenge",
            "why_ml_needed": "Requires learning each user's normal behavior pattern"
        },
        "creates_baseline": True,
        "baseline_user": "alice.johnson",
        "baseline_hours": [9, 10, 11, 12, 13, 14, 15, 16, 17],
        "event_count": 1
    },

    "ml_lateral_movement": {
        "id": "ml_lateral_movement",
        "name": "Lateral Movement",
        "category": "ml_behavioral",
        "description": "Same internal IP accessing multiple servers rapidly. Possible insider threat or compromised host.",
        "trigger": "ML: Same IP accessing multiple servers in short window",
        "block_duration": "Block on all servers + investigation",
        "rule_name": "ml_lateral_movement",
        "severity": "critical",
        "ip": "10.0.1.50",
        "alternate_ips": ["192.168.1.100", "172.16.0.25"],
        "why_blocked": "Unusual access pattern from internal network. Either insider threat or compromised machine.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Accepted password for {username} from {ip} port {port} ssh2",
        "usernames": ["deploy", "svc_account", "admin"],
        "ml_factors": [
            {"type": "multi_server_access", "score": 30, "description": "5 different servers in 10 minutes"},
            {"type": "service_account", "score": 10, "description": "Using deploy/service account"},
            {"type": "unusual_pattern", "score": 15, "description": "Not matching normal automation patterns"}
        ],
        "tooltip": {
            "what_it_tests": "ML cross-server correlation detecting lateral movement from private IPs",
            "expected_outcome": "Block on all servers, investigate source",
            "why_ml_needed": "Requires correlating events across multiple servers in real-time"
        },
        "multi_server": True,
        "server_count": 5,
        "event_count": 1
    },
}


# =============================================================================
# CATEGORY 4: ALERT-ONLY SCENARIOS (1)
# =============================================================================

ALERT_ONLY_SCENARIOS = {
    "alert_anomaly": {
        "id": "alert_anomaly",
        "name": "Alert: Behavioral Anomaly",
        "category": "alert_only",
        "action_type": "alert",
        "description": "Successful login with moderate risk score. Multiple minor anomalies detected but not enough to block.",
        "trigger": "ML risk score 30-50 on successful login",
        "block_duration": "NO BLOCK - Alert Only",
        "rule_name": "alert_behavioral_anomaly",
        "severity": "medium",
        "ip": "73.162.0.1",
        "alternate_ips": ["24.48.0.1", "82.132.234.1"],
        "why_alerted": "Multiple minor risk factors combined. Not enough for block but warrants monitoring.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Accepted password for {username} from {ip} port {port} ssh2",
        "usernames": ["dev.user", "engineer", "analyst"],
        "custom_time": "03:30:00",
        "ml_factors": [
            {"type": "unusual_time", "score": 25, "description": "3:30 AM login vs 9am-5pm pattern"},
            {"type": "new_ip_for_user", "score": 15, "description": "First time from this IP"}
        ],
        "tooltip": {
            "what_it_tests": "Alerting on moderate risk without blocking",
            "expected_outcome": "Alert sent via Telegram. No IP block.",
            "why_not_blocked": "Score below blocking threshold but warrants attention"
        },
        "creates_baseline": True,
        "baseline_user": "dev.user",
        "baseline_hours": [9, 10, 11, 12, 13, 14, 15, 16, 17],
        "event_count": 1
    },
}


# =============================================================================
# CATEGORY 5: PRIVATE IP SCENARIOS (1)
# =============================================================================

PRIVATE_IP_SCENARIOS = {
    "private_ip_insider": {
        "id": "private_ip_insider",
        "name": "Private IP: Insider Threat",
        "category": "private_ip",
        "description": "Internal network login at 3 AM with brute force pattern. Tests behavioral-only analysis for private IPs.",
        "trigger": "Behavioral: Unusual time + brute force from private IP",
        "block_duration": "Alert + elevated risk",
        "rule_name": "private_ip_behavioral",
        "severity": "high",
        "ip": "192.168.1.100",
        "alternate_ips": ["10.0.0.50", "172.16.0.25"],
        "why_blocked": "Private IPs use behavioral-only analysis (skip GeoIP/ThreatIntel). Late night + rapid attempts indicates insider threat.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Failed password for {username} from {ip} port {port} ssh2",
        "usernames": ["root", "admin", "deploy"],
        "custom_time": "03:00:00",
        "behavioral_factors": [
            {"type": "unusual_login_time", "score": 25, "description": "Login at 3:00 AM"},
            {"type": "new_ip_for_user", "score": 15, "description": "First login from this private IP"},
            {"type": "brute_force_pattern", "score": 30, "description": "20+ failed attempts in 24h"}
        ],
        "tooltip": {
            "what_it_tests": "Behavioral analysis for internal network IPs",
            "expected_outcome": "Risk score calculated from behavioral factors only",
            "why_different": "Private IPs skip GeoIP and ThreatIntel lookups - focus on behavior"
        },
        "is_private_ip": True,
        "event_count": 5
    },
}


# =============================================================================
# CATEGORY 6: BASELINE SCENARIOS (1)
# =============================================================================

BASELINE_SCENARIOS = {
    "clean_baseline": {
        "id": "clean_baseline",
        "name": "Clean Baseline",
        "category": "baseline",
        "description": "Clean IP with zero threat reputation. Tests that system does NOT create false positives.",
        "trigger": "None - clean successful login",
        "block_duration": "N/A - NO BLOCK expected",
        "severity": "low",
        "ip": "8.8.8.8",
        "alternate_ips": ["1.1.1.1"],
        "why_not_blocked": "AbuseIPDB score=0, no suspicious patterns. Legitimate Google DNS IP.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Accepted password for testuser from {ip} port {port} ssh2",
        "event_count": 1,
        "expected_outcome": {
            "block": False,
            "alert": False,
            "ml_score_max": 20
        }
    },
}


# =============================================================================
# COMBINED SCENARIOS
# =============================================================================

DEMO_SCENARIOS = {
    **UFW_BLOCKING_SCENARIOS,
    **FAIL2BAN_SCENARIOS,
    **ML_BEHAVIORAL_SCENARIOS,
    **ALERT_ONLY_SCENARIOS,
    **PRIVATE_IP_SCENARIOS,
    **BASELINE_SCENARIOS
}


def get_scenarios_by_category() -> Dict[str, List[Dict]]:
    """Get scenarios organized by blocking category"""
    return {
        "ufw_blocking": list(UFW_BLOCKING_SCENARIOS.values()),
        "fail2ban": list(FAIL2BAN_SCENARIOS.values()),
        "ml_behavioral": list(ML_BEHAVIORAL_SCENARIOS.values()),
        "alert_only": list(ALERT_ONLY_SCENARIOS.values()),
        "private_ip": list(PRIVATE_IP_SCENARIOS.values()),
        "baseline": list(BASELINE_SCENARIOS.values())
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

    # Try fresh IP pool for attack scenarios
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
    result = None
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

    if result and result.get('success'):
        enrichment = result.get('enrichment', {})
        blocking_result = enrichment.get('blocking', {})

        return {
            "success": True,
            "scenario_id": scenario_id,
            "scenario_name": scenario["name"],
            "ip": rotated_ip,
            "event_count": event_count,
            "event_id": result.get('event_id'),
            "is_private_ip": enrichment.get('is_private_ip', False),
            "blocking": blocking_result,
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

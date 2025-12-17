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
        "event_count": 2
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
        "description": "Normal IP with good reputation. Should NOT be blocked.",
        "trigger": "None - clean activity",
        "block_duration": "N/A",
        "severity": "low",
        "ip": "8.8.8.8",
        "alternate_ips": ["1.1.1.1"],
        "why_not_blocked": "Low abuse score, no suspicious patterns, legitimate source.",
        "log_template": "Dec {day} {time} server sshd[{pid}]: Accepted publickey for deploy from {ip} port {port} ssh2"
    },
}


# Combine all scenarios for backward compatibility
DEMO_SCENARIOS = {
    **UFW_BLOCKING_SCENARIOS,
    **FAIL2BAN_SCENARIOS,
    **BASELINE_SCENARIOS
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
        scenarios.append({
            "id": scenario["id"],
            "name": scenario["name"],
            "description": scenario["description"],
            "severity": scenario["severity"],
            "category": scenario.get("category", "unknown"),
            "ip": ip or scenario["ip"],
            "trigger": scenario.get("trigger", ""),
            "block_duration": scenario.get("block_duration", ""),
            "why_blocked": scenario.get("why_blocked", scenario.get("why_not_blocked", "")),
            "rule_name": scenario.get("rule_name", ""),
            "expected_results": {
                "rule_triggered": scenario.get("rule_name", ""),
                "block_action": scenario.get("block_duration", "NO BLOCK"),
                "threat_level": scenario.get("severity", "unknown").upper()
            }
        })
    return scenarios


def get_demo_scenario(scenario_id: str) -> Optional[Dict]:
    """Get a specific demo scenario"""
    return DEMO_SCENARIOS.get(scenario_id)


def get_rotated_ip(scenario_id: str) -> str:
    """Get IP for scenario with optional rotation"""
    scenario = DEMO_SCENARIOS.get(scenario_id)
    if not scenario:
        return None

    # Try fresh IP pool first
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
    scenario = DEMO_SCENARIOS.get(scenario_id)
    if not scenario:
        return None

    now = datetime.now()
    ip_to_use = custom_ip if custom_ip else get_rotated_ip(scenario_id)

    template = scenario.get("log_template", "")
    if not template:
        return None

    # Random username for credential stuffing scenarios
    usernames = scenario.get('usernames', ['root', 'admin', 'user'])

    log = template.format(
        day=now.day,
        time=now.strftime("%H:%M:%S"),
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

    # Process entries
    result = None
    for i in range(event_count):
        log_line = generate_demo_log(scenario_id, custom_ip=rotated_ip)
        if verbose:
            print(f"  [{i+1}] {log_line}")

        result = process_log_line(
            log_line,
            source_type='agent' if agent_id else 'simulation',
            agent_id=agent_id,
            skip_blocking=(agent_id is None)
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
                "blocking": blocking_result
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

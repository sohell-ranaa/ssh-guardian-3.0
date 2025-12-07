"""
SSH Guardian v3.0 - Demo Scenarios
Real-world malicious IP demonstrations for stakeholder presentations
"""

import sys
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src"))


# Known malicious IPs with verified threat intelligence
# These are real IPs that will return results from AbuseIPDB/VirusTotal
# Each scenario can have multiple IPs for rotation
# UPDATED: Scenarios aligned with aggressive blocking rules
DEMO_SCENARIOS = {
    # =============================================
    # CRITICAL TIER - AbuseIPDB >= 90 (Always Block)
    # =============================================
    "abuseipdb_critical": {
        "id": "abuseipdb_critical",
        "name": "AbuseIPDB Critical (90+)",
        "description": "Critical threat score (>=90) - ALWAYS BLOCKED even on successful login. 7-day ban.",
        "severity": "critical",
        "category": "reputation",
        "ip": "185.220.101.1",  # Known Tor exit with 100% abuse score
        "alternate_ips": ["185.220.101.2", "185.220.101.54", "193.56.28.103"],
        "rotate_ips": True,
        "expected_results": {
            "abuseipdb_score": ">=90",
            "block_action": "IMMEDIATE BLOCK (7 days)",
            "rule_triggered": "abuseipdb_critical_90",
            "threat_level": "CRITICAL",
            "ml_anomaly": True
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"
    },

    "tor_exit_attack": {
        "id": "tor_exit_attack",
        "name": "Tor Exit Node + Failed Login",
        "description": "Tor exit node with failed login - triggers tor_failed_login rule. 24-hour ban.",
        "severity": "critical",
        "category": "anonymization",
        "ip": "185.220.101.1",  # Known Tor exit node
        "alternate_ips": ["185.220.101.2", "185.220.101.3", "185.220.102.1"],
        "rotate_ips": True,
        "expected_results": {
            "abuseipdb_score": ">90",
            "block_action": "BLOCKED (24 hours)",
            "rule_triggered": "tor_failed_login",
            "threat_level": "HIGH",
            "ml_anomaly": True
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"
    },

    # =============================================
    # HIGH TIER - AbuseIPDB >= 70 (Block Immediately)
    # =============================================
    "abuseipdb_high": {
        "id": "abuseipdb_high",
        "name": "AbuseIPDB High (70+)",
        "description": "High threat score (>=70) - blocked immediately on any activity. 24-hour ban.",
        "severity": "critical",
        "category": "reputation",
        "ip": "45.142.212.61",  # Commonly reported attacker
        "alternate_ips": ["185.220.101.1", "193.56.28.103"],
        "rotate_ips": True,
        "expected_results": {
            "abuseipdb_score": ">=70",
            "block_action": "IMMEDIATE BLOCK (24 hours)",
            "rule_triggered": "abuseipdb_high_70",
            "threat_level": "HIGH",
            "ml_anomaly": True
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Failed password for admin from {ip} port {port} ssh2"
    },

    # =============================================
    # BRUTE FORCE - 5 fails in 10 minutes
    # =============================================
    "brute_force_5_fails": {
        "id": "brute_force_5_fails",
        "name": "Brute Force (5 fails/10min)",
        "description": "5 failed login attempts in 10 minutes - triggers brute_force_5_in_10min rule. 24-hour ban.",
        "severity": "critical",
        "category": "authentication",
        "ip": "91.240.118.172",  # Known attacker
        "alternate_ips": ["45.142.212.61", "193.56.28.103"],
        "rotate_ips": True,
        "expected_results": {
            "abuseipdb_score": "Variable",
            "block_action": "BLOCKED after 5 fails (24 hours)",
            "rule_triggered": "brute_force_5_in_10min",
            "threat_level": "HIGH",
            "ml_anomaly": True
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"
    },

    # =============================================
    # CREDENTIAL STUFFING - 5 unique usernames
    # =============================================
    "credential_stuffing": {
        "id": "credential_stuffing",
        "name": "Credential Stuffing (5 users)",
        "description": "5 different usernames in 15 minutes - triggers cred_stuff_5_users_15min rule. 48-hour ban.",
        "severity": "critical",
        "category": "authentication",
        "ip": "45.227.254.0",  # Known credential stuffing source
        "alternate_ips": ["193.56.28.103", "185.220.101.1"],
        "rotate_ips": True,
        "expected_results": {
            "abuseipdb_score": ">60",
            "block_action": "BLOCKED (48 hours)",
            "rule_triggered": "cred_stuff_5_users_15min",
            "threat_level": "HIGH",
            "ml_anomaly": True
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Failed password for invalid user {username} from {ip} port {port} ssh2"
    },

    # =============================================
    # VELOCITY/DDoS - 20 events per minute
    # =============================================
    "ddos_velocity": {
        "id": "ddos_velocity",
        "name": "DDoS/Velocity (20 events/min)",
        "description": "20+ events per minute - triggers ddos_20_per_min rule. 7-day ban.",
        "severity": "critical",
        "category": "ddos",
        "ip": "185.156.73.0",  # Known botnet IP
        "alternate_ips": ["91.240.118.172", "193.56.28.103"],
        "rotate_ips": True,
        "expected_results": {
            "abuseipdb_score": ">70",
            "block_action": "BLOCKED (7 days)",
            "rule_triggered": "ddos_20_per_min",
            "threat_level": "CRITICAL",
            "ml_anomaly": True
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Failed password for invalid user admin from {ip} port {port} ssh2"
    },

    # =============================================
    # VPN/PROXY + SCORE >= 30
    # =============================================
    "vpn_proxy_attack": {
        "id": "vpn_proxy_attack",
        "name": "VPN/Proxy + Score 30+",
        "description": "VPN/Proxy IP with AbuseIPDB >= 30 - triggers vpn_proxy_score_30 rule. 12-hour ban.",
        "severity": "high",
        "category": "anonymization",
        "ip": "103.216.221.19",  # Known VPN IP
        "alternate_ips": ["45.142.212.61", "91.240.118.172"],
        "rotate_ips": True,
        "expected_results": {
            "abuseipdb_score": ">=30",
            "block_action": "BLOCKED (12 hours)",
            "rule_triggered": "vpn_proxy_score_30",
            "threat_level": "MEDIUM-HIGH",
            "ml_anomaly": True
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Failed password for admin from {ip} port {port} ssh2"
    },

    # =============================================
    # HIGH-RISK COUNTRY + 2 FAILS
    # =============================================
    "high_risk_country": {
        "id": "high_risk_country",
        "name": "High-Risk Country + 2 Fails",
        "description": "Attack from CN/RU/KP/IR/BY with 2+ failed logins - triggers high_risk_country_2_fails. 24-hour ban.",
        "severity": "high",
        "category": "geographic",
        "ip": "218.92.0.107",  # China-based IP
        "alternate_ips": ["39.96.0.0", "45.142.212.61"],
        "rotate_ips": True,
        "expected_results": {
            "abuseipdb_score": "Variable",
            "block_action": "BLOCKED after 2 fails (24 hours)",
            "rule_triggered": "high_risk_country_2_fails",
            "threat_level": "HIGH",
            "ml_anomaly": True
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"
    },

    # =============================================
    # THREAT COMBO - Combined Signals
    # =============================================
    "threat_combo_tor": {
        "id": "threat_combo_tor",
        "name": "Threat Combo (Abuse 50 + Tor)",
        "description": "AbuseIPDB >= 50 + Tor + Failed login - triggers combo_abuse50_tor_fail. 48-hour ban.",
        "severity": "critical",
        "category": "combo",
        "ip": "185.220.101.54",  # Known Tor with high abuse
        "alternate_ips": ["185.220.101.1", "185.220.102.1"],
        "rotate_ips": True,
        "expected_results": {
            "abuseipdb_score": ">=50",
            "block_action": "BLOCKED (48 hours)",
            "rule_triggered": "combo_abuse50_tor_fail",
            "threat_level": "CRITICAL",
            "ml_anomaly": True
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"
    },

    "virustotal_5_vendors": {
        "id": "virustotal_5_vendors",
        "name": "VirusTotal 5+ Vendors",
        "description": "Flagged by 5+ VirusTotal vendors - triggers combo_vt_5_positives. 24-hour ban.",
        "severity": "critical",
        "category": "malware",
        "ip": "193.56.28.103",  # Known malicious infrastructure
        "alternate_ips": ["45.142.212.61", "185.156.73.0"],
        "rotate_ips": True,
        "expected_results": {
            "virustotal": ">=5 vendors",
            "block_action": "BLOCKED (24 hours)",
            "rule_triggered": "combo_vt_5_positives",
            "threat_level": "CRITICAL",
            "ml_anomaly": True
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Failed password for invalid user oracle from {ip} port {port} ssh2"
    },

    # =============================================
    # IMPOSSIBLE TRAVEL - 1000km in 2 hours
    # =============================================
    "impossible_travel": {
        "id": "impossible_travel",
        "name": "Impossible Travel (1000km/2hr)",
        "description": "Same username from location >1000km away within 2 hours. 24-hour ban + notification.",
        "severity": "high",
        "category": "geo_anomaly",
        "ip": "39.96.0.0",  # China (test with user who logged in from US recently)
        "alternate_ips": ["218.92.0.107", "45.142.212.61"],
        "rotate_ips": True,
        "expected_results": {
            "abuseipdb_score": "Variable",
            "block_action": "BLOCKED (24 hours) + NOTIFY",
            "rule_triggered": "impossible_travel_1000km_2hr",
            "threat_level": "HIGH",
            "ml_anomaly": True
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Failed password for admin from {ip} port {port} ssh2"
    },

    # =============================================
    # MEDIUM TIER - AbuseIPDB >= 50 (Block on 1 fail)
    # =============================================
    "abuseipdb_medium": {
        "id": "abuseipdb_medium",
        "name": "AbuseIPDB Medium (50+)",
        "description": "Medium threat score (>=50) - blocked on first failed login. 12-hour ban.",
        "severity": "high",
        "category": "reputation",
        "ip": "162.142.125.0",  # Known scanner
        "alternate_ips": ["91.240.118.172", "185.220.101.1"],
        "rotate_ips": True,
        "expected_results": {
            "abuseipdb_score": ">=50",
            "block_action": "BLOCKED on fail (12 hours)",
            "rule_triggered": "abuseipdb_medium_50",
            "threat_level": "MEDIUM-HIGH",
            "ml_anomaly": True
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Failed password for invalid user test from {ip} port {port} ssh2"
    },

    # =============================================
    # DATACENTER/HOSTING IP
    # =============================================
    "datacenter_attack": {
        "id": "datacenter_attack",
        "name": "Datacenter IP Attack",
        "description": "Attack from datacenter/hosting IP - +15 risk boost, often indicates compromised VPS.",
        "severity": "high",
        "category": "infrastructure",
        "ip": "167.172.248.37",  # DigitalOcean datacenter
        "alternate_ips": ["206.189.156.201", "159.89.133.246"],
        "rotate_ips": True,
        "expected_results": {
            "abuseipdb_score": ">30",
            "block_action": "Risk +15, may trigger other rules",
            "rule_triggered": "Multiple rules possible",
            "threat_level": "MEDIUM",
            "ml_anomaly": True
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"
    },

    # =============================================
    # NIGHT-TIME LOGIN (+20 Risk)
    # =============================================
    "night_time_login": {
        "id": "night_time_login",
        "name": "Night-Time Login (10PM-6AM)",
        "description": "Login during night hours gets +20 risk boost. Combined with other factors may trigger block.",
        "severity": "medium",
        "category": "time_anomaly",
        "ip": "45.142.212.61",
        "alternate_ips": ["193.56.28.103", "91.240.118.172"],
        "rotate_ips": True,
        "expected_results": {
            "risk_boost": "+20 for night time",
            "block_action": "Risk adjusted, rules evaluated",
            "rule_triggered": "Time-based risk adjustment",
            "threat_level": "ELEVATED",
            "ml_anomaly": "Possible"
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Failed password for admin from {ip} port {port} ssh2"
    },

    # =============================================
    # CLEAN BASELINE - For Comparison
    # =============================================
    "clean_baseline": {
        "id": "clean_baseline",
        "name": "Clean IP Baseline",
        "description": "Google DNS (clean reputation) - demonstrates no blocking for legitimate IPs.",
        "severity": "low",
        "category": "baseline",
        "ip": "8.8.8.8",  # Google DNS - known clean
        "alternate_ips": ["8.8.4.4", "1.1.1.1"],  # Cloudflare DNS
        "rotate_ips": False,
        "expected_results": {
            "abuseipdb_score": "0-10",
            "block_action": "NO BLOCK",
            "rule_triggered": "None",
            "threat_level": "CLEAN",
            "ml_anomaly": False
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Accepted publickey for deploy from {ip} port {port} ssh2"
    },

    # =============================================
    # REPEAT OFFENDER - Escalating Blocks
    # =============================================
    "repeat_offender": {
        "id": "repeat_offender",
        "name": "Repeat Offender (Escalation)",
        "description": "Previously blocked IP - block duration escalates: 2nd=2x, 3rd=7 days, 4th+=30 days.",
        "severity": "critical",
        "category": "repeat",
        "ip": "185.156.73.0",  # Known repeat offender
        "alternate_ips": ["193.56.28.103", "45.142.212.61"],
        "rotate_ips": True,
        "expected_results": {
            "abuseipdb_score": ">70",
            "block_action": "ESCALATED BLOCK (2x → 7d → 30d)",
            "rule_triggered": "repeat_offender_escalation",
            "threat_level": "CRITICAL",
            "ml_anomaly": True
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"
    }
}


def get_demo_scenarios(use_fresh_ips: bool = True) -> List[Dict]:
    """
    Get list of all demo scenarios for UI

    Args:
        use_fresh_ips: If True, attempts to get fresh IPs from the pool for each scenario.
                       If False, uses the default hardcoded IPs.
    """
    scenarios = []
    for scenario_id, scenario in DEMO_SCENARIOS.items():
        # Get IP - either fresh from pool or rotated from defaults
        if use_fresh_ips:
            ip = get_rotated_ip(scenario_id)
        else:
            ip = scenario["ip"]

        scenarios.append({
            "id": scenario["id"],
            "name": scenario["name"],
            "description": scenario["description"],
            "severity": scenario["severity"],
            "category": scenario["category"],
            "ip": ip or scenario["ip"],  # Fallback to default if rotation fails
            "expected_results": scenario["expected_results"]
        })
    return scenarios


def get_demo_scenario(scenario_id: str) -> Optional[Dict]:
    """Get a specific demo scenario"""
    return DEMO_SCENARIOS.get(scenario_id)


def get_rotated_ip(scenario_id: str) -> str:
    """
    Get IP for scenario - prefers fresh IPs from pool, falls back to hardcoded.

    Returns:
        IP address from fresh pool or scenario defaults
    """
    import random

    scenario = DEMO_SCENARIOS.get(scenario_id)
    if not scenario:
        return None

    # Map scenario categories to IP pool categories
    category_map = {
        # Critical tier
        'abuseipdb_critical': 'brute_force',
        'tor_exit_attack': 'tor_exit',
        'abuseipdb_high': 'brute_force',
        # Brute force / credential stuffing
        'brute_force_5_fails': 'brute_force',
        'credential_stuffing': 'brute_force',
        # DDoS / Velocity
        'ddos_velocity': 'ddos_botnet',
        # Anonymization
        'vpn_proxy_attack': 'brute_force',
        # Geographic
        'high_risk_country': 'brute_force',
        # Threat combos
        'threat_combo_tor': 'tor_exit',
        'virustotal_5_vendors': 'botnet',
        # Geo anomaly
        'impossible_travel': 'brute_force',
        # Medium tier
        'abuseipdb_medium': 'scanner',
        # Infrastructure
        'datacenter_attack': 'brute_force',
        # Time-based
        'night_time_login': 'brute_force',
        # Repeat offender
        'repeat_offender': 'brute_force'
    }

    # Try to get fresh IP from pool first
    try:
        from simulation.ip_fetcher import get_fresh_ip
        pool_category = category_map.get(scenario_id, 'brute_force')
        fresh_ip = get_fresh_ip(pool_category)
        if fresh_ip:
            return fresh_ip
    except Exception:
        pass  # Fall back to hardcoded IPs

    # Fallback: use hardcoded rotation
    if scenario.get('rotate_ips', False) and scenario.get('alternate_ips'):
        all_ips = [scenario['ip']] + scenario['alternate_ips']
        return random.choice(all_ips)

    return scenario['ip']


def generate_demo_log(scenario_id: str, custom_ip: str = None) -> Optional[str]:
    """
    Generate a log line for a demo scenario

    Args:
        scenario_id: ID of the scenario
        custom_ip: Optional custom IP to use (for rotation)
    """
    import random

    scenario = DEMO_SCENARIOS.get(scenario_id)
    if not scenario:
        return None

    now = datetime.now()
    ip_to_use = custom_ip if custom_ip else get_rotated_ip(scenario_id)

    # Get template and handle special cases
    template = scenario["log_template"]

    # For credential stuffing, add random usernames
    usernames = ['admin', 'root', 'user', 'oracle', 'postgres', 'mysql', 'test', 'ubuntu', 'deploy']

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
    """
    Execute a single demo scenario with full enrichment pipeline.

    Args:
        scenario_id: ID of the demo scenario to run
        verbose: Print progress messages
        agent_id: Optional agent ID to target (for full pipeline mode)
        run_full_pipeline: If True, runs full pipeline including IP blocking and UFW commands

    Returns:
        Dict with demo results
    """
    from core.log_processor import process_log_line

    scenario = DEMO_SCENARIOS.get(scenario_id)
    if not scenario:
        return {"success": False, "error": f"Unknown scenario: {scenario_id}"}

    if verbose:
        print(f"\n{'='*60}")
        print(f"DEMO: {scenario['name']}")
        print(f"{'='*60}")
        print(f"Description: {scenario['description']}")
        print(f"IP: {scenario['ip']}")
        print(f"Expected: {scenario['expected_results']}")
        print(f"{'='*60}")

    # Generate log line with rotated IP
    rotated_ip = get_rotated_ip(scenario_id)
    log_line = generate_demo_log(scenario_id, custom_ip=rotated_ip)

    if verbose:
        print(f"\nUsing IP: {rotated_ip} (Rotation: {'ON' if scenario.get('rotate_ips') else 'OFF'})")
        print(f"Log: {log_line}")
        print(f"\nProcessing...")

    # Process through full pipeline
    # Skip blocking if no agent selected (analysis-only mode)
    result = process_log_line(
        log_line,
        source_type='agent' if agent_id else 'simulation',
        agent_id=agent_id,
        skip_blocking=(agent_id is None)  # Only block when agent is selected
    )

    if result.get('success'):
        enrichment = result.get('enrichment', {})
        event_id = result.get('event_id')

        # Pipeline step results
        pipeline_steps = {
            'event_created': {'status': 'success', 'event_id': event_id},
            'enrichment': {'status': 'success' if enrichment else 'skipped'},
            'ip_blocked': {'status': 'skipped', 'is_blocked': False},
            'ufw_command': {'status': 'skipped', 'command_exists': False},
            'notification': {'status': 'skipped', 'count': 0}
        }

        # Run full pipeline if requested (IP blocking, UFW commands, notifications)
        if run_full_pipeline and agent_id:
            from simulation.pipeline_executor import execute_pipeline
            pipeline_steps = execute_pipeline(
                event_id=event_id,
                source_ip=rotated_ip,
                agent_id=agent_id,
                enrichment=enrichment
            )

        # Get blocking result from enrichment
        blocking_result = enrichment.get('blocking', {})

        demo_result = {
            "success": True,
            "scenario_id": scenario_id,
            "scenario_name": scenario["name"],
            "ip": rotated_ip,  # Use the actual rotated IP
            "default_ip": scenario["ip"],  # Keep default for reference
            "ip_rotated": rotated_ip != scenario["ip"],  # Flag if IP was rotated
            "expected": scenario["expected_results"],
            "event_id": event_id,
            "event_type": result.get('event_type'),
            "agent_id": agent_id,
            "run_full_pipeline": run_full_pipeline,
            "pipeline_steps": pipeline_steps,
            "blocking": blocking_result,  # Include blocking result
            "actual_results": {
                "geoip": enrichment.get('geoip'),
                "ml": enrichment.get('ml'),
                "threat_intel": enrichment.get('threat_intel'),
                "blocking": blocking_result  # Also in actual_results for consistency
            }
        }

        # Update pipeline steps with blocking info
        if blocking_result.get('blocked'):
            pipeline_steps['ip_blocked'] = {
                'status': 'success',
                'is_blocked': True,
                'block_id': blocking_result.get('block_id'),
                'triggered_rules': blocking_result.get('triggered_rules', []),
                'duration': blocking_result.get('adjusted_duration')
            }

        if verbose:
            print(f"\n{'='*60}")
            print("RESULTS:")
            print(f"{'='*60}")

            # Threat Intel
            threat = enrichment.get('threat_intel', {}) or {}
            if threat:
                abuse = threat.get('abuseipdb', {}) or {}
                vt = threat.get('virustotal', {}) or {}
                abuseipdb_score = threat.get('abuseipdb_score') or abuse.get('score', 'N/A')
                abuseipdb_reports = threat.get('abuseipdb_reports') or abuse.get('reports', 'N/A')
                vt_positives = threat.get('virustotal_positives') or vt.get('positives', 0)
                vt_total = threat.get('virustotal_total') or vt.get('total', 0)
                threat_level = threat.get('overall_threat_level') or threat.get('threat_level', 'unknown')
                print(f"AbuseIPDB Score: {abuseipdb_score}")
                print(f"AbuseIPDB Reports: {abuseipdb_reports}")
                print(f"VirusTotal: {vt_positives}/{vt_total} detections")
                print(f"Threat Level: {threat_level.upper() if threat_level else 'UNKNOWN'}")

            # ML Results
            ml = enrichment.get('ml', {})
            if ml.get('ml_available'):
                print(f"\nML Risk Score: {ml.get('risk_score')}/100")
                print(f"ML Threat Type: {ml.get('threat_type')}")
                # Convert confidence to float to handle Decimal types
                confidence = float(ml.get('confidence', 0)) if ml.get('confidence') else 0.0
                print(f"ML Confidence: {confidence*100:.1f}%")
                print(f"Anomaly Detected: {'YES' if ml.get('is_anomaly') else 'NO'}")

            print(f"{'='*60}\n")

        return demo_result
    else:
        return {"success": False, "error": result.get('error')}


def run_full_demo(verbose: bool = True) -> Dict:
    """
    Run all demo scenarios and return comprehensive results.

    Args:
        verbose: Print progress messages

    Returns:
        Dict with all demo results
    """
    results = []
    summary = {
        "total_scenarios": len(DEMO_SCENARIOS),
        "successful": 0,
        "anomalies_detected": 0,
        "high_risk_detected": 0
    }

    if verbose:
        print("\n" + "=" * 70)
        print("SSH GUARDIAN v3.0 - FULL DEMONSTRATION")
        print(f"Running {len(DEMO_SCENARIOS)} scenarios...")
        print("=" * 70)

    for scenario_id in DEMO_SCENARIOS:
        result = run_demo_scenario(scenario_id, verbose=verbose)
        results.append(result)

        if result.get('success'):
            summary['successful'] += 1

            actual = result.get('actual_results', {})
            ml = actual.get('ml', {})

            if ml.get('is_anomaly'):
                summary['anomalies_detected'] += 1

            if ml.get('risk_score', 0) >= 60:
                summary['high_risk_detected'] += 1

    if verbose:
        print("\n" + "=" * 70)
        print("DEMONSTRATION SUMMARY")
        print("=" * 70)
        print(f"Total Scenarios: {summary['total_scenarios']}")
        print(f"Successful: {summary['successful']}")
        print(f"Anomalies Detected: {summary['anomalies_detected']}")
        print(f"High Risk (>60): {summary['high_risk_detected']}")
        print("=" * 70 + "\n")

    return {
        "success": True,
        "summary": summary,
        "results": results,
        "timestamp": datetime.now().isoformat()
    }

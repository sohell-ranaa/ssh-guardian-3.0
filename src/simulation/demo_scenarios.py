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
DEMO_SCENARIOS = {
    "tor_exit_attack": {
        "id": "tor_exit_attack",
        "name": "Tor Exit Node Attack",
        "description": "Known Tor exit node attempting root login - demonstrates detection of anonymized attacks",
        "severity": "critical",
        "category": "anonymization",
        "ip": "185.220.101.1",  # Known Tor exit node
        "alternate_ips": ["185.220.101.2", "185.220.101.3", "185.220.102.1"],  # More Tor exits
        "rotate_ips": True,
        "expected_results": {
            "abuseipdb_score": ">90",
            "virustotal": "Multiple detections",
            "threat_level": "HIGH",
            "ml_anomaly": True
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"
    },

    "high_abuse_ip": {
        "id": "high_abuse_ip",
        "name": "High AbuseIPDB Score Attack",
        "description": "IP with high abuse score attempting brute force - demonstrates reputation-based detection",
        "severity": "critical",
        "category": "reputation",
        "ip": "45.142.212.61",  # Commonly reported attacker
        "alternate_ips": ["185.220.101.1", "193.56.28.103"],
        "rotate_ips": True,
        "expected_results": {
            "abuseipdb_score": ">50",
            "virustotal": "Possible detections",
            "threat_level": "MEDIUM-HIGH",
            "ml_anomaly": True
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Failed password for admin from {ip} port {port} ssh2"
    },

    "botnet_ip": {
        "id": "botnet_ip",
        "name": "Botnet C2 IP Attack",
        "description": "Known botnet command-and-control IP - demonstrates threat intelligence integration",
        "severity": "critical",
        "category": "malware",
        "ip": "193.56.28.103",  # Known malicious infrastructure
        "alternate_ips": ["45.142.212.61", "185.156.73.0"],
        "rotate_ips": True,
        "expected_results": {
            "abuseipdb_score": "Variable",
            "virustotal": "Multiple detections",
            "threat_level": "HIGH",
            "ml_anomaly": True
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Failed password for invalid user oracle from {ip} port {port} ssh2"
    },

    "scanner_ip": {
        "id": "scanner_ip",
        "name": "Mass Scanner Attack",
        "description": "Internet-wide scanner probing services - demonstrates reconnaissance detection",
        "severity": "high",
        "category": "reconnaissance",
        "ip": "91.240.118.172",  # Known scanner
        "alternate_ips": ["162.142.125.0", "185.220.101.1"],
        "rotate_ips": True,
        "expected_results": {
            "abuseipdb_score": "Variable",
            "virustotal": "Possible detections",
            "threat_level": "MEDIUM-HIGH",
            "ml_anomaly": True
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Failed password for invalid user test from {ip} port {port} ssh2"
    },

    "geographic_anomaly": {
        "id": "geographic_anomaly",
        "name": "Geographic Anomaly",
        "description": "Attack from high-risk geographic region - demonstrates geo-based detection",
        "severity": "medium",
        "category": "geographic",
        "ip": "218.92.0.107",  # China-based IP
        "alternate_ips": ["39.96.0.0", "45.142.212.61"],
        "rotate_ips": True,
        "expected_results": {
            "abuseipdb_score": "Variable",
            "virustotal": "Possible detections",
            "threat_level": "LOW-MEDIUM",
            "ml_anomaly": "Possible"
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"
    },

    "clean_baseline": {
        "id": "clean_baseline",
        "name": "Clean IP Baseline",
        "description": "Google DNS (clean reputation) - demonstrates baseline for comparison",
        "severity": "low",
        "category": "baseline",
        "ip": "8.8.8.8",  # Google DNS - known clean
        "alternate_ips": ["8.8.4.4", "1.1.1.1"],  # Cloudflare DNS
        "rotate_ips": False,
        "expected_results": {
            "abuseipdb_score": "0-10",
            "virustotal": "0 detections",
            "threat_level": "CLEAN",
            "ml_anomaly": False
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Accepted publickey for deploy from {ip} port {port} ssh2"
    },

    # NEW SCENARIOS
    "vpn_proxy_attack": {
        "id": "vpn_proxy_attack",
        "name": "VPN/Proxy Attack",
        "description": "Attack from known VPN/proxy service - demonstrates anonymization detection",
        "severity": "high",
        "category": "anonymization",
        "ip": "103.216.221.19",  # Known VPN IP
        "alternate_ips": ["45.142.212.61", "91.240.118.172"],
        "rotate_ips": True,
        "expected_results": {
            "abuseipdb_score": ">40",
            "virustotal": "Possible detections",
            "threat_level": "MEDIUM-HIGH",
            "ml_anomaly": True
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Failed password for admin from {ip} port {port} ssh2"
    },

    "credential_stuffing": {
        "id": "credential_stuffing",
        "name": "Credential Stuffing Attack",
        "description": "Automated credential stuffing with multiple usernames - demonstrates pattern recognition",
        "severity": "critical",
        "category": "authentication",
        "ip": "45.227.254.0",  # Known credential stuffing source
        "alternate_ips": ["193.56.28.103", "185.220.101.1"],
        "rotate_ips": True,
        "expected_results": {
            "abuseipdb_score": ">60",
            "virustotal": "Multiple detections",
            "threat_level": "HIGH",
            "ml_anomaly": True
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Failed password for invalid user {username} from {ip} port {port} ssh2"
    },

    "datacenter_attack": {
        "id": "datacenter_attack",
        "name": "Datacenter/Hosting IP Attack",
        "description": "Attack from datacenter IP - often indicates compromised VPS",
        "severity": "high",
        "category": "infrastructure",
        "ip": "167.172.248.37",  # DigitalOcean datacenter
        "alternate_ips": ["206.189.156.201", "159.89.133.246"],
        "rotate_ips": True,
        "expected_results": {
            "abuseipdb_score": ">30",
            "virustotal": "Possible detections",
            "threat_level": "MEDIUM",
            "ml_anomaly": True
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"
    },

    "port_scanner": {
        "id": "port_scanner",
        "name": "Port Scanner Attack",
        "description": "Automated port scanning activity - demonstrates reconnaissance detection",
        "severity": "medium",
        "category": "reconnaissance",
        "ip": "162.142.125.0",  # Known scanner
        "alternate_ips": ["91.240.118.172", "185.220.101.1"],
        "rotate_ips": True,
        "expected_results": {
            "abuseipdb_score": ">20",
            "virustotal": "Possible detections",
            "threat_level": "LOW-MEDIUM",
            "ml_anomaly": True
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Failed password for invalid user test from {ip} port {port} ssh2"
    },

    "ransomware_c2": {
        "id": "ransomware_c2",
        "name": "Ransomware C2 Server",
        "description": "Known ransomware command & control server - critical threat",
        "severity": "critical",
        "category": "malware",
        "ip": "185.220.101.54",  # Known malicious infra
        "alternate_ips": ["193.56.28.103", "45.142.212.61"],
        "rotate_ips": True,
        "expected_results": {
            "abuseipdb_score": ">80",
            "virustotal": "Multiple detections",
            "threat_level": "CRITICAL",
            "ml_anomaly": True
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"
    },

    "ddos_botnet": {
        "id": "ddos_botnet",
        "name": "DDoS Botnet Node",
        "description": "Compromised host in DDoS botnet - demonstrates botnet detection",
        "severity": "critical",
        "category": "malware",
        "ip": "185.156.73.0",  # Known botnet IP
        "alternate_ips": ["91.240.118.172", "193.56.28.103"],
        "rotate_ips": True,
        "expected_results": {
            "abuseipdb_score": ">70",
            "virustotal": "Multiple detections",
            "threat_level": "HIGH",
            "ml_anomaly": True
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Failed password for invalid user admin from {ip} port {port} ssh2"
    },

    "nation_state_apt": {
        "id": "nation_state_apt",
        "name": "Nation-State APT",
        "description": "Advanced Persistent Threat from nation-state actor - demonstrates high-sophistication attacks",
        "severity": "critical",
        "category": "apt",
        "ip": "39.96.0.0",  # Alibaba Cloud - often used by APTs
        "alternate_ips": ["218.92.0.107", "45.142.212.61"],
        "rotate_ips": True,
        "expected_results": {
            "abuseipdb_score": ">50",
            "virustotal": "Multiple detections",
            "threat_level": "HIGH",
            "ml_anomaly": True
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"
    }
}


def get_demo_scenarios() -> List[Dict]:
    """Get list of all demo scenarios for UI"""
    scenarios = []
    for scenario_id, scenario in DEMO_SCENARIOS.items():
        scenarios.append({
            "id": scenario["id"],
            "name": scenario["name"],
            "description": scenario["description"],
            "severity": scenario["severity"],
            "category": scenario["category"],
            "ip": scenario["ip"],
            "expected_results": scenario["expected_results"]
        })
    return scenarios


def get_demo_scenario(scenario_id: str) -> Optional[Dict]:
    """Get a specific demo scenario"""
    return DEMO_SCENARIOS.get(scenario_id)


def get_rotated_ip(scenario_id: str) -> str:
    """
    Get IP for scenario with optional rotation.

    Returns:
        IP address - either default or rotated from alternate_ips
    """
    import random

    scenario = DEMO_SCENARIOS.get(scenario_id)
    if not scenario:
        return None

    # Check if rotation is enabled
    if scenario.get('rotate_ips', False) and scenario.get('alternate_ips'):
        # Randomly choose between default IP and alternates
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


def run_demo_scenario(scenario_id: str, verbose: bool = True) -> Dict:
    """
    Execute a single demo scenario with full enrichment pipeline.

    Args:
        scenario_id: ID of the demo scenario to run
        verbose: Print progress messages

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
    result = process_log_line(log_line, source_type='agent')

    if result.get('success'):
        enrichment = result.get('enrichment', {})

        demo_result = {
            "success": True,
            "scenario_id": scenario_id,
            "scenario_name": scenario["name"],
            "ip": rotated_ip,  # Use the actual rotated IP
            "default_ip": scenario["ip"],  # Keep default for reference
            "ip_rotated": rotated_ip != scenario["ip"],  # Flag if IP was rotated
            "expected": scenario["expected_results"],
            "event_id": result.get('event_id'),
            "event_type": result.get('event_type'),
            "actual_results": {
                "geoip": enrichment.get('geoip'),
                "ml": enrichment.get('ml'),
                "threat_intel": enrichment.get('threat_intel')
            }
        }

        if verbose:
            print(f"\n{'='*60}")
            print("RESULTS:")
            print(f"{'='*60}")

            # Threat Intel
            threat = enrichment.get('threat_intel', {})
            if threat:
                abuse = threat.get('abuseipdb', {})
                vt = threat.get('virustotal', {})
                print(f"AbuseIPDB Score: {abuse.get('score', 'N/A')}")
                print(f"AbuseIPDB Reports: {abuse.get('reports', 'N/A')}")
                print(f"VirusTotal: {vt.get('positives', 0)}/{vt.get('total', 0)} detections")
                print(f"Threat Level: {threat.get('threat_level', 'unknown').upper()}")

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

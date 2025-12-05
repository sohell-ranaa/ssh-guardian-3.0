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
DEMO_SCENARIOS = {
    "tor_exit_attack": {
        "id": "tor_exit_attack",
        "name": "Tor Exit Node Attack",
        "description": "Known Tor exit node attempting root login - demonstrates detection of anonymized attacks",
        "severity": "critical",
        "category": "anonymization",
        "ip": "185.220.101.1",  # Known Tor exit node
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
        "expected_results": {
            "abuseipdb_score": "0-10",
            "virustotal": "0 detections",
            "threat_level": "CLEAN",
            "ml_anomaly": False
        },
        "log_template": "Dec {day} {time} prod-server sshd[{pid}]: Accepted publickey for deploy from {ip} port {port} ssh2"
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


def generate_demo_log(scenario_id: str) -> Optional[str]:
    """Generate a log line for a demo scenario"""
    import random

    scenario = DEMO_SCENARIOS.get(scenario_id)
    if not scenario:
        return None

    now = datetime.now()
    log = scenario["log_template"].format(
        day=now.day,
        time=now.strftime("%H:%M:%S"),
        pid=random.randint(10000, 99999),
        ip=scenario["ip"],
        port=random.randint(40000, 65000)
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

    # Generate log line
    log_line = generate_demo_log(scenario_id)

    if verbose:
        print(f"\nLog: {log_line}")
        print(f"\nProcessing...")

    # Process through full pipeline
    result = process_log_line(log_line, source_type='agent')

    if result.get('success'):
        enrichment = result.get('enrichment', {})

        demo_result = {
            "success": True,
            "scenario_id": scenario_id,
            "scenario_name": scenario["name"],
            "ip": scenario["ip"],
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
                print(f"ML Confidence: {ml.get('confidence', 0)*100:.1f}%")
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

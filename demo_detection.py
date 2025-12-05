#!/usr/bin/env python3
"""
SSH Guardian v3.0 - Detection Demo Script
Run this to demonstrate the full detection pipeline to supervisors/stakeholders
"""

import sys
import os

# Change to project root
os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.append('dbs')
sys.path.append('src')

from core.log_processor import process_log_line
import json
from datetime import datetime


def print_header():
    print("\n" + "=" * 80)
    print("   SSH GUARDIAN v3.0 - THREAT DETECTION DEMONSTRATION")
    print("   " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 80)


def print_section(title):
    print(f"\n{'─' * 80}")
    print(f"  {title}")
    print(f"{'─' * 80}")


def run_demo():
    print_header()

    # Known malicious/suspicious IPs for demonstration
    test_cases = [
        {
            'name': '🔴 Tor Exit Node Attack',
            'description': 'Known Tor exit node attempting root login',
            'log': 'Dec  5 10:00:01 prod-server sshd[9999]: Failed password for root from 185.220.101.1 port 54321 ssh2',
            'expected': 'HIGH RISK - Known Tor exit with 100/100 AbuseIPDB score'
        },
        {
            'name': '🟠 Brute Force Attack',
            'description': 'Invalid user enumeration from hosting provider',
            'log': 'Dec  5 10:00:02 prod-server sshd[9999]: Failed password for invalid user administrator from 45.227.255.206 port 54322 ssh2',
            'expected': 'ML should detect anomaly based on behavior pattern'
        },
        {
            'name': '🟡 Geographic Anomaly',
            'description': 'Login attempt from high-risk geographic location',
            'log': 'Dec  5 10:00:03 prod-server sshd[9999]: Failed password for root from 218.92.0.107 port 54323 ssh2',
            'expected': 'VirusTotal detections + high-risk country'
        },
        {
            'name': '🟢 Legitimate Login (Baseline)',
            'description': 'Successful login from clean IP',
            'log': 'Dec  5 10:00:04 prod-server sshd[9999]: Accepted publickey for deploy from 8.8.8.8 port 54324 ssh2',
            'expected': 'LOW RISK - Clean IP, successful auth'
        },
    ]

    results = []

    for i, test in enumerate(test_cases, 1):
        print_section(f"TEST {i}: {test['name']}")
        print(f"  📝 Description: {test['description']}")
        print(f"  📋 Expected: {test['expected']}")
        print(f"  📨 Log Line: {test['log'][:70]}...")
        print()

        # Process the log line
        result = process_log_line(test['log'], source_type='agent')

        if result.get('success'):
            enrichment = result.get('enrichment', {})

            # Extract results
            ml = enrichment.get('ml', {})
            threat = enrichment.get('threat_intel', {})

            print("\n  📊 DETECTION RESULTS:")
            print("  " + "─" * 50)

            # Threat Intel
            if threat:
                abuse = threat.get('abuseipdb', {})
                vt = threat.get('virustotal', {})
                level = threat.get('threat_level', 'unknown').upper()

                print(f"  │ AbuseIPDB Score:    {abuse.get('score', 'N/A')}/100 ({abuse.get('reports', 0)} reports)")
                print(f"  │ VirusTotal:         {vt.get('positives', 0)}/{vt.get('total', 0)} vendors")
                print(f"  │ API Threat Level:   {level}")

            # ML Prediction
            if ml.get('ml_available'):
                risk = ml.get('risk_score', 0)
                risk_bar = '█' * (risk // 10) + '░' * (10 - risk // 10)

                print(f"  │ ")
                print(f"  │ ML Risk Score:      {risk}/100 [{risk_bar}]")
                print(f"  │ ML Threat Type:     {ml.get('threat_type') or 'normal'}")
                print(f"  │ ML Confidence:      {ml.get('confidence', 0)*100:.1f}%")
                print(f"  │ Anomaly Detected:   {'🚨 YES' if ml.get('is_anomaly') else '✓ NO'}")

            print("  " + "─" * 50)

            # Store for summary
            results.append({
                'test': test['name'],
                'risk': ml.get('risk_score', 0),
                'anomaly': ml.get('is_anomaly', False),
                'threat_level': threat.get('threat_level', 'unknown') if threat else 'unknown',
                'abuse_score': threat.get('abuseipdb', {}).get('score', 0) if threat else 0
            })
        else:
            print(f"  ❌ Error: {result.get('error')}")

    # Print Summary
    print_section("📈 SUMMARY")
    print("\n  Test Case                      │ Risk │ Anomaly │ Threat Level │ AbuseIPDB")
    print("  " + "─" * 75)

    for r in results:
        anomaly = "🚨 YES" if r['anomaly'] else "   NO"
        print(f"  {r['test']:<30} │ {r['risk']:>3}  │ {anomaly:<7} │ {r['threat_level']:<12} │ {r['abuse_score']}")

    print("\n" + "=" * 80)
    print("  DEMONSTRATION COMPLETE")
    print("=" * 80 + "\n")


if __name__ == '__main__':
    run_demo()
